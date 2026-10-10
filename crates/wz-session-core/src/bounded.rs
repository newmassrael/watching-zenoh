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
//! and only the storage backing swaps. Two backings, selected by two
//! features, because "an allocator is linked" and "the declared
//! capacities are hard" are different facts about a build:
//!
//! - **growable** (`alloc` on, `bounded-heapless` off — the AP profile)
//!   — backed by `alloc::vec::Vec<T>`. [`push`](BoundedVec::push) never
//!   fails; the declared capacity `N` is advisory (AP is the
//!   dynamic-opt-in side and may exceed it).
//! - **fixed** (`alloc` off, OR `bounded-heapless` on — the MCU
//!   profiles) — backed by `heapless::Vec<T, N>`.
//!   [`push`](BoundedVec::push) returns [`CapacityFull`] when the
//!   declared capacity `N` is full. There is no silent drop — the
//!   caller decides what to do with the rejected value, mirroring
//!   zenoh-pico's table-full reject (and the §2.1 build-time-enforced
//!   bounded declared-subscription table).
//!
//! `bounded-heapless` is what lets an MCU build keep `alloc` for the
//! rest of the session machinery and still get every
//! [`crate::caps`] limit as a hard bound; before it, `alloc` alone chose
//! the growable backing, so on every MCU deploy (all of which link an
//! allocator) the caps were advisory and `TableFull` was unreachable.
//! [`crate::bounded::ENFORCES_CAPACITY`] states which backing a build compiled, for a
//! consumer that must refuse to build on the wrong one.
//!
//! The fallible-push signature is identical on both backings, so the
//! caller writes one capacity-aware code path; the growable build's
//! `Ok(())` arm is simply never taken on the failure side. `N` is the
//! deploy-declared capacity (the wiring of `N` from `deploy.yaml`
//! lands with the first registry migration; this module only fixes the
//! container contract).

#[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
use alloc::string::String;
#[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
use alloc::vec::Vec;

use core::fmt;
use core::ops::{Deref, DerefMut};

/// Whether this build compiled the FIXED backing, on which every push past
/// the declared capacity `N` is refused. `false` means the growable backing,
/// on which `N` is advisory and no push fails.
///
/// For a consumer whose code relies on one of the two: an AP crate that
/// treats a registration as infallible asserts `!ENFORCES_CAPACITY` at
/// compile time, so a build graph that unifies `bounded-heapless` into it
/// fails to build instead of panicking at the first table that fills.
pub const ENFORCES_CAPACITY: bool = cfg!(any(not(feature = "alloc"), feature = "bounded-heapless"));

/// Error returned by [`BoundedVec::push`] when the fixed backing has
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
/// growable (AP) vs fixed (MCU) backing contract.
#[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
pub struct BoundedVec<T, const N: usize> {
    inner: Vec<T>,
}

/// Capacity-generic owned sequence. See the [module docs](self) for the
/// growable (AP) vs fixed (MCU) backing contract.
#[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
pub struct BoundedVec<T, const N: usize> {
    inner: heapless::Vec<T, N>,
}

impl<T, const N: usize> BoundedVec<T, N> {
    /// Construct an empty backing store. `const` on both backings so a
    /// registry may hold a `BoundedVec` in a `const`/`static` slot.
    #[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
    pub const fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Construct an empty backing store. `const` on both backings so a
    /// registry may hold a `BoundedVec` in a `const`/`static` slot.
    #[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
    pub const fn new() -> Self {
        Self {
            inner: heapless::Vec::new(),
        }
    }

    /// The declared logical capacity `N`. Advisory on the growable
    /// backing (AP may exceed it); the hard limit `push` enforces on
    /// the fixed backing.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// How many more pushes are guaranteed to succeed: `N - len` on the
    /// fixed backing, and `usize::MAX` on the growable one, where no push
    /// fails.
    ///
    /// For a caller that stages a group of entries which is only correct
    /// WHOLE (a reply chain and its terminating `Final`): checking room for
    /// the whole group first is what lets it refuse the group instead of
    /// staging half of it.
    #[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
    pub fn free_slots(&self) -> usize {
        usize::MAX
    }

    /// How many more pushes are guaranteed to succeed. See the growable
    /// arm for the contract; this one answers `N - len`.
    #[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
    pub fn free_slots(&self) -> usize {
        N - self.inner.len()
    }

    /// Append `value`. On the growable backing this always returns
    /// `Ok(())`. On the fixed backing it returns
    /// `Err(CapacityFull(value))` once `N` entries are present.
    #[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
    pub fn push(&mut self, value: T) -> Result<(), CapacityFull<T>> {
        self.inner.push(value);
        Ok(())
    }

    /// Append `value`. On the growable backing this always returns
    /// `Ok(())`. On the fixed backing it returns
    /// `Err(CapacityFull(value))` once `N` entries are present.
    #[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
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

/// Byte-specific, because the caller is a FILLER rather than a pusher.
impl<const N: usize> BoundedVec<u8, N> {
    /// Shorten to `len`, dropping the tail. No-op when already shorter.
    ///
    /// The counterpart to [`Self::grow_for_fill`]: a filler that used less
    /// than it reserved gives the remainder back through here, so the two
    /// calls together leave exactly what was written. Both backings spell it
    /// the same way, so this needs no split.
    pub fn truncate(&mut self, len: usize) {
        self.inner.truncate(len);
    }

    /// Materialise `want` more bytes at the end and hand back exactly those,
    /// for a writer that fills them IN PLACE -- a socket read, a DMA
    /// completion -- rather than pushing one byte at a time.
    ///
    /// This is the shape [`Self::push`] cannot be. A filler that writes
    /// through a `&mut [u8]` needs the bytes to EXIST before it runs and
    /// reports how many it actually used only afterwards, so the sequence is
    /// grow -> fill -> truncate rather than push-per-byte. It is the same seam
    /// `wz-link-lwip`'s `RxSlots::buf` opens over a pool slot; this is the
    /// heap-backed half, so one staging trait can serve both.
    ///
    /// TAKES A LENGTH rather than handing back the declared capacity, and that
    /// is the load-bearing choice: this type's contract is that a live
    /// collection costs what it actually staged, and returning an `N`-wide
    /// slice would force zero-filling to `N` and break exactly the property
    /// that makes the heap backing cheap. The cost here is `want`.
    ///
    /// The two backings differ the same way [`Self::push`] documents: `N` is
    /// advisory on the growable backing (AP may exceed it) and a hard limit on
    /// the fixed one, where passing it returns `CapacityFull` rather than
    /// growing.
    #[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
    pub fn grow_for_fill(&mut self, want: usize) -> Result<&mut [u8], CapacityFull<()>> {
        let start = self.inner.len();
        let end = start.checked_add(want).ok_or(CapacityFull(()))?;
        self.inner.resize(end, 0);
        Ok(&mut self.inner[start..end])
    }

    /// Materialise `want` more bytes at the end and hand back exactly those.
    /// See the growable arm for the contract; this one enforces `N`.
    #[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
    pub fn grow_for_fill(&mut self, want: usize) -> Result<&mut [u8], CapacityFull<()>> {
        let start = self.inner.len();
        let end = start.checked_add(want).ok_or(CapacityFull(()))?;
        // Checked here rather than left to `resize`, so the refusal is this
        // type's declared bound `N` and not whatever the backing happens to
        // have room for.
        if end > N {
            return Err(CapacityFull(()));
        }
        self.inner.resize(end, 0).map_err(|()| CapacityFull(()))?;
        Ok(&mut self.inner[start..end])
    }
}

impl<T, const N: usize> Default for BoundedVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

// By-value `IntoIterator` consumes the backing into an owning iterator on
// both profiles. Registries that must remove-then-fire under the fixed
// backing (the reply registry's `fire_final_for` / `sweep_timed_out`
// drain-partition-fire pattern) take the table with `core::mem::take` and
// iterate it by value into bounded `keep` / `fired` partitions — no heap
// temporary on the MCU profile.
#[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
impl<T, const N: usize> IntoIterator for BoundedVec<T, N> {
    type Item = T;
    type IntoIter = alloc::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

#[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
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
/// - **growable (AP)** — backed by `alloc::string::String`;
///   [`push_str`](BoundedString::push_str) never fails, `N` is
///   advisory.
/// - **fixed (MCU)** — backed by `heapless::String<N>`;
///   [`push_str`](BoundedString::push_str) returns [`CapacityFull`]
///   when the append would exceed the declared `N` *bytes*, leaving
///   the buffer unchanged (heapless append is atomic — no partial
///   write). The caller decides; never a silent truncation.
///
/// Implements [`core::fmt::Write`] on both backings, so the value
/// modules can build output with `write!` / `core::fmt` machinery and
/// get the same capacity-failure surface (`fmt::Error` on overflow).
#[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
pub struct BoundedString<const N: usize> {
    inner: String,
}

/// Capacity-generic owned UTF-8 string. See the type docs for the
/// growable (AP) vs fixed (MCU) backing contract.
#[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
pub struct BoundedString<const N: usize> {
    inner: heapless::String<N>,
}

impl<const N: usize> BoundedString<N> {
    /// Construct an empty string. `const` on both backings.
    #[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
    pub const fn new() -> Self {
        Self {
            inner: String::new(),
        }
    }

    /// Construct an empty string. `const` on both backings.
    #[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
    pub const fn new() -> Self {
        Self {
            inner: heapless::String::new(),
        }
    }

    /// The declared logical byte capacity `N`. Advisory on the growable
    /// backing; the hard byte limit `push_str` / `push` enforce on the
    /// fixed backing.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Append a string slice. `Ok(())` always on the growable backing;
    /// `Err(CapacityFull(()))` on the fixed backing when the append
    /// would exceed `N` bytes (buffer left unchanged).
    #[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
    pub fn push_str(&mut self, s: &str) -> Result<(), CapacityFull<()>> {
        self.inner.push_str(s);
        Ok(())
    }

    /// Append a string slice. `Ok(())` always on the growable backing;
    /// `Err(CapacityFull(()))` on the fixed backing when the append
    /// would exceed `N` bytes (buffer left unchanged).
    #[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
    pub fn push_str(&mut self, s: &str) -> Result<(), CapacityFull<()>> {
        self.inner.push_str(s).map_err(|_| CapacityFull(()))
    }

    /// Append one `char`. Capacity semantics mirror [`push_str`].
    #[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
    pub fn push(&mut self, c: char) -> Result<(), CapacityFull<char>> {
        self.inner.push(c);
        Ok(())
    }

    /// Append one `char`. Capacity semantics mirror [`push_str`].
    #[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
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
// `write!` / `core::fmt`; the fixed backing surfaces a full buffer
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

    // Capacity overflow is backing-specific: only the fixed backing
    // enforces `N`. On the growable backing push is infinite (AP is the
    // dynamic-opt-in side), so the overflow assertion is gated off it.
    #[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
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

    #[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
    #[test]
    fn push_past_declared_capacity_grows_on_alloc() {
        let mut v: BoundedVec<u32, 2> = BoundedVec::new();
        for i in 0..8 {
            assert!(v.push(i).is_ok());
        }
        assert_eq!(v.len(), 8);
        assert_eq!(v.capacity(), 2);
    }

    // `free_slots` is what a whole-group stager reserves against, so it has
    // to agree with `push` on each backing: exactly the pushes that succeed.
    #[test]
    fn free_slots_counts_the_pushes_that_still_succeed() {
        let mut v: BoundedVec<u32, 2> = BoundedVec::new();
        v.push(1).unwrap();
        if ENFORCES_CAPACITY {
            assert_eq!(v.free_slots(), 1);
            v.push(2).unwrap();
            assert_eq!(v.free_slots(), 0);
            assert!(v.push(3).is_err());
        } else {
            assert_eq!(v.free_slots(), usize::MAX);
            v.push(2).unwrap();
            assert!(v.push(3).is_ok(), "the growable backing refuses nothing");
            assert_eq!(v.free_slots(), usize::MAX);
        }
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

    // The fixed backing enforces the byte cap atomically (no partial
    // write). Gated off the growable backing, which grows past `N`.
    #[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
    #[test]
    fn string_push_past_capacity_rejects_atomically_no_alloc() {
        let mut s: BoundedString<4> = BoundedString::new();
        assert!(s.push_str("abcd").is_ok());
        assert!(s.push_str("e").is_err());
        assert!(s.push('x').is_err());
        // Buffer unchanged by the rejected appends.
        assert_eq!(s.as_str(), "abcd");
    }

    #[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
    #[test]
    fn string_grows_past_declared_capacity_on_alloc() {
        let mut s: BoundedString<4> = BoundedString::new();
        assert!(s.push_str("abcdefgh").is_ok());
        assert_eq!(s.as_str(), "abcdefgh");
        assert_eq!(s.capacity(), 4);
    }
}
