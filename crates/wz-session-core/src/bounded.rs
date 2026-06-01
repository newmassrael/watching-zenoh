// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
