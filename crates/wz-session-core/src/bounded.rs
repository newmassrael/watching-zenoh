// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Capacity-generic backing seams (`BoundedVec<T, N, P>` +
//! `BoundedString<N, P>`) for the application-layer registries and the
//! owned-output value modules.
//!
//! ARCHITECTURE.md §2.4 mandates `static-first, dynamic-opt-in`: one
//! registry implementation that backs onto a heap-free bounded buffer
//! on MCU (`platform.class = mcu`, the no-heap permanent constraint
//! §2.3) and onto an unbounded `alloc::Vec` on AP (a general-purpose
//! machine with none of those constraints, §2.3 note). This module is
//! that seam: registry logic is written once against `BoundedVec`, and
//! only the storage backing swaps.
//!
//! # The storage policy
//!
//! The backing is a type parameter, a [`Storage`] policy, not a feature that
//! selects code (`docs/storage-policy-and-link-layer.md`, D1). There are two
//! policies, because "an allocator is linked" and "the declared capacities are
//! hard" are different facts about a build:
//!
//! - [`Heap`] (needs `alloc`) -- backed by `alloc::vec::Vec<T>` and
//!   `alloc::string::String`. [`push`](BoundedVec::push) never fails; the
//!   declared capacity `N` is advisory (AP is the dynamic-opt-in side and may
//!   exceed it).
//! - [`Static`] -- backed by `heapless::Vec<T, N>` and `heapless::String<N>`.
//!   [`push`](BoundedVec::push) returns [`CapacityFull`] when the declared
//!   capacity `N` is full. There is no silent drop: the caller decides what to
//!   do with the rejected value, mirroring zenoh-pico's table-full reject (and
//!   the §2.1 build-time-enforced bounded declared-subscription table).
//!
//! A container names its policy as its last parameter and defaults it to
//! [`Profile`], the policy this build's features choose (`alloc` on and
//! `bounded-heapless` off selects [`Heap`]; `alloc` off, or `bounded-heapless`
//! on, selects [`Static`]). Every existing `BoundedVec<T, N>` is therefore the
//! build's profile and reads as before. A test that wants BOTH policies in one
//! build writes the algorithm once, generic over `P: Storage`, and runs it on
//! each (see the tests at the end of this file).
//!
//! `bounded-heapless` is what lets an MCU build keep `alloc` for the rest of the
//! session machinery and still get every [`crate::caps`] limit as a hard bound.
//! [`ENFORCES_CAPACITY`] states which policy the profile is, for a consumer that
//! must refuse to build on the wrong one.
//!
//! The fallible-push signature is identical on both policies, so the caller
//! writes one capacity-aware code path; the [`Heap`] build's `Ok(())` arm is
//! simply never taken on the failure side. `N` is the deploy-declared capacity.

use core::fmt;
use core::ops::{Deref, DerefMut};

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Whether this build's [`Profile`] is the FIXED policy, on which every push past
/// the declared capacity `N` is refused. `false` means the [`Heap`] policy, on
/// which `N` is advisory and no push fails.
///
/// For a consumer whose code relies on one of the two: an AP crate that
/// treats a registration as infallible asserts `!ENFORCES_CAPACITY` at
/// compile time, so a build graph that unifies `bounded-heapless` into it
/// fails to build instead of panicking at the first table that fills.
pub const ENFORCES_CAPACITY: bool = <Profile as Storage>::ENFORCES_CAPACITY;

/// Error returned by [`BoundedVec::push`] when the fixed backing has
/// reached its declared capacity `N`. Carries the rejected value back
/// to the caller so it can be recovered, retried, or logged -- never
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

/// How a container holds its elements: the storage policy of
/// `docs/storage-policy-and-link-layer.md` D1. Implemented by [`Heap`] and
/// [`Static`]; a container is generic over it and the algorithm around the
/// container is written once.
pub trait Storage {
    /// Whether a push past the declared capacity is refused (`true`) or the
    /// backing grows past it (`false`).
    const ENFORCES_CAPACITY: bool;

    /// The element sequence of a [`BoundedVec<T, N, Self>`].
    type Seq<T, const N: usize>: SeqBacking<T>;

    /// The UTF-8 text of a [`BoundedString<N, Self>`].
    type Text<const N: usize>: TextBacking;

    /// The integer a table of this policy addresses its own bytes with (a span
    /// into an arena). A policy that fixes its capacity in the type needs only as
    /// many bits as the capacity, and its rows are that much smaller; one that
    /// grows with the allocator needs the width of an allocation.
    type Offset: SpanOffset;
}

/// An unsigned integer that addresses bytes of a table: the width a [`Storage`]
/// policy gives its spans.
pub trait SpanOffset: Copy {
    /// The largest byte offset this width can hold.
    const MAX: usize;

    /// The offset `n`, which the caller has checked against [`Self::MAX`].
    fn from_usize(n: usize) -> Self;

    /// This offset as a `usize`.
    fn to_usize(self) -> usize;
}

impl SpanOffset for u16 {
    const MAX: usize = u16::MAX as usize;

    #[inline(always)]
    fn from_usize(n: usize) -> Self {
        n as u16
    }

    #[inline(always)]
    fn to_usize(self) -> usize {
        usize::from(self)
    }
}

impl SpanOffset for u32 {
    const MAX: usize = u32::MAX as usize;

    #[inline(always)]
    fn from_usize(n: usize) -> Self {
        n as u32
    }

    #[inline(always)]
    fn to_usize(self) -> usize {
        self as usize
    }
}

/// The operations a [`BoundedVec`] needs of the sequence a [`Storage`] policy
/// holds. Each policy spells them with its own container; the container above
/// them is written once.
pub trait SeqBacking<T>: Sized + IntoIterator<Item = T> {
    /// The empty sequence. A function and not an associated constant: a constant
    /// of a type with an inline buffer is materialised, so every use of it
    /// writes the whole buffer (measured: a 260-byte clear in the keyexpr
    /// canonizer), where a call is inlined to a length of zero and nothing else.
    fn empty() -> Self;

    /// The elements, in order.
    fn as_slice(&self) -> &[T];

    /// The elements, in order, mutably.
    fn as_mut_slice(&mut self) -> &mut [T];

    /// How many more pushes are guaranteed to succeed.
    fn free_slots(&self) -> usize;

    /// Append `value`, or hand it back when the policy's capacity is full.
    fn push(&mut self, value: T) -> Result<(), CapacityFull<T>>;

    /// Remove and return the last element, if any.
    fn pop(&mut self) -> Option<T>;

    /// Keep only the elements for which `keep` returns `true`, in order.
    fn retain<F: FnMut(&T) -> bool>(&mut self, keep: F);

    /// Remove every element.
    fn clear(&mut self);

    /// Shorten to `len`; a no-op when already shorter.
    fn truncate(&mut self, len: usize);

    /// Grow or shorten to `len`, filling new slots with `fill`. The refusal is
    /// the policy's declared capacity, not whatever the backing happens to have
    /// room for.
    fn resize(&mut self, len: usize, fill: T) -> Result<(), CapacityFull<()>>
    where
        T: Clone;

    /// Append every element of `src` in one operation, all or nothing.
    fn extend_from_slice(&mut self, src: &[T]) -> Result<(), CapacityFull<()>>
    where
        T: Clone;
}

/// The operations a [`BoundedString`] needs of the text a [`Storage`] policy
/// holds.
pub trait TextBacking: Sized + Clone {
    /// The empty text. A function for the reason [`SeqBacking::empty`] is.
    fn empty() -> Self;

    /// The contents.
    fn as_str(&self) -> &str;

    /// Append `s`, leaving the text unchanged when it is refused.
    fn push_str(&mut self, s: &str) -> Result<(), CapacityFull<()>>;

    /// Append one `char`, leaving the text unchanged when it is refused.
    fn push(&mut self, c: char) -> Result<(), CapacityFull<char>>;

    /// Remove every byte.
    fn clear(&mut self);
}

/// The growable policy: the allocator. `N` is advisory; nothing is refused.
#[cfg(feature = "alloc")]
pub struct Heap;

#[cfg(feature = "alloc")]
impl Storage for Heap {
    const ENFORCES_CAPACITY: bool = false;
    type Seq<T, const N: usize> = Vec<T>;
    type Text<const N: usize> = String;
    type Offset = u32;
}

/// The static policy: a capacity fixed in the type and no allocator. A push past
/// `N` is refused and hands the value back.
pub struct Static;

impl Storage for Static {
    const ENFORCES_CAPACITY: bool = true;
    type Seq<T, const N: usize> = heapless::Vec<T, N>;
    type Text<const N: usize> = heapless::String<N>;
    type Offset = u16;
}

/// The policy this build's features choose, and the default of every container's
/// policy parameter: [`Heap`] when `alloc` is on and `bounded-heapless` is off.
#[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
pub type Profile = Heap;

/// The policy this build's features choose, and the default of every container's
/// policy parameter: [`Static`] when `alloc` is off, or `bounded-heapless` is on.
#[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
pub type Profile = Static;

#[cfg(feature = "alloc")]
impl<T> SeqBacking<T> for Vec<T> {
    #[inline(always)]
    fn empty() -> Self {
        Vec::new()
    }

    fn as_slice(&self) -> &[T] {
        Vec::as_slice(self)
    }

    fn as_mut_slice(&mut self) -> &mut [T] {
        Vec::as_mut_slice(self)
    }

    fn free_slots(&self) -> usize {
        usize::MAX
    }

    fn push(&mut self, value: T) -> Result<(), CapacityFull<T>> {
        Vec::push(self, value);
        Ok(())
    }

    fn pop(&mut self) -> Option<T> {
        Vec::pop(self)
    }

    fn retain<F: FnMut(&T) -> bool>(&mut self, keep: F) {
        Vec::retain(self, keep);
    }

    fn clear(&mut self) {
        Vec::clear(self);
    }

    fn truncate(&mut self, len: usize) {
        Vec::truncate(self, len);
    }

    fn resize(&mut self, len: usize, fill: T) -> Result<(), CapacityFull<()>>
    where
        T: Clone,
    {
        Vec::resize(self, len, fill);
        Ok(())
    }

    fn extend_from_slice(&mut self, src: &[T]) -> Result<(), CapacityFull<()>>
    where
        T: Clone,
    {
        Vec::extend_from_slice(self, src);
        Ok(())
    }
}

impl<T, const N: usize> SeqBacking<T> for heapless::Vec<T, N> {
    #[inline(always)]
    fn empty() -> Self {
        heapless::Vec::new()
    }

    fn as_slice(&self) -> &[T] {
        heapless::Vec::as_slice(self)
    }

    fn as_mut_slice(&mut self) -> &mut [T] {
        heapless::Vec::as_mut_slice(self)
    }

    fn free_slots(&self) -> usize {
        N - self.len()
    }

    fn push(&mut self, value: T) -> Result<(), CapacityFull<T>> {
        heapless::Vec::push(self, value).map_err(CapacityFull)
    }

    fn pop(&mut self) -> Option<T> {
        heapless::Vec::pop(self)
    }

    fn retain<F: FnMut(&T) -> bool>(&mut self, keep: F) {
        heapless::Vec::retain(self, keep);
    }

    fn clear(&mut self) {
        heapless::Vec::clear(self);
    }

    fn truncate(&mut self, len: usize) {
        heapless::Vec::truncate(self, len);
    }

    fn resize(&mut self, len: usize, fill: T) -> Result<(), CapacityFull<()>>
    where
        T: Clone,
    {
        // Checked here rather than left to `resize`, so the refusal is the
        // declared bound `N` and not whatever the backing happens to have room
        // for.
        if len > N {
            return Err(CapacityFull(()));
        }
        heapless::Vec::resize(self, len, fill).map_err(|_| CapacityFull(()))
    }

    fn extend_from_slice(&mut self, src: &[T]) -> Result<(), CapacityFull<()>>
    where
        T: Clone,
    {
        heapless::Vec::extend_from_slice(self, src).map_err(|_| CapacityFull(()))
    }
}

#[cfg(feature = "alloc")]
impl TextBacking for String {
    #[inline(always)]
    fn empty() -> Self {
        String::new()
    }

    fn as_str(&self) -> &str {
        String::as_str(self)
    }

    fn push_str(&mut self, s: &str) -> Result<(), CapacityFull<()>> {
        String::push_str(self, s);
        Ok(())
    }

    fn push(&mut self, c: char) -> Result<(), CapacityFull<char>> {
        String::push(self, c);
        Ok(())
    }

    fn clear(&mut self) {
        String::clear(self);
    }
}

impl<const N: usize> TextBacking for heapless::String<N> {
    #[inline(always)]
    fn empty() -> Self {
        heapless::String::new()
    }

    fn as_str(&self) -> &str {
        heapless::String::as_str(self)
    }

    fn push_str(&mut self, s: &str) -> Result<(), CapacityFull<()>> {
        heapless::String::push_str(self, s).map_err(|_| CapacityFull(()))
    }

    fn push(&mut self, c: char) -> Result<(), CapacityFull<char>> {
        heapless::String::push(self, c).map_err(|_| CapacityFull(c))
    }

    fn clear(&mut self) {
        heapless::String::clear(self);
    }
}

/// Capacity-generic owned sequence. See the [module docs](self) for the
/// [`Heap`] vs [`Static`] policy contract.
pub struct BoundedVec<T, const N: usize, P: Storage = Profile> {
    inner: P::Seq<T, N>,
}

// The `const` constructors are written per concrete policy, because a `const fn`
// cannot call a trait function and a trait constant would be materialised at every
// use (see [`SeqBacking::empty`]). Generic code constructs through `Default`.
impl<T, const N: usize> BoundedVec<T, N, Static> {
    /// An empty table of the static policy. `const`, so a registry may hold it in
    /// a `const`/`static` slot.
    pub const fn new_static() -> Self {
        Self {
            inner: heapless::Vec::new(),
        }
    }
}

#[cfg(feature = "alloc")]
impl<T, const N: usize> BoundedVec<T, N, Heap> {
    /// An empty table of the heap policy. `const`, as [`Self::new_static`] is.
    pub const fn new_heap() -> Self {
        Self { inner: Vec::new() }
    }
}

impl<T, const N: usize> BoundedVec<T, N, Profile> {
    /// An empty table of this build's profile. `const` on both policies so a
    /// registry may hold a `BoundedVec` in a `const`/`static` slot. Defined for
    /// the profile alone, so `BoundedVec::new()` names its policy by itself.
    #[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
    pub const fn new() -> Self {
        Self::new_heap()
    }

    /// An empty table of this build's profile. See the heap form.
    #[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
    pub const fn new() -> Self {
        Self::new_static()
    }
}

impl<T, const N: usize, P: Storage> BoundedVec<T, N, P> {
    /// The declared logical capacity `N`. Advisory on [`Heap`] (AP may exceed
    /// it); the hard limit `push` enforces on [`Static`].
    pub const fn capacity(&self) -> usize {
        N
    }

    /// How many more pushes are guaranteed to succeed: `N - len` on [`Static`],
    /// and `usize::MAX` on [`Heap`], where no push fails.
    ///
    /// For a caller that stages a group of entries which is only correct
    /// WHOLE (a reply chain and its terminating `Final`): checking room for
    /// the whole group first is what lets it refuse the group instead of
    /// staging half of it.
    pub fn free_slots(&self) -> usize {
        self.inner.free_slots()
    }

    /// Append `value`. On [`Heap`] this always returns `Ok(())`. On [`Static`]
    /// it returns `Err(CapacityFull(value))` once `N` entries are present.
    pub fn push(&mut self, value: T) -> Result<(), CapacityFull<T>> {
        self.inner.push(value)
    }

    /// Remove and return the last entry, if any.
    pub fn pop(&mut self) -> Option<T> {
        self.inner.pop()
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
    /// entry behind -- every fired entry is already out of `self`.
    ///
    /// No-alloc: `self` is taken out via [`core::mem::take`] and rebuilt
    /// from the retained partition; `self` and the returned vec share
    /// capacity `N` (retained + extracted == taken <= N), so neither push
    /// can exceed `N`.
    pub fn drain_partition<F>(&mut self, mut extract: F) -> Self
    where
        F: FnMut(&mut T) -> bool,
    {
        let mut extracted: Self = Self::default();
        let mut keep: Self = Self::default();
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
impl<const N: usize, P: Storage> BoundedVec<u8, N, P> {
    /// Shorten to `len`, dropping the tail. No-op when already shorter.
    ///
    /// The counterpart to [`Self::grow_for_fill`]: a filler that used less
    /// than it reserved gives the remainder back through here, so the two
    /// calls together leave exactly what was written.
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
    /// The two policies differ the same way [`Self::push`] documents: `N` is
    /// advisory on [`Heap`] (AP may exceed it) and a hard limit on [`Static`],
    /// where passing it returns `CapacityFull` rather than growing.
    pub fn grow_for_fill(&mut self, want: usize) -> Result<&mut [u8], CapacityFull<()>> {
        let start = self.inner.as_slice().len();
        let end = start.checked_add(want).ok_or(CapacityFull(()))?;
        self.inner.resize(end, 0)?;
        Ok(&mut self.inner.as_mut_slice()[start..end])
    }

    /// Append every byte of `src` in one operation.
    ///
    /// R3365 -- the bulk form of [`Self::push`]. A caller that appends a slice by
    /// pushing its bytes one at a time pays a capacity check and a store per byte
    /// and keeps the compiler from turning the loop into a copy: measured on the
    /// reassembly path, one function that did exactly that was 85% of the
    /// instructions a subscriber executed for a 64 KiB message, about ten per byte.
    ///
    /// All or nothing on [`Static`]: `src` is refused whole when it does not fit,
    /// where a push loop would have staged a prefix first. [`Heap`] always
    /// succeeds, `N` being advisory there.
    pub fn extend_from_slice(&mut self, src: &[u8]) -> Result<(), CapacityFull<()>> {
        self.inner.extend_from_slice(src)
    }
}

/// The [`Heap`] policy's own buffer, moved out: no copy. What lets a collection
/// that was filled in place be handed on as storage of its own (a completed
/// reassembly chain, lent up to the application). Only [`Heap`] has a `Vec` to
/// give; the static policy's bytes are inline.
#[cfg(feature = "alloc")]
impl<const N: usize> BoundedVec<u8, N, Heap> {
    /// The buffer, moved out.
    pub fn into_vec(self) -> Vec<u8> {
        self.inner
    }
}

impl<T, const N: usize, P: Storage> Default for BoundedVec<T, N, P> {
    #[inline(always)]
    fn default() -> Self {
        Self {
            inner: <P::Seq<T, N> as SeqBacking<T>>::empty(),
        }
    }
}

// By-value `IntoIterator` consumes the backing into an owning iterator on both
// policies. Registries that must remove-then-fire under the static policy (the
// reply registry's `fire_final_for` / `sweep_timed_out` drain-partition-fire
// pattern) take the table with `core::mem::take` and iterate it by value into
// bounded `keep` / `fired` partitions -- no heap temporary on the MCU profile.
impl<T, const N: usize, P: Storage> IntoIterator for BoundedVec<T, N, P> {
    type Item = T;
    type IntoIter = <P::Seq<T, N> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

// Deref to the element slice gives `len` / `is_empty` / `iter` / `get` /
// indexing / `as_slice` for free on both policies, so the registry read paths
// are policy-agnostic without a hand-forwarded method per accessor.
impl<T, const N: usize, P: Storage> Deref for BoundedVec<T, N, P> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.inner.as_slice()
    }
}

impl<T, const N: usize, P: Storage> DerefMut for BoundedVec<T, N, P> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.inner.as_mut_slice()
    }
}

/// Capacity-generic owned UTF-8 string -- the string-shaped sibling of
/// [`BoundedVec`], for the owned-output value modules (canonicalized
/// keyexprs, locator addresses, diagnostic chunks). Same policy contract as
/// [`BoundedVec`]:
///
/// - **[`Heap`]** -- backed by `alloc::string::String`;
///   [`push_str`](BoundedString::push_str) never fails, `N` is advisory.
/// - **[`Static`]** -- backed by `heapless::String<N>`;
///   [`push_str`](BoundedString::push_str) returns [`CapacityFull`]
///   when the append would exceed the declared `N` *bytes*, leaving
///   the buffer unchanged (heapless append is atomic -- no partial
///   write). The caller decides; never a silent truncation.
///
/// Implements [`core::fmt::Write`] on both policies, so the value
/// modules can build output with `write!` / `core::fmt` machinery and
/// get the same capacity-failure surface (`fmt::Error` on overflow).
pub struct BoundedString<const N: usize, P: Storage = Profile> {
    inner: P::Text<N>,
}

impl<const N: usize> BoundedString<N, Static> {
    /// An empty string of the static policy. `const`; see [`BoundedVec::new_static`].
    pub const fn new_static() -> Self {
        Self {
            inner: heapless::String::new(),
        }
    }
}

#[cfg(feature = "alloc")]
impl<const N: usize> BoundedString<N, Heap> {
    /// An empty string of the heap policy. `const`, as [`Self::new_static`] is.
    pub const fn new_heap() -> Self {
        Self {
            inner: String::new(),
        }
    }
}

impl<const N: usize> BoundedString<N, Profile> {
    /// An empty string of this build's profile. `const` on both policies.
    #[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
    pub const fn new() -> Self {
        Self::new_heap()
    }

    /// An empty string of this build's profile. See the heap form.
    #[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
    pub const fn new() -> Self {
        Self::new_static()
    }
}

impl<const N: usize, P: Storage> BoundedString<N, P> {
    /// The declared logical byte capacity `N`. Advisory on [`Heap`]; the hard
    /// byte limit `push_str` / `push` enforce on [`Static`].
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Append a string slice. `Ok(())` always on [`Heap`];
    /// `Err(CapacityFull(()))` on [`Static`] when the append would exceed `N`
    /// bytes (buffer left unchanged).
    pub fn push_str(&mut self, s: &str) -> Result<(), CapacityFull<()>> {
        self.inner.push_str(s)
    }

    /// Append one `char`. Capacity semantics mirror [`push_str`].
    ///
    /// [`push_str`]: BoundedString::push_str
    pub fn push(&mut self, c: char) -> Result<(), CapacityFull<char>> {
        self.inner.push(c)
    }

    /// Borrow the contents as a `&str`.
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    /// Remove all bytes, keeping the allocated/declared capacity.
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

impl<const N: usize, P: Storage> Default for BoundedString<N, P> {
    #[inline(always)]
    fn default() -> Self {
        Self {
            inner: <P::Text<N> as TextBacking>::empty(),
        }
    }
}

impl<const N: usize, P: Storage> Clone for BoundedString<N, P> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<const N: usize, P: Storage> Deref for BoundedString<N, P> {
    type Target = str;

    fn deref(&self) -> &str {
        self.inner.as_str()
    }
}

impl<const N: usize, P: Storage> fmt::Display for BoundedString<N, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.inner.as_str())
    }
}

impl<const N: usize, P: Storage> fmt::Debug for BoundedString<N, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.inner.as_str(), f)
    }
}

// Compare against `str` / `&str` literals by content. Lets callers and
// tests write `bounded == "literal"` without reaching for `.as_str()`
// (the canon owned-output modules return `BoundedString` and are
// asserted against literal expectations). Policy-agnostic.
impl<const N: usize, P: Storage> PartialEq<str> for BoundedString<N, P> {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl<const N: usize, P: Storage> PartialEq<&str> for BoundedString<N, P> {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

// Content equality between two bounded strings (capacity-independent and
// policy-independent), so a `BoundedString` is usable inside `Result`/`Option`
// equality assertions and as a comparand in registry dedup.
impl<const N: usize, const M: usize, P: Storage, Q: Storage> PartialEq<BoundedString<M, Q>>
    for BoundedString<N, P>
{
    fn eq(&self, other: &BoundedString<M, Q>) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<const N: usize, P: Storage> Eq for BoundedString<N, P> {}

// `fmt::Write` lets the owned-output modules build a BoundedString with
// `write!` / `core::fmt`; the static policy surfaces a full buffer as
// `fmt::Error`, the standard `core::fmt` capacity-failure channel.
impl<const N: usize, P: Storage> fmt::Write for BoundedString<N, P> {
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

    // The profile is one of the two policies, and the one the features name.
    #[test]
    fn the_profile_is_the_policy_the_features_choose() {
        assert_eq!(ENFORCES_CAPACITY, <Profile as Storage>::ENFORCES_CAPACITY);
        assert_eq!(
            ENFORCES_CAPACITY,
            cfg!(any(not(feature = "alloc"), feature = "bounded-heapless"))
        );
    }

    // ---- The algorithm once, the policy as an instantiation ----------------
    //
    // Each function below is written generic over `P: Storage` and run on every
    // policy this build can name: `Static` always, `Heap` when `alloc` is on. The
    // two instances use the same code and the same assertions; what differs is
    // the policy's own contract, read from `P::ENFORCES_CAPACITY`, never from a
    // feature gate. A registry migrated to the policy parameter takes the same
    // shape: its fill-to-N and refuse-at-N+1 test is one generic function.

    /// Fill to `N`, then one more: refused with the value handed back on a policy
    /// that enforces `N`, accepted on one that does not.
    fn fill_to_n_then_one_more<P: Storage>() {
        let mut v: BoundedVec<u32, 3, P> = BoundedVec::default();
        for i in 0..3 {
            assert!(v.push(i).is_ok(), "entry {i} is within the capacity");
        }
        assert_eq!(v.len(), 3);

        let beyond = v.push(99);
        if P::ENFORCES_CAPACITY {
            assert_eq!(beyond.unwrap_err().0, 99, "the refused value comes back");
            assert_eq!(v.len(), 3, "a refused push leaves the table as it was");
        } else {
            assert!(beyond.is_ok(), "an advisory capacity refuses nothing");
            assert_eq!(v.len(), 4);
        }
        assert_eq!(v.capacity(), 3, "the declared capacity does not move");
    }

    /// `free_slots` is what a whole-group stager reserves against, so it has to
    /// agree with `push` on each policy: exactly the pushes that succeed.
    fn free_slots_counts_the_pushes_that_still_succeed<P: Storage>() {
        let mut v: BoundedVec<u32, 2, P> = BoundedVec::default();
        v.push(1).unwrap();
        if P::ENFORCES_CAPACITY {
            assert_eq!(v.free_slots(), 1);
            v.push(2).unwrap();
            assert_eq!(v.free_slots(), 0);
            assert!(v.push(3).is_err());
        } else {
            assert_eq!(v.free_slots(), usize::MAX);
            v.push(2).unwrap();
            assert!(v.push(3).is_ok(), "the growable policy refuses nothing");
            assert_eq!(v.free_slots(), usize::MAX);
        }
    }

    /// Order, removal, and the take-and-rebuild partition behave the same on
    /// every policy: only the refusal differs, and the partition never reaches it
    /// (retained + extracted == taken <= N).
    fn removal_and_partition_keep_order<P: Storage>() {
        let mut v: BoundedVec<u32, 6, P> = BoundedVec::default();
        for i in 0..6 {
            v.push(i).unwrap();
        }
        assert_eq!(v.pop(), Some(5));
        v.retain(|&x| x != 1);
        assert_eq!(v.as_ref(), &[0, 2, 3, 4]);

        let evens = v.drain_partition(|x| *x % 2 == 0);
        assert_eq!(evens.as_ref(), &[0, 2, 4]);
        assert_eq!(v.as_ref(), &[3]);

        v.clear();
        assert!(v.is_empty());
        assert_eq!(v.pop(), None);
    }

    /// The byte filler: grow, fill in place, give back what was not used. The
    /// refusal at `N` is the policy's, and a refusal leaves the bytes as they were.
    fn byte_filler_grows_fills_and_truncates<P: Storage>() {
        let mut v: BoundedVec<u8, 8, P> = BoundedVec::default();
        let window = v.grow_for_fill(5).unwrap();
        window.copy_from_slice(b"abcde");
        v.truncate(3);
        assert_eq!(v.as_ref(), b"abc");

        assert!(v.extend_from_slice(b"de").is_ok());
        assert_eq!(v.as_ref(), b"abcde");

        // 3 more bytes make 8: exactly the capacity, accepted by both policies.
        assert!(v.extend_from_slice(b"fgh").is_ok());
        assert_eq!(v.len(), 8);

        // One more byte is past N: refused whole by a policy that enforces it.
        let past = v.extend_from_slice(b"i");
        let grown = v.grow_for_fill(1).is_ok();
        if P::ENFORCES_CAPACITY {
            assert!(past.is_err() && !grown);
            assert_eq!(v.as_ref(), b"abcdefgh", "a refused fill changes nothing");
        } else {
            assert!(past.is_ok() && grown);
        }
    }

    /// Text: an append is atomic on a policy that enforces `N` (no partial write),
    /// and `Display`/equality read the same on every policy.
    fn text_append_is_atomic_where_the_capacity_is_hard<P: Storage>() {
        use core::fmt::Write;
        let mut s: BoundedString<4, P> = BoundedString::default();
        assert!(s.push_str("abcd").is_ok());

        let more = s.push_str("e");
        let ch = s.push('x');
        if P::ENFORCES_CAPACITY {
            assert!(more.is_err() && ch.is_err());
            assert_eq!(s.as_str(), "abcd", "a refused append changes nothing");
            assert!(write!(s, "z").is_err(), "fmt::Write reports the refusal");
        } else {
            assert!(more.is_ok() && ch.is_ok());
            assert_eq!(s.as_str(), "abcdex");
        }
        assert_eq!(s.capacity(), 4);
        assert_eq!(s.clone().as_str(), s.as_str());
    }

    /// A table of a policy builds from `Default` and is empty, on every policy.
    fn default_is_empty<P: Storage>() {
        let v: BoundedVec<u32, 2, P> = BoundedVec::default();
        let s: BoundedString<2, P> = BoundedString::default();
        assert!(v.is_empty() && s.is_empty());
    }

    /// The `const` constructors are usable in a `static` initialiser: a registry
    /// held in a session slot is a `static`. Each policy has its own, because a
    /// `const fn` cannot call a trait function.
    #[test]
    fn the_const_constructors_make_statics() {
        static FIXED: BoundedVec<u32, 2, Static> = BoundedVec::new_static();
        static FIXED_TEXT: BoundedString<2, Static> = BoundedString::new_static();
        const PROFILE: BoundedVec<u32, 2> = BoundedVec::new();
        assert!(FIXED.is_empty() && FIXED_TEXT.is_empty() && PROFILE.is_empty());
        #[cfg(feature = "alloc")]
        {
            static GROWN: BoundedVec<u32, 2, Heap> = BoundedVec::new_heap();
            static GROWN_TEXT: BoundedString<2, Heap> = BoundedString::new_heap();
            assert!(GROWN.is_empty() && GROWN_TEXT.is_empty());
        }
    }

    macro_rules! on_every_policy {
        ($($case:ident),* $(,)?) => {
            mod on_static {
                use super::*;
                $(#[test] fn $case() { super::$case::<Static>(); })*
            }
            #[cfg(feature = "alloc")]
            mod on_heap {
                use super::*;
                $(#[test] fn $case() { super::$case::<Heap>(); })*
            }
        };
    }

    on_every_policy!(
        fill_to_n_then_one_more,
        free_slots_counts_the_pushes_that_still_succeed,
        removal_and_partition_keep_order,
        byte_filler_grows_fills_and_truncates,
        text_append_is_atomic_where_the_capacity_is_hard,
        default_is_empty,
    );

    /// Both policies in ONE build, side by side: what the feature selector could
    /// not do. The static table refuses the entry the heap table accepts.
    #[cfg(feature = "alloc")]
    #[test]
    fn both_policies_coexist_in_one_build() {
        let mut fixed: BoundedVec<u32, 1, Static> = BoundedVec::new_static();
        let mut grown: BoundedVec<u32, 1, Heap> = BoundedVec::new_heap();
        for i in 0..2 {
            let _ = fixed.push(i);
            let _ = grown.push(i);
        }
        assert_eq!(fixed.as_ref(), &[0]);
        assert_eq!(grown.as_ref(), &[0, 1]);

        // Content equality does not depend on the policy.
        let mut a: BoundedString<8, Static> = BoundedString::new_static();
        let mut b: BoundedString<8, Heap> = BoundedString::new_heap();
        a.push_str("k/v").unwrap();
        b.push_str("k/v").unwrap();
        assert!(a == b);
    }
}
