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
//! The backing is a type parameter, a [`Storage`](crate::bounded::Storage) policy, not a feature
//! that selects code, so heap or no heap is the instantiation and the algorithm exists once.
//! There are three policies, because "an allocator is linked", "the declared capacities are
//! hard" and "the capacities are known when the session opens" are different facts about a build:
//!
//! - [`Heap`](crate::bounded::Heap) (needs `alloc`) -- backed by `alloc::vec::Vec<T>` and
//!   `alloc::string::String`. [`push`](crate::bounded::BoundedVec::push) never fails; the
//!   declared capacity `N` is advisory (AP is the dynamic-opt-in side and may
//!   exceed it).
//! - [`Static`](crate::bounded::Static) -- backed by `heapless::Vec<T, N>` and
//!   `heapless::String<N>`. [`push`](crate::bounded::BoundedVec::push) returns
//!   [`CapacityFull`](crate::bounded::CapacityFull) when the declared
//!   capacity `N` is full. There is no silent drop: the caller decides what to
//!   do with the rejected value, mirroring zenoh-pico's table-full reject (and
//!   the §2.1 build-time-enforced bounded declared-subscription table).
//! - [`Lent`](crate::bounded::Lent) -- backed by a span of an [`Arena`](crate::bounded::Arena),
//!   the memory a session reserved when it opened, as many rows as the limit the open resolved,
//!   with `N` as their ceiling. [`push`](crate::bounded::BoundedVec::push) refuses past those
//!   rows as [`Static`](crate::bounded::Static) refuses past `N`. A C library whose limits come
//!   from its configuration document sizes its tables when a session opens, and allocates
//!   nothing after (`docs/c-abi-no-heap-pools.md`, section 2).
//!
//! A container names its policy as its last parameter and defaults it to
//! [`Profile`](crate::bounded::Profile), the policy this build's features choose (`alloc` on and
//! `bounded-heapless` off selects [`Heap`](crate::bounded::Heap); `alloc` off, or
//! `bounded-heapless` on, selects [`Static`](crate::bounded::Static)). Every existing
//! `BoundedVec<T, N>` is therefore the
//! build's profile and reads as before. No build's profile is [`Lent`](crate::bounded::Lent): a
//! lent table is made by the arena that lends it its rows, never by `Default`. A test that wants BOTH policies in one
//! build writes the algorithm once, generic over `P: Storage`, and runs it on
//! each (see the tests at the end of this file).
//!
//! `bounded-heapless` is what lets an MCU build keep `alloc` for the rest of the
//! session machinery and still get every [`crate::caps`] limit as a hard bound.
//! [`ENFORCES_CAPACITY`](crate::bounded::ENFORCES_CAPACITY) states which policy the profile is,
//! for a consumer that must refuse to build on the wrong one.
//!
//! The fallible-push signature is identical on both policies, so the caller
//! writes one capacity-aware code path; the [`Heap`](crate::bounded::Heap) build's `Ok(())` arm
//! is simply never taken on the failure side. `N` is the deploy-declared capacity.

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use crate::byte_cells::LentByteCells;

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Whether this build's [`Profile`] is the FIXED policy, on which every push past
/// the declared capacity `N` is refused. `false` means the [`Heap`] policy, on
/// which `N` is advisory and no push fails.
///
/// For a consumer whose code relies on one of the two: an AP crate whose tables
/// must not be held to an MCU image's capacities asserts `!ENFORCES_CAPACITY`
/// at compile time, so a build graph that unifies `bounded-heapless` into it
/// fails to build. No registration relies on it to be infallible: a table held
/// to a stated quota refuses on either backing, and every registration returns
/// that refusal.
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

/// How a container holds its elements: the storage policy, a type parameter of
/// the session shell rather than a feature. Implemented by [`Heap`] and
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

    /// A table of values by the `u64` id a peer gave them, of at most `N` ids where
    /// the policy enforces a capacity. A policy chooses the representation, not only
    /// the room: the growable policy keeps the hash map the registries always had
    /// (a lookup stays constant time however many ids a router's peers declare), and
    /// the static policy keeps `N` rows in an inline array whose lookup is a short
    /// scan, which is what a few dozen rows cost least in RAM and in code.
    type Ids<V, const N: usize>: crate::id_map::IdMap<V> + Default;

    /// What a table of this policy moves after every change to it, for a reader that
    /// must not take the table's lock to ask "has anything changed since I looked": a
    /// shared counter where the policy can share one (the allocator, 64-bit atomics),
    /// and nothing where it cannot, so a table of the static policy carries no field
    /// for it.
    type Epoch: EpochCounter;

    /// A peer's keyexpr-alias table of this policy as the id space a
    /// [`MappingSpaces`](crate::wireexpr_resolve::MappingSpaces) reads. The policy knows
    /// which table it keeps, so a reader that holds one through a generic table never
    /// has to.
    #[cfg(feature = "storage-profile")]
    fn peer_space(
        aliases: &crate::id_map::PeerAliases<Self>,
    ) -> crate::wireexpr_resolve::PeerSpace<'_>
    where
        Self: Sized;
}

/// The counter of a table's changes; see [`Storage::Epoch`].
pub trait EpochCounter: Default {
    /// A change to the table has been made: move the counter after it.
    fn moved(&self);
}

impl EpochCounter for () {
    #[inline(always)]
    fn moved(&self) {}
}

#[cfg(all(feature = "alloc", target_has_atomic = "64"))]
impl EpochCounter for alloc::sync::Arc<core::sync::atomic::AtomicU64> {
    #[inline]
    fn moved(&self) {
        self.fetch_add(1, core::sync::atomic::Ordering::Release);
    }
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

    /// Append the value `make` returns, built where it is kept, or `false` when the policy's
    /// capacity is full (and `make` is not called). A fixed sequence writes the value into its
    /// slot, so a large element is not a value of its own in the frame of the caller as it is
    /// when passed to [`Self::push`].
    fn push_with<F: FnOnce() -> T>(&mut self, make: F) -> bool;

    /// Remove and return the last element, if any.
    fn pop(&mut self) -> Option<T>;

    /// Remove and return the element at `index`, shifting the ones after it down so the
    /// order holds. Panics when `index` is out of bounds.
    fn remove(&mut self, index: usize) -> T;

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
pub trait TextBacking: Sized + Clone + core::ops::Deref<Target = str> + AsRef<str> {
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
    type Ids<V, const N: usize> = crate::id_map::GrowableIdMap<V>;
    #[cfg(target_has_atomic = "64")]
    type Epoch = alloc::sync::Arc<core::sync::atomic::AtomicU64>;
    #[cfg(not(target_has_atomic = "64"))]
    type Epoch = ();

    #[cfg(feature = "storage-profile")]
    fn peer_space(
        aliases: &crate::id_map::PeerAliases<Self>,
    ) -> crate::wireexpr_resolve::PeerSpace<'_> {
        crate::wireexpr_resolve::PeerSpace::of_map(aliases.as_map())
    }
}

/// The static policy: a capacity fixed in the type and no allocator. A push past
/// `N` is refused and hands the value back.
pub struct Static;

impl Storage for Static {
    const ENFORCES_CAPACITY: bool = true;
    type Seq<T, const N: usize> = heapless::Vec<T, N>;
    type Text<const N: usize> = heapless::String<N>;
    type Offset = u16;
    type Ids<V, const N: usize> = crate::id_map::FixedIdMap<V, N>;
    type Epoch = ();

    #[cfg(feature = "storage-profile")]
    fn peer_space(
        aliases: &crate::id_map::PeerAliases<Self>,
    ) -> crate::wireexpr_resolve::PeerSpace<'_> {
        crate::wireexpr_resolve::PeerSpace::of_table(aliases)
    }
}

/// The policy of storage lent at open: a table whose rows are a span of an [`Arena`], the memory a
/// session reserved when it opened, as many rows as the limit the open resolved, the build's `N`
/// being their ceiling. The algorithm, the refusal and its error are [`Static`]'s; only where
/// the rows lie differs.
///
/// What a row holds is laid out as the static policy lays it out: a key's text inline in its row
/// (a key is a part of the row that owns it, not a table of its own), and a table keyed by a peer's
/// ids inline at its build capacity, as the peer-written tables are held until their storage is
/// lent too (`docs/c-abi-no-heap-pools.md`, section 4.5). A sequence a row holds of its own is
/// lent from the arena by the row's maker: one made by `Default` under this policy has no rows, as
/// a table the arena lent nothing has none.
pub struct Lent;

impl Storage for Lent {
    const ENFORCES_CAPACITY: bool = true;
    type Seq<T, const N: usize> = LentSeq<T>;
    type Text<const N: usize> = heapless::String<N>;
    // A span of a lent table addresses rows of an arena a host session may size past 64 KiB.
    type Offset = u32;
    type Ids<V, const N: usize> = crate::id_map::FixedIdMap<V, N>;
    type Epoch = ();

    #[cfg(feature = "storage-profile")]
    fn peer_space(
        aliases: &crate::id_map::PeerAliases<Self>,
    ) -> crate::wireexpr_resolve::PeerSpace<'_> {
        crate::wireexpr_resolve::PeerSpace::of_table(aliases)
    }
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

    fn push_with<F: FnOnce() -> T>(&mut self, make: F) -> bool {
        Vec::push(self, make());
        true
    }

    fn pop(&mut self) -> Option<T> {
        Vec::pop(self)
    }

    fn remove(&mut self, index: usize) -> T {
        Vec::remove(self, index)
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

    fn push_with<F: FnOnce() -> T>(&mut self, make: F) -> bool {
        let len = self.len();
        if len == N {
            return false;
        }
        // SAFETY: `len < N`, so the slot at `len` is inside the buffer and holds no value; it is
        // written whole before the length covers it, and `make` panicking leaves both as they were.
        unsafe {
            self.as_mut_ptr().add(len).write(make());
            self.set_len(len + 1);
        }
        true
    }

    fn pop(&mut self) -> Option<T> {
        heapless::Vec::pop(self)
    }

    fn remove(&mut self, index: usize) -> T {
        heapless::Vec::remove(self, index)
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
    /// it); the hard limit `push` enforces on [`Static`]; on [`Lent`] the ceiling of the rows the
    /// table was lent, which `push` enforces.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// How many more pushes are guaranteed to succeed: `N - len` on [`Static`],
    /// the rows lent less `len` on [`Lent`], and `usize::MAX` on [`Heap`], where no push fails.
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

    /// Append the value `make` returns, built where the table keeps it, and say whether there
    /// was room (`make` is not called when there is none). For an element that is large: handed
    /// to [`Self::push`] it is a value in the caller's frame and then a second one in `push`'s.
    pub fn push_with<F: FnOnce() -> T>(&mut self, make: F) -> bool {
        self.inner.push_with(make)
    }

    /// Remove and return the last entry, if any.
    pub fn pop(&mut self) -> Option<T> {
        self.inner.pop()
    }

    /// Remove and return the entry at `index`, the entries after it moving down so the order
    /// holds. A table whose index is its declaration order (a replay walks it by position) keeps
    /// it. Panics when `index` is out of bounds, as `Vec::remove` does.
    pub fn remove(&mut self, index: usize) -> T {
        self.inner.remove(index)
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

    /// Take the next element for which `extract` is true out of the table, scanning from
    /// `*at`: the element is removed from `self` and returned, and `*at` stays where it
    /// was, since the element after it now stands there; `None` once the scan has passed
    /// the last element. `extract` receives `&mut T`, so it may mutate an element before
    /// deciding (e.g. decrement a counter and extract on reaching zero), and an element it
    /// declines keeps what it did to it. Order is the table's.
    ///
    /// This is the no-alloc *take-then-fire* seam the pending-table registries share (the
    /// reply and liveliness-get `sweep_timed_out` / `fire_final_for` / `finish_all` bodies):
    /// the borrow checker forbids firing a captured callback while a `&mut self.pending`
    /// iteration is live, so the caller takes one entry out here, fires it, and asks for the
    /// next. The entry is out of the table before its callback runs, so a panicking callback
    /// cannot leave a half-swept entry behind.
    ///
    /// ONE ENTRY AT A TIME, which is the point of the shape. The form this replaced
    /// (`drain_partition`) returned every extracted entry as a table of its own, by value,
    /// and the caller moved each of them out again to fire it: the frame of the function held
    /// the table, the copy being built and the entry, a few times the size of the table. A
    /// table of entries that each hold a sink and a keyexpr is kilobytes, and the frame sat on
    /// the path of every event of a node that asks (3,696 bytes on the kit's asking client,
    /// the largest frame of its stack chain). A scan that keeps one entry holds one.
    ///
    /// In place: the rest of the table stays where it is, so it keeps the storage it has (a
    /// heap table is not rebuilt, and its next push does not allocate).
    pub fn take_next_where<F>(&mut self, at: &mut usize, mut extract: F) -> Option<T>
    where
        F: FnMut(&mut T) -> bool,
    {
        while *at < self.inner.as_slice().len() {
            if extract(&mut self.inner.as_mut_slice()[*at]) {
                return Some(self.inner.remove(*at));
            }
            *at += 1;
        }
        None
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

// ---- The lent policy's rows, and the arena that lends them ---------------------------------

/// The rows of a table of the [`Lent`] policy: a span of an [`Arena`], its values at the start.
/// It owns its values and not its memory: dropped, it drops what it holds and gives no memory
/// back, the memory being the arena's owner's to release whole.
pub struct LentSeq<T> {
    base: NonNull<T>,
    len: usize,
    /// The rows the arena lent: the most the table holds.
    room: usize,
    _owns: PhantomData<T>,
}

// SAFETY: a lent table owns its values and the rows it was lent, which nothing else reaches, as a
// `Vec` owns its buffer: it may move to another thread when its values may, and be shared when
// they may be.
unsafe impl<T: Send> Send for LentSeq<T> {}
// SAFETY: as `Send`: a shared table hands out shared references to its values only.
unsafe impl<T: Sync> Sync for LentSeq<T> {}

impl<T> LentSeq<T> {
    /// The `room` rows at `base`, none of them holding a value yet.
    ///
    /// # Safety
    /// `base` is aligned for `T`, and the `room` rows of `T` from it are valid for reads and
    /// writes, hold no value and are used by nothing else for as long as the table lives.
    const unsafe fn lent(base: NonNull<T>, room: usize) -> Self {
        Self {
            base,
            len: 0,
            room,
            _owns: PhantomData,
        }
    }

    /// Drop the values from `len` on. The length is shortened first, so a value whose drop
    /// panics leaks the ones after it rather than letting them be dropped twice.
    fn drop_from(&mut self, len: usize) {
        if len >= self.len {
            return;
        }
        let tail = self.len - len;
        self.len = len;
        // SAFETY: the `tail` rows from `len` held values, which the length no longer covers, so
        // each is dropped here once.
        unsafe {
            core::ptr::drop_in_place(core::ptr::slice_from_raw_parts_mut(
                self.base.as_ptr().add(len),
                tail,
            ));
        }
    }
}

impl<T> Drop for LentSeq<T> {
    fn drop(&mut self) {
        self.drop_from(0);
    }
}

impl<T> SeqBacking<T> for LentSeq<T> {
    #[inline(always)]
    fn empty() -> Self {
        Self {
            base: NonNull::dangling(),
            len: 0,
            room: 0,
            _owns: PhantomData,
        }
    }

    fn as_slice(&self) -> &[T] {
        // SAFETY: the first `len` rows hold values, and `base` is aligned and non-null even for a
        // table lent nothing.
        unsafe { core::slice::from_raw_parts(self.base.as_ptr(), self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: as `as_slice`, and `&mut self` makes this the only borrow of them.
        unsafe { core::slice::from_raw_parts_mut(self.base.as_ptr(), self.len) }
    }

    fn free_slots(&self) -> usize {
        self.room - self.len
    }

    fn push(&mut self, value: T) -> Result<(), CapacityFull<T>> {
        if self.len == self.room {
            return Err(CapacityFull(value));
        }
        // SAFETY: `len < room`, so the row at `len` is one this table was lent and holds no value.
        unsafe { self.base.as_ptr().add(self.len).write(value) };
        self.len += 1;
        Ok(())
    }

    fn push_with<F: FnOnce() -> T>(&mut self, make: F) -> bool {
        if self.len == self.room {
            return false;
        }
        // SAFETY: as `push`; `make` panicking leaves the row and the length as they were.
        unsafe { self.base.as_ptr().add(self.len).write(make()) };
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        // SAFETY: the row at the old last index held a value, which the length no longer covers,
        // so it is read out once.
        Some(unsafe { self.base.as_ptr().add(self.len).read() })
    }

    fn remove(&mut self, index: usize) -> T {
        assert!(
            index < self.len,
            "removal index {index} is past a lent table of {} values",
            self.len
        );
        // SAFETY: `index < len`: the value at `index` is read out once, and the rows after it, which
        // hold values, move down over it before the length drops by one.
        unsafe {
            let at = self.base.as_ptr().add(index);
            let value = at.read();
            core::ptr::copy(at.add(1), at, self.len - index - 1);
            self.len -= 1;
            value
        }
    }

    fn retain<F: FnMut(&T) -> bool>(&mut self, mut keep: F) {
        // Each value is asked once, in order: one taken out moves the next to where it stood.
        let mut index = 0;
        while index < self.len {
            if keep(&self.as_slice()[index]) {
                index += 1;
            } else {
                self.remove(index);
            }
        }
    }

    fn clear(&mut self) {
        self.drop_from(0);
    }

    fn truncate(&mut self, len: usize) {
        self.drop_from(len);
    }

    fn resize(&mut self, len: usize, fill: T) -> Result<(), CapacityFull<()>>
    where
        T: Clone,
    {
        if len > self.room {
            return Err(CapacityFull(()));
        }
        self.drop_from(len);
        while self.len < len {
            // Within the rows checked above, so every push is taken.
            if self.push(fill.clone()).is_err() {
                break;
            }
        }
        Ok(())
    }

    fn extend_from_slice(&mut self, src: &[T]) -> Result<(), CapacityFull<()>>
    where
        T: Clone,
    {
        if src.len() > self.room - self.len {
            return Err(CapacityFull(()));
        }
        for value in src {
            // Within the rows checked above, so every push is taken.
            if self.push(value.clone()).is_err() {
                break;
            }
        }
        Ok(())
    }
}

impl<T> IntoIterator for LentSeq<T> {
    type Item = T;
    type IntoIter = LentIntoIter<T>;

    fn into_iter(self) -> LentIntoIter<T> {
        // The values move to the iterator, which drops what it is not asked for.
        let seq = core::mem::ManuallyDrop::new(self);
        LentIntoIter {
            base: seq.base,
            next: 0,
            end: seq.len,
            _owns: PhantomData,
        }
    }
}

/// The values of a lent table, taken out of it in order.
pub struct LentIntoIter<T> {
    base: NonNull<T>,
    next: usize,
    end: usize,
    _owns: PhantomData<T>,
}

// SAFETY: as `LentSeq`'s: the iterator owns the values it has not handed out yet.
unsafe impl<T: Send> Send for LentIntoIter<T> {}
// SAFETY: as `Send`; a shared iterator hands out nothing.
unsafe impl<T: Sync> Sync for LentIntoIter<T> {}

impl<T> Iterator for LentIntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        if self.next == self.end {
            return None;
        }
        let index = self.next;
        self.next += 1;
        // SAFETY: the rows `next..end` hold values this iterator owns; this one is read out once
        // and the cursor has passed it.
        Some(unsafe { self.base.as_ptr().add(index).read() })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.end - self.next;
        (left, Some(left))
    }
}

impl<T> ExactSizeIterator for LentIntoIter<T> {}

impl<T> Drop for LentIntoIter<T> {
    fn drop(&mut self) {
        let (from, left) = (self.next, self.end - self.next);
        self.next = self.end;
        // SAFETY: the rows `from..end` hold values no call handed out; each is dropped here once.
        unsafe {
            core::ptr::drop_in_place(core::ptr::slice_from_raw_parts_mut(
                self.base.as_ptr().add(from),
                left,
            ));
        }
    }
}

/// The alignment every span an [`Arena`] lends starts on: the widest a scalar of a row asks for
/// on the targets wz builds for (`u128` on a 64-bit host), which [`Arena::lend`] checks of each
/// row type when the build is compiled. One alignment for every span makes an arena the sum of its
/// spans, in whatever order they are lent.
pub const ARENA_ALIGN: usize = 16;

/// Memory reserved once for the tables of a session, lent to them in spans: each table of the
/// [`Lent`] policy is one span (`docs/c-abi-no-heap-pools.md`, section 5).
///
/// It lends and never takes back. A session lends every table it holds when it opens, and the
/// arena's owner releases the memory whole once every table lent from it is gone, so a lent span
/// is never handed out twice and no table outlives its memory. What the arena knows of itself is
/// its size and its high-water mark: the bytes lent so far, which only grow, so once every table
/// is lent the mark is what the session took, and a reservation sized right leaves nothing over.
#[derive(Debug)]
pub struct Arena {
    base: NonNull<u8>,
    bytes: usize,
    lent: usize,
}

/// Why an [`Arena`] lent no table. A refused lend takes nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LendRefused {
    /// More rows than the table's type allows: the build's ceiling `N`.
    OverCeiling {
        /// The rows asked for.
        rows: usize,
        /// The ceiling.
        ceiling: usize,
    },
    /// The span does not fit in what is left of the arena.
    Exhausted {
        /// The bytes of the span; `None` past the address space.
        asked: Option<usize>,
        /// The bytes left.
        left: usize,
    },
}

impl fmt::Display for LendRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OverCeiling { rows, ceiling } => write!(
                f,
                "a lent table of {rows} rows is over the {ceiling} its build allows"
            ),
            Self::Exhausted {
                asked: Some(asked),
                left,
            } => write!(
                f,
                "a lent table of {asked} bytes is over the {left} the arena has left"
            ),
            Self::Exhausted { asked: None, left } => write!(
                f,
                "a lent table past the address space is over the {left} bytes the arena has left"
            ),
        }
    }
}

impl core::error::Error for LendRefused {}

impl Arena {
    /// An arena of the `bytes` bytes at `base`, none of them lent.
    ///
    /// # Safety
    /// `base` is aligned to [`ARENA_ALIGN`], and the `bytes` bytes from it are valid for reads
    /// and writes and used by nothing else for as long as the arena or any table it lends lives.
    pub const unsafe fn over(base: NonNull<u8>, bytes: usize) -> Self {
        Self {
            base,
            bytes,
            lent: 0,
        }
    }

    /// The arena's size in bytes.
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// The high-water mark: the bytes lent so far.
    pub const fn high_water(&self) -> usize {
        self.lent
    }

    /// The bytes a span of `bytes` takes: rounded up to [`ARENA_ALIGN`], so the next span starts
    /// aligned. `None` past the address space.
    pub const fn span(bytes: usize) -> Option<usize> {
        match bytes.checked_add(ARENA_ALIGN - 1) {
            Some(up) => Some(up & !(ARENA_ALIGN - 1)),
            None => None,
        }
    }

    /// The bytes a table of `rows` rows of `T` takes in an arena. `None` past the address
    /// space.
    pub const fn table_bytes<T>(rows: usize) -> Option<usize> {
        match rows.checked_mul(core::mem::size_of::<T>()) {
            Some(bytes) => Self::span(bytes),
            None => None,
        }
    }

    /// Lend a table of `rows` rows, at most the build's ceiling `N`: the next span of the arena,
    /// none of its rows holding a value. Refused, taking nothing, past the ceiling or past what is
    /// left.
    pub fn lend<T, const N: usize>(
        &mut self,
        rows: usize,
    ) -> Result<BoundedVec<T, N, Lent>, LendRefused> {
        const {
            assert!(
                core::mem::align_of::<T>() <= ARENA_ALIGN,
                "a row of a lent table asks for more alignment than an arena's spans start on"
            )
        };
        if rows > N {
            return Err(LendRefused::OverCeiling { rows, ceiling: N });
        }
        let left = self.bytes - self.lent;
        let span = match Self::table_bytes::<T>(rows) {
            Some(span) if span <= left => span,
            asked => return Err(LendRefused::Exhausted { asked, left }),
        };
        // SAFETY: the span starts `lent` bytes into the arena, a multiple of `ARENA_ALIGN` from a
        // base aligned to it, so it is aligned for `T` (asserted above); it lies inside the
        // arena, and no table was lent it before, as `lent` only grows.
        let inner = unsafe {
            let at = NonNull::new_unchecked(self.base.as_ptr().add(self.lent)).cast::<T>();
            LentSeq::lent(at, rows)
        };
        self.lent += span;
        Ok(BoundedVec { inner })
    }

    /// The bytes a table of `count` buffers of `size` bytes takes in an arena
    /// ([`Self::lend_byte_cells`]): a span of their flags and a span of their bytes. `None` past
    /// the address space.
    pub const fn byte_cells_bytes(size: usize, count: usize) -> Option<usize> {
        match Self::byte_cells_spans(size, count) {
            Some((flags, bytes)) => flags.checked_add(bytes),
            None => None,
        }
    }

    /// The two spans of a table of `count` buffers of `size` bytes: its flags', then its bytes'.
    const fn byte_cells_spans(size: usize, count: usize) -> Option<(usize, usize)> {
        let flags = match count.checked_mul(LentByteCells::FLAG_BYTES) {
            Some(flags) => Self::span(flags),
            None => None,
        };
        let bytes = match count.checked_mul(size) {
            Some(bytes) => Self::span(bytes),
            None => None,
        };
        match (flags, bytes) {
            (Some(flags), Some(bytes)) => Some((flags, bytes)),
            _ => None,
        }
    }

    /// Lend a table of `count` buffers of `size` bytes, every one free and its bytes zero: the
    /// next span holds the flags that say which are lent, and the one after it their bytes. A
    /// buffer a link claims from it is a [`ByteBuf`](crate::byte_cells::ByteBuf), as one of a
    /// table the image declares is. Refused, taking nothing, past what is left.
    ///
    /// The table's memory is this arena's: whoever owns the arena gives it back only once every
    /// copy of the table and every buffer claimed from it is gone, as it does for a lent table.
    pub fn lend_byte_cells(
        &mut self,
        size: usize,
        count: usize,
    ) -> Result<LentByteCells, LendRefused> {
        let left = self.bytes - self.lent;
        let (flags, bytes) = match Self::byte_cells_spans(size, count) {
            Some((flags, bytes)) if flags.checked_add(bytes).is_some_and(|all| all <= left) => {
                (flags, bytes)
            }
            spans => {
                return Err(LendRefused::Exhausted {
                    asked: spans.and_then(|(flags, bytes)| flags.checked_add(bytes)),
                    left,
                })
            }
        };
        // SAFETY: both spans lie inside the arena past what it has lent, as `lent` only grows, so
        // nothing else uses them. A flag is one byte with no alignment of its own and the bytes are
        // bytes, so any address in the arena is aligned for them. Each flag is written `false`
        // and each byte zero before the table is made, which is what `LentByteCells::over` asks.
        let table = unsafe {
            let at = self.base.as_ptr().add(self.lent);
            let taken = at.cast::<Cell<bool>>();
            for cell in 0..count {
                taken.add(cell).write(Cell::new(false));
            }
            let data = at.add(flags);
            core::ptr::write_bytes(data, 0, count * size);
            LentByteCells::over(
                NonNull::new_unchecked(taken),
                NonNull::new_unchecked(data),
                size,
                count,
            )
        };
        self.lent += flags + bytes;
        Ok(table)
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

    /// Every element `extract` takes, in the order they are taken.
    fn taken<const N: usize, P: Storage>(
        v: &mut BoundedVec<u32, N, P>,
        mut extract: impl FnMut(&mut u32) -> bool,
    ) -> sce_forge_runtime::heapless::Vec<u32, 8> {
        let mut at = 0;
        let mut out = sce_forge_runtime::heapless::Vec::new();
        while let Some(x) = v.take_next_where(&mut at, &mut extract) {
            out.push(x).unwrap();
        }
        out
    }

    #[test]
    fn take_next_where_extracts_matches_and_retains_rest_in_order() {
        let mut v: BoundedVec<u32, 4> = BoundedVec::new();
        for i in 0..4 {
            v.push(i).unwrap();
        }
        // Take evens; odds retained, both in the table's order.
        assert_eq!(taken(&mut v, |x| *x % 2 == 0), [0, 2]);
        assert_eq!(v.as_ref(), &[1, 3]);
    }

    #[test]
    fn take_next_where_predicate_may_mutate_before_deciding() {
        let mut v: BoundedVec<u32, 4> = BoundedVec::new();
        for i in 1..=3 {
            v.push(i).unwrap();
        }
        // Decrement each, take those that reach zero (mirrors the
        // reply registry's remaining_finals counter path).
        let out = taken(&mut v, |x| {
            *x -= 1;
            *x == 0
        });
        assert_eq!(out.len(), 1); // only the original `1` reaches 0
        assert_eq!(v.as_ref(), &[1, 2]); // 2->1, 3->2 retained, decremented
    }

    #[test]
    fn take_next_where_decides_each_element_once() {
        // The counter path above runs the predicate once per element across the whole
        // scan: an element declined is not asked again by the next call, and one taken
        // is gone, so no element is decremented twice.
        let mut v: BoundedVec<u32, 4> = BoundedVec::new();
        for i in [1, 2, 1, 3] {
            v.push(i).unwrap();
        }
        let mut asked = 0;
        let out = taken(&mut v, |x| {
            asked += 1;
            *x -= 1;
            *x == 0
        });
        assert_eq!(out, [0, 0]);
        assert_eq!(asked, 4);
        assert_eq!(v.as_ref(), &[1, 2]);
    }

    #[test]
    fn take_next_where_empty_and_all_match() {
        let mut empty: BoundedVec<u32, 4> = BoundedVec::new();
        assert!(taken(&mut empty, |_| true).is_empty());
        assert!(empty.is_empty());

        let mut all: BoundedVec<u32, 4> = BoundedVec::new();
        all.push(7).unwrap();
        all.push(8).unwrap();
        assert_eq!(taken(&mut all, |_| true), [7, 8]);
        assert!(all.is_empty());
    }

    #[test]
    fn take_next_where_takes_adjacent_matches_without_skipping() {
        let mut v: BoundedVec<u32, 6> = BoundedVec::new();
        for x in [2, 4, 6, 1, 8, 3] {
            v.push(x).unwrap();
        }
        assert_eq!(taken(&mut v, |x| *x % 2 == 0), [2, 4, 6, 8]);
        assert_eq!(v.as_ref(), &[1, 3]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn take_next_where_leaves_a_heap_table_its_storage() {
        let mut v: BoundedVec<u32, 4, Heap> = BoundedVec::default();
        for i in 0..4 {
            v.push(i).unwrap();
        }
        let room = v.inner.capacity();
        assert!(room >= 4);
        assert_eq!(taken(&mut v, |_| true), [0, 1, 2, 3]);
        assert!(v.is_empty());
        assert_eq!(v.inner.capacity(), room);
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
    // policy this build can name: `Static` and `Lent` always, `Heap` when `alloc` is
    // on. The instances use the same code and the same assertions; what differs is
    // the policy's own contract, read from `P::ENFORCES_CAPACITY`, never from a
    // feature gate. A registry migrated to the policy parameter takes the same
    // shape: its fill-to-N and refuse-at-N+1 test is one generic function.

    /// One block of an arena's memory in a test, aligned as an arena's spans start.
    #[derive(Clone, Copy)]
    #[repr(C, align(16))]
    struct Block {
        _bytes: [u8; ARENA_ALIGN],
    }

    /// An arena over `bytes` bytes of memory the test process leaks, so it outlives every table
    /// lent from it.
    fn arena_of(bytes: usize) -> Arena {
        let blocks = bytes.div_ceil(ARENA_ALIGN).max(1);
        let region: &'static mut [Block] =
            std::vec![Block { _bytes: [0; ARENA_ALIGN] }; blocks].leak();
        // SAFETY: the region is aligned to `ARENA_ALIGN`, as its blocks are, holds at least
        // `bytes` bytes, and is leaked, so nothing else uses it and it outlives every lent table.
        unsafe { Arena::over(NonNull::from(region).cast::<u8>(), bytes) }
    }

    /// A table of each policy with room for its `N`, for the algorithm to run on: the growable
    /// and the static ones as `Default` makes them, a lent one lent `N` rows of an arena of its
    /// own, so the three are filled and refused alike.
    trait Fresh: Storage + Sized {
        fn table<T, const N: usize>() -> BoundedVec<T, N, Self>;
    }

    impl Fresh for Static {
        fn table<T, const N: usize>() -> BoundedVec<T, N, Self> {
            BoundedVec::default()
        }
    }

    #[cfg(feature = "alloc")]
    impl Fresh for Heap {
        fn table<T, const N: usize>() -> BoundedVec<T, N, Self> {
            BoundedVec::default()
        }
    }

    impl Fresh for Lent {
        fn table<T, const N: usize>() -> BoundedVec<T, N, Self> {
            let bytes = Arena::table_bytes::<T>(N).expect("a test table fits the address space");
            arena_of(bytes)
                .lend(N)
                .expect("the arena is laid out for the table")
        }
    }

    /// A table of byte buffers takes a span of flags and a span of bytes, which is what
    /// `Arena::byte_cells_bytes` says it takes; its buffers are zero and apart; and a table past
    /// what is left, or past the address space, is refused and takes nothing.
    #[test]
    fn an_arena_lends_a_table_of_byte_buffers_and_refuses_one_past_what_is_left() {
        let asked = Arena::byte_cells_bytes(10, 3).expect("within the address space");
        assert_eq!(
            Some(asked),
            Arena::span(3 * LentByteCells::FLAG_BYTES)
                .and_then(|flags| Arena::span(30).map(|bytes| flags + bytes))
        );
        let mut arena = arena_of(asked + ARENA_ALIGN);
        let table = arena
            .lend_byte_cells(10, 3)
            .expect("the arena holds the table");
        assert_eq!(arena.high_water(), asked);
        assert_eq!((table.size(), table.capacity()), (10, 3));
        let mut first = table.claim().expect("a buffer");
        assert!(first.as_mut_slice().iter().all(|&b| b == 0), "lent zero");
        let second = table.claim().expect("a second buffer");
        let (a, b) = (first.raw().0 as usize, second.raw().0 as usize);
        assert!(a.abs_diff(b) >= 10, "two buffers never overlap");
        assert_eq!(
            arena.lend_byte_cells(10, 3).err(),
            Some(LendRefused::Exhausted {
                asked: Some(asked),
                left: ARENA_ALIGN,
            })
        );
        assert_eq!(
            arena.lend_byte_cells(1, usize::MAX).err(),
            Some(LendRefused::Exhausted {
                asked: None,
                left: ARENA_ALIGN,
            })
        );
        assert_eq!(arena.high_water(), asked, "a refused table takes nothing");
    }

    /// Fill to `N`, then one more: refused with the value handed back on a policy
    /// that enforces `N`, accepted on one that does not.
    fn fill_to_n_then_one_more<P: Fresh>() {
        let mut v: BoundedVec<u32, 3, P> = P::table();
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
    fn free_slots_counts_the_pushes_that_still_succeed<P: Fresh>() {
        let mut v: BoundedVec<u32, 2, P> = P::table();
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

    /// Order, removal, and the take-out scan behave the same on every policy: only the
    /// refusal differs, and the scan never reaches it (it pushes nothing).
    fn removal_and_partition_keep_order<P: Fresh>() {
        let mut v: BoundedVec<u32, 6, P> = P::table();
        for i in 0..6 {
            v.push(i).unwrap();
        }
        assert_eq!(v.pop(), Some(5));
        v.retain(|&x| x != 1);
        assert_eq!(v.as_ref(), &[0, 2, 3, 4]);

        let mut at = 0;
        let mut evens: sce_forge_runtime::heapless::Vec<u32, 8> =
            sce_forge_runtime::heapless::Vec::new();
        while let Some(x) = v.take_next_where(&mut at, |x| *x % 2 == 0) {
            evens.push(x).unwrap();
        }
        assert_eq!(evens.as_slice(), &[0, 2, 4]);
        assert_eq!(v.as_ref(), &[3]);

        v.clear();
        assert!(v.is_empty());
        assert_eq!(v.pop(), None);
    }

    /// Removing by position hands the entry back and keeps the order of the rest, and the room it
    /// left is pushed into again, on every policy.
    fn remove_at_keeps_order_and_frees_the_row<P: Fresh>() {
        let mut v: BoundedVec<u32, 3, P> = P::table();
        for i in 0..3 {
            v.push(i).unwrap();
        }
        assert_eq!(v.remove(1), 1);
        assert_eq!(v.as_ref(), &[0, 2]);
        assert!(v.push(7).is_ok(), "the removed entry's row is free again");
        assert_eq!(v.as_ref(), &[0, 2, 7]);
        assert_eq!(v.remove(0), 0);
        assert_eq!(v.as_ref(), &[2, 7]);
    }

    /// The byte filler: grow, fill in place, give back what was not used. The
    /// refusal at `N` is the policy's, and a refusal leaves the bytes as they were.
    fn byte_filler_grows_fills_and_truncates<P: Fresh>() {
        let mut v: BoundedVec<u8, 8, P> = P::table();
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
            mod on_lent {
                use super::*;
                $(#[test] fn $case() { super::$case::<Lent>(); })*
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
        remove_at_keeps_order_and_frees_the_row,
        byte_filler_grows_fills_and_truncates,
        text_append_is_atomic_where_the_capacity_is_hard,
        default_is_empty,
    );

    /// A lent table holds the rows its open lent it, under the ceiling `N` its type names: the
    /// push past those rows is refused with the value handed back, as the push past `N` is on the
    /// static policy, and the table of the same type lent its whole ceiling takes it.
    #[test]
    fn a_lent_table_refuses_at_its_open_length_below_its_ceiling() {
        let mut arena = arena_of(64);
        let mut v: BoundedVec<u32, 8, Lent> = arena.lend(3).expect("three rows fit");
        assert_eq!(v.capacity(), 8, "the ceiling is the build's");
        assert_eq!(v.free_slots(), 3, "the room is what the open lent");
        for i in 0..3 {
            v.push(i).expect("within the lent rows");
        }
        assert_eq!(
            v.push(99).unwrap_err().0,
            99,
            "the refused value comes back"
        );
        assert!(!v.push_with(|| 7), "a built-in-place push is refused alike");
        assert_eq!(
            v.as_ref(),
            &[0, 1, 2],
            "a refused push leaves the table as it was"
        );
        // Control: the same type lent its whole ceiling takes the fourth.
        let mut whole: BoundedVec<u32, 8, Lent> = arena.lend(8).expect("eight rows fit");
        for i in 0..4 {
            whole.push(i).expect("within the ceiling");
        }
    }

    /// A byte table lent fewer rows than its ceiling refuses a fill or an append past them whole.
    #[test]
    fn a_lent_byte_table_refuses_a_fill_past_its_rows_whole() {
        let mut v: BoundedVec<u8, 16, Lent> = arena_of(16).lend(4).expect("four rows fit");
        assert!(v.extend_from_slice(b"abc").is_ok());
        assert!(
            v.extend_from_slice(b"de").is_err(),
            "five bytes are past four rows"
        );
        assert!(v.grow_for_fill(2).is_err());
        assert_eq!(v.as_ref(), b"abc", "a refused fill changes nothing");
        assert!(v.grow_for_fill(1).is_ok());
        assert_eq!(v.len(), 4);
    }

    /// A lend past the ceiling, or past what the arena has left, is refused and takes nothing.
    #[test]
    fn a_lend_past_the_ceiling_or_the_arena_is_refused_and_takes_nothing() {
        let mut arena = arena_of(32);
        assert!(matches!(
            arena.lend::<u32, 4>(5),
            Err(LendRefused::OverCeiling {
                rows: 5,
                ceiling: 4
            })
        ));
        assert!(matches!(
            arena.lend::<u64, 8>(5),
            Err(LendRefused::Exhausted {
                asked: Some(48),
                left: 32
            })
        ));
        assert!(matches!(
            arena.lend::<u8, { usize::MAX }>(usize::MAX),
            Err(LendRefused::Exhausted {
                asked: None,
                left: 32
            })
        ));
        assert_eq!(arena.high_water(), 0, "a refused lend takes nothing");
        let _fits: BoundedVec<u64, 8, Lent> = arena.lend(4).expect("32 bytes fit");
        assert_eq!(arena.high_water(), 32);
        assert!(matches!(
            arena.lend::<u8, 1>(1),
            Err(LendRefused::Exhausted {
                asked: Some(16),
                left: 0
            })
        ));
    }

    /// Each span starts aligned, so an arena laid out for its tables is the sum of their spans,
    /// and lending them all brings the high-water mark to its size and no further.
    #[test]
    fn the_high_water_mark_is_the_sum_of_the_spans_lent() {
        assert_eq!(Arena::span(0), Some(0));
        assert_eq!(Arena::span(3), Some(16));
        assert_eq!(Arena::span(20), Some(32));
        assert_eq!(Arena::span(usize::MAX), None);
        assert_eq!(Arena::table_bytes::<u32>(5), Some(32));
        assert_eq!(Arena::table_bytes::<u64>(usize::MAX), None);
        let mut arena = arena_of(48);
        let _a: BoundedVec<u8, 3, Lent> = arena.lend(3).expect("16 bytes fit");
        assert_eq!(arena.high_water(), 16);
        let _b: BoundedVec<u32, 5, Lent> = arena.lend(5).expect("32 bytes fit");
        assert_eq!(arena.high_water(), 48);
        assert_eq!(arena.high_water(), arena.bytes());
    }

    /// Two tables lent from one arena never share a row.
    #[test]
    fn two_lent_tables_never_share_rows() {
        let mut arena = arena_of(32);
        let mut a: BoundedVec<u8, 16, Lent> = arena.lend(16).expect("first");
        let mut b: BoundedVec<u8, 16, Lent> = arena.lend(16).expect("second");
        a.extend_from_slice(&[1; 16]).expect("within a's rows");
        b.extend_from_slice(&[2; 16]).expect("within b's rows");
        assert!(a.iter().all(|&x| x == 1));
        assert!(b.iter().all(|&x| x == 2));
    }

    /// Counts its drops, to tell a value dropped once from one dropped twice or never.
    struct Counted<'a>(u32, &'a core::cell::Cell<usize>);

    impl Drop for Counted<'_> {
        fn drop(&mut self) {
            self.1.set(self.1.get() + 1);
        }
    }

    /// A lent table drops each value once: one popped, one removed, those left behind by a scan
    /// that stopped, and those the table still held when it was dropped.
    #[test]
    fn a_lent_table_drops_each_value_once() {
        let drops = core::cell::Cell::new(0);
        let mut arena = arena_of(Arena::table_bytes::<Counted<'_>>(6).expect("fits"));
        let mut v: BoundedVec<Counted<'_>, 6, Lent> = arena.lend(6).expect("six rows fit");
        for i in 0..6 {
            v.push(Counted(i, &drops)).expect("within the rows");
        }
        drop(v.pop());
        assert_eq!(drops.get(), 1);
        v.retain(|c| c.0 != 1);
        assert_eq!(drops.get(), 2);
        assert_eq!(v.iter().map(|c| c.0).sum::<u32>(), 2 + 3 + 4);
        let mut values = v.into_iter();
        drop(values.next());
        assert_eq!(drops.get(), 3);
        assert_eq!(values.len(), 3);
        drop(values);
        assert_eq!(
            drops.get(),
            6,
            "the values the scan left are dropped with it"
        );

        let mut held: BoundedVec<Counted<'_>, 2, Lent> = arena_of(64).lend(2).expect("fits");
        held.push(Counted(7, &drops)).expect("within the rows");
        drop(held);
        assert_eq!(drops.get(), 7, "a dropped table drops what it held");
    }

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
