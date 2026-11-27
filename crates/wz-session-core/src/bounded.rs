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
//! There are five policies, because "an allocator is linked", "the declared capacities are
//! hard", "the capacities are known when the session opens", "the build lays the session out" and
//! "a table takes its memory at its first value" are different facts about a build; when a table
//! takes its memory is stated by each policy ([`Taken`](crate::bounded::Taken)):
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
//! - [`Region`](crate::bounded::Region) -- [`Lent`](crate::bounded::Lent)'s rows, placed where a
//!   struct the build lays out holds them ([`place_seqs`](crate::bounded::place_seqs)), every
//!   table and row of it empty as the allocator's zeroed bytes ([`ZeroEmpty`](crate::bounded::ZeroEmpty)).
//! - [`OnUse`](crate::bounded::OnUse) (needs `alloc`) -- [`Region`](crate::bounded::Region)'s shape,
//!   each table's rows taken from the allocator at its first value, all of its count at once, and
//!   never moved after ([`FirstUse`](crate::on_use::FirstUse)); a key is an allocation of its own
//!   counted against the session's key budget ([`HeapKey`](crate::on_use::HeapKey)). A table never
//!   used takes nothing.
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

use crate::byte_cells::{CellFlag, LentByteCells};

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

/// An integer a row keeps a key's length in ([`Storage::KeyLen`]).
pub trait KeyLength: Copy + core::fmt::Debug + 'static {
    /// `len` in this integer, `None` past what it holds.
    fn of(len: usize) -> Option<Self>;

    /// The length.
    fn get(self) -> usize;
}

impl KeyLength for u16 {
    fn of(len: usize) -> Option<Self> {
        u16::try_from(len).ok()
    }

    fn get(self) -> usize {
        usize::from(self)
    }
}

impl KeyLength for u32 {
    fn of(len: usize) -> Option<Self> {
        u32::try_from(len).ok()
    }

    fn get(self) -> usize {
        // No target this crate builds for has a `usize` narrower than 32 bits.
        self as usize
    }
}

/// How a container holds its elements: the storage policy, a type parameter of
/// the session shell rather than a feature. Implemented by [`Heap`] and
/// [`Static`]; a container is generic over it and the algorithm around the
/// container is written once.
///
/// A policy is a tag of types, never a borrow: `'static`, so a borrow of a table of any policy
/// is well formed for every lifetime the borrow is named by, and a signature generic over a policy
/// and a lifetime asks nothing more of the policy.
pub trait Storage: 'static {
    /// Whether a push past the declared capacity is refused (`true`) or the
    /// backing grows past it (`false`).
    const ENFORCES_CAPACITY: bool;

    /// Whether a table of this policy has rows only where its maker lent it some from an
    /// arena (`true`), so a sequence a table makes for itself by `Default` has none. Where a row
    /// lies is [`Self::ROWS_STAY_APART`]'s question, and when its memory is taken [`Self::TAKEN`]'s.
    const LENT_AT_OPEN: bool;

    /// Whether every table of this policy keeps its rows apart from itself, behind a pointer, where
    /// none moves while it stands: what a reader of a row where it lies, with the tables let go (a
    /// callback's call on another thread), needs of the policy, since no `&mut` of a table reaches
    /// such a row. The lent, the region and the on-use policies keep them so; the static policy
    /// keeps its rows inline in the table, and the growable one's sequences move theirs as they grow.
    const ROWS_STAY_APART: bool;

    /// When a table of this policy takes the memory its rows lie in ([`Taken`]).
    const TAKEN: Taken;

    /// The policy of a working buffer an algorithm over a table of this policy keeps while it
    /// runs (a key's chunks while it is canonized): this policy where it can make one for itself,
    /// the static policy, on the stack, where its rows are only ever lent.
    type Scratch: Storage;

    /// The element sequence of a [`BoundedVec<T, N, Self>`].
    type Seq<T, const N: usize>: SeqBacking<T>;

    /// The column a [`SlotMap`](crate::slot_map::SlotMap) of this policy keeps its rows in, in
    /// which a row stays where it was put while it stands: the policy's own sequence where it
    /// never moves an element to make room, and on the growable policy chunks that are only ever
    /// added ([`Chunked`](crate::slot_map::Chunked)).
    type Rows<T, const N: usize>: crate::slot_map::RowColumn<T>;

    /// The UTF-8 text of a [`BoundedString<N, Self>`].
    type Text<const N: usize>: TextBacking;

    /// The key a row of a table of this policy keeps: its own allocation on the growable policy,
    /// a buffer of [`MAX_KEYEXPR_BYTES`](crate::caps::MAX_KEYEXPR_BYTES) inline in the row on the
    /// static one, and on the lent one the place of a block of the session's key arena
    /// ([`KeyRef`](crate::key_arena::KeyRef)), a few words whatever the key's length.
    type Key: KeyBacking;

    /// The integer a declaration's row keeps the length of its key in
    /// ([`KeyexprHead`](crate::session_tables::KeyexprHead)): on the bounded policies the
    /// narrowest that holds the build's bound on a key's length ([`crate::caps::KeyLen`]), so a
    /// row is as small as its fields allow; on the growable one `u32`, the most a key's length is
    /// on the wire, as that policy bounds no key.
    type KeyLen: KeyLength;

    /// Where a table of this policy makes the keys its rows keep ([`Self::Key`]): nothing to hand
    /// a table where the key is its own text, and on the lent policy the session's key arena,
    /// which the table is handed with its rows. One made by `Default` was handed none, and refuses
    /// every key as a table at its limit refuses a row.
    type Keys: KeyMaker<Self::Key>;

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
    ///
    /// A table is lent the owner's handle to where its rows lie ([`Self::Keys`]) for each operation
    /// ([`PeerIds::lend`](crate::id_map::PeerIds::lend)): the lent table is what answers
    /// [`IdMap`](crate::id_map::IdMap).
    type Ids<V, const N: usize>: crate::id_map::PeerIds<V, Self::Keys> + Default;

    /// A table a peer writes that is a sequence, of at most `N` rows: the policy's own sequence
    /// where it keeps its rows itself, and on the lent policy a list whose rows lie in a pool every
    /// face of the session shares ([`PooledRows`](crate::row_pool::PooledRows)), handed to the
    /// table with the session's other pools.
    ///
    /// A table is lent the owner's handle to where its rows lie ([`Self::Keys`]) for each operation
    /// ([`PeerSeq::lend`](crate::row_pool::PeerSeq::lend)): the lent table is what answers
    /// [`RowList`](crate::row_pool::RowList).
    type Pooled<T, const N: usize>: crate::row_pool::PeerSeq<T, Self::Keys>;

    /// What a table of this policy moves after every change to it, for a reader that
    /// must not take the table's lock to ask "has anything changed since I looked": a
    /// shared counter where the policy can share one (the allocator, 64-bit atomics),
    /// and nothing where it cannot, so a table of the static policy carries no field
    /// for it.
    type Epoch: EpochCounter;

    /// What a form only the growable policy makes holds beside its own fields (a plain map of a
    /// peer's keys, our own table of declarations standing in a sender's half): nothing on the
    /// growable policy, and on a bounded one a type of no value, so the arm that reads such a form
    /// ends where it starts ([`HeapOnly::granted`]) and is not compiled into the policy's reads.
    type HeapForm: HeapOnly;

    /// Where the peer's side of a table of this policy composes a key it cannot lend while it
    /// delivers one of the peer's messages (a mapping's literal with the message's suffix after
    /// it, or a literal of the session's own space): the delivering call's own buffer on the
    /// growable and the static policy, and on the lent one a row lent at open
    /// ([`ComposeRow`](crate::wireexpr_resolve::ComposeRow)), so composing a key takes no
    /// memory after it.
    #[cfg(feature = "storage-profile")]
    type Compose: crate::wireexpr_resolve::ComposeRoom;
}

/// When a table of a [`Storage`] policy takes the memory its rows lie in ([`Storage::TAKEN`]): a
/// fact of its own, apart from whether the build links an allocator ([`Profile`]) and from where
/// the rows lie ([`Storage::ROWS_STAY_APART`]). An engine states the moment its session takes
/// its memory at, and the policy it lays its tables out by answers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Taken {
    /// When the image is built: the rows lie in the table, at its build count.
    AtBuild,
    /// When the session opens, from the limits it resolved, and nothing after
    /// (`docs/upstream-parity.md`, D12).
    AtOpen,
    /// At a table's first value, all of its count's rows at once, and nothing after for that table.
    AtFirstUse,
    /// As a table grows.
    AsItGrows,
}

/// A policy's [`Storage::HeapForm`]: the unit on the growable policy, and a type of no value on a
/// bounded one.
pub trait HeapOnly: Copy + Send + Sync + 'static {
    /// Called first by an arm that reads a form only the growable policy makes: nothing there,
    /// and on a bounded policy never reached, its value being one that cannot be made, so the
    /// compiler drops the arm.
    fn granted(self);
}

impl HeapOnly for () {
    #[inline(always)]
    fn granted(self) {}
}

impl HeapOnly for core::convert::Infallible {
    #[inline(always)]
    fn granted(self) {
        match self {}
    }
}

/// A type whose value of all zero bytes is valid and is its empty state: a table of no rows, a count
/// of nothing, a key arena not yet opened. A region the build lays out holds only such types, so the
/// block the allocator hands zeroed is every table of a session empty, written by nothing and built
/// on no stack (`bytemuck`'s `Zeroable`, the emptiness stated besides).
///
/// # Safety
/// A value of the type whose every byte is zero is a valid value of it, and it holds nothing a drop
/// would give back.
pub unsafe trait ZeroEmpty {}

macro_rules! zero_empty_scalars {
    ($($ty:ty),* $(,)?) => {
        $(
            // SAFETY: zero is a valid value of every integer type, `false` of `bool`, and the unit is
            // no bytes; none holds anything to give back.
            unsafe impl ZeroEmpty for $ty {}
        )*
    };
}

zero_empty_scalars!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize, bool, ());

// SAFETY: an array of zero bytes is its elements' zero values, each valid and empty.
unsafe impl<T: ZeroEmpty, const N: usize> ZeroEmpty for [T; N] {}

// SAFETY: `MaybeUninit` is valid as any bytes, and dropping it drops nothing.
unsafe impl<T> ZeroEmpty for core::mem::MaybeUninit<T> {}

// SAFETY: a `Cell` has its value's layout, which zero bytes make its zero value.
unsafe impl<T: ZeroEmpty> ZeroEmpty for Cell<T> {}

// SAFETY: the null pointer is `None`, guaranteed for an `Option` of a `NonNull`.
unsafe impl<T> ZeroEmpty for Option<NonNull<T>> {}

// SAFETY: a `PhantomData` is no bytes.
unsafe impl<T: ?Sized> ZeroEmpty for PhantomData<T> {}

// SAFETY: an `AtomicBool` has the layout of a `bool`, whose zero byte is `false`.
#[cfg(target_has_atomic = "8")]
unsafe impl ZeroEmpty for core::sync::atomic::AtomicBool {}

/// A value or none, whose all zero bytes are none whatever the value's type: a flag and a place
/// for the value. An `Option<T>` is `None` at zero bytes only where `T` has a niche the language
/// guarantees (a reference, `NonNull`, a `NonZero` integer), so a field of a region that may hold
/// a counted handle, a transport or a generated value is one of these instead, and the region's
/// zeroed block holds none of them.
pub struct ZeroOption<T> {
    held: bool,
    value: core::mem::MaybeUninit<T>,
}

impl<T> ZeroOption<T> {
    /// No value, as all zero bytes are.
    pub const NONE: Self = Self {
        held: false,
        value: core::mem::MaybeUninit::uninit(),
    };

    /// `value`, held.
    pub const fn some(value: T) -> Self {
        Self {
            held: true,
            value: core::mem::MaybeUninit::new(value),
        }
    }

    /// Whether a value is held.
    pub const fn is_some(&self) -> bool {
        self.held
    }

    /// Whether no value is held.
    pub const fn is_none(&self) -> bool {
        !self.held
    }

    /// The value held, by reference.
    pub fn as_ref(&self) -> Option<&T> {
        if self.held {
            // SAFETY: `held` is set only once the value is written, and cleared before it is read
            // out, so the value is initialised.
            Some(unsafe { self.value.assume_init_ref() })
        } else {
            None
        }
    }

    /// The value held, by unique reference.
    pub fn as_mut(&mut self) -> Option<&mut T> {
        if self.held {
            // SAFETY: as `as_ref`; `&mut self` makes this the only borrow of the value.
            Some(unsafe { self.value.assume_init_mut() })
        } else {
            None
        }
    }

    /// What the value held points at.
    pub fn as_deref(&self) -> Option<&T::Target>
    where
        T: Deref,
    {
        self.as_ref().map(Deref::deref)
    }

    /// The value held, taken out, leaving none.
    pub fn take(&mut self) -> Option<T> {
        if self.held {
            self.held = false;
            // SAFETY: the value is initialised (`held` was set), and `held` is cleared first, so
            // the value is read out once and neither read nor dropped in place again.
            Some(unsafe { self.value.assume_init_read() })
        } else {
            None
        }
    }

    /// Hold `value`, answering the value held before.
    pub fn replace(&mut self, value: T) -> Option<T> {
        let before = self.take();
        self.value.write(value);
        self.held = true;
        before
    }

    /// Hold `value`, or none; the value held before is dropped.
    pub fn set(&mut self, value: Option<T>) {
        let before = match value {
            Some(value) => self.replace(value),
            None => self.take(),
        };
        drop(before);
    }
}

impl<T> Drop for ZeroOption<T> {
    fn drop(&mut self) {
        drop(self.take());
    }
}

impl<T> Default for ZeroOption<T> {
    fn default() -> Self {
        Self::NONE
    }
}

impl<T> From<Option<T>> for ZeroOption<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(value) => Self::some(value),
            None => Self::NONE,
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for ZeroOption<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_ref().fmt(f)
    }
}

// SAFETY: `false` is a valid `bool` and says no value is held; a `MaybeUninit` is valid as any
// bytes; and dropping a value that holds none drops nothing.
unsafe impl<T> ZeroEmpty for ZeroOption<T> {}

/// A policy each of whose sequences and texts is [`ZeroEmpty`] whatever it holds: a table of it is
/// empty at all zero bytes for every row type, which a bound on each sequence could state only by
/// naming the row's type, a private one of the table's own.
///
/// # Safety
/// For every `T` and `N`, `Self::Seq<T, N>` and `Self::Text<N>` are `ZeroEmpty`.
pub unsafe trait ZeroSeqs: Storage {}

// SAFETY: heapless 0.8's `Vec` is its length and an array of `MaybeUninit` rows; a length of zero is
// a sequence of no rows, which holds nothing to drop. The crate pins `heapless = "0.8"`.
unsafe impl<T, const N: usize> ZeroEmpty for heapless::Vec<T, N> {}

// SAFETY: heapless 0.8's `String` is a `Vec<u8, N>` of its bytes; of none, the empty text.
unsafe impl<const N: usize> ZeroEmpty for heapless::String<N> {}

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

    /// Whether the next push is taken, its room made now where the sequence takes its memory at
    /// its first value ([`FirstUse`](crate::on_use::FirstUse)): what a caller that grows two
    /// sequences as one asks of each before it pushes to either, so a refusal of the second leaves
    /// the first as it was. A sequence whose rows are there already answers [`Self::free_slots`].
    fn make_room(&mut self) -> bool {
        self.free_slots() != 0
    }

    /// Append `value`, or hand it back when the policy's capacity is full.
    fn push(&mut self, value: T) -> Result<(), CapacityFull<T>>;

    /// Append the value `make` returns, built where it is kept, or `false` when the policy's
    /// capacity is full (and `make` is not called). A fixed sequence writes the value into its
    /// slot, so a large element is not a value of its own in the frame of the caller as it is
    /// when passed to [`Self::push`].
    fn push_with<F: FnOnce() -> T>(&mut self, make: F) -> bool;

    /// The sequence as a lent table, where the policy's sequence is one ([`LentSeq`], of the
    /// lent and the region policies), so a body compiled once for every row type can grow it by
    /// the rows' stride. `None` for a sequence that grows by its own type.
    fn as_lent(&mut self) -> Option<&mut LentSeq<T>> {
        None
    }

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

    /// Append every element of `src` in one copy, all or nothing. `Copy`, so a fixed or lent
    /// backing copies the slice whole where an element loop would be inlined, and vectorised, at
    /// each caller.
    fn extend_from_slice(&mut self, src: &[T]) -> Result<(), CapacityFull<()>>
    where
        T: Copy;
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

/// The operations a row needs of the key a [`Storage`] policy keeps ([`Storage::Key`]): it reads
/// as its text, and a clone of it is the same key for another row.
pub trait KeyBacking: Clone + fmt::Debug + Deref<Target = str> + AsRef<str> {
    /// The key's text.
    fn as_str(&self) -> &str;

    /// The key of the session's key arena this is, when the policy keeps its keys there: what a
    /// holder that reads the key past the call may hold a count of
    /// ([`KeyRef::hold_apart`](crate::key_arena::KeyRef::hold_apart)). `None`, the provided
    /// answer, for a key that is its own text.
    fn held(&self) -> Option<&crate::key_arena::KeyRef> {
        None
    }
}

/// Why a table kept no key ([`KeyMaker::key`]). Nothing was taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyUnkept {
    /// The key is longer than a row of the policy holds,
    /// [`MAX_KEYEXPR_BYTES`](crate::caps::MAX_KEYEXPR_BYTES).
    TooLong,
    /// No room is left where the policy keeps its keys: the session's key arena has none, or the
    /// table was handed no key arena.
    NoRoom,
}

/// Where a table of a [`Storage`] policy makes the keys its rows keep ([`Storage::Keys`]).
pub trait KeyMaker<K>: Clone + Default + fmt::Debug {
    /// `text` as a row keeps it, or why it is not kept: a key is never cut short.
    fn key(&self, text: &str) -> Result<K, KeyUnkept>;

    /// [`Self::key`], sharing the key a holder of the same text keeps already where the policy's
    /// keys are shared ones: a row of the session's own declarations takes no second block for a
    /// text its session holds. The policies whose key is its own text keep it again.
    fn shared(&self, text: &str) -> Result<K, KeyUnkept> {
        self.key(text)
    }
}

/// The keys of the policies whose key is its own text ([`Heap`], [`Static`]): nothing to hand a
/// table, and a key refused only when a row cannot hold it.
#[derive(Clone, Copy, Debug, Default)]
pub struct InlineKeys;

#[cfg(feature = "alloc")]
impl KeyBacking for String {
    fn as_str(&self) -> &str {
        String::as_str(self)
    }
}

impl<const N: usize> KeyBacking for heapless::String<N> {
    fn as_str(&self) -> &str {
        heapless::String::as_str(self)
    }
}

#[cfg(feature = "alloc")]
impl KeyMaker<String> for InlineKeys {
    fn key(&self, text: &str) -> Result<String, KeyUnkept> {
        Ok(String::from(text))
    }
}

impl<const N: usize> KeyMaker<heapless::String<N>> for InlineKeys {
    fn key(&self, text: &str) -> Result<heapless::String<N>, KeyUnkept> {
        let mut key = heapless::String::new();
        push_text(&mut key, text).map_err(|_| KeyUnkept::TooLong)?;
        Ok(key)
    }
}

/// The growable policy: the allocator. `N` is advisory; nothing is refused.
#[cfg(feature = "alloc")]
pub struct Heap;

#[cfg(feature = "alloc")]
impl Storage for Heap {
    const ENFORCES_CAPACITY: bool = false;
    const LENT_AT_OPEN: bool = false;
    const ROWS_STAY_APART: bool = false;
    const TAKEN: Taken = Taken::AsItGrows;
    type Scratch = Heap;
    type Seq<T, const N: usize> = Vec<T>;
    type Rows<T, const N: usize> = crate::slot_map::Chunked<T>;
    type Text<const N: usize> = String;
    type Key = String;
    type KeyLen = u32;
    type Keys = InlineKeys;
    type Offset = u32;
    type Ids<V, const N: usize> = crate::id_map::GrowableIdMap<V>;
    type Pooled<T, const N: usize> = BoundedVec<T, N, Heap>;
    #[cfg(target_has_atomic = "64")]
    type Epoch = alloc::sync::Arc<core::sync::atomic::AtomicU64>;
    #[cfg(not(target_has_atomic = "64"))]
    type Epoch = ();
    type HeapForm = ();
    #[cfg(feature = "storage-profile")]
    type Compose = ();
}

/// The static policy: a capacity fixed in the type and no allocator. A push past
/// `N` is refused and hands the value back.
pub struct Static;

impl Storage for Static {
    const ENFORCES_CAPACITY: bool = true;
    const LENT_AT_OPEN: bool = false;
    const ROWS_STAY_APART: bool = false;
    const TAKEN: Taken = Taken::AtBuild;
    type Scratch = Static;
    type Seq<T, const N: usize> = heapless::Vec<T, N>;
    type Rows<T, const N: usize> = BoundedVec<T, N, Static>;
    type Text<const N: usize> = heapless::String<N>;
    type Key = heapless::String<{ crate::caps::MAX_KEYEXPR_BYTES }>;
    type KeyLen = crate::caps::KeyLen;
    type Keys = InlineKeys;
    type Offset = u16;
    type Ids<V, const N: usize> = crate::id_map::FixedIdMap<V, N>;
    type Pooled<T, const N: usize> = BoundedVec<T, N, Static>;
    type Epoch = ();
    type HeapForm = core::convert::Infallible;
    #[cfg(feature = "storage-profile")]
    type Compose = ();
}

/// The policy of storage lent at open: a table whose rows are a span of an [`Arena`], the memory a
/// session reserved when it opened, as many rows as the limit the open resolved, the build's `N`
/// being their ceiling. The algorithm, the refusal and its error are [`Static`]'s; only where
/// the rows lie differs.
///
/// A row keeps its key as the place of a block of the session's key arena
/// ([`KeyRef`](crate::key_arena::KeyRef)), which the table is handed with its rows
/// ([`LentKeys`](crate::key_arena::LentKeys)), and not a buffer of the longest key: a key takes
/// the bytes it has, and gives them back when its row goes (`docs/c-abi-no-heap-pools.md`,
/// section 9.4). With `peer-row-pools`, a table a peer writes, keyed by the peer's ids or not, keeps
/// its rows where the session's open put them ([`RowSpace`](crate::row_pool::RowSpace)): in a pool
/// every face of a session of many shares, the table a list of the rows it holds, at most its build
/// capacity, so a face holds the rows its peer declared and not the most it could; or, for a session
/// of one face, in a span of the table's own laid out as an inline table is (section 4.5). Without
/// it, a build of one face, those tables are inline at their build capacity, as the static
/// policy's are. A sequence a row holds of its own is lent from the arena by the row's maker: one
/// made by `Default` under this policy has no rows, no pool and no key arena, as a table the arena
/// lent nothing has none.
pub struct Lent;

impl Storage for Lent {
    const ENFORCES_CAPACITY: bool = true;
    const LENT_AT_OPEN: bool = true;
    const ROWS_STAY_APART: bool = true;
    const TAKEN: Taken = Taken::AtOpen;
    type Scratch = Static;
    type Seq<T, const N: usize> = LentSeq<T>;
    type Rows<T, const N: usize> = BoundedVec<T, N, Lent>;
    // A working text (a key being canonized) is on the stack; what a row keeps is its `Key`.
    type Text<const N: usize> = heapless::String<N>;
    type Key = crate::key_arena::KeyRef;
    type KeyLen = crate::caps::KeyLen;
    type Keys = crate::key_arena::LentKeys;
    // A span of a lent table addresses rows of an arena a host session may size past 64 KiB.
    type Offset = u32;
    #[cfg(feature = "peer-row-pools")]
    type Ids<V, const N: usize> = crate::id_map::PooledIdMap<V, N>;
    #[cfg(not(feature = "peer-row-pools"))]
    type Ids<V, const N: usize> = crate::id_map::FixedIdMap<V, N>;
    #[cfg(feature = "peer-row-pools")]
    type Pooled<T, const N: usize> = crate::row_pool::PooledRows<crate::row_pool::Seq<T>, N>;
    #[cfg(not(feature = "peer-row-pools"))]
    type Pooled<T, const N: usize> = BoundedVec<T, N, Static>;
    type Epoch = ();
    type HeapForm = core::convert::Infallible;
    #[cfg(feature = "storage-profile")]
    type Compose = crate::wireexpr_resolve::ComposeRow;
}

/// The policy of storage a region the build laid out places: [`Lent`]'s rows, where the build's
/// layout puts them rather than an arena's walk. A session whose shape the build fixes is one
/// struct of its layers' tables and their rows, zeroed by the allocator in one block
/// ([`ZeroEmpty`]); [`place_seqs`] tells each table where its rows lie, and nothing is planned or
/// lent.
///
/// The rows of a table lie outside the table, as [`Lent`]'s do, so a call that reads its row where
/// it lies, with the tables let go, is not reached by a `&mut` of the table. A row keeps its key in
/// the region's [`KeyArena`](crate::key_arena::KeyArena), as [`Lent`]'s does in the arena's. A table
/// a peer writes keeps its rows inline at its build capacity, as the static policy's do: the
/// region holds one face, so there is no pool to share. A key composed while a peer's message is
/// delivered is composed in a row inline in the table (`wireexpr_resolve::ComposeInline`).
pub struct Region;

impl Storage for Region {
    const ENFORCES_CAPACITY: bool = true;
    const LENT_AT_OPEN: bool = true;
    const ROWS_STAY_APART: bool = true;
    const TAKEN: Taken = Taken::AtOpen;
    type Scratch = Static;
    type Seq<T, const N: usize> = LentSeq<T>;
    type Rows<T, const N: usize> = BoundedVec<T, N, Region>;
    type Text<const N: usize> = heapless::String<N>;
    type Key = crate::key_arena::KeyRef;
    type KeyLen = crate::caps::KeyLen;
    type Keys = crate::key_arena::LentKeys;
    type Offset = u32;
    type Ids<V, const N: usize> = crate::id_map::FixedIdMap<V, N>;
    type Pooled<T, const N: usize> = BoundedVec<T, N, Static>;
    type Epoch = ();
    type HeapForm = core::convert::Infallible;
    #[cfg(feature = "storage-profile")]
    type Compose = crate::wireexpr_resolve::ComposeInline;
}

/// The policy of storage taken on use: [`Region`]'s shape, its memory taken from the allocator by
/// each table at its first value rather than reserved when the session opens. A table is made with
/// its count and no memory ([`BoundedVec::counted`]); its first value takes all its count's rows in
/// one allocation ([`FirstUse`](crate::on_use::FirstUse)), which never grows nor moves, so a row
/// stays where it was put as on the lent policy, and a value past the count, or one the allocator
/// refuses, is handed back as one past [`Static`]'s `N` is. A row keeps its key as an allocation of
/// its own ([`HeapKey`](crate::on_use::HeapKey)), counted against the session's key budget
/// ([`KeyBudget`](crate::on_use::KeyBudget)), so a key past the budget is refused as one past the
/// key arena is. A table never used takes nothing.
///
/// A table a peer writes keeps its rows inline at its build capacity, and a key composed while a
/// peer's message is delivered is composed in a row inline in the table, as on [`Region`].
#[cfg(feature = "alloc")]
pub struct OnUse;

#[cfg(feature = "alloc")]
impl Storage for OnUse {
    const ENFORCES_CAPACITY: bool = true;
    const LENT_AT_OPEN: bool = false;
    const ROWS_STAY_APART: bool = true;
    const TAKEN: Taken = Taken::AtFirstUse;
    type Scratch = Static;
    type Seq<T, const N: usize> = crate::on_use::FirstUse<T, N>;
    type Rows<T, const N: usize> = BoundedVec<T, N, OnUse>;
    type Text<const N: usize> = heapless::String<N>;
    type Key = crate::on_use::HeapKey;
    type KeyLen = crate::caps::KeyLen;
    type Keys = crate::on_use::BudgetKeys;
    type Offset = u32;
    type Ids<V, const N: usize> = crate::id_map::FixedIdMap<V, N>;
    type Pooled<T, const N: usize> = BoundedVec<T, N, Static>;
    type Epoch = ();
    type HeapForm = core::convert::Infallible;
    #[cfg(feature = "storage-profile")]
    type Compose = crate::wireexpr_resolve::ComposeInline;
}

// SAFETY: heapless 0.8's `Vec` and `String`, both `ZeroEmpty`.
unsafe impl ZeroSeqs for Static {}
// SAFETY: a `LentSeq` and a heapless 0.8 `String`, both `ZeroEmpty`.
unsafe impl ZeroSeqs for Lent {}
// SAFETY: as `Lent`'s.
unsafe impl ZeroSeqs for Region {}

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
        T: Copy,
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
        // A `heapless::Vec` never holds more than `N`.
        N.wrapping_sub(self.len())
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
            self.set_len(len.wrapping_add(1));
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
        T: Copy,
    {
        let len = self.len();
        let Some(end) = append_end::<N>(len, src.len()) else {
            return Err(CapacityFull(()));
        };
        // SAFETY: the values are written into the buffer's room past its length, checked above,
        // and the length is set after them; `T: Copy` has no drop and is copied bitwise.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), self.as_mut_ptr().add(len), src.len());
            self.set_len(end);
        }
        Ok(())
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
        push_heap_text(self, s)
    }

    fn push(&mut self, c: char) -> Result<(), CapacityFull<char>> {
        push_heap_text(self, c.encode_utf8(&mut [0u8; 4])).map_err(|_| CapacityFull(c))
    }

    fn clear(&mut self) {
        String::clear(self);
    }
}

/// Append `s` to `text` with one copy, all or nothing: refused, `text` is left as it was.
/// heapless's own `push_str` appends a byte at a time, a loop each caller inlines; every heapless
/// text of the crate appends through this instead.
#[inline]
pub fn push_text<const N: usize>(
    text: &mut heapless::String<N>,
    s: &str,
) -> Result<(), CapacityFull<()>> {
    // SAFETY: what is appended is a whole `str`, so the text stays UTF-8, and `push_bytes` writes
    // all of it or none.
    push_bytes(unsafe { text.as_mut_vec() }, s.as_bytes())
}

/// Where an append of `add` bytes to a heapless buffer of capacity `N` that holds `len` ends, or
/// `None` when the buffer has no room for it: the one room check of [`push_bytes`], which a reader
/// that refuses what such a buffer would not keep asks too.
#[inline]
pub const fn append_end<const N: usize>(len: usize, add: usize) -> Option<usize> {
    match len.checked_add(add) {
        Some(end) if end <= N => Some(end),
        _ => None,
    }
}

/// Append `s` to `bytes` with one copy, all or nothing: refused, `bytes` is left as it was.
/// heapless's own `extend_from_slice` and `from_slice` copy a byte at a time, a loop each caller
/// inlines; every heapless byte buffer of the crate, and every heapless text through
/// [`push_text`], appends through this instead.
#[inline]
pub fn push_bytes<const N: usize>(
    bytes: &mut heapless::Vec<u8, N>,
    s: &[u8],
) -> Result<(), CapacityFull<()>> {
    let len = bytes.len();
    let Some(end) = append_end::<N>(len, s.len()) else {
        return Err(CapacityFull(()));
    };
    // SAFETY: the bytes are written into the buffer's room past its length, checked above, and
    // the length is set after them; `u8` needs no drop, so nothing is lost if the length is not.
    unsafe {
        core::ptr::copy_nonoverlapping(s.as_ptr(), bytes.as_mut_ptr().add(len), s.len());
        bytes.set_len(end);
    }
    Ok(())
}

/// Append `s` to `bytes` on the heap with one copy, all or nothing: refused, `bytes` is left as
/// it was. The room is asked of the heap with `try_reserve`, so a full heap is a refusal the caller
/// answers, where `Vec::extend_from_slice` would end the program; every heap text and byte buffer
/// of the crate that a door appends to appends through this.
#[cfg(feature = "alloc")]
pub fn push_heap_bytes(bytes: &mut Vec<u8>, s: &[u8]) -> Result<(), CapacityFull<()>> {
    bytes.try_reserve(s.len()).map_err(|_| CapacityFull(()))?;
    let len = bytes.len();
    // SAFETY: room for `s.len()` bytes past the length was reserved above; the bytes are written
    // there and the length set after them, and `u8` needs no drop.
    unsafe {
        core::ptr::copy_nonoverlapping(s.as_ptr(), bytes.as_mut_ptr().add(len), s.len());
        bytes.set_len(len.saturating_add(s.len()));
    }
    Ok(())
}

/// [`push_heap_bytes`] for a heap text: `s` appended whole, or refused with `text` as it was.
#[cfg(feature = "alloc")]
pub fn push_heap_text(text: &mut String, s: &str) -> Result<(), CapacityFull<()>> {
    // SAFETY: what is appended is a whole `str`, so the text stays UTF-8, and `push_heap_bytes`
    // writes all of it or none.
    push_heap_bytes(unsafe { text.as_mut_vec() }, s.as_bytes())
}

/// A copy of `s` on the heap of its own, or `None` when the heap has no room for it.
#[cfg(feature = "alloc")]
pub fn heap_copy(s: &[u8]) -> Option<Vec<u8>> {
    let mut copy = Vec::new();
    push_heap_bytes(&mut copy, s).ok()?;
    Some(copy)
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
        push_text(self, s)
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
// Transparent, so a region's layout finds a table's sequence where it finds the table.
#[repr(transparent)]
pub struct BoundedVec<T, const N: usize, P: Storage = Profile> {
    inner: P::Seq<T, N>,
}

// SAFETY: a `BoundedVec` is its policy's sequence alone, whose zero bytes are a sequence of no rows.
unsafe impl<T, const N: usize, P: Storage> ZeroEmpty for BoundedVec<T, N, P> where
    P::Seq<T, N>: ZeroEmpty
{
}

impl<T, const N: usize> BoundedVec<T, N, Lent> {
    /// The `room` rows at `base`, a span an arena lent, none of them holding a value yet: the
    /// table `Arena::lend` hands out, made by the caller that lent the span itself.
    ///
    /// # Safety
    /// `base` is aligned for `T`, and the `room` rows of `T` from it are valid for reads and
    /// writes, hold no value and are used by nothing else for as long as the table lives.
    pub(crate) const unsafe fn lent_over(base: NonNull<T>, room: u32) -> Self {
        // SAFETY: the caller's contract, which is `LentSeq::lent`'s.
        let inner = unsafe { LentSeq::lent(base, room) };
        Self { inner }
    }

    /// The table over the `M` rows at `places`, rows a region the build lays out keeps beside
    /// the table instead of an arena's span: `room` of them, at most the rows there, the build's
    /// ceiling `N` and what a lent table counts.
    ///
    /// # Safety
    /// `places` is aligned and valid for reads and writes, holds no value, and is reached by
    /// nothing but the table for as long as it lives.
    pub unsafe fn placed_over<const M: usize>(
        places: NonNull<[core::mem::MaybeUninit<T>; M]>,
        room: usize,
    ) -> Self {
        let room = room.min(M).min(N).min(u32::MAX as usize) as u32;
        // SAFETY: the caller's contract, for no more rows than lie at `places`: an array of
        // `MaybeUninit<T>` is laid out as as many rows of `T`.
        unsafe { Self::lent_over(places.cast::<T>(), room) }
    }

    /// The next row, for `write` to build a value in where the table keeps it, counted as held
    /// once `write` returns, and the value built; `None`, `write` not called, when the table holds
    /// every row it was lent. For a value too large to be one of its own in a frame, which
    /// [`Self::push_with`] does not promise.
    ///
    /// # Safety
    /// `write` leaves a whole `T` in the row it is handed, and does not unwind.
    pub unsafe fn push_in_place(
        &mut self,
        write: impl FnOnce(&mut core::mem::MaybeUninit<T>),
    ) -> Option<&mut T> {
        let seq = &mut self.inner;
        seq.refuse_unlent();
        if seq.len == seq.room {
            return None;
        }
        // SAFETY: `len < room`, so the row at `len` is one this table was lent and holds no
        // value; a `MaybeUninit<T>` has the layout of `T`.
        let row = unsafe {
            &mut *seq
                .rows()
                .as_ptr()
                .add(seq.len())
                .cast::<core::mem::MaybeUninit<T>>()
        };
        write(&mut *row);
        seq.len = seq.len.saturating_add(1);
        // SAFETY: the caller's contract: `write` left a whole value in the row.
        Some(unsafe { row.assume_init_mut() })
    }
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
impl<T, const N: usize> BoundedVec<T, N, OnUse> {
    /// A table of at most `rows` values, held to the build's `N`, that takes no memory until its
    /// first value and then all of its rows at once: what a session's open makes each of its tables
    /// with, from the limits it resolved. `Default` makes one of `N`.
    pub const fn counted(rows: usize) -> Self {
        Self {
            inner: crate::on_use::FirstUse::counted(rows),
        }
    }

    /// Whether the table took its rows.
    pub fn holds_rows(&self) -> bool {
        self.inner.holds_rows()
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

    /// Whether the next push is taken, its room made now where the policy takes a table's memory at
    /// its first value ([`SeqBacking::make_room`]).
    pub fn make_room(&mut self) -> bool {
        self.inner.make_room()
    }

    /// The policy's sequence as a lent table, where it is one ([`SeqBacking::as_lent`]).
    pub(crate) fn as_lent(&mut self) -> Option<&mut LentSeq<T>> {
        self.inner.as_lent()
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
        while let Some(entry) = self.inner.as_mut_slice().get_mut(*at) {
            if extract(entry) {
                return Some(self.inner.remove(*at));
            }
            // Below the table's length, so the next place does not wrap.
            *at = at.wrapping_add(1);
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
        self.inner
            .as_mut_slice()
            .get_mut(start..end)
            .ok_or(CapacityFull(()))
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

// A table is its rows: two are equal when they hold equal rows in the same order, and one reads
// as the list of them, whatever room each was given. Through the slice, so a type that holds a
// table derives its own equality and its own reading with no field written out by hand.
impl<T: PartialEq, const N: usize, P: Storage> PartialEq for BoundedVec<T, N, P> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl<T: Eq, const N: usize, P: Storage> Eq for BoundedVec<T, N, P> {}

impl<T: fmt::Debug, const N: usize, P: Storage> fmt::Debug for BoundedVec<T, N, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

// ---- The lent policy's rows, and the arena that lends them ---------------------------------

/// The rows of a table of the [`Lent`] policy: a span of an [`Arena`], its values at the start.
/// It owns its values and not its memory: dropped, it drops what it holds and gives no memory
/// back, the memory being the arena's owner's to release whole.
// `repr(C)`: the same three words for every `T`, so a region's layout places the rows of any
// table through one body (`place_seqs`).
#[repr(C)]
pub struct LentSeq<T> {
    /// The first row, or `None` for a table made by `Default` or of all zero bytes, which was
    /// lent none and is no table to put a value in (`refuse_unlent`).
    base: Option<NonNull<T>>,
    /// The rows that hold values, and the rows the arena lent, the most the table holds: each
    /// under `u32::MAX`, which [`Arena::lend`] holds a table to, so a table is a pointer and two
    /// words of 32 bits on every target.
    len: u32,
    room: u32,
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
    const unsafe fn lent(base: NonNull<T>, room: u32) -> Self {
        Self {
            base: Some(base),
            len: 0,
            room,
            _owns: PhantomData,
        }
    }

    /// The rows that hold values.
    #[inline(always)]
    fn len(&self) -> usize {
        self.len as usize
    }

    /// The first row: aligned and non-null even for a table lent none, whose `room` of zero keeps
    /// every write away from it.
    #[inline(always)]
    fn rows(&self) -> NonNull<T> {
        match self.base {
            Some(base) => base,
            None => NonNull::dangling(),
        }
    }

    /// The rows the arena lent.
    #[inline(always)]
    fn room(&self) -> usize {
        self.room as usize
    }

    /// Stop a debug build at a value put in a table no arena lent rows to. Such a table refuses
    /// every value as a full one does, so a release build refuses it; but it is a defect of the
    /// table's maker, not a table at its limit, and a refusal that looks like the limit would hide
    /// it.
    #[inline(always)]
    fn refuse_unlent(&self) {
        debug_assert!(
            self.base.is_some(),
            "a value was put in a lent table no arena lent rows to: a table of this policy is \
             made by `Arena::lend`, and a working buffer takes the policy's `Storage::Scratch`"
        );
    }

    /// Drop the values from `len` on. The length is shortened first, so a value whose drop
    /// panics leaks the ones after it rather than letting them be dropped twice.
    fn drop_from(&mut self, len: usize) {
        if len >= self.len() {
            return;
        }
        // `len < self.len`, checked above.
        let tail = self.len().wrapping_sub(len);
        // Below the length, which is a `u32`.
        self.len = len as u32;
        if !core::mem::needs_drop::<T>() {
            return;
        }
        // SAFETY: the `tail` rows from `len` held values of `T`, `size_of::<T>()` bytes apart,
        // which the length no longer covers, so each is dropped here once, by `drop_row::<T>`.
        unsafe {
            drop_rows(
                self.rows().as_ptr().add(len).cast::<u8>(),
                tail,
                core::mem::size_of::<T>(),
                drop_row::<T>,
            );
        }
    }
}

/// Drop `len` rows `stride` bytes apart from `first`, each by `drop_one`: the walk over the rows of
/// a lent table, one body for every row type, which hands each row to the drop of its own type.
///
/// # Safety
/// The `len` rows from `first` each hold a value `drop_one` drops, which nothing reads after.
#[inline(never)]
pub(crate) unsafe fn drop_rows(
    first: *mut u8,
    len: usize,
    stride: usize,
    drop_one: unsafe fn(*mut u8),
) {
    let mut row = first;
    for _ in 0..len {
        // SAFETY: the caller's contract: `row` is one of the `len` rows, each a value to drop.
        unsafe { drop_one(row) };
        row = row.wrapping_add(stride);
    }
}

/// Drop the `T` at `row`.
///
/// # Safety
/// `row` holds a value of `T`, aligned for it, which nothing reads after.
pub(crate) unsafe fn drop_row<T>(row: *mut u8) {
    // SAFETY: the caller's contract.
    unsafe { core::ptr::drop_in_place(row.cast::<T>()) }
}

// SAFETY: `LentSeq` is `repr(C)` of an `Option<NonNull<T>>`, whose null is `None`, two `u32`s and a
// `PhantomData`: all zero bytes are a table lent no rows and holding no value, which drops nothing.
unsafe impl<T> ZeroEmpty for LentSeq<T> {}

impl<T, const N: usize> BoundedVec<T, N, Region> {
    /// Count the first `len` rows of a table a region placed as holding values: rows its owner
    /// wrote where they lie before the table was placed over them, so a value too large for a frame
    /// is never one (a region's sets of face tables, each written field by field in its row). A
    /// count past the rows placed is held to them.
    ///
    /// # Safety
    /// The table holds no value yet, and each of its first `len` rows (at most the rows placed)
    /// holds a value of `T` that nothing else owns or drops.
    pub unsafe fn assume_held(&mut self, len: usize) {
        debug_assert_eq!(
            self.inner.len, 0,
            "a table counts rows it was placed over once"
        );
        let held = if len < self.inner.room() {
            len
        } else {
            self.inner.room()
        };
        // At most the room, which is a `u32`.
        self.inner.len = held as u32;
    }
}

/// Where a region the build lays out keeps the rows of one table of the [`Lent`] shape: a line of
/// the region's own description, which [`place_seqs`] reads. Offsets are bytes from the region's
/// start, so the description is a constant of the region's type (`core::mem::offset_of!`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeqPlace {
    /// Where the table's [`LentSeq`] lies.
    pub seq: usize,
    /// Where its rows lie.
    pub rows: usize,
    /// How many rows lie there.
    pub room: u32,
}

impl SeqPlace {
    /// The place of a table of rows of `T` whose sequence lies at `seq`, its `room` rows at `rows`.
    /// A room past what a lent table counts stops the build that describes it.
    pub const fn of<T>(seq: usize, rows: usize, room: usize) -> Self {
        assert!(
            room <= u32::MAX as usize,
            "a lent table counts its rows in 32 bits"
        );
        assert!(
            matches!(rows.checked_rem(core::mem::align_of::<T>()), Some(0)),
            "a table's rows start where their type's alignment allows"
        );
        Self {
            seq,
            rows,
            room: room as u32,
        }
    }

    /// [`Self::of`] for a table whose rows are `ROOM`, the length of the array the region's type
    /// keeps them in: a const of the caller's, as the length of any storage is.
    pub const fn of_room<T, const ROOM: usize>(seq: usize, rows: usize) -> Self {
        Self::of::<T>(seq, rows, ROOM)
    }
}

/// Tell each table `places` names where its rows lie in the region at `region`, and how many: the
/// one body that joins a region's tables to their rows, a walk of the region's description and not
/// of a plan. Each table is left holding no value, as one an arena lent.
///
/// # Safety
/// For each place: a [`LentSeq`] of a table of rows of some `T` lies at `seq` in the region and
/// holds no value; the `room` rows of `T` from `rows` lie in the region, are aligned for `T`, and
/// are reached by nothing but that table for as long as it lives; no two places name the same rows.
pub unsafe fn place_seqs(region: NonNull<u8>, places: &[SeqPlace]) {
    for place in places {
        // `LentSeq` is `repr(C)`, so its fields lie at the same offsets whatever its row type.
        let seq = region
            .as_ptr()
            .wrapping_add(place.seq)
            .cast::<LentSeq<u8>>();
        // SAFETY: the caller's contract: `seq` is a sequence in the region and `rows` its rows,
        // inside the region, which is not null; the fields are written through the raw pointer, so
        // no reference to the sequence or its rows is made.
        unsafe {
            let rows = NonNull::new_unchecked(region.as_ptr().add(place.rows));
            core::ptr::addr_of_mut!((*seq).base).write(Some(rows));
            core::ptr::addr_of_mut!((*seq).len).write(0);
            core::ptr::addr_of_mut!((*seq).room).write(place.room);
        }
    }
}

/// Put one row after the last of the lent table at `seq`, whose rows lie `stride` bytes apart:
/// `write` writes it at its place, and the length counts it after. `false`, and `write` not
/// called, when the table holds every row it was lent. One body for every row type, for a table
/// that grows where only its rows' stride is known (a slot map's free slots).
///
/// # Safety
/// `seq` points at a live [`LentSeq`] of rows of some `T` whose size is `stride`, reached by
/// nothing else during the call, and `write` writes a whole `T` at the place it is handed.
pub(crate) unsafe fn push_erased(
    seq: NonNull<LentSeq<u8>>,
    stride: usize,
    write: unsafe fn(NonNull<u8>),
) -> bool {
    let seq = seq.as_ptr();
    // SAFETY: the caller's contract. `LentSeq` is `repr(C)`, so its fields lie at the same offsets
    // whatever its row type, and they are read and written through the raw pointer, so no
    // reference to a table of another row type is made. `len < room`, so the row at `len` is one
    // the table was lent, `len` strides from the first, and holds no value.
    unsafe {
        let len = (*seq).len;
        if len == (*seq).room {
            return false;
        }
        let Some(base) = (*seq).base else {
            return false;
        };
        let at = base.as_ptr().add((len as usize).wrapping_mul(stride));
        write(NonNull::new_unchecked(at));
        (*seq).len = len.wrapping_add(1);
    }
    true
}

impl<T> Drop for LentSeq<T> {
    fn drop(&mut self) {
        self.drop_from(0);
    }
}

/// A region's description: the lines that place its tables' rows ([`SeqPlace`]) and the offsets of
/// the tables' handles to the region's key arena, at most `MAX` of each. A constant of the
/// region's type, joined from its tables' own descriptions (`SlotMap::places` and the like) by
/// const fns, so one walk of it ([`place_region`](crate::key_arena::place_region)) joins every table
/// of a session to its rows and its keys, whichever kinds the build keeps.
///
/// [`SlotMap::places`]: crate::slot_map::SlotMap::places
#[derive(Clone, Copy, Debug)]
pub struct RegionLines<const MAX: usize> {
    seqs: [SeqPlace; MAX],
    seq_count: usize,
    keys: [usize; MAX],
    key_count: usize,
}

impl<const MAX: usize> RegionLines<MAX> {
    /// A description of no line.
    pub const EMPTY: Self = Self {
        seqs: [SeqPlace {
            seq: 0,
            rows: 0,
            room: 0,
        }; MAX],
        seq_count: 0,
        keys: [0; MAX],
        key_count: 0,
    };

    /// This description and the line `line`. A description past `MAX` lines stops the build that
    /// writes it.
    pub const fn seq(mut self, line: SeqPlace) -> Self {
        let placed = match self.seqs.split_at_mut_checked(self.seq_count) {
            Some((_, [free, ..])) => {
                *free = line;
                true
            }
            _ => false,
        };
        assert!(
            placed,
            "a region's description holds every line of its tables"
        );
        self.seq_count = self.seq_count.wrapping_add(1);
        self
    }

    /// This description and each of `lines`, in order.
    pub const fn seqs(mut self, lines: &[SeqPlace]) -> Self {
        let mut rest = lines;
        while let [line, tail @ ..] = rest {
            self = self.seq(*line);
            rest = tail;
        }
        self
    }

    /// This description and a table's handle to the key arena at `at` in the region: a
    /// [`LentKeys`](crate::key_arena::LentKeys). Past `MAX` handles it stops the build.
    pub const fn keys_at(mut self, at: usize) -> Self {
        let placed = match self.keys.split_at_mut_checked(self.key_count) {
            Some((_, [free, ..])) => {
                *free = at;
                true
            }
            _ => false,
        };
        assert!(
            placed,
            "a region's description holds every key handle of its tables"
        );
        self.key_count = self.key_count.wrapping_add(1);
        self
    }

    /// This description and every line of `other`, each moved `by` bytes on: the description of
    /// a part of the region that lies `by` bytes from its start.
    pub const fn with<const PART: usize>(mut self, other: &RegionLines<PART>, by: usize) -> Self {
        let mut seqs = other.seq_lines();
        while let [line, tail @ ..] = seqs {
            self = self.seq(SeqPlace {
                seq: line.seq.wrapping_add(by),
                rows: line.rows.wrapping_add(by),
                room: line.room,
            });
            seqs = tail;
        }
        let mut keys = other.key_lines();
        while let [at, tail @ ..] = keys {
            self = self.keys_at(at.wrapping_add(by));
            keys = tail;
        }
        self
    }

    /// The lines that place the tables' rows.
    pub const fn seq_lines(&self) -> &[SeqPlace] {
        match self.seqs.split_at_checked(self.seq_count) {
            Some((lines, _)) => lines,
            None => &self.seqs,
        }
    }

    /// Where the tables keep their handles to the key arena.
    pub const fn key_lines(&self) -> &[usize] {
        match self.keys.split_at_checked(self.key_count) {
            Some((keys, _)) => keys,
            None => &self.keys,
        }
    }
}

impl<T> SeqBacking<T> for LentSeq<T> {
    #[inline(always)]
    fn empty() -> Self {
        Self {
            base: None,
            len: 0,
            room: 0,
            _owns: PhantomData,
        }
    }

    fn as_slice(&self) -> &[T] {
        // SAFETY: the first `len` rows hold values, and `base` is aligned and non-null even for a
        // table lent nothing.
        unsafe { core::slice::from_raw_parts(self.rows().as_ptr(), self.len()) }
    }

    fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: as `as_slice`, and `&mut self` makes this the only borrow of them.
        unsafe { core::slice::from_raw_parts_mut(self.rows().as_ptr(), self.len()) }
    }

    // `len` never passes `room`, so the counts below are exact.
    fn free_slots(&self) -> usize {
        self.room().wrapping_sub(self.len())
    }

    fn push(&mut self, value: T) -> Result<(), CapacityFull<T>> {
        self.refuse_unlent();
        if self.len == self.room {
            return Err(CapacityFull(value));
        }
        // SAFETY: `len < room`, so the row at `len` is one this table was lent and holds no value.
        unsafe { self.rows().as_ptr().add(self.len()).write(value) };
        self.len = self.len.wrapping_add(1);
        Ok(())
    }

    fn push_with<F: FnOnce() -> T>(&mut self, make: F) -> bool {
        self.refuse_unlent();
        if self.len == self.room {
            return false;
        }
        // SAFETY: as `push`; `make` panicking leaves the row and the length as they were.
        unsafe { self.rows().as_ptr().add(self.len()).write(make()) };
        self.len = self.len.wrapping_add(1);
        true
    }

    fn as_lent(&mut self) -> Option<&mut LentSeq<T>> {
        Some(self)
    }

    fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        self.len = self.len.wrapping_sub(1);
        // SAFETY: the row at the old last index held a value, which the length no longer covers,
        // so it is read out once.
        Some(unsafe { self.rows().as_ptr().add(self.len()).read() })
    }

    fn remove(&mut self, index: usize) -> T {
        assert!(
            index < self.len(),
            "removal index {index} is past a lent table of {} values",
            self.len
        );
        // SAFETY: `index < len`: the value at `index` is read out once, and the rows after it, which
        // hold values, move down over it before the length drops by one.
        unsafe {
            let at = self.rows().as_ptr().add(index);
            let value = at.read();
            core::ptr::copy(
                at.add(1),
                at,
                self.len().wrapping_sub(index).wrapping_sub(1),
            );
            self.len = self.len.wrapping_sub(1);
            value
        }
    }

    fn retain<F: FnMut(&T) -> bool>(&mut self, mut keep: F) {
        // Each value is asked once, in order: one taken out moves the next to where it stood.
        let mut index = 0usize;
        while let Some(value) = self.as_slice().get(index) {
            if keep(value) {
                index = index.wrapping_add(1);
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
        self.refuse_unlent();
        if len > self.room() {
            return Err(CapacityFull(()));
        }
        self.drop_from(len);
        while self.len() < len {
            // Within the rows checked above, so every push is taken.
            if self.push(fill.clone()).is_err() {
                break;
            }
        }
        Ok(())
    }

    fn extend_from_slice(&mut self, src: &[T]) -> Result<(), CapacityFull<()>>
    where
        T: Copy,
    {
        self.refuse_unlent();
        if src.len() > self.room().wrapping_sub(self.len()) {
            return Err(CapacityFull(()));
        }
        // SAFETY: the `src.len()` rows from `len` are rows this table was lent, checked above, and
        // hold no value; `T: Copy` is copied bitwise. The new length is within `room`, a `u32`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr(),
                self.rows().as_ptr().add(self.len()),
                src.len(),
            );
        }
        self.len = self.len().wrapping_add(src.len()) as u32;
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
            base: seq.rows(),
            next: 0,
            end: seq.len(),
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
        // Below `end`, checked above.
        self.next = self.next.wrapping_add(1);
        // SAFETY: the rows `next..end` hold values this iterator owns; this one is read out once
        // and the cursor has passed it.
        Some(unsafe { self.base.as_ptr().add(index).read() })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.end.wrapping_sub(self.next);
        (left, Some(left))
    }
}

impl<T> ExactSizeIterator for LentIntoIter<T> {}

impl<T> Drop for LentIntoIter<T> {
    fn drop(&mut self) {
        let (from, left) = (self.next, self.end.wrapping_sub(self.next));
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

/// What a length is rounded up by before [`ARENA_ALIGN`]'s multiple is cut from it.
const ARENA_ROUND_UP: usize = ARENA_ALIGN - 1;

/// What an arena of no bytes points at ([`Arena::empty`]): an address aligned as every span of an
/// arena starts.
#[repr(align(16))]
struct SpanStart;

const _: () = assert!(
    core::mem::align_of::<SpanStart>() == ARENA_ALIGN,
    "an empty arena's spans start aligned as every arena's do"
);

static NO_BYTES: SpanStart = SpanStart;

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
    /// Whether every byte not lent yet is zero ([`Self::over_zeroed`]): a table whose empty state
    /// is all-zero bytes is then lent as the memory lies.
    zeroed: bool,
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

/// Lends the tables of a set from an [`Arena`] in the order they are asked, keeping the first
/// refusal: every table asked after it is lent no rows, as a table made without an arena is, and
/// [`Self::finish`] hands the refusal back. The set is built whole either way and given up whole,
/// once, so its maker has no path of its own for each table that gives up the ones before it.
pub struct TableLender<'a> {
    arena: &'a mut Arena,
    refused: Option<LendRefused>,
}

impl<'a> TableLender<'a> {
    /// A lender of the tables of one set from `arena`.
    pub fn new(arena: &'a mut Arena) -> Self {
        Self {
            arena,
            refused: None,
        }
    }

    /// The span of `rows` rows of `stride` bytes, at most `ceiling`, as the arena lends it
    /// (`Arena::lend_rows`). Once a table is refused, this one among them, a span of no rows
    /// where the arena has got to, which takes nothing and starts on [`ARENA_ALIGN`] as every span
    /// does: the table made over it holds no value, as a full one, so its maker needs no path of
    /// its own for a refusal.
    ///
    /// The rows are `stride` bytes each, counted here: every table of a session's open is lent
    /// through this one body, out of line, and each would carry the count and the refusal's
    /// bookkeeping of its own.
    #[inline(never)]
    pub(crate) fn lend_stride(
        &mut self,
        rows: usize,
        ceiling: usize,
        stride: usize,
    ) -> (NonNull<u8>, u32) {
        if self.refused.is_none() {
            match self
                .arena
                .lend_rows(rows, ceiling, Arena::stride_bytes(rows, stride))
            {
                Ok(span) => return span,
                Err(why) => self.refused = Some(why),
            }
        }
        (self.arena.next_span(), 0)
    }

    /// The table `lend` lends from the arena; the table of no rows when it is refused or a table
    /// before it was.
    pub fn lend_with<T: Default>(
        &mut self,
        lend: impl FnOnce(&mut Arena) -> Result<T, LendRefused>,
    ) -> T {
        if self.refused.is_none() {
            match lend(&mut *self.arena) {
                Ok(table) => return table,
                Err(why) => self.refused = Some(why),
            }
        }
        T::default()
    }

    /// A table of `rows` rows of `T`, at most the build's ceiling `N`, as [`Arena::lend`] lends
    /// one; a table of no rows, which takes no value, once a table is refused, this one among them.
    pub fn table<T, const N: usize>(&mut self, rows: usize) -> BoundedVec<T, N, Lent> {
        const {
            assert!(
                core::mem::align_of::<T>() <= ARENA_ALIGN,
                "a row of a lent table asks for more alignment than an arena's spans start on"
            )
        };
        let (at, room) = self.lend_stride(rows, N, core::mem::size_of::<T>());
        // SAFETY: `lend_stride` handed out a span of `room` rows of `T` lent to nothing before,
        // or a span of no rows, starting on `ARENA_ALIGN`, which is at least `T`'s alignment
        // (asserted above).
        unsafe { BoundedVec::lent_over(at.cast::<T>(), room) }
    }

    /// A table of `count` buffers of `size` bytes, as [`Arena::lend_byte_cells`] lends one; a
    /// table of no buffer once a table is refused, this one among them.
    pub fn byte_cells(&mut self, size: usize, count: usize) -> LentByteCells {
        self.byte_cells_of(size, count)
    }

    /// [`Self::byte_cells`] with flags of the form `F` ([`CellFlag`]).
    pub fn byte_cells_of<F: CellFlag>(&mut self, size: usize, count: usize) -> LentByteCells<F> {
        let cells = self.cell_spans(size, count);
        // SAFETY: `cell_spans` answered the spans `Arena::cell_spans` lent, or none of no cell,
        // whose dangling places a table of no cell never reads.
        unsafe { cells.table() }
    }

    /// The spans of a table of `count` buffers of `size` bytes, as [`Arena::cell_spans`] lends
    /// them; none, of no cell, once a table is refused, this one among them. Untyped and out of
    /// line, so every form of flag lends through one body.
    #[inline(never)]
    fn cell_spans(&mut self, size: usize, count: usize) -> CellSpans {
        if self.refused.is_none() {
            match self.arena.cell_spans(size, count) {
                Ok(cells) => return cells,
                Err(why) => self.refused = Some(why),
            }
        }
        CellSpans::NONE
    }

    /// A key arena of `bytes` bytes of blocks, as [`Arena::lend_keys`] lends one, as the tables
    /// that keep their keys in it hold it; no arena, which keeps no key, once a table is refused,
    /// this one among them. [`Self::finish_keys`] hands back the arena itself.
    pub fn keys(
        &mut self,
        bytes: usize,
        longest: crate::limits::MaxKeyexprBytesHeld,
    ) -> crate::key_arena::LentKeys {
        if self.refused.is_none() {
            match self.arena.lend_keys(bytes, longest) {
                Ok(keys) => return crate::key_arena::LentKeys::from(keys),
                Err(why) => self.refused = Some(why),
            }
        }
        crate::key_arena::LentKeys::default()
    }

    /// The first refusal, if a table was refused, else the key arena `keys` holds: the one
    /// [`Self::keys`] lent, which a lend that refused nothing always holds. Refused as an arena
    /// with no room left when `keys` holds none.
    pub fn finish_keys(
        self,
        keys: crate::key_arena::LentKeys,
    ) -> Result<crate::key_arena::KeySpace, LendRefused> {
        match keys.space() {
            Some(space) => self.finish().map(|()| space),
            None => {
                let left = self.arena.bytes().saturating_sub(self.arena.high_water());
                Err(self
                    .refused
                    .unwrap_or(LendRefused::Exhausted { asked: None, left }))
            }
        }
    }

    /// The first refusal, if a table was refused.
    pub fn finish(self) -> Result<(), LendRefused> {
        match self.refused {
            Some(why) => Err(why),
            None => Ok(()),
        }
    }
}

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
            zeroed: false,
        }
    }

    /// An arena of the `bytes` bytes at `base`, none of them lent and every one of them zero: memory
    /// handed zeroed, as the allocator's zeroed block or a region in `.bss` is. A table it lends
    /// whose empty state is all-zero bytes is lent as the memory lies and written by nothing, so a
    /// page no table of it uses stays unwritten. The spans it lends only grow from its start, so
    /// what it has not lent stays as it was handed.
    ///
    /// # Safety
    /// As [`Self::over`], and every one of the `bytes` bytes is zero.
    pub const unsafe fn over_zeroed(base: NonNull<u8>, bytes: usize) -> Self {
        Self {
            base,
            bytes,
            lent: 0,
            zeroed: true,
        }
    }

    /// An arena of no bytes, which lends only tables of no rows: the storage of a table no memory
    /// was given for. Such a table was lent, so it refuses every value as a full table does, and
    /// is not the defect of a maker that lent it nothing (`LentSeq::refuse_unlent`).
    pub fn empty() -> Self {
        Self {
            // No byte of it is read or written: every span it lends is of no bytes, and starts
            // here, aligned for every row an arena lends.
            base: NonNull::from(&NO_BYTES).cast::<u8>(),
            bytes: 0,
            lent: 0,
            zeroed: false,
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
        match bytes.checked_add(ARENA_ROUND_UP) {
            Some(up) => Some(up & !ARENA_ROUND_UP),
            None => None,
        }
    }

    /// The bytes a table of `rows` rows of `T` takes in an arena. `None` past the address
    /// space.
    pub const fn table_bytes<T>(rows: usize) -> Option<usize> {
        Self::stride_bytes(rows, core::mem::size_of::<T>())
    }

    /// The bytes `rows` rows of `stride` bytes each take in an arena: [`Self::table_bytes`] of
    /// rows known by their bytes alone. `None` past the address space.
    pub const fn stride_bytes(rows: usize, stride: usize) -> Option<usize> {
        match rows.checked_mul(stride) {
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
        let (at, room) =
            self.lend_rows(rows, N, Self::stride_bytes(rows, core::mem::size_of::<T>()))?;
        // SAFETY: `lend_rows` handed out a span of `room` rows of `T` lent to nothing before,
        // inside the arena, starting on `ARENA_ALIGN`, which is at least `T`'s alignment
        // (asserted above).
        Ok(unsafe { BoundedVec::lent_over(at.cast::<T>(), room) })
    }

    /// Where the next span starts: a span of no bytes, aligned to [`ARENA_ALIGN`] as every span
    /// is, which no row lies in.
    fn next_span(&self) -> NonNull<u8> {
        // SAFETY: `lent` never passes `bytes`, so the address is inside the arena or one past its
        // end, a multiple of `ARENA_ALIGN` from a base aligned to it.
        unsafe { NonNull::new_unchecked(self.base.as_ptr().add(self.lent)) }
    }

    /// The untyped half of [`Self::lend`], compiled once for every row type: the span of `rows`
    /// rows taking `bytes` (`None` past the address space), at most `ceiling`, and the rows
    /// counted in 32 bits. Refused, taking nothing, past the ceiling, past what is left or past a
    /// 32-bit count. A table of several columns lends each through this, in one body of its own
    /// for every row type (`slot_map`).
    #[inline(never)]
    pub(crate) fn lend_rows(
        &mut self,
        rows: usize,
        ceiling: usize,
        bytes: Option<usize>,
    ) -> Result<(NonNull<u8>, u32), LendRefused> {
        if rows > ceiling {
            return Err(LendRefused::OverCeiling { rows, ceiling });
        }
        // `lent` never passes `bytes`.
        let left = self.bytes.wrapping_sub(self.lent);
        let span = match bytes {
            Some(span) if span <= left => span,
            asked => return Err(LendRefused::Exhausted { asked, left }),
        };
        // A table counts its rows in 32 bits (`LentSeq`): only rows of no bytes, or an arena
        // past 4 GiB, reach a count past them.
        let Ok(room) = u32::try_from(rows) else {
            return Err(LendRefused::OverCeiling {
                rows,
                ceiling: u32::MAX as usize,
            });
        };
        // SAFETY: the span starts `lent` bytes into the arena, a multiple of `ARENA_ALIGN` from a
        // base aligned to it; it lies inside the arena, and nothing was lent it before, as `lent`
        // only grows.
        let at = unsafe { NonNull::new_unchecked(self.base.as_ptr().add(self.lent)) };
        self.lent = self.lent.wrapping_add(span);
        Ok((at, room))
    }

    /// Lend a key arena of `bytes` bytes of blocks: the next span of the arena, its state first,
    /// which the rows of the session's tables keep their keys in
    /// ([`KeySpace`](crate::key_arena::KeySpace)), each at most `longest` bytes, the session's
    /// `MAX_KEYEXPR_BYTES`. Refused, taking nothing, past what is left or past the most a key arena
    /// addresses.
    ///
    /// The key arena's memory is this arena's: whoever owns the arena gives it back only once every
    /// key made from it is gone, as it does for a lent table.
    pub fn lend_keys(
        &mut self,
        bytes: usize,
        longest: crate::limits::MaxKeyexprBytesHeld,
    ) -> Result<crate::key_arena::KeySpace, LendRefused> {
        // `lent` never passes `bytes`.
        let left = self.bytes.wrapping_sub(self.lent);
        let span = match crate::key_arena::KeySpace::span_bytes(bytes) {
            Some(span) if span <= left => span,
            asked => return Err(LendRefused::Exhausted { asked, left }),
        };
        // SAFETY: the span starts `lent` bytes into the arena, a multiple of `ARENA_ALIGN` from a
        // base aligned to it; it lies inside the arena, and nothing was lent it before, as `lent`
        // only grows; `span_bytes` answered, so `bytes` is within what a key arena addresses.
        let keys = unsafe {
            crate::key_arena::KeySpace::over(
                NonNull::new_unchecked(self.base.as_ptr().add(self.lent)),
                bytes,
                longest,
            )
        };
        self.lent = self.lent.wrapping_add(span);
        Ok(keys)
    }

    /// Lend a pool of `rows` rows of the kind `K`: the next span of the arena, its state first,
    /// whose rows the tables of a session's faces share ([`RowPool`](crate::row_pool::RowPool)).
    /// Refused, taking nothing, past what is left or past the most rows a pool names.
    ///
    /// The pool's memory is this arena's: whoever owns the arena gives it back only once every
    /// table holding a row of the pool is gone, as it does for a lent table.
    pub fn lend_pool<K: crate::row_pool::RowKind>(
        &mut self,
        rows: usize,
    ) -> Result<crate::row_pool::RowPool<K>, LendRefused> {
        crate::row_pool::RowPool::lent(self, rows)
    }

    /// Lend a span of one table's own of `rows` rows of the kind `K`
    /// ([`RowSpace`](crate::row_pool::RowSpace)): the next span of the arena, the rows from its
    /// start and no state, for the one table it is moved into. Refused, taking nothing, past what
    /// is left or past the most rows a span names.
    pub fn lend_own<K: crate::row_pool::RowKind>(
        &mut self,
        rows: usize,
    ) -> Result<crate::row_pool::RowSpace<K>, LendRefused> {
        crate::row_pool::RowSpace::lent_own(self, rows)
    }

    /// The next span of the arena, of `bytes` bytes rounded up to [`ARENA_ALIGN`], for the caller
    /// to lay rows out in. Refused, taking nothing, past what is left or when `bytes` is `None`
    /// (past the address space).
    pub fn lend_span(&mut self, bytes: Option<usize>) -> Result<NonNull<u8>, LendRefused> {
        // `lent` never passes `bytes`.
        let left = self.bytes.wrapping_sub(self.lent);
        let span = match bytes.and_then(Self::span) {
            Some(span) if span <= left => span,
            asked => return Err(LendRefused::Exhausted { asked, left }),
        };
        // SAFETY: the span starts `lent` bytes into the arena, a multiple of `ARENA_ALIGN` from a
        // base aligned to it; it lies inside the arena, and nothing was lent it before, as `lent`
        // only grows.
        let at = unsafe { NonNull::new_unchecked(self.base.as_ptr().add(self.lent)) };
        self.lent = self.lent.wrapping_add(span);
        Ok(at)
    }

    /// The next span of the arena, of `bytes` bytes rounded up to [`ARENA_ALIGN`], as an arena of
    /// its own, none of it lent: what a table set lent after the open is lent from, its bytes
    /// counted and taken now and written by nothing until then. Over zeroed memory where this
    /// arena is, since what an arena has not lent is as it was handed. Refused, taking nothing,
    /// past what is left or when `bytes` is `None` (past the address space).
    pub fn split_off(&mut self, bytes: Option<usize>) -> Result<Self, LendRefused> {
        let base = self.lend_span(bytes)?;
        // `lend_span` lent the span `bytes` rounds up to, so it is within the address space.
        let span = bytes.and_then(Self::span).unwrap_or_default();
        Ok(Self {
            base,
            bytes: span,
            lent: 0,
            zeroed: self.zeroed,
        })
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
    /// table the image declares is. An arena over zeroed memory ([`Self::over_zeroed`]) lends the
    /// table as it lies, since a free flag and a zero byte are both all-zero; any other writes
    /// them. Refused, taking nothing, past what is left.
    ///
    /// The table's memory is this arena's: whoever owns the arena gives it back only once every
    /// copy of the table and every buffer claimed from it is gone, as it does for a lent table.
    pub fn lend_byte_cells(
        &mut self,
        size: usize,
        count: usize,
    ) -> Result<LentByteCells, LendRefused> {
        self.lend_byte_cells_of::<Cell<bool>>(size, count)
    }

    /// [`Self::lend_byte_cells`] with flags of the form `F` ([`CellFlag`]): atomic ones for a
    /// table whose buffers are given back on any thread. Every form lays its flag out in the same
    /// byte, so the table takes the same spans.
    pub fn lend_byte_cells_of<F: CellFlag>(
        &mut self,
        size: usize,
        count: usize,
    ) -> Result<LentByteCells<F>, LendRefused> {
        let cells = self.cell_spans(size, count)?;
        // SAFETY: `cell_spans` lent both spans to this table alone, its flags zero and its bytes
        // zero.
        Ok(unsafe { cells.table() })
    }

    /// The untyped half of [`Self::lend_byte_cells_of`], compiled once for every form of flag: the
    /// next span holds `count` flags, each written zero, the byte of a free flag of every form,
    /// and the one after it `count` buffers of `size` bytes, written zero. Refused, taking
    /// nothing, past what is left.
    #[inline(never)]
    fn cell_spans(&mut self, size: usize, count: usize) -> Result<CellSpans, LendRefused> {
        // `lent` never passes `bytes`.
        let left = self.bytes.wrapping_sub(self.lent);
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
        // bytes, so any address in the arena is aligned for them. Each flag byte and each buffer
        // byte is zero before the table is made: written so here, or so already in a zeroed arena,
        // whose bytes past what it lent are zero, which is a flag's `false` (`CellFlag` is
        // `ZeroEmpty`).
        let cells = unsafe {
            let at = self.base.as_ptr().add(self.lent);
            let data = at.add(flags);
            if !self.zeroed {
                core::ptr::write_bytes(at, 0, count.wrapping_mul(LentByteCells::FLAG_BYTES));
                // `byte_cells_spans` answered, so the product does not overflow.
                core::ptr::write_bytes(data, 0, count.wrapping_mul(size));
            }
            CellSpans {
                taken: NonNull::new_unchecked(at),
                bytes: NonNull::new_unchecked(data),
                size,
                count,
            }
        };
        self.lent = self.lent.wrapping_add(flags).wrapping_add(bytes);
        Ok(cells)
    }
}

/// The spans of a table of byte buffers, apart from the form of its flags: what the untyped half of
/// a lend answers ([`Arena::cell_spans`]) and each form's shell makes its table of.
#[derive(Clone, Copy)]
struct CellSpans {
    taken: NonNull<u8>,
    bytes: NonNull<u8>,
    size: usize,
    count: usize,
}

impl CellSpans {
    /// The spans of no cell, which a table made of them never reads.
    const NONE: Self = Self {
        taken: NonNull::dangling(),
        bytes: NonNull::dangling(),
        size: 0,
        count: 0,
    };

    /// The table of the form `F` over these spans.
    ///
    /// # Safety
    /// The spans are [`Self::NONE`], or were lent by [`Arena::cell_spans`] to this table alone:
    /// `count` flag bytes, each zero, and `count` buffers of `size` bytes, each initialised, in
    /// memory that outlives every copy of the table and every buffer it lends.
    #[inline(always)]
    unsafe fn table<F: CellFlag>(self) -> LentByteCells<F> {
        const {
            assert!(
                core::mem::size_of::<F>() == core::mem::size_of::<Cell<bool>>()
                    && core::mem::align_of::<F>() == 1,
                "a table's flag is one byte with no alignment of its own"
            )
        };
        // SAFETY: the caller's; a flag of every form is a `bool` in its byte, whose zero is
        // `false`, the free flag `LentByteCells::over` asks for.
        unsafe { LentByteCells::over(self.taken.cast::<F>(), self.bytes, self.size, self.count) }
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

// SAFETY: a `BoundedString` is its policy's text alone, whose zero bytes are the empty text.
unsafe impl<const N: usize, P: Storage> ZeroEmpty for BoundedString<N, P> where P::Text<N>: ZeroEmpty
{}

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

    /// A form only the growable policy makes holds nothing more there, and on every bounded policy
    /// a value of a type that has none, so the arms that read such a form are dropped from the
    /// bounded policies' reads. Turned red by a bounded policy whose `HeapForm` has a value.
    #[test]
    fn only_the_growable_policy_has_a_value_of_its_heap_forms() {
        use core::any::TypeId;
        use core::convert::Infallible;
        for bounded in [
            TypeId::of::<<Static as Storage>::HeapForm>(),
            TypeId::of::<<Lent as Storage>::HeapForm>(),
            TypeId::of::<<Region as Storage>::HeapForm>(),
            #[cfg(feature = "alloc")]
            TypeId::of::<<OnUse as Storage>::HeapForm>(),
        ] {
            assert_eq!(bounded, TypeId::of::<Infallible>());
        }
        #[cfg(feature = "alloc")]
        assert_eq!(
            TypeId::of::<<Heap as Storage>::HeapForm>(),
            TypeId::of::<()>()
        );
    }

    /// Each policy states when its tables take their memory and whether their rows lie apart from
    /// them: the lent and the region policies at the session's open, their rows apart; the static
    /// one when the image is built, its rows inline; the growable one as it grows, its sequences
    /// moving their rows. Turned red by a policy that answers another's moment, which an engine's
    /// assertion of its own moment reads, or that claims rows apart it keeps inline or moves, which
    /// `row_may_lie_in` of the session's tables reads.
    #[test]
    fn each_policy_states_when_its_tables_take_their_memory() {
        assert_eq!(<Static as Storage>::TAKEN, Taken::AtBuild);
        assert_eq!(<Lent as Storage>::TAKEN, Taken::AtOpen);
        assert_eq!(<Region as Storage>::TAKEN, Taken::AtOpen);
        assert_eq!(
            [
                <Static as Storage>::ROWS_STAY_APART,
                <Lent as Storage>::ROWS_STAY_APART,
                <Region as Storage>::ROWS_STAY_APART,
            ],
            [false, true, true]
        );
        #[cfg(feature = "alloc")]
        {
            assert_eq!(<Heap as Storage>::TAKEN, Taken::AsItGrows);
            assert_eq!(
                [
                    <Heap as Storage>::ROWS_STAY_APART,
                    <Heap as Storage>::LENT_AT_OPEN,
                ],
                [false, false]
            );
            assert_eq!(<OnUse as Storage>::TAKEN, Taken::AtFirstUse);
            assert_eq!(
                [
                    <OnUse as Storage>::ROWS_STAY_APART,
                    <OnUse as Storage>::LENT_AT_OPEN,
                    <OnUse as Storage>::ENFORCES_CAPACITY,
                ],
                [true, false, true]
            );
        }
    }

    /// A table of the on-use policy takes no memory until its first value, then holds its count and
    /// not the build's `N`, its rows never moving; one made by `Default` holds `N`. Turned red by a
    /// table that takes its rows when it is made, or that a count does not bound.
    #[cfg(feature = "alloc")]
    #[test]
    fn an_on_use_table_takes_its_rows_at_its_first_value_and_holds_its_count() {
        let mut table: BoundedVec<u32, 8, OnUse> = BoundedVec::counted(2);
        assert!(!table.holds_rows());
        assert_eq!(table.free_slots(), 2);
        assert!(table.is_empty());
        assert!(table.push(1).is_ok());
        assert!(table.holds_rows());
        let first: *const u32 = &table[0];
        assert!(table.push(2).is_ok());
        assert!(table.push(3).is_err(), "past the count, under N");
        assert!(core::ptr::eq(&table[0], first));
        assert_eq!(table.capacity(), 8, "the declared ceiling does not move");
        let whole: BoundedVec<u32, 8, OnUse> = BoundedVec::default();
        assert_eq!(whole.free_slots(), 8);
        assert!(!whole.holds_rows());
    }

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

    /// Two tables are equal when they hold the same rows in order, and a table reads as the list
    /// of its rows and of nothing past them. Turned red by an equality or a reading of the room
    /// rather than the rows.
    #[test]
    fn a_table_is_equal_to_and_reads_as_its_rows() {
        use core::fmt::Write;

        let mut one: BoundedVec<u32, 4, Static> = BoundedVec::new_static();
        let mut other: BoundedVec<u32, 4, Static> = BoundedVec::new_static();
        assert_eq!(one, other);
        assert!(one.push(1).is_ok());
        assert_ne!(one, other);
        assert!(other.push(1).is_ok());
        assert_eq!(one, other);
        assert!(one.push(2).is_ok());
        assert!(other.push(3).is_ok());
        assert_ne!(one, other);
        let mut text: heapless::String<16> = heapless::String::new();
        assert!(write!(text, "{one:?}").is_ok());
        assert_eq!(text.as_str(), "[1, 2]");
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

    /// A span split off an arena is taken from it whole, rounded up to the alignment, and lends its
    /// own spans from its start; it lies over zeroed memory exactly where its arena does; one past
    /// what is left is refused and takes nothing. Turned red by a split that takes none of its
    /// arena's bytes, or that forgets the memory it lies over is zero.
    #[test]
    fn a_span_split_off_an_arena_lends_from_its_start() {
        let mut arena = arena_of(4 * ARENA_ALIGN);
        let mut split = arena
            .split_off(Some(ARENA_ALIGN + 1))
            .expect("the arena holds the span");
        assert_eq!(arena.high_water(), 2 * ARENA_ALIGN, "rounded up");
        assert_eq!((split.bytes(), split.high_water()), (2 * ARENA_ALIGN, 0));
        assert!(
            !split.zeroed,
            "CONTROL: the arena's memory is not said to be zero"
        );
        split
            .lend::<u64, 4>(4)
            .expect("the split holds four rows of eight bytes");
        assert_eq!(split.high_water(), 2 * ARENA_ALIGN);
        assert_eq!(
            arena.high_water(),
            2 * ARENA_ALIGN,
            "the split lends its own bytes"
        );
        assert_eq!(
            arena.split_off(Some(3 * ARENA_ALIGN)).err(),
            Some(LendRefused::Exhausted {
                asked: Some(3 * ARENA_ALIGN),
                left: 2 * ARENA_ALIGN,
            })
        );
        assert_eq!(
            arena.high_water(),
            2 * ARENA_ALIGN,
            "a refused split takes nothing"
        );
        let region: &'static mut [Block] = std::vec![Block { _bytes: [0; ARENA_ALIGN] }; 2].leak();
        // SAFETY: the region is aligned to `ARENA_ALIGN`, holds `2 * ARENA_ALIGN` bytes, every one
        // zero, and is leaked, so nothing else uses it and it outlives every lent table.
        let mut zeroed =
            unsafe { Arena::over_zeroed(NonNull::from(region).cast::<u8>(), 2 * ARENA_ALIGN) };
        let split = zeroed
            .split_off(Some(ARENA_ALIGN))
            .expect("the arena holds the span");
        assert!(split.zeroed, "a split of zeroed memory lies over zero");
    }

    /// A lender keeps its first refusal for every kind of table it lends: after it a table of
    /// rows, a table of buffers and a key arena are each lent nothing, the arena lends no byte
    /// more, and `finish_keys` hands the first refusal back. The CONTROL is the same three lent
    /// with nothing refused, which take their bytes and hand the key arena back.
    #[test]
    fn a_lender_lends_no_kind_of_table_after_its_first_refusal() {
        let longest = crate::limits::SessionLimits::defaults().max_keyexpr_bytes_held();
        let mut whole = arena_of(1 << 12);
        let mut lend = TableLender::new(&mut whole);
        let rows: BoundedVec<u32, 4, Lent> = lend.table(4);
        let cells = lend.byte_cells(8, 2);
        let keys = lend.keys(64, longest);
        assert!(
            lend.finish_keys(keys).is_ok(),
            "CONTROL: nothing is refused"
        );
        assert_eq!(rows.free_slots(), 4);
        assert!(cells.claim().is_some());
        assert!(whole.high_water() > 0);

        let mut short = arena_of(1 << 12);
        let mut lend = TableLender::new(&mut short);
        let past: BoundedVec<u32, 4, Lent> = lend.table(5);
        let rows: BoundedVec<u32, 4, Lent> = lend.table(4);
        let cells = lend.byte_cells(8, 2);
        let keys = lend.keys(64, longest);
        assert!(matches!(
            lend.finish_keys(keys),
            Err(LendRefused::OverCeiling {
                rows: 5,
                ceiling: 4
            })
        ));
        assert_eq!(short.high_water(), 0);
        assert_eq!((past.free_slots(), rows.free_slots()), (0, 0));
        assert!(cells.claim().is_none());
        assert!(keys.space().is_none());
    }

    /// A table of byte buffers lent over memory that held other bytes, for each form of flag: its
    /// flags are written free and its bytes zero, so each of its cells is claimed once and none past
    /// its count; a lender that refused a table before lends it no cell. Turned red by a lend that
    /// leaves the flags' span as it found it, or that answers a count other than the one asked.
    #[test]
    fn a_table_of_buffers_lent_over_used_memory_claims_each_cell_once() {
        fn claims_each_cell_once<F: CellFlag>() {
            let mut arena = arena_of(1 << 10);
            // SAFETY: the arena's own bytes, none of them lent yet.
            unsafe { core::ptr::write_bytes(arena.base.as_ptr(), 0xA5, arena.bytes()) };
            let mut lend = TableLender::new(&mut arena);
            let cells = lend.byte_cells_of::<F>(8, 3);
            assert!(lend.finish().is_ok());
            assert_eq!((cells.size(), cells.capacity()), (8, 3));
            let claims: std::vec::Vec<_> = core::iter::from_fn(|| cells.claim()).collect();
            assert_eq!(
                claims.len(),
                3,
                "every cell is free, and none past the count"
            );
            assert!(claims
                .iter()
                .all(|cell| cell.as_slice().iter().all(|&b| b == 0)));

            let mut short = arena_of(16);
            let mut lend = TableLender::new(&mut short);
            let _past: BoundedVec<u64, 4, Lent> = lend.table(4);
            let none = lend.byte_cells_of::<F>(8, 3);
            assert!(lend.finish().is_err());
            assert_eq!(none.capacity(), 0);
            assert!(none.claim().is_none());
        }
        claims_each_cell_once::<Cell<bool>>();
        #[cfg(target_has_atomic = "8")]
        claims_each_cell_once::<core::sync::atomic::AtomicBool>();
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

    #[cfg(feature = "alloc")]
    impl Fresh for OnUse {
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

    /// An arena of no bytes lends a table of no rows, which refuses a value as a full table does,
    /// and refuses a table of one row as exhausted, lending nothing.
    #[test]
    fn an_empty_arena_lends_only_tables_of_no_rows() {
        let mut arena = Arena::empty();
        let mut table: BoundedVec<u64, 4, Lent> = arena.lend(0).expect("no rows take no bytes");
        assert!(matches!(table.push(7), Err(CapacityFull(7))));
        assert!(table.is_empty());
        assert_eq!(table.free_slots(), 0);
        assert_eq!(
            arena.lend::<u64, 4>(1).err(),
            Some(LendRefused::Exhausted {
                asked: Arena::table_bytes::<u64>(1),
                left: 0,
            })
        );
        assert_eq!(arena.high_water(), 0);
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

    /// A table of byte buffers lent from an arena over zeroed memory is lent as the memory lies,
    /// written by nothing: a region marked with a byte that is not zero, handed to the arena as if
    /// it were zeroed, keeps its mark after the lend. The CONTROL is the same lend from an arena
    /// over memory not said to be zero, which writes the flags free and the bytes zero. Turned red
    /// by a zeroed arena's lend that writes its table.
    #[test]
    fn a_zeroed_arena_lends_byte_buffers_without_writing_them() {
        const MARK: u8 = 0x5a;
        let asked = Arena::byte_cells_bytes(10, 3).expect("within the address space");
        let lent_over = |zeroed: bool| {
            let blocks = asked.div_ceil(ARENA_ALIGN);
            let region: &'static mut [Block] = std::vec![
                Block {
                    _bytes: [MARK; ARENA_ALIGN]
                };
                blocks
            ]
            .leak();
            let base = NonNull::from(region).cast::<u8>();
            // SAFETY: the region is aligned to `ARENA_ALIGN`, holds `asked` bytes and is leaked.
            // It is not zero: the zeroed arena is told it is to show what its lend writes, and no
            // table lent from it is used, only the region's raw bytes read.
            let mut arena = unsafe {
                if zeroed {
                    Arena::over_zeroed(base, asked)
                } else {
                    Arena::over(base, asked)
                }
            };
            let _table = arena
                .lend_byte_cells(10, 3)
                .expect("the arena holds the table");
            // SAFETY: the region's `asked` bytes, leaked, read after the lend.
            unsafe { core::slice::from_raw_parts(base.as_ptr(), asked) }.to_vec()
        };
        assert!(
            lent_over(true).iter().all(|byte| *byte == MARK),
            "the zeroed arena's lend wrote its table"
        );
        let written = lent_over(false);
        let flags = Arena::span(3 * LentByteCells::FLAG_BYTES).expect("a small span");
        assert!(
            written[..3].iter().all(|byte| *byte == 0),
            "CONTROL: flags free"
        );
        assert!(
            written[flags..flags + 30].iter().all(|byte| *byte == 0),
            "CONTROL: bytes zero"
        );
    }

    /// A table lent from an arena over memory that is zero holds free buffers whose bytes are zero,
    /// with nothing written by the lend: every buffer is claimed once and the one past them is
    /// refused. Turned red by a flag whose all-zero byte is not `false` (a table that reads as
    /// all lent), or by a zeroed arena that lends a span it lent before.
    #[test]
    fn a_zeroed_arena_lends_free_buffers_of_zero_bytes() {
        let asked = Arena::byte_cells_bytes(10, 3).expect("within the address space");
        let blocks = asked.div_ceil(ARENA_ALIGN) * 2;
        let region: &'static mut [Block] =
            std::vec![Block { _bytes: [0; ARENA_ALIGN] }; blocks].leak();
        // SAFETY: the region is aligned to `ARENA_ALIGN`, holds `2 * asked` bytes at least, every
        // one zero, and is leaked, so nothing else uses it and it outlives every lent table.
        let mut arena =
            unsafe { Arena::over_zeroed(NonNull::from(region).cast::<u8>(), blocks * ARENA_ALIGN) };
        let first = arena
            .lend_byte_cells(10, 3)
            .expect("the arena holds the table");
        let atomic = arena
            .lend_byte_cells_of::<core::sync::atomic::AtomicBool>(10, 3)
            .expect("the arena holds a second table");
        assert_eq!(
            arena.high_water(),
            2 * asked,
            "two tables, each its own span"
        );
        let mut held = std::vec::Vec::new();
        while let Some(mut buffer) = first.claim() {
            assert!(buffer.as_mut_slice().iter().all(|&b| b == 0), "lent zero");
            held.push(buffer);
        }
        assert_eq!(held.len(), 3, "every buffer free, none past them");
        let mut atomics = std::vec::Vec::new();
        while let Some(buffer) = atomic.claim() {
            atomics.push(buffer);
        }
        assert_eq!(atomics.len(), 3, "every atomic flag free");
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
            #[cfg(feature = "alloc")]
            mod on_first_use {
                use super::*;
                $(#[test] fn $case() { super::$case::<OnUse>(); })*
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

    /// A heapless text takes a whole `str` in one copy: an append that fits lands after what the
    /// text holds, one that fills the capacity to the byte is taken, and one past it, a character
    /// of several bytes included, is refused with the text left as it was. Turned red by a length
    /// set before the room is checked, or by a refused append that writes part of itself.
    #[test]
    fn a_heapless_text_takes_a_whole_str_or_nothing() {
        let mut text: heapless::String<6> = heapless::String::new();
        assert!(push_text(&mut text, "ab").is_ok());
        assert!(push_text(&mut text, "").is_ok());
        assert!(push_text(&mut text, "cd").is_ok());
        assert_eq!(text.as_str(), "abcd");
        assert!(
            push_text(&mut text, "\u{e9}").is_ok(),
            "two bytes into two of room"
        );
        assert_eq!(text.as_str().len(), 6);
        assert!(push_text(&mut text, "x").is_err());
        assert_eq!(text.as_str(), "abcd\u{e9}");

        let mut short: heapless::String<3> = heapless::String::new();
        assert!(push_text(&mut short, "a").is_ok());
        assert!(
            push_text(&mut short, "\u{20ac}").is_err(),
            "three bytes past two of room"
        );
        assert_eq!(short.as_str(), "a");
    }

    /// The room check ends an append where it fits, at the capacity included, and answers none
    /// past it or past the end of the address space.
    #[test]
    fn an_append_ends_inside_the_capacity_or_nowhere() {
        assert_eq!(append_end::<4>(1, 3), Some(4));
        assert_eq!(append_end::<4>(0, 0), Some(0));
        assert_eq!(append_end::<4>(1, 4), None);
        assert_eq!(append_end::<4>(usize::MAX, 1), None);
    }

    /// A heapless byte buffer takes a whole slice in one copy: an append that fits lands after what
    /// the buffer holds, one that fills the capacity to the byte is taken, and one past it is
    /// refused with the buffer left as it was. Turned red by a length set before the room is
    /// checked, or by a refused append that writes part of itself.
    #[test]
    fn a_heapless_byte_buffer_takes_a_whole_slice_or_nothing() {
        let mut bytes: heapless::Vec<u8, 6> = heapless::Vec::new();
        assert!(push_bytes(&mut bytes, &[1, 2]).is_ok());
        assert!(push_bytes(&mut bytes, &[]).is_ok());
        assert!(push_bytes(&mut bytes, &[3, 4, 5, 6]).is_ok());
        assert_eq!(bytes.as_slice(), &[1, 2, 3, 4, 5, 6]);
        assert!(push_bytes(&mut bytes, &[7]).is_err());
        assert_eq!(bytes.as_slice(), &[1, 2, 3, 4, 5, 6]);

        let mut short: heapless::Vec<u8, 3> = heapless::Vec::new();
        assert!(push_bytes(&mut short, &[9]).is_ok());
        assert!(
            push_bytes(&mut short, &[8, 8, 8]).is_err(),
            "three past two of room"
        );
        assert_eq!(short.as_slice(), &[9]);
    }

    /// A table of the lent policy that no arena lent rows to is a defect of its maker, not a table
    /// at its limit: a debug build stops at the value put in it rather than refusing it as full.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "no arena lent rows to")]
    fn a_value_put_in_a_lent_table_no_arena_lent_stops_a_debug_build() {
        let mut table: BoundedVec<u32, 4, Lent> = BoundedVec::default();
        let _ = table.push(1);
    }

    /// A table lent no rows by its arena (a limit of 0) is a table at its limit: it refuses the
    /// value as full, and nothing stops.
    #[test]
    fn a_lent_table_of_no_rows_refuses_as_full() {
        let mut table: BoundedVec<u32, 4, Lent> = arena_of(ARENA_ALIGN)
            .lend(0)
            .expect("no rows fit any arena");
        assert_eq!(table.push(1).map_err(|full| full.0), Err(1));
    }

    /// A table placed over a region's rows takes the rows asked, at most the rows there and the
    /// build's ceiling, and keeps its values in them. Turned red by a table that takes more rows
    /// than lie there or than its ceiling, or that keeps its rows anywhere else.
    #[test]
    fn a_table_placed_over_rows_takes_them_at_most() {
        let mut places = [core::mem::MaybeUninit::<u32>::uninit(); 3];
        let at = NonNull::from(&mut places);
        // SAFETY: the rows are this frame's, hold no value and are reached by this table alone,
        // which is dropped before the next one is placed over them.
        let mut table = unsafe { BoundedVec::<u32, { usize::MAX }, Lent>::placed_over(at, 5) };
        assert_eq!(table.free_slots(), 3, "held to the rows there");
        assert!(table.push(7).is_ok());
        assert_eq!(table.as_ptr(), at.cast::<u32>().as_ptr().cast_const());
        drop(table);
        // SAFETY: as above; the table before is gone.
        let ceiling = unsafe { BoundedVec::<u32, 2, Lent>::placed_over(at, 3) };
        assert_eq!(ceiling.free_slots(), 2, "held to the build's ceiling");
        drop(ceiling);
        // SAFETY: as above.
        let fewer = unsafe { BoundedVec::<u32, 8, Lent>::placed_over(at, 1) };
        assert_eq!(fewer.free_slots(), 1, "CONTROL: the rows asked, under both");
    }

    /// A lent table is a pointer and two 32-bit counts, whatever its rows: a set of a session's
    /// tables holds many. A table of more rows than a 32-bit count names is refused at the lend,
    /// taking nothing, by that count; the CONTROL is the table of as many rows as it names.
    #[test]
    fn a_lent_table_is_a_pointer_and_two_32_bit_counts() {
        assert_eq!(
            core::mem::size_of::<BoundedVec<u64, 8, Lent>>(),
            core::mem::size_of::<usize>() + 8
        );
        #[cfg(target_pointer_width = "64")]
        {
            let mut arena = arena_of(0);
            let most = u32::MAX as usize;
            let past: Result<BoundedVec<(), { usize::MAX }, Lent>, _> = arena.lend(most + 1);
            assert_eq!(
                past.err(),
                Some(LendRefused::OverCeiling {
                    rows: most + 1,
                    ceiling: most
                })
            );
            assert_eq!(arena.high_water(), 0, "nothing was taken");
            let at_most: Result<BoundedVec<(), { usize::MAX }, Lent>, _> = arena.lend(most);
            assert_eq!(
                at_most.map(|table| table.free_slots()).ok(),
                Some(most),
                "CONTROL: as many rows as the count names"
            );
        }
    }

    /// A value pushed in place is built in the next row the table was lent and is held from then
    /// on, handed back to write; once the rows lent are held, the push is refused and `write` is
    /// not called. The CONTROL is the table's contents, the values in the order built.
    #[test]
    fn a_push_in_place_builds_in_the_next_lent_row_and_refuses_past_them() {
        let mut arena = arena_of(64);
        let mut v: BoundedVec<u32, 8, Lent> = arena.lend(2).expect("two rows fit");
        for value in [5_u32, 6] {
            // SAFETY: the closure writes a whole `u32` and does not unwind.
            let held = unsafe {
                v.push_in_place(|row| {
                    row.write(value);
                })
            };
            let held = held.expect("within the lent rows");
            assert_eq!(*held, value, "the value built is handed back");
            *held += 10;
        }
        let mut called = false;
        // SAFETY: as above; this closure is never called.
        let refused = unsafe {
            v.push_in_place(|row| {
                called = true;
                row.write(0);
            })
        };
        assert!(refused.is_none(), "past the lent rows");
        assert!(!called, "and nothing was written");
        assert_eq!(v.as_ref(), &[15, 16], "CONTROL: in the order built");
    }

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

    /// A lender counts a table's bytes off the stride of its rows: rows of three bytes take the
    /// span of their bytes rounded up, so the next table finds the arena full, and rows past the
    /// address space are refused naming no size. Turned red by a lend that counts a row by another
    /// figure than its own bytes.
    #[test]
    fn a_lender_counts_a_tables_bytes_off_the_stride_of_its_rows() {
        assert_eq!(Arena::stride_bytes(5, 3), Some(16));
        assert_eq!(Arena::stride_bytes(5, 3), Arena::table_bytes::<[u8; 3]>(5));
        assert_eq!(Arena::stride_bytes(usize::MAX, 2), None);
        let mut arena = arena_of(16);
        let mut lend = TableLender::new(&mut arena);
        let rows: BoundedVec<[u8; 3], 8, Lent> = lend.table(5);
        let past: BoundedVec<u8, 1, Lent> = lend.table(1);
        assert_eq!(
            lend.finish(),
            Err(LendRefused::Exhausted {
                asked: Some(16),
                left: 0
            })
        );
        assert_eq!((rows.free_slots(), past.free_slots()), (5, 0));
        assert_eq!(arena.high_water(), 16);

        let mut wide = arena_of(64);
        let mut lend = TableLender::new(&mut wide);
        let none: BoundedVec<u16, { usize::MAX }, Lent> = lend.table(usize::MAX);
        assert_eq!(
            lend.finish(),
            Err(LendRefused::Exhausted {
                asked: None,
                left: 64
            })
        );
        assert_eq!(none.free_slots(), 0);
        assert_eq!(wide.high_water(), 0);
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

    /// A row at least a word wide, whose drop marks its own bit: dropped at the wrong place, it
    /// marks a bit of what lies there instead.
    struct Wide<'a> {
        _pad: [u64; 3],
        bit: u32,
        seen: &'a core::cell::Cell<u32>,
    }

    impl Drop for Wide<'_> {
        fn drop(&mut self) {
            self.seen.set(self.seen.get() | (1 << self.bit));
        }
    }

    /// A lent table of rows wider than a byte drops each row once at its own place, the rows cut
    /// off the end first and the rest with the table.
    #[test]
    fn a_lent_table_drops_each_wide_row_at_its_place() {
        let seen = core::cell::Cell::new(0);
        let mut arena = arena_of(Arena::table_bytes::<Wide<'_>>(4).expect("fits"));
        let mut v: BoundedVec<Wide<'_>, 4, Lent> = arena.lend(4).expect("four rows fit");
        for bit in 0..4 {
            v.push(Wide {
                _pad: [0; 3],
                bit,
                seen: &seen,
            })
            .expect("within the rows");
        }
        drop(v.pop());
        drop(v.pop());
        assert_eq!(seen.get(), 0b1100, "the rows taken off the end are dropped");
        drop(v);
        assert_eq!(seen.get(), 0b1111, "and the rest with the table");
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

    /// A value of all zero bytes of a type a region holds, as the allocator's zeroed block is.
    fn zeroed<T: ZeroEmpty>() -> T {
        // SAFETY: `ZeroEmpty`: all zero bytes are a valid value of `T`.
        unsafe { core::mem::zeroed() }
    }

    /// Every container a region holds reads as empty from all zero bytes: the sequences of each
    /// policy, the texts, a pointer of none. Turned red by a `ZeroEmpty` type whose zero is not its
    /// empty state (a `LentSeq` whose `None` were not its first word's zero, say).
    #[test]
    fn zero_bytes_are_every_container_empty() {
        assert!(zeroed::<heapless::Vec<u32, 4>>().is_empty());
        assert!(zeroed::<heapless::String<4>>().is_empty());
        assert!(zeroed::<BoundedVec<u32, 4, Static>>().is_empty());
        assert!(zeroed::<BoundedString<8, Static>>().is_empty());
        let unplaced = zeroed::<BoundedVec<u32, 4, Region>>();
        assert!(unplaced.is_empty());
        assert_eq!(unplaced.free_slots(), 0, "a table placed no rows has none");
        assert!(zeroed::<Option<NonNull<u8>>>().is_none());
        assert_eq!(zeroed::<[u16; 3]>(), [0; 3]);
        assert_eq!(zeroed::<Cell<u32>>().get(), 0);
    }

    /// A `ZeroOption` of all zero bytes holds nothing; one that holds a value lends it, gives it
    /// up once to `take`, answers the value it held to `replace` and `set`, and drops what it holds
    /// exactly once. Turned red by a `held` flag whose zero meant a value, or by a value dropped
    /// twice or not at all.
    #[test]
    fn a_zero_option_of_zero_bytes_holds_nothing_and_drops_what_it_holds_once() {
        let none = zeroed::<ZeroOption<std::rc::Rc<u32>>>();
        assert!(none.is_none());
        assert!(none.as_ref().is_none());
        drop(none);

        let counted = std::rc::Rc::new(7u32);
        let mut place = ZeroOption::some(std::rc::Rc::clone(&counted));
        assert!(place.is_some());
        assert_eq!(place.as_deref(), Some(&7));
        assert_eq!(std::rc::Rc::strong_count(&counted), 2);
        let taken = place.take().expect("the value held");
        assert!(place.is_none());
        assert!(place.take().is_none(), "a value is given up once");
        assert!(place.replace(taken).is_none());
        let before = place.replace(std::rc::Rc::new(8));
        assert_eq!(before.as_deref(), Some(&7));
        drop(before);
        assert_eq!(std::rc::Rc::strong_count(&counted), 1);
        place.set(Some(std::rc::Rc::clone(&counted)));
        assert_eq!(std::rc::Rc::strong_count(&counted), 2);
        if let Some(value) = place.as_mut() {
            *value = std::rc::Rc::new(9);
        }
        assert_eq!(std::rc::Rc::strong_count(&counted), 1);
        place.set(Some(std::rc::Rc::clone(&counted)));
        drop(place);
        assert_eq!(
            std::rc::Rc::strong_count(&counted),
            1,
            "the value held is dropped with its place"
        );
        assert!(ZeroOption::from(None::<u8>).is_none());
        assert_eq!(ZeroOption::from(Some(3u8)).as_ref(), Some(&3));
    }

    /// A region of two tables of the lent shape and one of the static policy, with the rows of
    /// the first two beside them, as a session's region lays its layers' out.
    #[repr(C)]
    struct TwoTables {
        names: BoundedVec<u32, 4, Region>,
        words: BoundedVec<u64, 3, Region>,
        inline: BoundedVec<u16, 2, Static>,
        name_rows: [core::mem::MaybeUninit<u32>; 4],
        word_rows: [core::mem::MaybeUninit<u64>; 3],
    }

    // SAFETY: every field is `ZeroEmpty`.
    unsafe impl ZeroEmpty for TwoTables {}

    /// The region's description: each table of the lent shape, where its rows lie, how many.
    const TWO_TABLES: [SeqPlace; 2] = [
        SeqPlace::of::<u32>(
            core::mem::offset_of!(TwoTables, names),
            core::mem::offset_of!(TwoTables, name_rows),
            4,
        ),
        SeqPlace::of::<u64>(
            core::mem::offset_of!(TwoTables, words),
            core::mem::offset_of!(TwoTables, word_rows),
            3,
        ),
    ];

    /// A place whose room is a const of the caller's is the place `SeqPlace::of` makes of that
    /// room. Turned red by `of_room` placing a room other than `ROOM`.
    #[test]
    fn a_place_of_a_const_room_is_the_place_of_that_room() {
        assert_eq!(
            SeqPlace::of_room::<u64, 3>(
                core::mem::offset_of!(TwoTables, words),
                core::mem::offset_of!(TwoTables, word_rows),
            ),
            TWO_TABLES[1]
        );
    }

    /// A region zeroed by the allocator in one block is every table empty; placed by its
    /// description, each table of the lent shape takes as many values as it has rows and refuses
    /// the next, and the static table beside them is untouched. Turned red by `place_seqs` writing
    /// a room other than the description's, or a row place other than its own.
    #[test]
    fn a_region_placed_by_its_description_holds_each_tables_rows() {
        let layout = std::alloc::Layout::new::<TwoTables>();
        // SAFETY: the layout is of a type of some bytes.
        let block = unsafe { std::alloc::alloc_zeroed(layout) };
        let region = NonNull::new(block.cast::<TwoTables>()).expect("the test allocator answers");
        // SAFETY: the block is the region's, zeroed, which `ZeroEmpty` makes every table empty.
        let tables = unsafe { &mut *region.as_ptr() };
        assert!(tables.names.is_empty() && tables.words.is_empty() && tables.inline.is_empty());
        // SAFETY: the description names the region's two tables and their own rows, aligned
        // (`SeqPlace::of`), which nothing else reaches while the tables live.
        unsafe { place_seqs(region.cast::<u8>(), &TWO_TABLES) };
        for name in 0..4 {
            assert!(tables.names.push(name).is_ok());
        }
        assert!(matches!(tables.names.push(9), Err(CapacityFull(9))));
        for word in [7u64, 8, 9] {
            assert!(tables.words.push(word).is_ok());
        }
        assert!(matches!(tables.words.push(10), Err(CapacityFull(10))));
        assert_eq!(tables.names.as_ref(), &[0, 1, 2, 3]);
        assert_eq!(tables.words.as_ref(), &[7, 8, 9]);
        assert_eq!(
            tables.names.as_ptr().cast::<u8>(),
            block
                .wrapping_add(core::mem::offset_of!(TwoTables, name_rows))
                .cast_const(),
            "the rows lie where the description says"
        );
        assert!(tables.inline.is_empty());
        tables.names.clear();
        assert_eq!(tables.names.free_slots(), 4);
        // SAFETY: the tables hold nothing that drops; the block goes back with its layout.
        unsafe { std::alloc::dealloc(block, layout) };
    }

    /// The region's room composes a key in the row it holds, and of all zero bytes holds none.
    #[cfg(feature = "storage-profile")]
    #[test]
    fn an_inline_room_composes_in_its_own_row() {
        use crate::wireexpr_resolve::{ComposeInline, ComposeRoom};
        let mut room = zeroed::<ComposeInline>();
        // The trait ties the buffer to the frame's borrow, so each use takes it again.
        assert_eq!(room.buffer(&mut ()).as_str(), "");
        assert!(room.buffer(&mut ()).push_str("demo/key").is_ok());
        assert_eq!(room.buffer(&mut ()).as_str(), "demo/key");
    }
}

#[cfg(test)]
mod region_held_tests {
    use super::{place_seqs, BoundedVec, Region, SeqPlace};
    use core::mem::{offset_of, MaybeUninit};
    use core::ptr::NonNull;

    #[repr(C)]
    struct OneTable {
        table: BoundedVec<u32, 4, Region>,
        rows: [MaybeUninit<u32>; 3],
    }

    /// Rows written before their table was placed over them are the table's values once counted,
    /// and a count past the rows placed is held to them; the table then refuses past its room.
    /// Turned red by `assume_held` counting past the room, or by a placed table that counts no row.
    #[test]
    fn a_region_table_counts_the_rows_written_before_it_was_placed() {
        let mut one = OneTable {
            table: BoundedVec::default(),
            rows: [MaybeUninit::uninit(); 3],
        };
        one.rows[0].write(7);
        one.rows[1].write(9);
        let base = NonNull::from(&mut one).cast::<u8>();
        let line = SeqPlace::of::<u32>(offset_of!(OneTable, table), offset_of!(OneTable, rows), 3);
        // SAFETY: the line names the table and its three rows in `one`, aligned, which only the
        // table reaches from here.
        unsafe { place_seqs(base, &[line]) };
        assert_eq!(
            one.table.len(),
            0,
            "a placed table holds nothing until counted"
        );
        // SAFETY: the first two rows hold values nothing else owns.
        unsafe { one.table.assume_held(2) };
        assert!(one.table.iter().copied().eq([7, 9]));
        assert!(one.table.push(11).is_ok());
        assert!(one.table.push(13).is_err(), "three rows were placed");
        let mut other = OneTable {
            table: BoundedVec::default(),
            rows: [
                MaybeUninit::new(1),
                MaybeUninit::new(2),
                MaybeUninit::new(3),
            ],
        };
        let base = NonNull::from(&mut other).cast::<u8>();
        // SAFETY: as above.
        unsafe { place_seqs(base, &[line]) };
        // SAFETY: every row placed holds a value.
        unsafe { other.table.assume_held(8) };
        assert_eq!(
            other.table.len(),
            3,
            "a count past the rows is held to them"
        );
    }
}
