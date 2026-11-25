// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A fixed-capacity slot map: the table every row of the session's one table set lies in
//! (`docs/c-abi-l3-tables.md`, section 3).
//!
//! # Handles
//!
//! A row is named by a [`Handle`]: its slot's index, counted from one so the index part is never
//! zero and an `Option<Handle<K>>` costs nothing, and the generation the slot was at when the row
//! was taken. A slot's generation moves when its row leaves it, so a handle kept past its row names
//! nothing rather than the slot's next row. `K` is a marker of the table, so a handle of one table
//! is not accepted by another (`docs/c-abi-architecture.md`, P10).
//!
//! # Pins
//!
//! A row whose callback is being called is pinned ([`SlotMap::pin`]). Removing a pinned row
//! retires it: it leaves every lookup and iteration at once, keeps its slot and its generation, and
//! is handed back by the last [`SlotMap::unpin`], so whatever it owns is dropped after the last call
//! of it has returned (P11).
//!
//! # One untyped core
//!
//! The free list, the generations, the pins and the bound are kept in a column of metadata and
//! decided by one core that knows nothing of the rows' type, compiled once for every table
//! (P5). What is typed is a column of `Option<T>` beside it and the few lines that move a value in
//! and out of it. Both columns are `BoundedVec`s of the storage policy `P`: lent from the
//! session's arena at its open on the lent policy ([`SlotMap::lent`]), fixed on the static one,
//! growable on the heap one, where `N` is advisory as it is for every table of that policy and
//! the bound is the one [`SlotMap::limit_to`] sets, or [`MAX_SLOTS`]. A table at its bound
//! refuses an insert and hands the value back; nothing grows past it (P3).
//!
//! [`Handle`]: crate::slot_map::Handle
//! [`SlotMap::pin`]: crate::slot_map::SlotMap::pin
//! [`SlotMap::unpin`]: crate::slot_map::SlotMap::unpin
//! [`SlotMap::lent`]: crate::slot_map::SlotMap::lent
//! [`SlotMap::limit_to`]: crate::slot_map::SlotMap::limit_to
//! [`MAX_SLOTS`]: crate::slot_map::MAX_SLOTS

use core::fmt;
use core::marker::PhantomData;
use core::num::{NonZeroU16, NonZeroU32};

use crate::bounded::{
    Arena, BoundedVec, CapacityFull, LendRefused, Lent, Profile, Region, SeqPlace, Storage,
    TableLender, ZeroEmpty, ZeroSeqs, ARENA_ALIGN,
};
use core::mem::MaybeUninit;
use core::ptr::NonNull;

/// The most rows a slot map holds: a slot's index is a `u16` counted from one.
pub const MAX_SLOTS: usize = u16::MAX as usize;

/// No slot: the end of the free list. A link names a slot counted from one, as a handle does, so
/// a table of all zero bytes has an empty free list.
const NIL: u16 = 0;

/// The link that names the slot at `at`: its place counted from one. Every place is under
/// [`MAX_SLOTS`], so the link fits.
fn link(at: usize) -> u16 {
    u16::try_from(at.wrapping_add(1)).unwrap_or(NIL)
}

/// The place `link` names, or `None` for [`NIL`].
fn linked(link: u16) -> Option<usize> {
    usize::from(link).checked_sub(1)
}

/// A row of a slot map whose kind is `K`, for as long as the row is in it.
pub struct Handle<K> {
    index: NonZeroU16,
    generation: u16,
    kind: PhantomData<fn() -> K>,
}

impl<K> Handle<K> {
    /// The handle of the row at `at`, taken at `generation`; `None` past [`MAX_SLOTS`].
    fn at(at: usize, generation: u16) -> Option<Self> {
        let index = u16::try_from(at.checked_add(1)?).ok()?;
        Some(Self {
            index: NonZeroU16::new(index)?,
            generation,
            kind: PhantomData,
        })
    }

    /// The place of the row in its table.
    fn place(self) -> usize {
        usize::from(self.index.get()).saturating_sub(1)
    }

    /// The handle as one word, for a C handle to keep: the index in the low half, the generation
    /// in the high half. Never zero.
    pub fn to_bits(self) -> NonZeroU32 {
        let bits = u32::from(self.generation).wrapping_shl(16) | u32::from(self.index.get());
        // The low half is the index, which is never zero, so the word is not.
        NonZeroU32::new(bits).unwrap_or(NonZeroU32::MIN)
    }

    /// The handle a word of [`Self::to_bits`] holds; `None` for a word whose index half is zero,
    /// which no handle writes.
    pub fn from_bits(bits: NonZeroU32) -> Option<Self> {
        let word = bits.get();
        Some(Self {
            index: NonZeroU16::new((word & 0xFFFF) as u16)?,
            generation: word.wrapping_shr(16) as u16,
            kind: PhantomData,
        })
    }
}

impl<K> Clone for Handle<K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K> Copy for Handle<K> {}

impl<K> PartialEq for Handle<K> {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index && self.generation == other.generation
    }
}

impl<K> Eq for Handle<K> {}

impl<K> fmt::Debug for Handle<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Handle({}@{})", self.index, self.generation)
    }
}

/// A table's slots apart from its rows: how many it holds and where its live rows lie, read with
/// one body for every table whatever its rows are ([`SlotMap::slots`]). A row is named by the bits
/// of its handle ([`Handle::to_bits`]), so a caller that reads tables of several kinds in one
/// order names a row of any of them by one value.
#[derive(Clone, Copy, Debug)]
pub struct Slots<'a> {
    meta: &'a [Meta],
    held: u16,
}

impl Slots<'_> {
    /// The slots of a table a build keeps none of: no row.
    pub const NONE: Slots<'static> = Slots { meta: &[], held: 0 };

    /// How many slots hold a row, retired rows among them, as [`SlotMap::len`] counts them.
    pub fn len(self) -> usize {
        usize::from(self.held)
    }

    /// Whether no slot holds a row.
    pub fn is_empty(self) -> bool {
        self.held == 0
    }

    /// The rank among the live rows, in slot order, of the live row `row` names, `row` the bits
    /// of its handle: [`SlotMap::rank_of`] of it. `None` when it names none.
    pub fn rank_of(self, row: NonZeroU32) -> Option<usize> {
        let handle = Handle::<()>::from_bits(row)?;
        let at = Core::find(self.meta, handle.place(), handle.generation, false)?;
        Some(Core::rank(self.meta, at))
    }

    /// The bits of the handle of the live row at `rank` in slot order: the row
    /// [`SlotMap::nth_live`] finds.
    pub fn nth_live(self, rank: usize) -> Option<NonZeroU32> {
        let (at, generation) = Core::nth_live(self.meta, rank)?;
        Handle::<()>::at(at, generation).map(Handle::to_bits)
    }
}

/// A row pinned by a call of what it owns: handed back to [`SlotMap::unpin`] when the call has
/// returned. Not copied, so each pin is given back once.
#[must_use = "a pinned row stays in its slot until it is unpinned"]
pub struct Pinned<K> {
    handle: Handle<K>,
}

impl<K> Pinned<K> {
    /// The row pinned.
    pub fn handle(&self) -> Handle<K> {
        self.handle
    }
}

impl<K> fmt::Debug for Pinned<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Pinned").field(&self.handle).finish()
    }
}

/// What removing a row did.
#[derive(Debug, PartialEq, Eq)]
pub enum Removal<T> {
    /// The row left its slot and is handed back, for the caller to drop where it chooses.
    Taken(T),
    /// The row is pinned: it is retired, gone from every lookup, and the last
    /// [`SlotMap::unpin`] hands it back.
    AfterCalls,
}

impl<T> Removal<T> {
    /// The row, when it was handed back now.
    pub fn taken(self) -> Option<T> {
        match self {
            Self::Taken(row) => Some(row),
            Self::AfterCalls => None,
        }
    }
}

/// What a slot holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// No row: the slot is on the free list.
    Free,
    /// A row the table names.
    Live,
    /// A row removed while pinned, kept until its last pin is given back.
    Retired,
}

/// One slot's metadata, apart from its row so the core reads no row.
#[derive(Clone, Copy, Debug)]
struct Meta {
    generation: u16,
    /// The link of the next free slot ([`link`]), or [`NIL`], while the slot is free.
    next: u16,
    pins: u16,
    state: State,
}

impl Meta {
    /// A slot added after every slot there was, holding a row.
    const ADDED: Self = Self {
        generation: 0,
        next: NIL,
        pins: 0,
        state: State::Live,
    };
}

/// The slot the core took for a row: its place and generation, and whether it is one to add after
/// every slot there is, so both columns take one more place for it.
struct Taken {
    at: usize,
    generation: u16,
    grown: bool,
}

/// What retiring a row did.
enum Retired {
    /// The slot at this place is free again: its row leaves now.
    Now(usize),
    /// The row is pinned and stays until its last pin is given back.
    Deferred,
}

/// What giving back a pin did.
enum Unpinned {
    /// The row is still in its slot.
    Held,
    /// The row was retired and this was its last pin: the slot at this place is free again.
    Freed(usize),
}

/// The free list, the bound and the count of a slot map: everything that does not depend on the
/// rows' type.
#[derive(Debug)]
struct Core {
    /// The link of the first free slot ([`link`]), or [`NIL`].
    free: u16,
    /// The slots that hold a row, retired ones among them.
    held: u16,
    /// The most slots that may hold a row at once, its bits inverted: zero is no bound but the
    /// columns' own room, so a table of all zero bytes is bound by the rows it was placed.
    unlimit: u16,
}

// SAFETY: a core of zero bytes has no free slot, holds none and is bound only by its columns.
unsafe impl crate::bounded::ZeroEmpty for Core {}

impl Core {
    /// A core of no rows, holding at most `rows`.
    fn new(rows: usize) -> Self {
        let mut core = Self {
            free: NIL,
            held: 0,
            unlimit: 0,
        };
        core.limit_to(rows);
        core
    }

    /// Hold at most `rows` slots from here on.
    fn limit_to(&mut self, rows: usize) {
        self.unlimit = !u16::try_from(rows.min(MAX_SLOTS)).unwrap_or(u16::MAX);
    }

    /// The most slots that may hold a row at once.
    fn limit(&self) -> u16 {
        !self.unlimit
    }

    /// A live slot for a row: a free one, or else the one after every slot there is, counted
    /// here and pushed by the caller, when both columns have a place for it (`room`). `None`,
    /// nothing taken, when the table is at its bound or has neither.
    ///
    /// Untyped and over the column as a slice, so it is one body for every table of every policy
    /// and bound, where each insert inlined the slot's bookkeeping of its own.
    #[inline(never)]
    fn take_slot(&mut self, meta: &mut [Meta], room: bool) -> Option<Taken> {
        if self.held >= self.limit() {
            return None;
        }
        if let Some(at) = linked(self.free) {
            let slot = meta.get_mut(at)?;
            self.free = slot.next;
            slot.next = NIL;
            slot.pins = 0;
            slot.state = State::Live;
            self.held = self.held.saturating_add(1);
            return Some(Taken {
                at,
                generation: slot.generation,
                grown: false,
            });
        }
        let at = meta.len();
        // A slot's index is a `u16` counted from one: the place past the last has none.
        if at >= MAX_SLOTS || !room {
            return None;
        }
        self.held = self.held.saturating_add(1);
        Some(Taken {
            at,
            generation: 0,
            grown: true,
        })
    }

    /// `place`, when its slot holds a live row taken at `generation`, or with `retired_too` a
    /// retired one.
    #[inline(never)]
    fn find(meta: &[Meta], place: usize, generation: u16, retired_too: bool) -> Option<usize> {
        let slot = meta.get(place)?;
        let named = slot.generation == generation
            && (slot.state == State::Live || (retired_too && slot.state == State::Retired));
        named.then_some(place)
    }

    /// Put the slot at `at` back on the free list.
    fn free(&mut self, meta: &mut [Meta], at: usize) {
        let Some(slot) = meta.get_mut(at) else {
            return;
        };
        slot.state = State::Free;
        slot.pins = 0;
        slot.generation = slot.generation.wrapping_add(1);
        slot.next = self.free;
        self.free = link(at);
        self.held = self.held.saturating_sub(1);
    }

    /// Remove the live row at `place` taken at `generation`: freed now, or retired while pinned.
    #[inline(never)]
    fn retire(&mut self, meta: &mut [Meta], place: usize, generation: u16) -> Option<Retired> {
        let at = Self::find(meta, place, generation, false)?;
        self.retire_at(meta, at)
    }

    /// [`Self::retire`] of the live row at `at`, found already.
    #[inline(never)]
    fn retire_at(&mut self, meta: &mut [Meta], at: usize) -> Option<Retired> {
        let slot = meta.get_mut(at)?;
        if slot.pins == 0 {
            self.free(meta, at);
            Some(Retired::Now(at))
        } else {
            slot.state = State::Retired;
            Some(Retired::Deferred)
        }
    }

    /// Pin the live row at `place` taken at `generation`; `false` when it names none or its pins
    /// are at their count's end.
    #[inline(never)]
    fn pin(meta: &mut [Meta], place: usize, generation: u16) -> bool {
        Self::find(meta, place, generation, false).is_some_and(|at| Self::pin_at(meta, at))
    }

    /// [`Self::pin`] of the live row at `at`, found already.
    #[inline(never)]
    fn pin_at(meta: &mut [Meta], at: usize) -> bool {
        let Some(slot) = meta.get_mut(at) else {
            return false;
        };
        match slot.pins.checked_add(1) {
            Some(pins) => {
                slot.pins = pins;
                true
            }
            None => false,
        }
    }

    /// Give back a pin of the row at `place` taken at `generation`.
    #[inline(never)]
    fn unpin(&mut self, meta: &mut [Meta], place: usize, generation: u16) -> Option<Unpinned> {
        let at = Self::find(meta, place, generation, true)?;
        let slot = meta.get_mut(at)?;
        slot.pins = slot.pins.checked_sub(1)?;
        if slot.pins == 0 && slot.state == State::Retired {
            self.free(meta, at);
            Some(Unpinned::Freed(at))
        } else {
            Some(Unpinned::Held)
        }
    }

    /// How many slots before `place` hold a live row: the rank of a live row at `place` in slot
    /// order, the order every table walks its rows in.
    #[inline(never)]
    fn rank(meta: &[Meta], place: usize) -> usize {
        meta.iter()
            .take(place)
            .filter(|slot| slot.state == State::Live)
            .count()
    }

    /// The place and the generation of the live row at `rank` in slot order.
    #[inline(never)]
    fn nth_live(meta: &[Meta], rank: usize) -> Option<(usize, u16)> {
        meta.iter()
            .enumerate()
            .filter(|(_, slot)| slot.state == State::Live)
            .nth(rank)
            .map(|(at, slot)| (at, slot.generation))
    }

    /// The next slot at or after `cursor` whose state is `state`, the cursor moved past it.
    #[inline(never)]
    fn next_in(meta: &[Meta], cursor: &mut usize, state: State) -> Option<(usize, u16)> {
        while let Some(slot) = meta.get(*cursor) {
            let at = *cursor;
            *cursor = at.saturating_add(1);
            if slot.state == state {
                return Some((at, slot.generation));
            }
        }
        None
    }
}

/// The column a [`SlotMap`] keeps its rows in ([`Storage::Rows`]): read and changed by a row's
/// place, grown by one row at its end, and walked in place order. A row stays where it was put
/// while it stands, so a holder may reach it by its address.
pub trait RowColumn<T> {
    /// The rows, in place order.
    type Iter<'a>: Iterator<Item = &'a T>
    where
        Self: 'a,
        T: 'a;

    /// The rows, in place order, to change.
    type IterMut<'a>: Iterator<Item = &'a mut T>
    where
        Self: 'a,
        T: 'a;

    /// A column of no rows.
    fn empty() -> Self;

    /// The row at `at`.
    fn get(&self, at: usize) -> Option<&T>;

    /// The row at `at`, to change.
    fn get_mut(&mut self, at: usize) -> Option<&mut T>;

    /// Whether a row may still be put after the last one.
    fn has_room(&self) -> bool;

    /// Room for one more row after the last, made now where the column makes its room as it
    /// grows: `false` when there is none, and a push would be refused.
    fn room_for_one(&mut self) -> bool;

    /// Put `value` after the last row; refused, handing it back, where no room was made for it
    /// ([`Self::room_for_one`]).
    fn push(&mut self, value: T) -> Result<(), CapacityFull<T>>;

    /// The rows, in place order.
    fn iter(&self) -> Self::Iter<'_>;

    /// The rows, in place order, to change.
    fn iter_mut(&mut self) -> Self::IterMut<'_>;
}

// A sequence of a policy that never moves an element to make room: a fixed buffer, or what it was
// lent.
impl<T, const N: usize, P: Storage> RowColumn<T> for BoundedVec<T, N, P> {
    type Iter<'a>
        = core::slice::Iter<'a, T>
    where
        Self: 'a,
        T: 'a;

    type IterMut<'a>
        = core::slice::IterMut<'a, T>
    where
        Self: 'a,
        T: 'a;

    fn empty() -> Self {
        Self::default()
    }

    fn get(&self, at: usize) -> Option<&T> {
        <[T]>::get(self, at)
    }

    fn get_mut(&mut self, at: usize) -> Option<&mut T> {
        <[T]>::get_mut(self, at)
    }

    fn has_room(&self) -> bool {
        self.free_slots() != 0
    }

    fn room_for_one(&mut self) -> bool {
        self.free_slots() != 0
    }

    fn push(&mut self, value: T) -> Result<(), CapacityFull<T>> {
        BoundedVec::push(self, value)
    }

    fn iter(&self) -> Self::Iter<'_> {
        <[T]>::iter(self)
    }

    fn iter_mut(&mut self) -> Self::IterMut<'_> {
        <[T]>::iter_mut(self)
    }
}

/// How many rows a chunk of a [`Chunked`] column holds.
#[cfg(feature = "alloc")]
pub const CHUNK_ROWS: usize = 32;

/// The rows of a table of the growable policy, kept in chunks of [`CHUNK_ROWS`] that are only ever
/// added: a chunk once made is neither moved nor grown, so a row stays where it was put however
/// many rows come after it, and the column has no bound but the allocator's. A holder that keeps a
/// row's address (a key's declaration, [`KeyexprHead`](crate::session_tables::KeyexprHead)) reads
/// it there for as long as the row stands, as it does on a policy of a fixed table.
#[cfg(feature = "alloc")]
pub struct Chunked<T> {
    /// Each made with room for `CHUNK_ROWS` rows and filled to no more, so a push into it does not
    /// move it; growing this list moves the chunks' handles and none of their rows.
    chunks: alloc::vec::Vec<alloc::vec::Vec<T>>,
}

#[cfg(feature = "alloc")]
impl<T> RowColumn<T> for Chunked<T> {
    type Iter<'a>
        = core::iter::Flatten<core::slice::Iter<'a, alloc::vec::Vec<T>>>
    where
        Self: 'a,
        T: 'a;

    type IterMut<'a>
        = core::iter::Flatten<core::slice::IterMut<'a, alloc::vec::Vec<T>>>
    where
        Self: 'a,
        T: 'a;

    fn empty() -> Self {
        Self {
            chunks: alloc::vec::Vec::new(),
        }
    }

    fn get(&self, at: usize) -> Option<&T> {
        self.chunks.get(at / CHUNK_ROWS)?.get(at % CHUNK_ROWS)
    }

    fn get_mut(&mut self, at: usize) -> Option<&mut T> {
        self.chunks
            .get_mut(at / CHUNK_ROWS)?
            .get_mut(at % CHUNK_ROWS)
    }

    fn has_room(&self) -> bool {
        true
    }

    fn room_for_one(&mut self) -> bool {
        if self
            .chunks
            .last()
            .is_some_and(|chunk| chunk.len() < CHUNK_ROWS)
        {
            return true;
        }
        let mut chunk = alloc::vec::Vec::new();
        if chunk.try_reserve_exact(CHUNK_ROWS).is_err() || self.chunks.try_reserve(1).is_err() {
            return false;
        }
        self.chunks.push(chunk);
        true
    }

    fn push(&mut self, value: T) -> Result<(), CapacityFull<T>> {
        match self.chunks.last_mut() {
            // Filled to no more than the room it was made with, so the chunk does not move.
            Some(chunk) if chunk.len() < CHUNK_ROWS => {
                chunk.push(value);
                Ok(())
            }
            _ => Err(CapacityFull(value)),
        }
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.chunks.iter().flatten()
    }

    fn iter_mut(&mut self) -> Self::IterMut<'_> {
        self.chunks.iter_mut().flatten()
    }
}

/// A live row of a [`SlotMap`], found by its handle once ([`SlotMap::entry`]): what is done with
/// it through here is done to the slot that one look found.
pub struct Entry<'a, K, T, const N: usize, P: Storage> {
    map: &'a mut SlotMap<K, T, N, P>,
    at: usize,
}

impl<K, T, const N: usize, P: Storage> Entry<'_, K, T, N, P> {
    /// The row.
    pub fn get(&self) -> Option<&T> {
        self.map.rows.get(self.at)?.as_ref()
    }

    /// The row, to change.
    pub fn get_mut(&mut self) -> Option<&mut T> {
        self.map.rows.get_mut(self.at)?.as_mut()
    }

    /// Pin the row while what it owns is called, as [`SlotMap::pin`] does; `false` when its pins
    /// are at their count's end. The pin is given back by the row's handle
    /// ([`SlotMap::release`]).
    pub fn pin(&mut self) -> bool {
        Core::pin_at(&mut self.map.meta, self.at)
    }

    /// Remove the row, as [`SlotMap::remove`] does: handed back now, or by its last unpin when it
    /// is pinned.
    pub fn remove(self) -> Option<Removal<T>> {
        match self.map.core.retire_at(&mut self.map.meta, self.at)? {
            Retired::Now(at) => self.map.rows.get_mut(at)?.take().map(Removal::Taken),
            Retired::Deferred => Some(Removal::AfterCalls),
        }
    }
}

/// A table of at most `N` rows of `T`, named by [`Handle<K>`], kept as the storage policy `P`
/// keeps a table. See the module.
pub struct SlotMap<K, T, const N: usize, P: Storage = Profile> {
    meta: BoundedVec<Meta, N, P>,
    rows: P::Rows<Option<T>, N>,
    core: Core,
    kind: PhantomData<fn() -> K>,
}

impl<K, T, const N: usize, P: Storage> SlotMap<K, T, N, P> {
    /// A table of no rows, holding at most `N` on a policy that enforces its capacity and at most
    /// [`MAX_SLOTS`] on the growable one. On the lent policy a table made so was lent no rows and
    /// refuses every insert; [`SlotMap::lent`] makes the one a session holds.
    pub fn new() -> Self {
        Self {
            meta: BoundedVec::default(),
            rows: <P::Rows<Option<T>, N> as RowColumn<Option<T>>>::empty(),
            core: Core::new(Self::ceiling()),
            kind: PhantomData,
        }
    }

    /// The most rows the policy lets the table hold: `N` where it enforces a capacity.
    fn ceiling() -> usize {
        if P::ENFORCES_CAPACITY {
            N
        } else {
            MAX_SLOTS
        }
    }

    /// Hold at most `rows` rows from here on: the value the session's limits resolved, under the
    /// build's `N` where the policy enforces it. A bound under the rows held now refuses every
    /// insert until enough leave.
    pub fn limit_to(&mut self, rows: usize) {
        self.core.limit_to(rows.min(Self::ceiling()));
    }

    /// The most rows the table holds at once.
    pub fn capacity(&self) -> usize {
        usize::from(self.core.limit()).min(Self::ceiling())
    }

    /// How many slots hold a row, retired rows among them.
    pub fn len(&self) -> usize {
        usize::from(self.core.held)
    }

    /// Whether no slot holds a row.
    pub fn is_empty(&self) -> bool {
        self.core.held == 0
    }

    /// Whether an insert would be refused for want of a slot.
    pub fn is_full(&self) -> bool {
        self.core.held >= self.core.limit()
            || (self.core.free == NIL && (self.meta.free_slots() == 0 || !self.rows.has_room()))
    }

    /// Keep `value` in a free slot: its handle, or `value` back when the table is full.
    pub fn insert(&mut self, value: T) -> Result<Handle<K>, CapacityFull<T>> {
        self.insert_with(value, core::convert::identity)
            .map_err(CapacityFull)
    }

    /// Keep the row `make` builds of `parts` in a free slot: its handle, or `parts` back, with
    /// `make` not called, when the table is full. A caller whose row holds what the refusal hands
    /// back builds it only once a slot was found, and so has no row to take apart on a refusal.
    pub fn insert_with<A>(&mut self, parts: A, make: impl FnOnce(A) -> T) -> Result<Handle<K>, A> {
        // The slot is found first and the row written once, whichever way it was found: a row
        // written in each way would be written twice in every caller of every row type.
        let room = self.meta.free_slots() != 0 && self.rows.room_for_one();
        let Some(taken) = self.core.take_slot(&mut self.meta, room) else {
            return Err(parts);
        };
        if taken.grown {
            // Both columns were found to have a place, so neither push is refused; the row's is
            // empty until the value is written once below.
            let _ = self.meta.push(Meta::ADDED);
            let _ = self.rows.push(None);
        }
        match (
            Handle::at(taken.at, taken.generation),
            self.rows.get_mut(taken.at),
        ) {
            (Some(handle), Some(row)) => {
                *row = Some(make(parts));
                Ok(handle)
            }
            // A place under `MAX_SLOTS` names a handle and the two columns are the same length,
            // so this is not reached; the slot goes back, free, and the parts with the refusal.
            _ => {
                self.core.free(&mut self.meta, taken.at);
                Err(parts)
            }
        }
    }

    /// The live row `handle` names.
    pub fn get(&self, handle: Handle<K>) -> Option<&T> {
        let at = Core::find(&self.meta, handle.place(), handle.generation, false)?;
        self.rows.get(at)?.as_ref()
    }

    /// The live row `handle` names, to change.
    pub fn get_mut(&mut self, handle: Handle<K>) -> Option<&mut T> {
        let at = Core::find(&self.meta, handle.place(), handle.generation, false)?;
        self.rows.get_mut(at)?.as_mut()
    }

    /// The live row `handle` names, found once for what the caller does with it next: read it,
    /// change it, pin it and remove it through the [`Entry`] with no second look at the handle,
    /// which a row that went in between could not have answered since the entry borrows the table.
    /// `None` when it names no live row.
    pub fn entry(&mut self, handle: Handle<K>) -> Option<Entry<'_, K, T, N, P>> {
        let at = Core::find(&self.meta, handle.place(), handle.generation, false)?;
        Some(Entry { map: self, at })
    }

    /// Whether `handle` names a live row.
    pub fn contains(&self, handle: Handle<K>) -> bool {
        self.get(handle).is_some()
    }

    /// Whether the row `handle` names still holds its slot, live or retired: what a caller that
    /// removed a pinned row waits on, since the row is handed back to whoever gives back its last
    /// pin, and is dropped there, after the last call of it.
    pub fn holds_slot(&self, handle: Handle<K>) -> bool {
        Core::find(&self.meta, handle.place(), handle.generation, true).is_some()
    }

    /// Remove the row `handle` names: handed back now, or, when it is pinned, by its last unpin.
    /// `None` when it names no live row.
    pub fn remove(&mut self, handle: Handle<K>) -> Option<Removal<T>> {
        match self
            .core
            .retire(&mut self.meta, handle.place(), handle.generation)?
        {
            Retired::Now(at) => self.rows.get_mut(at)?.take().map(Removal::Taken),
            Retired::Deferred => Some(Removal::AfterCalls),
        }
    }

    /// Pin the live row `handle` names while what it owns is called; `None` when it names none.
    pub fn pin(&mut self, handle: Handle<K>) -> Option<Pinned<K>> {
        Core::pin(&mut self.meta, handle.place(), handle.generation).then_some(Pinned { handle })
    }

    /// The row `pinned` holds in its slot, live or retired.
    pub fn pinned(&self, pinned: &Pinned<K>) -> Option<&T> {
        let handle = pinned.handle;
        let at = Core::find(&self.meta, handle.place(), handle.generation, true)?;
        self.rows.get(at)?.as_ref()
    }

    /// Give back a pin: the row when it was removed while pinned and this was its last pin, for
    /// the caller to drop now that no call of it runs.
    pub fn unpin(&mut self, pinned: Pinned<K>) -> Option<T> {
        let handle = pinned.handle;
        match self
            .core
            .unpin(&mut self.meta, handle.place(), handle.generation)?
        {
            Unpinned::Held => None,
            Unpinned::Freed(at) => self.rows.get_mut(at)?.take(),
        }
    }

    /// Give back the pin a row `handle` names was retired under, by its handle: the row when that
    /// was its last pin. What a table whose calls end without it held gives back once the call
    /// that ended last says the row may go.
    pub fn release(&mut self, handle: Handle<K>) -> Option<T> {
        self.unpin(Pinned { handle })
    }

    /// The rank of the live row `handle` names among the live rows, in slot order, the order
    /// [`Self::iter`] hands them in; `None` when it names none. Read off the slots alone, so
    /// every table answers it with one body whatever its rows are.
    pub fn rank_of(&self, handle: Handle<K>) -> Option<usize> {
        let at = Core::find(&self.meta, handle.place(), handle.generation, false)?;
        Some(Core::rank(&self.meta, at))
    }

    /// The table's slots apart from its rows ([`Slots`]).
    pub fn slots(&self) -> Slots<'_> {
        Slots {
            meta: &self.meta,
            held: self.core.held,
        }
    }

    /// The live row at `rank` in slot order, with its handle: the one [`Self::iter`] hands
    /// `rank`-th, found off the slots alone as [`Self::rank_of`] is.
    pub fn nth_live(&self, rank: usize) -> Option<(Handle<K>, &T)> {
        let (at, generation) = Core::nth_live(&self.meta, rank)?;
        Some((Handle::at(at, generation)?, self.rows.get(at)?.as_ref()?))
    }

    /// The next live row at or after `cursor`, the cursor moved past it, so a caller can walk the
    /// table while it changes it.
    pub fn next_from(&self, cursor: &mut usize) -> Option<(Handle<K>, &T)> {
        self.next_in(cursor, State::Live)
    }

    /// The next retired row at or after `cursor`, the cursor moved past it: one removed while
    /// pinned, which keeps its slot until its last pin is given back. What a walk that finds the
    /// rows whose last call ended reads, so no list of them is kept beside the table.
    pub fn next_retired_from(&self, cursor: &mut usize) -> Option<(Handle<K>, &T)> {
        self.next_in(cursor, State::Retired)
    }

    /// The next row at or after `cursor` whose slot is in `state`, the cursor moved past it.
    fn next_in(&self, cursor: &mut usize, state: State) -> Option<(Handle<K>, &T)> {
        while let Some((at, generation)) = Core::next_in(&self.meta, cursor, state) {
            if let (Some(handle), Some(Some(row))) = (Handle::at(at, generation), self.rows.get(at))
            {
                return Some((handle, row));
            }
        }
        None
    }

    /// The live row at `place`, whatever its generation, with its handle, to change: what a
    /// reader that keeps places rather than handles reads, one that is valid only while the table
    /// does not change (a match cache kept against a count that moves with every insert and
    /// removal), and that hands each row on under the handle the table gave it.
    pub(crate) fn live_handle_at_mut(&mut self, place: usize) -> Option<(Handle<K>, &mut T)> {
        let slot = self.meta.get(place)?;
        if slot.state != State::Live {
            return None;
        }
        let handle = Handle::at(place, slot.generation)?;
        Some((handle, self.rows.get_mut(place)?.as_mut()?))
    }

    /// The live row at `place`, whatever its generation, with its handle, to read:
    /// [`Self::live_handle_at_mut`] for a reader that must not change the row.
    pub(crate) fn live_handle_at(&self, place: usize) -> Option<(Handle<K>, &T)> {
        let slot = self.meta.get(place)?;
        if slot.state != State::Live {
            return None;
        }
        let handle = Handle::at(place, slot.generation)?;
        Some((handle, self.rows.get(place)?.as_ref()?))
    }

    /// Every live row with its place and its handle, in slot order, to read.
    pub(crate) fn live_handles(&self) -> impl Iterator<Item = (usize, Handle<K>, &T)> + '_ {
        self.iter()
            .map(|(handle, row)| (handle.place(), handle, row))
    }

    /// Every live row with its place and its handle, in slot order, to change.
    pub(crate) fn live_handles_mut(
        &mut self,
    ) -> impl Iterator<Item = (usize, Handle<K>, &mut T)> + '_ {
        self.meta
            .iter()
            .zip(self.rows.iter_mut())
            .enumerate()
            .filter_map(|(at, (slot, row))| match (slot.state, row) {
                (State::Live, Some(row)) => Some((at, Handle::at(at, slot.generation)?, row)),
                _ => None,
            })
    }

    /// Every live row, in slot order.
    pub fn iter(&self) -> impl Iterator<Item = (Handle<K>, &T)> + '_ {
        self.meta
            .iter()
            .zip(self.rows.iter())
            .enumerate()
            .filter_map(|(at, (slot, row))| match (slot.state, row) {
                (State::Live, Some(row)) => Some((Handle::at(at, slot.generation)?, row)),
                _ => None,
            })
    }

    /// Every live row, in slot order, to change.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (Handle<K>, &mut T)> + '_ {
        self.meta
            .iter()
            .zip(self.rows.iter_mut())
            .enumerate()
            .filter_map(|(at, (slot, row))| match (slot.state, row) {
                (State::Live, Some(row)) => Some((Handle::at(at, slot.generation)?, row)),
                _ => None,
            })
    }
}

impl<K, T, const N: usize, P: Storage> Default for SlotMap<K, T, N, P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, T, const N: usize, P: Storage> fmt::Debug for SlotMap<K, T, N, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlotMap")
            .field("len", &self.len())
            .field("capacity", &self.capacity())
            .finish()
    }
}

impl<K, T, const N: usize> SlotMap<K, T, N, Lent> {
    /// A table of `rows` rows lent from `arena`: its metadata column, then its rows. Refused,
    /// with what was lent before kept by the arena, past the build's `N` or past what the arena
    /// has left.
    pub fn lent(arena: &mut Arena, rows: usize) -> Result<Self, LendRefused> {
        let mut lend = TableLender::new(arena);
        let table = Self::lent_from(&mut lend, rows);
        lend.finish().map(|()| table)
    }

    /// A table of `rows` rows lent by `lend`, as [`Self::lent`] lends one; a table of no rows,
    /// which refuses every insert, when it is refused or a table before it was. The columns are
    /// lent by one body for every row type (`lend_columns`), which tells them apart by the bytes
    /// of a row alone.
    pub fn lent_from(lend: &mut TableLender<'_>, rows: usize) -> Self {
        const {
            assert!(
                core::mem::align_of::<Option<T>>() <= ARENA_ALIGN,
                "a row of a lent table asks for more alignment than an arena's spans start on"
            )
        };
        let columns = lend_columns(lend, rows, N, Arena::table_bytes::<Option<T>>(rows));
        // SAFETY: `lend_columns` lent the rows' column for `room` rows of `Option<T>`, its
        // bytes counted for that type, lent to nothing before and starting on `ARENA_ALIGN`,
        // which is at least the type's alignment (asserted above), or a span of no rows that
        // starts there too; the metadata column likewise.
        let (meta, values) = unsafe {
            (
                BoundedVec::lent_over(columns.meta, columns.room),
                BoundedVec::lent_over(columns.rows.cast::<Option<T>>(), columns.room),
            )
        };
        Self {
            meta,
            rows: values,
            core: columns.core,
            kind: PhantomData,
        }
    }

    /// The bytes a table of `rows` rows takes in an arena ([`Self::lent`]). `None` past the
    /// address space.
    pub const fn arena_bytes(rows: usize) -> Option<usize> {
        match (
            Arena::table_bytes::<Meta>(rows),
            Arena::table_bytes::<Option<T>>(rows),
        ) {
            (Some(meta), Some(values)) => meta.checked_add(values),
            _ => None,
        }
    }
}

/// The two columns of a lent table: where the arena lent each, the rows each has room for, and
/// the core that counts them.
struct LentColumns {
    meta: NonNull<Meta>,
    rows: NonNull<u8>,
    room: u32,
    core: Core,
}

// SAFETY: both columns are sequences of a policy whose sequences are empty at all zero bytes
// (`ZeroSeqs`), the core of zero bytes holds nothing and is bound by its columns, and the marker is
// no bytes.
unsafe impl<K, T, const N: usize, P: ZeroSeqs> ZeroEmpty for SlotMap<K, T, N, P> {}

/// The rows of a [`SlotMap`] of the region policy, which a region lays out beside the table: its
/// metadata column's and its rows' column's, `N` of each.
#[repr(C)]
pub struct SlotRows<T, const N: usize> {
    meta: [MaybeUninit<Meta>; N],
    rows: [MaybeUninit<Option<T>>; N],
}

// SAFETY: both columns are `MaybeUninit`, valid as any bytes, and hold no value until placed.
unsafe impl<T, const N: usize> ZeroEmpty for SlotRows<T, N> {}

impl<K, T, const N: usize> SlotMap<K, T, N, Region> {
    /// The lines of a region's description ([`place_seqs`]) that place this table's two columns,
    /// the table at `at` in the region and its [`SlotRows`] at `rows`.
    ///
    /// [`place_seqs`]: crate::bounded::place_seqs
    pub const fn places(at: usize, rows: usize) -> [SeqPlace; 2] {
        [
            SeqPlace::of::<Meta>(
                at.wrapping_add(core::mem::offset_of!(Self, meta)),
                rows.wrapping_add(core::mem::offset_of!(SlotRows<T, N>, meta)),
                N,
            ),
            SeqPlace::of::<Option<T>>(
                at.wrapping_add(core::mem::offset_of!(Self, rows)),
                rows.wrapping_add(core::mem::offset_of!(SlotRows<T, N>, rows)),
                N,
            ),
        ]
    }
}

/// Lend a table's two columns by `lend`, `rows` rows of each, at most `ceiling`: its metadata
/// column, then its rows' column of `values` bytes (`None` past the address space). Columns of
/// no rows, and a core that holds none, when one is refused or a table before them was. Out of
/// line and untyped but for the bytes of a row, so the tables of every row type are lent by this
/// one body.
#[inline(never)]
fn lend_columns(
    lend: &mut TableLender<'_>,
    rows: usize,
    ceiling: usize,
    values: Option<usize>,
) -> LentColumns {
    const {
        assert!(
            core::mem::align_of::<Meta>() <= ARENA_ALIGN,
            "a slot's metadata asks for more alignment than an arena's spans start on"
        )
    };
    let (meta, lent) = lend.lend_rows(rows, ceiling, Arena::table_bytes::<Meta>(rows));
    let (values, room) = lend.lend_rows(rows, ceiling, values);
    // A refusal of the rows' column leaves the metadata's lent: neither holds a row then.
    let room = room.min(lent);
    LentColumns {
        meta: meta.cast::<Meta>(),
        rows: values,
        room,
        core: Core::new(room as usize),
    }
}

#[cfg(test)]
mod tests;
