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

use core::fmt;
use core::marker::PhantomData;
use core::num::{NonZeroU16, NonZeroU32};

use crate::bounded::{Arena, BoundedVec, CapacityFull, LendRefused, Lent, Profile, Storage};

/// The most rows a slot map holds: a slot's index is a `u16` counted from one.
pub const MAX_SLOTS: usize = u16::MAX as usize;

/// No slot: the end of the free list.
const NIL: u16 = u16::MAX;

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
    /// The next free slot, or [`NIL`], while the slot is free.
    next: u16,
    pins: u16,
    state: State,
}

/// What the core found for a row to take.
enum Claim {
    /// The free slot at this place, now live.
    Reused(usize),
    /// No slot is free: the next one is to be added after every slot there is.
    Grow,
    /// The table is at its bound.
    Full,
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
    /// The first free slot, or [`NIL`].
    free: u16,
    /// The slots that hold a row, retired ones among them.
    held: u16,
    /// The most slots that may hold a row at once.
    limit: u16,
}

impl Core {
    /// A core of no rows, holding at most `rows`.
    fn new(rows: usize) -> Self {
        Self {
            free: NIL,
            held: 0,
            limit: u16::try_from(rows.min(MAX_SLOTS)).unwrap_or(u16::MAX),
        }
    }

    /// Find a slot for a row.
    #[inline(never)]
    fn claim(&mut self, meta: &mut [Meta]) -> Claim {
        if self.held >= self.limit {
            return Claim::Full;
        }
        if self.free != NIL {
            let at = usize::from(self.free);
            let Some(slot) = meta.get_mut(at) else {
                return Claim::Full;
            };
            self.free = slot.next;
            slot.next = NIL;
            slot.pins = 0;
            slot.state = State::Live;
            self.held = self.held.saturating_add(1);
            return Claim::Reused(at);
        }
        if meta.len() >= MAX_SLOTS {
            return Claim::Full;
        }
        Claim::Grow
    }

    /// A slot was added after every slot there was, holding a row.
    fn grown(&mut self) {
        self.held = self.held.saturating_add(1);
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
        self.free = u16::try_from(at).unwrap_or(NIL);
        self.held = self.held.saturating_sub(1);
    }

    /// Remove the live row at `place` taken at `generation`: freed now, or retired while pinned.
    #[inline(never)]
    fn retire(&mut self, meta: &mut [Meta], place: usize, generation: u16) -> Option<Retired> {
        let at = Self::find(meta, place, generation, false)?;
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
        let Some(at) = Self::find(meta, place, generation, false) else {
            return false;
        };
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

    /// The next live slot at or after `cursor`, the cursor moved past it.
    #[inline(never)]
    fn next_live(meta: &[Meta], cursor: &mut usize) -> Option<(usize, u16)> {
        while let Some(slot) = meta.get(*cursor) {
            let at = *cursor;
            *cursor = at.saturating_add(1);
            if slot.state == State::Live {
                return Some((at, slot.generation));
            }
        }
        None
    }
}

/// A table of at most `N` rows of `T`, named by [`Handle<K>`], kept as the storage policy `P`
/// keeps a table. See the module.
pub struct SlotMap<K, T, const N: usize, P: Storage = Profile> {
    meta: BoundedVec<Meta, N, P>,
    rows: BoundedVec<Option<T>, N, P>,
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
            rows: BoundedVec::default(),
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
        self.core.limit =
            u16::try_from(rows.min(Self::ceiling()).min(MAX_SLOTS)).unwrap_or(u16::MAX);
    }

    /// The most rows the table holds at once.
    pub fn capacity(&self) -> usize {
        usize::from(self.core.limit)
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
        self.core.held >= self.core.limit
            || (self.core.free == NIL
                && (self.meta.free_slots() == 0 || self.rows.free_slots() == 0))
    }

    /// Keep `value` in a free slot: its handle, or `value` back when the table is full.
    pub fn insert(&mut self, value: T) -> Result<Handle<K>, CapacityFull<T>> {
        match self.core.claim(&mut self.meta) {
            Claim::Full => Err(CapacityFull(value)),
            Claim::Reused(at) => {
                let generation = self.meta.get(at).map_or(0, |slot| slot.generation);
                match (self.rows.get_mut(at), Handle::at(at, generation)) {
                    (Some(row), Some(handle)) => {
                        *row = Some(value);
                        Ok(handle)
                    }
                    // The two columns are the same length and every place is under `MAX_SLOTS`,
                    // so neither is reached; the slot goes back and the value with the refusal.
                    _ => {
                        self.core.free(&mut self.meta, at);
                        Err(CapacityFull(value))
                    }
                }
            }
            Claim::Grow => {
                let at = self.meta.len();
                let Some(handle) = Handle::at(at, 0) else {
                    return Err(CapacityFull(value));
                };
                if self.meta.free_slots() == 0 || self.rows.free_slots() == 0 {
                    return Err(CapacityFull(value));
                }
                let slot = Meta {
                    generation: 0,
                    next: NIL,
                    pins: 0,
                    state: State::Live,
                };
                if self.meta.push(slot).is_err() {
                    return Err(CapacityFull(value));
                }
                // The row's place is pushed empty and filled after, so a refused push still holds
                // `value` to hand back.
                if self.rows.push(None).is_err() {
                    let _ = self.meta.pop();
                    return Err(CapacityFull(value));
                }
                match self.rows.get_mut(at) {
                    Some(row) => *row = Some(value),
                    None => {
                        let _ = self.rows.pop();
                        let _ = self.meta.pop();
                        return Err(CapacityFull(value));
                    }
                }
                self.core.grown();
                Ok(handle)
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

    /// The next live row at or after `cursor`, the cursor moved past it, so a caller can walk the
    /// table while it changes it.
    pub fn next_from(&self, cursor: &mut usize) -> Option<(Handle<K>, &T)> {
        while let Some((at, generation)) = Core::next_live(&self.meta, cursor) {
            if let (Some(handle), Some(Some(row))) = (Handle::at(at, generation), self.rows.get(at))
            {
                return Some((handle, row));
            }
        }
        None
    }

    /// Every live row with its place, in slot order, to change: [`Self::live_handle_at_mut`]'s
    /// places.
    pub(crate) fn live_places_mut(&mut self) -> impl Iterator<Item = (usize, &mut T)> + '_ {
        self.meta
            .iter()
            .zip(self.rows.iter_mut())
            .enumerate()
            .filter_map(|(at, (slot, row))| match (slot.state, row) {
                (State::Live, Some(row)) => Some((at, row)),
                _ => None,
            })
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
        let meta = arena.lend::<Meta, N>(rows)?;
        let values = arena.lend::<Option<T>, N>(rows)?;
        Ok(Self {
            meta,
            rows: values,
            core: Core::new(rows),
            kind: PhantomData,
        })
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

#[cfg(test)]
mod tests;
