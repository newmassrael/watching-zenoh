// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The id-keyed tables a PEER writes: the keyexpr aliases it declares, and the
//! subscribers, queryables and tokens it declares to us (fixed-memory step S9a).
//!
//! Every one of them is `{ wire id -> value }`, written by the remote end of a
//! session and nobody else, and every one of them was a `HashMap` that a peer
//! could grow without bound. They are the same container here, for the reason
//! [`crate::bounded::BoundedVec`] is one: ARCHITECTURE.md §2.4 wants ONE
//! registry implementation over two backings, so the logic is written once
//! against [`crate::id_map::IdMap`] and only the storage swaps with the profile.
//!
//! - **growable** (`alloc` on, `bounded-heapless` off: the AP profile) is a
//!   `GrowableIdMap`: the `hashbrown::HashMap` the registries
//!   always held, whose room never refuses; the declared capacity is advisory.
//! - **fixed** (`alloc` off, or `bounded-heapless` on: the MCU profiles) is a
//!   [`crate::id_map::FixedIdMap`]: `N` rows in an inline array.
//! - **lent** (the cooperative engine's tables, lent at a session's open) is a
//!   [`crate::id_map::PooledIdMap`]: at most `N` rows, each in a pool every face of the session
//!   shares ([`crate::row_pool`]), refused as a full fixed table refuses when the table holds `N`
//!   or the pool has no row left.
//!   [`bind`](crate::id_map::IdMap::bind) of an id the table does not hold, with
//!   the table full, is a typed refusal ([`crate::bounded::CapacityFull`],
//!   carrying the value back), is COUNTED
//!   ([`refusals`](crate::id_map::IdMap::refusals)) and allocates nothing.
//!   Rebinding an id the table already holds replaces it in place and needs no
//!   room, which is what a peer that re-declares an id expects.
//! - **on use** (the tables a session takes at their first row) is a `CountedIdMap`: its count's
//!   rows taken at its first id, and each NEW id a row of its kind of the session's key budget, so
//!   the faces of a session hold what their peers write to the session's bounds together.
//!
//! The bound a session's creator states for a table ([`crate::limits::SessionLimits`])
//! is asked through [`bind_within`](crate::id_map::IdMap::bind_within) on both
//! backings: a NEW id past it is refused the way a full fixed table refuses one,
//! handed back and counted, so the two backings refuse the same declarations.
//!
//! A refusal is the PEER's to see, never a panic and never a thing another
//! session pays for: the registries drop the declaration that did not fit and
//! carry on, and under `session-slot` each session owns its tables (the
//! `peer_tables` module), so one peer filling its own changes nothing in
//! another's.
//!
//! The linear scan is deliberate. The capacities are single digits to a few
//! dozen (`caps::MAX_PEER_KEYEXPR_ALIASES`, `caps::MAX_REMOTE_DECLS`), a lookup is
//! one comparison per row on a table that lives in cache, and an indexed
//! no-alloc map would spend more RAM than the rows it indexes.

#[cfg(feature = "alloc")]
use hashbrown::HashMap;

#[cfg(feature = "alloc")]
use crate::bounded::{BoundedVec, SeqBacking, Static};
use crate::bounded::{CapacityFull, KeyMaker, KeyUnkept, Profile, Storage};
use crate::caps;
#[cfg(feature = "alloc")]
use crate::row_pool::RowList;

/// A table of values by the id the peer gave them.
///
/// The method names do not shadow `HashMap`'s (`get`, `insert`, `remove`), so a
/// call through this trait reads the same on both backings and a stray inherent
/// call cannot silently pick the other signature.
pub trait IdMap<V> {
    /// The value bound to `id`, if any.
    fn find(&self, id: u64) -> Option<&V>;

    /// The value bound to `id`, mutably, if any.
    fn find_mut(&mut self, id: u64) -> Option<&mut V>;

    /// Bind `id` to `value`, returning what it replaced. A fixed table with no
    /// room for a NEW id refuses with the value handed back and counts it; an id
    /// already bound is replaced in place and never refused.
    fn bind(&mut self, id: u64, value: V) -> Result<Option<V>, CapacityFull<V>>;

    /// [`Self::bind`] under a bound above the table's room: a NEW id is first
    /// asked `admits(count)`, with the count binding it would leave, and one it
    /// refuses is refused as a full table refuses it, handed back and counted. An
    /// id already bound is replaced in place and `admits` is not asked, so a
    /// lowered bound keeps what the table holds.
    fn bind_within<F: FnOnce(usize) -> bool>(
        &mut self,
        id: u64,
        value: V,
        admits: F,
    ) -> Result<Option<V>, CapacityFull<V>>;

    /// Drop the binding of `id`, returning what it held.
    fn unbind(&mut self, id: u64) -> Option<V>;

    /// Drop every binding. The refusal count is kept: it counts what the table
    /// was asked and could not take over its life, not what it holds.
    fn reset(&mut self);

    /// How many ids are bound.
    fn count(&self) -> usize;

    /// Every binding, in no order a caller may rely on.
    fn entries<'a>(&'a self) -> impl Iterator<Item = (u64, &'a V)>
    where
        V: 'a;

    /// How many NEW ids were refused since the table was made, for want of room
    /// or past the bound [`Self::bind_within`] asked, or as [`Self::count_refused`]
    /// counts them. Zero on the growable backing while no bound refuses, as its room
    /// refuses nothing.
    fn refusals(&self) -> u32;

    /// Count a binding refused before it reached the table, for want of room where the value
    /// it would have held is kept (a key the session's key arena has no room for): the
    /// declaration is dropped as one the table has no room for is, and counted with them.
    fn count_refused(&mut self);

    /// Whether any id is bound.
    fn is_bound(&self) -> bool {
        self.count() != 0
    }
}

/// What a table of values by a peer's ids answers to a reader for as long as `'a`, the borrow it
/// was lent for: the part of [`IdMap`] that writes nothing, which a table lent its owner's space
/// only to read answers too ([`LentIdsRef`]). What it hands out lives for `'a`, not for the
/// reader value, so a lent table made in a call hands out what outlives it. Every [`IdMap`]
/// answers it by a shared reference.
///
/// A reader is a copy of a shared borrow (`Copy`), so [`Self::into_entries`] takes it by value: an
/// `impl Trait` a trait method returns captures every lifetime in its signature, and one taken
/// from `&self` would tie the iterator to the reader value, which a view made in the call that
/// returns the iterator does not outlive. It is named apart from [`IdMap::entries`]: a shared
/// reference to a table answers both traits, and a call on a table must name one method.
pub trait IdRead<'a, V: 'a>: Copy {
    /// The value bound to `id`, if any.
    fn find(&self, id: u64) -> Option<&'a V>;

    /// How many ids are bound.
    fn count(&self) -> usize;

    /// Every binding, in no order a caller may rely on, for as long as `'a`.
    fn into_entries(self) -> impl Iterator<Item = (u64, &'a V)> + 'a;

    /// How many NEW ids were refused since the table was made ([`IdMap::refusals`]).
    fn refusals(&self) -> u32;

    /// Whether any id is bound.
    fn is_bound(&self) -> bool {
        self.count() != 0
    }
}

impl<'a, V: 'a, T: IdMap<V> + ?Sized> IdRead<'a, V> for &'a T {
    fn find(&self, id: u64) -> Option<&'a V> {
        T::find(*self, id)
    }

    fn count(&self) -> usize {
        T::count(*self)
    }

    fn into_entries(self) -> impl Iterator<Item = (u64, &'a V)> + 'a {
        T::entries(self)
    }

    fn refusals(&self) -> u32 {
        T::refusals(*self)
    }
}

impl<V, T: IdMap<V> + ?Sized> IdMap<V> for &mut T {
    fn find(&self, id: u64) -> Option<&V> {
        T::find(self, id)
    }

    fn find_mut(&mut self, id: u64) -> Option<&mut V> {
        T::find_mut(self, id)
    }

    fn bind(&mut self, id: u64, value: V) -> Result<Option<V>, CapacityFull<V>> {
        T::bind(self, id, value)
    }

    fn bind_within<F: FnOnce(usize) -> bool>(
        &mut self,
        id: u64,
        value: V,
        admits: F,
    ) -> Result<Option<V>, CapacityFull<V>> {
        T::bind_within(self, id, value, admits)
    }

    fn unbind(&mut self, id: u64) -> Option<V> {
        T::unbind(self, id)
    }

    fn reset(&mut self) {
        T::reset(self);
    }

    fn count(&self) -> usize {
        T::count(self)
    }

    fn entries<'a>(&'a self) -> impl Iterator<Item = (u64, &'a V)>
    where
        V: 'a,
    {
        T::entries(self)
    }

    fn refusals(&self) -> u32 {
        T::refusals(self)
    }

    fn count_refused(&mut self) {
        T::count_refused(self);
    }
}

/// `N` rows of `(id, value)` in an inline array: the fixed backing of
/// [`IdMap`]. Nothing here ever touches a heap.
pub struct FixedIdMap<V, const N: usize> {
    rows: heapless::Vec<(u64, V), N>,
    refused: u32,
    /// The most ids the table has held: zero-sized unless the build keeps the mark
    /// (`pool-monitor`).
    high: crate::pool_gauge::HighWater,
}

impl<V, const N: usize> FixedIdMap<V, N> {
    /// An empty table. `const`, so a session slot that holds one can be a
    /// `static`.
    pub const fn new() -> Self {
        Self {
            rows: heapless::Vec::new(),
            refused: 0,
            high: crate::pool_gauge::HighWater::new(),
        }
    }

    /// The declared capacity `N`: the most ids the table holds at once.
    pub const fn capacity(&self) -> usize {
        N
    }
}

impl<V, const N: usize> crate::pool_gauge::PoolGauge for FixedIdMap<V, N> {
    fn pool_stat(&self, name: &'static str) -> crate::pool_gauge::PoolStat {
        crate::pool_gauge::PoolStat {
            name,
            capacity: crate::pool_gauge::count(N),
            in_use: crate::pool_gauge::count(self.rows.len()),
            high_water: self.high.get(),
            refused: u64::from(self.refused),
        }
    }
}

// SAFETY: its rows are a heapless 0.8 `Vec` (`ZeroEmpty`), its count of refusals zero, its mark
// one that has seen nothing: all zero bytes are a table of no ids.
unsafe impl<V, const N: usize> crate::bounded::ZeroEmpty for FixedIdMap<V, N> {}

impl<V, const N: usize> Default for FixedIdMap<V, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V, const N: usize> IdMap<V> for FixedIdMap<V, N> {
    fn find(&self, id: u64) -> Option<&V> {
        self.rows.iter().find(|(k, _)| *k == id).map(|(_, v)| v)
    }

    fn find_mut(&mut self, id: u64) -> Option<&mut V> {
        self.rows.iter_mut().find(|(k, _)| *k == id).map(|(_, v)| v)
    }

    fn bind(&mut self, id: u64, value: V) -> Result<Option<V>, CapacityFull<V>> {
        self.bind_within(id, value, |_| true)
    }

    fn bind_within<F: FnOnce(usize) -> bool>(
        &mut self,
        id: u64,
        value: V,
        admits: F,
    ) -> Result<Option<V>, CapacityFull<V>> {
        if let Some((_, held)) = self.rows.iter_mut().find(|(k, _)| *k == id) {
            return Ok(Some(core::mem::replace(held, value)));
        }
        if !admits(self.rows.len().saturating_add(1)) {
            self.refused = self.refused.saturating_add(1);
            return Err(CapacityFull(value));
        }
        match self.rows.push((id, value)) {
            Ok(()) => {
                self.high.note(self.rows.len());
                Ok(None)
            }
            Err((_, value)) => {
                self.refused = self.refused.saturating_add(1);
                Err(CapacityFull(value))
            }
        }
    }

    fn unbind(&mut self, id: u64) -> Option<V> {
        let at = self.rows.iter().position(|(k, _)| *k == id)?;
        Some(self.rows.remove(at).1)
    }

    fn reset(&mut self) {
        self.rows.clear();
    }

    fn count(&self) -> usize {
        self.rows.len()
    }

    fn entries<'a>(&'a self) -> impl Iterator<Item = (u64, &'a V)>
    where
        V: 'a,
    {
        self.rows.iter().map(|(k, v)| (*k, v))
    }

    fn refusals(&self) -> u32 {
        self.refused
    }

    fn count_refused(&mut self) {
        self.refused = self.refused.saturating_add(1);
    }
}

/// The lent backing of [`IdMap`]: at most `N` rows of `(id, value)`, where the session's open put
/// them ([`crate::row_pool::RowSpace`]): in a pool the faces of the session share, the table a
/// list of the rows it holds in the order they were bound, or in a span of the table's own laid
/// out as [`FixedIdMap`]'s rows are. A lookup scans the table's own rows, as [`FixedIdMap`]'s
/// does. A NEW id is refused, handed back and counted, as a full fixed table refuses it, when the
/// table holds `N` ids, its span or its pool has no row left (which the pool counts too); a held
/// id is replaced in place and needs no row. Made by `Default` it holds no rows and refuses every
/// new id until it is attached to some ([`Self::attach`]).
///
/// The table is a head and no pointer: its first row and its count, two `u16`s, and the count of
/// what it refused, the `u32` [`FixedIdMap`] keeps, so it takes no more than the room
/// [`FixedIdMap`] keeps beside its rows on any target (8 bytes, i386 System V's room, the least).
/// Its owner holds the space its rows lie in once and lends it for each operation
/// ([`Self::lend`]): the lent table is what answers [`IdMap`]. Dropped, it gives nothing back;
/// its owner gives its rows back first ([`IdMap::reset`] on the lent table).
pub struct PooledIdMap<V, const N: usize> {
    rows: crate::row_pool::PooledRows<crate::row_pool::Keyed<V>, N>,
    /// How many NEW ids were refused, as [`FixedIdMap`]'s count.
    refused: u32,
    /// The most ids the table has held: zero-sized unless the build keeps the mark
    /// (`pool-monitor`).
    high: crate::pool_gauge::HighWater,
}

impl<V, const N: usize> PooledIdMap<V, N> {
    /// An empty table with no rows. `const`, as [`FixedIdMap::new`] is.
    pub const fn new() -> Self {
        Self {
            rows: crate::row_pool::PooledRows::new(),
            refused: 0,
            high: crate::pool_gauge::HighWater::new(),
        }
    }

    /// Bind the ids that come from here on in rows of `space`, its owner's. A table already
    /// taking rows of a space of the same form keeps them; the refusals it counted are kept.
    pub fn attach(&mut self, space: &crate::row_pool::RowSpace<crate::row_pool::Keyed<V>>) {
        self.rows.attach(space);
    }

    /// The declared capacity `N`: the most ids the table holds at once, whatever its rows have.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// How many ids are bound: read off the head, with no space.
    pub fn count(&self) -> usize {
        self.rows.len()
    }

    /// How many NEW ids were refused since the table was made: read off the head, with no space.
    pub fn refusals(&self) -> u32 {
        self.refused
    }

    /// Count a binding refused before it reached the table, as [`IdMap::count_refused`] does.
    pub fn count_refused(&mut self) {
        self.refused = self.refused.saturating_add(1);
    }

    /// The ids the table holds, as a table of their own whose rows stay where they lie in the
    /// pool, and this one left holding none and binding ids in rows of the same pool, its refusals
    /// kept. `None`, taking nothing, for a table whose rows lie in a span of its own
    /// ([`PooledRows::split_off`](crate::row_pool::PooledRows::split_off)). Needs no space.
    pub fn split_off(&mut self) -> Option<Self> {
        self.rows.split_off().map(|rows| Self {
            rows,
            refused: 0,
            high: crate::pool_gauge::HighWater::new(),
        })
    }

    /// The table with its rows, to bind and unbind: `space` lent to it for as long as the borrow.
    ///
    /// # Safety
    /// `space` is the space this table was attached to ([`Self::attach`]): its owner's, which
    /// lends each of its tables the one space it attached it to.
    #[inline]
    pub unsafe fn lend<'a>(
        &'a mut self,
        space: &crate::row_pool::RowSpace<crate::row_pool::Keyed<V>>,
    ) -> LentIds<'a, V, N> {
        LentIds {
            // SAFETY: the caller's contract.
            rows: unsafe { self.rows.lend(space) },
            refused: &mut self.refused,
            high: &mut self.high,
        }
    }

    /// The table with its rows, to read: `space` lent to it for as long as the borrow.
    ///
    /// # Safety
    /// As [`Self::lend`]'s.
    #[inline]
    pub unsafe fn lend_ref<'a>(
        &'a self,
        space: &crate::row_pool::RowSpace<crate::row_pool::Keyed<V>>,
    ) -> LentIdsRef<'a, V, N> {
        LentIdsRef {
            // SAFETY: the caller's contract.
            rows: unsafe { self.rows.lend_ref(space) },
            refused: self.refused,
        }
    }
}

impl<V, const N: usize> Default for PooledIdMap<V, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V, const N: usize> crate::pool_gauge::PoolGauge for PooledIdMap<V, N> {
    fn pool_stat(&self, name: &'static str) -> crate::pool_gauge::PoolStat {
        crate::pool_gauge::PoolStat {
            name,
            capacity: crate::pool_gauge::count(N),
            in_use: crate::pool_gauge::count(self.rows.len()),
            high_water: self.high.get(),
            refused: u64::from(self.refused),
        }
    }
}

/// A table of values by a peer's ids as its owner holds it ([`Storage::Ids`]), lent the owner's
/// handle `H` (the policy's [`Storage::Keys`]) for each operation: the table itself on the
/// policies that keep their own rows, which need no handle, and on the lent one a [`PooledIdMap`]
/// lent the space the handle names for its slot. What answers [`IdMap`] and [`IdRead`] is the
/// lent table.
pub trait PeerIds<V, H>: Default {
    /// The table lent the handle, to bind and unbind.
    type Mut<'a>: IdMap<V>
    where
        Self: 'a,
        H: 'a,
        V: 'a;
    /// The table lent the handle, to read: what it hands out lives for the lend.
    type Ref<'a>: IdRead<'a, V> + Copy
    where
        Self: 'a,
        H: 'a,
        V: 'a;

    /// The table lent `keys` for its slot `slot`, to bind and unbind.
    ///
    /// # Safety
    /// `keys` is the handle of the owner that holds this table, and `slot` the one it attached the
    /// table's rows to: the owner lends each of its tables the one space it attached it to.
    unsafe fn lend<'a>(&'a mut self, keys: &'a H, slot: crate::row_pool::PeerSlot)
        -> Self::Mut<'a>;

    /// The table lent `keys` for its slot `slot`, to read.
    ///
    /// # Safety
    /// As [`Self::lend`]'s.
    unsafe fn lend_ref<'a>(&'a self, keys: &'a H, slot: crate::row_pool::PeerSlot)
        -> Self::Ref<'a>;

    /// Give back the rows the table holds where they lie apart from it, through `keys`: what its
    /// owner does before it drops the table or changes its handle. Nothing for a table that keeps
    /// its own rows, which its own drop gives back.
    ///
    /// # Safety
    /// As [`Self::lend`]'s.
    unsafe fn release(&mut self, keys: &H, slot: crate::row_pool::PeerSlot) {
        let _ = (keys, slot);
    }

    /// Count the table to `rows` rows while it holds no id: a table whose rows are counted when
    /// it is made (`CountedIdMap`) takes `rows` as its count from here on and answers `true`,
    /// and keeps its count while it holds an id. A table of a fixed capacity, of rows lent from a
    /// pool, or that grows has no count to change: `false`.
    fn recount(&mut self, rows: usize) -> bool {
        let _ = rows;
        false
    }
}

impl<V, const N: usize, H> PeerIds<V, H> for FixedIdMap<V, N> {
    type Mut<'a>
        = &'a mut Self
    where
        Self: 'a,
        H: 'a,
        V: 'a;
    type Ref<'a>
        = &'a Self
    where
        Self: 'a,
        H: 'a,
        V: 'a;

    unsafe fn lend<'a>(&'a mut self, _: &'a H, _: crate::row_pool::PeerSlot) -> &'a mut Self {
        self
    }

    unsafe fn lend_ref<'a>(&'a self, _: &'a H, _: crate::row_pool::PeerSlot) -> &'a Self {
        self
    }
}

#[cfg(feature = "alloc")]
impl<V, H> PeerIds<V, H> for GrowableIdMap<V> {
    type Mut<'a>
        = &'a mut Self
    where
        Self: 'a,
        H: 'a,
        V: 'a;
    type Ref<'a>
        = &'a Self
    where
        Self: 'a,
        H: 'a,
        V: 'a;

    unsafe fn lend<'a>(&'a mut self, _: &'a H, _: crate::row_pool::PeerSlot) -> &'a mut Self {
        self
    }

    unsafe fn lend_ref<'a>(&'a self, _: &'a H, _: crate::row_pool::PeerSlot) -> &'a Self {
        self
    }
}

impl<V, const N: usize> PeerIds<V, crate::key_arena::LentKeys> for PooledIdMap<V, N> {
    type Mut<'a>
        = LentIds<'a, V, N>
    where
        Self: 'a,
        V: 'a;
    type Ref<'a>
        = LentIdsRef<'a, V, N>
    where
        Self: 'a,
        V: 'a;

    unsafe fn lend<'a>(
        &'a mut self,
        keys: &'a crate::key_arena::LentKeys,
        slot: crate::row_pool::PeerSlot,
    ) -> LentIds<'a, V, N> {
        let space = crate::row_pool::lent_space::<crate::row_pool::Keyed<V>>(keys, slot);
        // SAFETY: the caller's contract: the space the owner's handle names for the slot is the one
        // this table was attached to.
        unsafe { PooledIdMap::lend(self, &space) }
    }

    unsafe fn lend_ref<'a>(
        &'a self,
        keys: &'a crate::key_arena::LentKeys,
        slot: crate::row_pool::PeerSlot,
    ) -> LentIdsRef<'a, V, N> {
        let space = crate::row_pool::lent_space::<crate::row_pool::Keyed<V>>(keys, slot);
        // SAFETY: as `lend`'s.
        unsafe { PooledIdMap::lend_ref(self, &space) }
    }

    unsafe fn release(
        &mut self,
        keys: &crate::key_arena::LentKeys,
        slot: crate::row_pool::PeerSlot,
    ) {
        let space = crate::row_pool::lent_space::<crate::row_pool::Keyed<V>>(keys, slot);
        // SAFETY: as `lend`'s.
        unsafe { PooledIdMap::lend(self, &space) }.reset();
    }
}

/// The on-use backing of [`IdMap`] (the `Ids` of [`OnUse`](crate::bounded::OnUse)): at most a
/// count of rows of `(id, value)`, `N` until its owner counts it anew while it holds no id
/// ([`PeerIds::recount`]), all of them taken from the allocator at its first id
/// ([`FirstUse`](crate::on_use::FirstUse)) and scanned as [`FixedIdMap`]'s are. A table never
/// bound takes nothing, and the count is the table's, not the build's: a group's face is counted
/// to every member's aliases where a peer's is held to its own.
///
/// It answers [`IdMap`] only lent its owner's handle ([`PeerIds::lend`], [`CountedIds`]): a
/// NEW id then takes a row of its slot's kind from the session's [`KeyBudget`](crate::on_use::KeyBudget)
/// as well, so the peers of every face hold their rows of each kind to the session's bound
/// together, as a lent session's pool holds them; each id let go of gives its row back. Its owner
/// gives every row back through the handle before it drops the table or changes the handle
/// ([`PeerIds::release`]), as a pooled table's owner does.
#[cfg(feature = "alloc")]
pub struct CountedIdMap<V, const N: usize> {
    rows: crate::on_use::FirstUse<(u64, V), { usize::MAX }>,
    /// How many NEW ids were refused, as [`FixedIdMap`]'s count.
    refused: u32,
    /// The most ids the table has held: zero-sized unless the build keeps the mark
    /// (`pool-monitor`).
    high: crate::pool_gauge::HighWater,
}

#[cfg(feature = "alloc")]
impl<V, const N: usize> CountedIdMap<V, N> {
    /// An empty table of `N` rows that has taken no memory.
    pub const fn new() -> Self {
        Self {
            rows: crate::on_use::FirstUse::counted(N),
            refused: 0,
            high: crate::pool_gauge::HighWater::new(),
        }
    }

    /// The most ids the table holds at once: its count.
    pub fn capacity(&self) -> usize {
        self.rows.count()
    }

    /// Whether the table took its rows.
    pub fn holds_rows(&self) -> bool {
        self.rows.holds_rows()
    }

    /// Count the table to `rows` while it holds no id, giving back the rows it took: `false`, the
    /// count kept, while it holds one. The refusals it counted are kept.
    pub fn recount(&mut self, rows: usize) -> bool {
        if !self.rows.as_slice().is_empty() {
            return false;
        }
        self.rows = crate::on_use::FirstUse::counted(rows);
        true
    }

    /// Where `id` lies among the rows.
    fn position(&self, id: u64) -> Option<usize> {
        self.rows
            .as_slice()
            .iter()
            .position(|(held, _)| *held == id)
    }

    /// Count a NEW id refused, and hand its value back.
    fn refuse(&mut self, value: V) -> CapacityFull<V> {
        self.refused = self.refused.saturating_add(1);
        CapacityFull(value)
    }
}

#[cfg(feature = "alloc")]
impl<V, const N: usize> Default for CountedIdMap<V, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "alloc")]
impl<V, const N: usize> crate::pool_gauge::PoolGauge for CountedIdMap<V, N> {
    fn pool_stat(&self, name: &'static str) -> crate::pool_gauge::PoolStat {
        crate::pool_gauge::PoolStat {
            name,
            capacity: crate::pool_gauge::count(self.rows.count()),
            in_use: crate::pool_gauge::count(self.rows.as_slice().len()),
            high_water: self.high.get(),
            refused: u64::from(self.refused),
        }
    }
}

/// A [`CountedIdMap`] lent its owner's handle, to bind and unbind: a NEW id takes a row of the
/// slot's kind from the session's budget the handle names, and each id let go of gives one back.
/// A handle of no budget holds the table to its own count alone.
#[cfg(feature = "alloc")]
pub struct CountedIds<'a, V, const N: usize> {
    table: &'a mut CountedIdMap<V, N>,
    budget: Option<&'a crate::on_use::KeyBudget>,
    slot: crate::row_pool::PeerSlot,
}

#[cfg(feature = "alloc")]
impl<V, const N: usize> CountedIds<'_, V, N> {
    /// Give `count` rows of the slot's kind back to the session's budget.
    fn give_back(&self, count: usize) {
        if let Some(budget) = self.budget {
            budget.give_peer_rows(self.slot, count);
        }
    }
}

#[cfg(feature = "alloc")]
impl<V, const N: usize> IdMap<V> for CountedIds<'_, V, N> {
    fn find(&self, id: u64) -> Option<&V> {
        let at = self.table.position(id)?;
        self.table.rows.as_slice().get(at).map(|(_, value)| value)
    }

    fn find_mut(&mut self, id: u64) -> Option<&mut V> {
        let at = self.table.position(id)?;
        self.table
            .rows
            .as_mut_slice()
            .get_mut(at)
            .map(|(_, value)| value)
    }

    fn bind(&mut self, id: u64, value: V) -> Result<Option<V>, CapacityFull<V>> {
        self.bind_within(id, value, |_| true)
    }

    fn bind_within<F: FnOnce(usize) -> bool>(
        &mut self,
        id: u64,
        value: V,
        admits: F,
    ) -> Result<Option<V>, CapacityFull<V>> {
        if let Some((_, held)) = self
            .table
            .rows
            .as_mut_slice()
            .iter_mut()
            .find(|(held, _)| *held == id)
        {
            return Ok(Some(core::mem::replace(held, value)));
        }
        let count = self.table.rows.as_slice().len().saturating_add(1);
        if !admits(count) || self.table.rows.free_slots() == 0 {
            return Err(self.table.refuse(value));
        }
        if let Some(budget) = self.budget {
            if !budget.take_peer_row(self.slot) {
                return Err(self.table.refuse(value));
            }
        }
        match self.table.rows.push((id, value)) {
            Ok(()) => {
                self.table.high.note(count);
                Ok(None)
            }
            // The allocator has no room for the table's rows: the session's row goes back.
            Err(CapacityFull((_, value))) => {
                self.give_back(1);
                Err(self.table.refuse(value))
            }
        }
    }

    fn unbind(&mut self, id: u64) -> Option<V> {
        let at = self.table.position(id)?;
        let (_, value) = self.table.rows.remove(at);
        self.give_back(1);
        Some(value)
    }

    fn reset(&mut self) {
        let held = self.table.rows.as_slice().len();
        self.table.rows.clear();
        self.give_back(held);
    }

    fn count(&self) -> usize {
        self.table.rows.as_slice().len()
    }

    fn entries<'e>(&'e self) -> impl Iterator<Item = (u64, &'e V)>
    where
        V: 'e,
    {
        self.table
            .rows
            .as_slice()
            .iter()
            .map(|(id, value)| (*id, value))
    }

    fn refusals(&self) -> u32 {
        self.table.refused
    }

    fn count_refused(&mut self) {
        self.table.refused = self.table.refused.saturating_add(1);
    }
}

/// A [`CountedIdMap`] lent its owner's handle, to read: a read takes nothing of the budget.
#[cfg(feature = "alloc")]
pub struct CountedIdsRef<'a, V, const N: usize>(&'a CountedIdMap<V, N>);

#[cfg(feature = "alloc")]
impl<V, const N: usize> Clone for CountedIdsRef<'_, V, N> {
    fn clone(&self) -> Self {
        *self
    }
}

#[cfg(feature = "alloc")]
impl<V, const N: usize> Copy for CountedIdsRef<'_, V, N> {}

#[cfg(feature = "alloc")]
impl<'a, V: 'a, const N: usize> IdRead<'a, V> for CountedIdsRef<'a, V, N> {
    fn find(&self, id: u64) -> Option<&'a V> {
        let table = self.0;
        let at = table.position(id)?;
        table.rows.as_slice().get(at).map(|(_, value)| value)
    }

    fn count(&self) -> usize {
        self.0.rows.as_slice().len()
    }

    fn into_entries(self) -> impl Iterator<Item = (u64, &'a V)> + 'a {
        self.0
            .rows
            .as_slice()
            .iter()
            .map(|(id, value)| (*id, value))
    }

    fn refusals(&self) -> u32 {
        self.0.refused
    }
}

#[cfg(feature = "alloc")]
impl<V, const N: usize> PeerIds<V, crate::on_use::BudgetKeys> for CountedIdMap<V, N> {
    type Mut<'a>
        = CountedIds<'a, V, N>
    where
        Self: 'a,
        V: 'a;
    type Ref<'a>
        = CountedIdsRef<'a, V, N>
    where
        Self: 'a,
        V: 'a;

    unsafe fn lend<'a>(
        &'a mut self,
        keys: &'a crate::on_use::BudgetKeys,
        slot: crate::row_pool::PeerSlot,
    ) -> CountedIds<'a, V, N> {
        CountedIds {
            table: self,
            budget: keys.budget(),
            slot,
        }
    }

    unsafe fn lend_ref<'a>(
        &'a self,
        _: &'a crate::on_use::BudgetKeys,
        _: crate::row_pool::PeerSlot,
    ) -> CountedIdsRef<'a, V, N> {
        CountedIdsRef(self)
    }

    unsafe fn release(
        &mut self,
        keys: &crate::on_use::BudgetKeys,
        slot: crate::row_pool::PeerSlot,
    ) {
        // SAFETY: as `lend`'s: the owner's handle, for the slot the table's rows are counted in.
        unsafe { <Self as PeerIds<V, crate::on_use::BudgetKeys>>::lend(self, keys, slot) }.reset();
    }

    fn recount(&mut self, rows: usize) -> bool {
        CountedIdMap::recount(self, rows)
    }
}

/// A table of values by a peer's ids beside the handle of the owner that holds it and the slot it
/// was attached to, to read: the table is lent the handle ([`PeerIds::lend_ref`]) at each read.
///
/// What a type that is passed on with a shorter borrow holds in place of [`PeerIds::Ref`]
/// ([`crate::wireexpr_resolve::MappingSpaces`], handed to a resolver whose buffer lives shorter
/// than the tables). `PeerIds::Ref<'a>` is a projection through `'a`, and a type that holds a
/// projection through a lifetime is invariant in it, so it could not be shortened; this pair
/// holds only shared borrows and is covariant in `'a`, as a `&'a` of the table is.
pub struct PairedIds<'a, T, H> {
    table: &'a T,
    keys: &'a H,
    slot: crate::row_pool::PeerSlot,
}

impl<T, H> Clone for PairedIds<'_, T, H> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T, H> Copy for PairedIds<'_, T, H> {}

impl<'a, T: 'a, H: 'a> PairedIds<'a, T, H> {
    /// `table` beside `keys`, its owner's handle, for the slot `slot`.
    ///
    /// # Safety
    /// As [`PeerIds::lend`]'s, for as long as `'a`: `keys` is the handle of the owner that holds
    /// `table`, and `slot` the one it attached the table's rows to.
    pub unsafe fn new(table: &'a T, keys: &'a H, slot: crate::row_pool::PeerSlot) -> Self {
        Self { table, keys, slot }
    }

    /// The table lent the handle, to read.
    pub fn lend<V: 'a>(self) -> <T as PeerIds<V, H>>::Ref<'a>
    where
        T: PeerIds<V, H>,
    {
        // SAFETY: the pairing the caller of `Self::new` promised for `'a`.
        unsafe { <T as PeerIds<V, H>>::lend_ref(self.table, self.keys, self.slot) }
    }
}

impl<'a, V: 'a, T: PeerIds<V, H> + 'a, H: 'a> IdRead<'a, V> for PairedIds<'a, T, H> {
    fn find(&self, id: u64) -> Option<&'a V> {
        self.lend::<V>().find(id)
    }

    fn count(&self) -> usize {
        self.lend::<V>().count()
    }

    fn into_entries(self) -> impl Iterator<Item = (u64, &'a V)> + 'a {
        self.lend::<V>().into_entries()
    }

    fn refusals(&self) -> u32 {
        self.lend::<V>().refusals()
    }
}

/// A [`PooledIdMap`] lent its owner's space, to bind and unbind ([`PooledIdMap::lend`]): the lent
/// backing of [`IdMap`].
pub struct LentIds<'a, V, const N: usize> {
    rows: crate::row_pool::LentRows<'a, crate::row_pool::Keyed<V>, N>,
    refused: &'a mut u32,
    high: &'a mut crate::pool_gauge::HighWater,
}

impl<V, const N: usize> IdMap<V> for LentIds<'_, V, N> {
    fn find(&self, id: u64) -> Option<&V> {
        self.rows.get_id(id)
    }

    fn find_mut(&mut self, id: u64) -> Option<&mut V> {
        self.rows.get_id_mut(id)
    }

    fn bind(&mut self, id: u64, value: V) -> Result<Option<V>, CapacityFull<V>> {
        self.bind_within(id, value, |_| true)
    }

    fn bind_within<F: FnOnce(usize) -> bool>(
        &mut self,
        id: u64,
        value: V,
        admits: F,
    ) -> Result<Option<V>, CapacityFull<V>> {
        if let Some(held) = self.rows.get_id_mut(id) {
            return Ok(Some(core::mem::replace(held, value)));
        }
        if !admits(self.rows.len().saturating_add(1)) {
            self.count_refused();
            return Err(CapacityFull(value));
        }
        match self.rows.push((id, value)) {
            Ok(()) => {
                self.high.note(self.rows.len());
                Ok(None)
            }
            Err(CapacityFull((_, value))) => {
                self.count_refused();
                Err(CapacityFull(value))
            }
        }
    }

    fn unbind(&mut self, id: u64) -> Option<V> {
        self.rows.remove_id(id)
    }

    fn reset(&mut self) {
        self.rows.clear();
    }

    fn count(&self) -> usize {
        self.rows.len()
    }

    fn entries<'b>(&'b self) -> impl Iterator<Item = (u64, &'b V)>
    where
        V: 'b,
    {
        self.rows.iter()
    }

    fn refusals(&self) -> u32 {
        *self.refused
    }

    fn count_refused(&mut self) {
        *self.refused = self.refused.saturating_add(1);
    }
}

/// A [`PooledIdMap`] lent its owner's space, to read ([`PooledIdMap::lend_ref`]).
pub struct LentIdsRef<'a, V, const N: usize> {
    rows: crate::row_pool::LentRowsRef<'a, crate::row_pool::Keyed<V>, N>,
    refused: u32,
}

impl<V, const N: usize> Clone for LentIdsRef<'_, V, N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V, const N: usize> Copy for LentIdsRef<'_, V, N> {}

impl<'a, V: 'a, const N: usize> IdRead<'a, V> for LentIdsRef<'a, V, N> {
    fn find(&self, id: u64) -> Option<&'a V> {
        self.rows.get_id(id)
    }

    fn count(&self) -> usize {
        self.rows.len()
    }

    fn into_entries(self) -> impl Iterator<Item = (u64, &'a V)> + 'a {
        self.rows.iter()
    }

    fn refusals(&self) -> u32 {
        self.refused
    }
}

/// The growable backing of [`IdMap`]: the `hashbrown` map the registries always
/// held, whose room refuses nothing, and the count of the NEW ids a bound refused
/// ([`IdMap::bind_within`]). The count is the table's own for the reason
/// [`FixedIdMap`]'s is: a refusal is counted where it is made, whichever refused.
#[cfg(feature = "alloc")]
pub struct GrowableIdMap<V> {
    map: HashMap<u64, V>,
    refused: u32,
}

#[cfg(feature = "alloc")]
impl<V> GrowableIdMap<V> {
    /// An empty table.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            refused: 0,
        }
    }

    /// The bindings as the map holds them, for a reader that takes the map itself.
    pub fn as_map(&self) -> &HashMap<u64, V> {
        &self.map
    }
}

#[cfg(feature = "alloc")]
impl<V> Default for GrowableIdMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "alloc")]
impl<V> IdMap<V> for GrowableIdMap<V> {
    fn find(&self, id: u64) -> Option<&V> {
        self.map.get(&id)
    }

    fn find_mut(&mut self, id: u64) -> Option<&mut V> {
        self.map.get_mut(&id)
    }

    fn bind(&mut self, id: u64, value: V) -> Result<Option<V>, CapacityFull<V>> {
        Ok(self.map.insert(id, value))
    }

    fn bind_within<F: FnOnce(usize) -> bool>(
        &mut self,
        id: u64,
        value: V,
        admits: F,
    ) -> Result<Option<V>, CapacityFull<V>> {
        if let Some(held) = self.map.get_mut(&id) {
            return Ok(Some(core::mem::replace(held, value)));
        }
        if !admits(self.map.len().saturating_add(1)) {
            self.refused = self.refused.saturating_add(1);
            return Err(CapacityFull(value));
        }
        self.map.insert(id, value);
        Ok(None)
    }

    fn unbind(&mut self, id: u64) -> Option<V> {
        self.map.remove(&id)
    }

    fn reset(&mut self) {
        self.map.clear();
    }

    fn count(&self) -> usize {
        self.map.len()
    }

    fn entries<'a>(&'a self) -> impl Iterator<Item = (u64, &'a V)>
    where
        V: 'a,
    {
        self.map.iter().map(|(k, v)| (*k, v))
    }

    fn refusals(&self) -> u32 {
        self.refused
    }

    fn count_refused(&mut self) {
        self.refused = self.refused.saturating_add(1);
    }
}

/// A keyexpr as a peer's table holds it, in the storage policy `P` ([`Storage::Key`]): a
/// `String` on the growable policy, a buffer of [`caps::MAX_KEYEXPR_BYTES`] bytes on the
/// static one, and the place of a block of the session's key arena on the lent one.
pub type KeyText<P = Profile> = <P as Storage>::Key;

/// A keyexpr the peer named is longer than [`caps::MAX_KEYEXPR_BYTES`], which a
/// table of the static policy cannot hold ([`key_text`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyexprTooLong;

/// `literal` as a table of policy `P` keeps it, made in `keys`, or why it is not kept: longer
/// than a row holds, or no room where the policy keeps its keys. The caller drops the
/// declaration, as it drops one the table has no room for.
pub fn key_text_as<P: Storage>(keys: &P::Keys, literal: &str) -> Result<KeyText<P>, KeyUnkept> {
    keys.key(literal)
}

/// [`key_text_as`] held to `quota`, the session's `MAX_KEYEXPR_BYTES`: a keyexpr
/// longer than the quota admits is refused as one the table cannot hold, on every
/// policy, before any room is asked for. Where the build fixes the bound to the rows'
/// capacity the quota compares nothing and the rows refuse alone.
#[inline]
pub fn key_text_within<P: Storage>(
    keys: &P::Keys,
    literal: &str,
    quota: crate::limits::MaxKeyexprBytesHeld,
) -> Result<KeyText<P>, KeyUnkept> {
    if !quota.admits(literal.len()) {
        return Err(KeyUnkept::TooLong);
    }
    key_text_as::<P>(keys, literal)
}

/// [`key_text_as`] in this build's storage profile, whose keys are their own text.
pub fn key_text(literal: &str) -> Result<KeyText, KeyexprTooLong> {
    key_text_as::<Profile>(&Default::default(), literal).map_err(|_| KeyexprTooLong)
}

/// The peer's keyexpr aliases: `DeclKexpr.id -> keyexpr`, at most
/// [`caps::MAX_PEER_KEYEXPR_ALIASES`] where the policy enforces a capacity.
pub type PeerAliases<P = Profile> =
    <P as Storage>::Ids<KeyText<P>, { caps::MAX_PEER_KEYEXPR_ALIASES }>;

/// The keyexprs the peer declared a subscriber, or a token, on: `id -> keyexpr`,
/// at most [`caps::MAX_REMOTE_DECLS`] where the policy enforces a capacity.
pub type DeclaredKeys<P = Profile> = <P as Storage>::Ids<KeyText<P>, { caps::MAX_REMOTE_DECLS }>;

/// What a peer's `DeclQueryable` is remembered as, in a table that holds one per
/// id: the keyexpr it answers on and whether it answers for it completely.
pub struct DeclaredQueryable<P: Storage = Profile> {
    /// The keyexpr the peer declared the queryable on, resolved.
    pub keyexpr: KeyText<P>,
    /// Whether the peer declared it `complete`.
    pub complete: bool,
}

/// The queryables the peer declared: `id -> (keyexpr, complete)`, at most
/// [`caps::MAX_REMOTE_DECLS`] where the policy enforces a capacity.
pub type DeclaredQueryables<P = Profile> =
    <P as Storage>::Ids<DeclaredQueryable<P>, { caps::MAX_REMOTE_DECLS }>;

/// The declarations of one peer that name a keyexpr the peer had already declared:
/// `{id -> the id the application was told the keyexpr under}`. A handful at most (a peer says
/// one entity twice, as an announcement and as the answer to an interest), so a vector read in
/// order is all it is: a tree would cost the binary of every build that holds a registry more
/// than it saves, which is measured (`capability_cost_gate.py`).
///
/// Every alias is an id the peer's table of declarations holds, so a policy that bounds that
/// table at [`caps::MAX_REMOTE_DECLS`] bounds this one there too: the rows are the policy's
/// sequence of a peer's rows (`Storage::Pooled`), inline on the static policy, in a pool the
/// session's faces share on the lent one and taken at the first alias on the on-use one, as the
/// peer's id tables are.
#[cfg(feature = "alloc")]
pub struct DeclaredAliases<P: Storage = Profile>(AliasRows<P>);

#[cfg(feature = "alloc")]
impl<P: Storage> Default for DeclaredAliases<P> {
    fn default() -> Self {
        Self(Default::default())
    }
}

#[cfg(all(feature = "alloc", feature = "peer-row-pools"))]
impl DeclaredAliases<crate::bounded::Lent> {
    /// Record the aliases that come from here on in rows of `space`, the session's. Aliases held in
    /// a space of the same form keep their rows; their owner gives back the ones held in a space of
    /// another form first ([`LentAliases::clear`]), as only that space reaches them.
    pub fn attach(&mut self, space: &crate::row_pool::RowSpace<crate::row_pool::Seq<(u64, u64)>>) {
        self.0.attach(space);
    }
}

#[cfg(feature = "alloc")]
impl DeclaredAliases<Static> {
    /// No aliases, of the static policy. `const`, so a session slot that holds one can be a
    /// `static`.
    pub const fn new_static() -> Self {
        Self(BoundedVec::new_static())
    }
}

#[cfg(feature = "alloc")]
impl<P: Storage> DeclaredAliases<P> {
    /// The aliases lent `keys` for their slot `slot`, to record and forget.
    ///
    /// # Safety
    /// As [`crate::row_pool::PeerSeq::lend`]'s: `keys` is the handle of the owner that holds these
    /// aliases, and `slot` the one it attached their rows to.
    #[inline]
    pub unsafe fn lend<'a>(
        &'a mut self,
        keys: &'a P::Keys,
        slot: crate::row_pool::PeerSlot,
    ) -> LentAliases<'a, P> {
        // SAFETY: the caller's contract.
        LentAliases(unsafe { crate::row_pool::PeerSeq::lend(&mut self.0, keys, slot) })
    }

    /// The aliases lent `keys` for their slot `slot`, to read.
    ///
    /// # Safety
    /// As [`Self::lend`]'s.
    #[inline]
    pub unsafe fn lend_ref<'a>(
        &'a self,
        keys: &'a P::Keys,
        slot: crate::row_pool::PeerSlot,
    ) -> LentAliasesRef<'a, P> {
        // SAFETY: the caller's contract.
        LentAliasesRef(unsafe { crate::row_pool::PeerSeq::lend_ref(&self.0, keys, slot) })
    }

    /// Give every row the aliases hold in the space `keys` names for `slot` back, through it: what
    /// their owner does before it changes its keys or goes. Aliases that keep their rows themselves
    /// keep them.
    ///
    /// # Safety
    /// As [`Self::lend`]'s.
    #[inline]
    pub unsafe fn release(&mut self, keys: &P::Keys, slot: crate::row_pool::PeerSlot) {
        // SAFETY: the caller's contract.
        unsafe { crate::row_pool::PeerSeq::release(&mut self.0, keys, slot) }
    }
}

/// The rows of [`DeclaredAliases`]: the policy's sequence of a peer's rows.
#[cfg(feature = "alloc")]
type AliasRows<P> = <P as Storage>::Pooled<(u64, u64), { caps::MAX_REMOTE_DECLS }>;

/// [`DeclaredAliases`] lent its owner's handle, to record and forget ([`DeclaredAliases::lend`]).
#[cfg(feature = "alloc")]
pub struct LentAliases<'a, P: Storage>(
    <AliasRows<P> as crate::row_pool::PeerSeq<(u64, u64), P::Keys>>::Mut<'a>,
);

/// [`DeclaredAliases`] lent its owner's handle, to read ([`DeclaredAliases::lend_ref`]).
#[cfg(feature = "alloc")]
pub struct LentAliasesRef<'a, P: Storage>(
    <AliasRows<P> as crate::row_pool::PeerSeq<(u64, u64), P::Keys>>::Ref<'a>,
);

/// The id the alias `id` stood for among `rows`, if `id` is one.
#[cfg(feature = "alloc")]
fn told_among<'r>(mut rows: impl Iterator<Item = &'r (u64, u64)>, id: u64) -> Option<u64> {
    rows.find(|(held, _)| *held == id).map(|(_, told)| *told)
}

#[cfg(feature = "alloc")]
impl<P: Storage> LentAliases<'_, P> {
    /// The id the application was told the keyexpr of `id` under, if `id` is an alias.
    pub fn told_as(&self, id: u64) -> Option<u64> {
        told_among(RowList::iter(&self.0), id)
    }

    /// Record that `id` repeats a keyexpr the application was told under `told`.
    pub fn insert(&mut self, id: u64, told: u64) {
        // The search's borrow ends with its statement: the iterator of a pooled list is a value
        // whose drop would hold the list through the arms of a `match` on it.
        let held = RowList::iter_mut(&mut self.0).find(|(held, _)| *held == id);
        if let Some(row) = held {
            row.1 = told;
            return;
        }
        let kept = RowList::push(&mut self.0, (id, told));
        debug_assert!(
            kept.is_ok(),
            "an alias is an id of the peer's declarations, which hold no more"
        );
    }

    /// Forget `id`, returning the id it stood for if it was an alias.
    pub fn remove(&mut self, id: u64) -> Option<u64> {
        RowList::remove_first(&mut self.0, |(held, _)| *held == id).map(|(_, told)| told)
    }

    /// Forget every alias, each row given back.
    pub fn clear(&mut self) {
        RowList::clear(&mut self.0);
    }

    /// Take the memory of the aliases' rows now, where they take it at their first alias:
    /// `false` where the allocator refuses it. Asked before a repeat is bound, so a repeat whose
    /// alias would find no row is refused before anything of it is kept.
    pub fn take_rows(&mut self) -> bool {
        RowList::take_rows(&mut self.0)
    }
}

#[cfg(feature = "alloc")]
impl<P: Storage> LentAliasesRef<'_, P> {
    /// The id the application was told the keyexpr of `id` under, if `id` is an alias.
    pub fn told_as(&self, id: u64) -> Option<u64> {
        told_among(crate::row_pool::RowRead::into_rows(self.0), id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps;

    /// The aliases of the static policy are inline, as many as the peer's declarations hold:
    /// each of `MAX_REMOTE_DECLS` is kept, a repeat rebinds its row, and an id is forgotten by
    /// itself.
    #[cfg(feature = "alloc")]
    #[test]
    fn static_aliases_hold_as_many_as_the_declarations() {
        use crate::row_pool::PeerSlot;
        let ids = caps::MAX_REMOTE_DECLS as u64;
        let mut table = DeclaredAliases::<Static>::new_static();
        let keys = crate::bounded::InlineKeys;
        {
            // SAFETY: the static policy keeps its rows itself and is lent no space.
            let mut aliases = unsafe { table.lend(&keys, PeerSlot::SubRepeats) };
            for id in 0..ids {
                aliases.insert(id, id + 100);
            }
            assert_eq!(aliases.told_as(0), Some(100));
            assert_eq!(
                aliases.told_as(ids - 1),
                Some(ids + 99),
                "the last one is kept"
            );
            aliases.insert(0, 7);
            assert_eq!(aliases.told_as(0), Some(7), "a repeat rebinds its row");
            assert_eq!(aliases.remove(0), Some(7));
            assert_eq!(aliases.told_as(0), None);
        }
        // SAFETY: as above.
        let read = unsafe { table.lend_ref(&keys, PeerSlot::SubRepeats) };
        assert_eq!(
            read.told_as(1),
            Some(101),
            "a reader sees what was recorded"
        );
        // SAFETY: as above.
        unsafe { table.lend(&keys, PeerSlot::SubRepeats) }.clear();
        // SAFETY: as above.
        let read = unsafe { table.lend_ref(&keys, PeerSlot::SubRepeats) };
        assert_eq!(read.told_as(1), None);
    }

    /// One block of an arena's memory in a test, aligned as an arena's spans start.
    #[derive(Clone, Copy)]
    #[repr(C, align(16))]
    struct Block {
        _bytes: [u8; crate::bounded::ARENA_ALIGN],
    }

    /// An arena over `bytes` bytes of memory the test process leaks, so it outlives every row.
    fn arena_of(bytes: usize) -> crate::bounded::Arena {
        use crate::bounded::{Arena, ARENA_ALIGN};
        let blocks = bytes.div_ceil(ARENA_ALIGN).max(1);
        let region: &'static mut [Block] =
            std::vec![Block { _bytes: [0; ARENA_ALIGN] }; blocks].leak();
        // SAFETY: the region is aligned to `ARENA_ALIGN`, holds at least `bytes` bytes, and is
        // leaked, so nothing else uses it and it outlives every row.
        unsafe { Arena::over(core::ptr::NonNull::from(region).cast::<u8>(), bytes) }
    }

    /// A shared pool of `rows` rows of `K`, lent from an arena of its own.
    fn pool_of<K: crate::row_pool::RowKind>(rows: usize) -> crate::row_pool::RowPool<K> {
        let bytes = crate::row_pool::RowSpace::<K>::pool_bytes(rows).expect("a test pool fits");
        arena_of(bytes)
            .lend_pool(rows)
            .expect("the arena is the pool's span")
    }

    /// Where one table keeps `rows` rows of `K`: a shared pool's, or with `own` a span of the
    /// table's own.
    fn space_of<K: crate::row_pool::RowKind>(
        rows: usize,
        own: bool,
    ) -> crate::row_pool::RowSpace<K> {
        use crate::bounded::Arena;
        use crate::row_pool::RowSpace;
        if !own {
            return pool_of::<K>(rows).space();
        }
        let bytes = Arena::span(RowSpace::<K>::own_bytes(rows).expect("fits")).expect("fits");
        arena_of(bytes)
            .lend_own(rows)
            .expect("the arena is the span")
    }

    /// Without `peer-row-pools` the aliases of a peer whose tables are lent are inline as the static
    /// policy's: they take an alias with no arena having lent them a row.
    #[cfg(all(feature = "alloc", not(feature = "peer-row-pools")))]
    #[test]
    fn lent_aliases_need_no_arena_without_pools() {
        let mut table = DeclaredAliases::<crate::bounded::Lent>::default();
        let keys = crate::key_arena::LentKeys::default();
        // SAFETY: without `peer-row-pools` the aliases keep their rows inline: no space is lent.
        let mut aliases = unsafe { table.lend(&keys, crate::row_pool::PeerSlot::SubRepeats) };
        aliases.insert(3, 1);
        assert_eq!(aliases.told_as(3), Some(1));
        assert_eq!(aliases.remove(3), Some(1));
    }

    /// The aliases of a peer whose tables are lent keep their rows in the session's pool: one is
    /// recorded, read and forgotten there, and its row goes back with it.
    #[cfg(all(feature = "alloc", feature = "peer-row-pools"))]
    #[test]
    fn lent_aliases_keep_their_rows_in_the_sessions_pool() {
        let pool = pool_of::<crate::row_pool::Seq<(u64, u64)>>(2);
        let space = pool.space();
        let mut table = DeclaredAliases::<crate::bounded::Lent>::default();
        table.attach(&space);
        // SAFETY: the aliases were just attached to `space`, the one space this test lends them.
        let mut aliases = LentAliases::<crate::bounded::Lent>(unsafe { table.0.lend(&space) });
        aliases.insert(3, 1);
        aliases.insert(3, 2);
        assert_eq!(aliases.told_as(3), Some(2), "a repeat rebinds its row");
        assert_eq!(pool.counts().used, 1, "in one row of the pool");
        assert_eq!(aliases.remove(3), Some(2));
        assert_eq!(pool.counts().used, 0, "the row went back");
    }

    /// `table` attached to `space` and lent it: the one place these tests pair a table with its
    /// space.
    fn lent_ids<'a, V, const N: usize>(
        table: &'a mut PooledIdMap<V, N>,
        space: &crate::row_pool::RowSpace<crate::row_pool::Keyed<V>>,
    ) -> LentIds<'a, V, N> {
        table.attach(space);
        // SAFETY: the table was just attached to `space`, and each test lends every table the one
        // space it attached it to.
        unsafe { table.lend(space) }
    }

    /// A lent table refuses a NEW id as a fixed one of its capacity does, and as one whose pool
    /// has no row left: handed back and counted, by the table and by the pool, what it held kept.
    #[test]
    fn a_pooled_table_refuses_past_its_bound_and_past_its_pool() {
        let pool = pool_of::<crate::row_pool::Keyed<u32>>(3);
        let space = pool.space();
        let (mut table, mut other): (PooledIdMap<u32, 2>, PooledIdMap<u32, 2>) =
            (PooledIdMap::new(), PooledIdMap::new());
        {
            let mut table = lent_ids(&mut table, &space);
            assert!(table.bind(1, 10).is_ok() && table.bind(2, 20).is_ok());
            assert_eq!(
                (table.bind(3, 30).err().map(|c| c.0), table.refusals()),
                (Some(30), 1),
                "the table's own bound"
            );
        }
        assert_eq!(pool.counts().refused, 0, "the pool had a row left");
        {
            let mut other = lent_ids(&mut other, &space);
            assert!(other.bind(7, 70).is_ok(), "the pool's last row");
            assert_eq!(
                (
                    other.bind(8, 80).err().map(|c| c.0),
                    other.refusals(),
                    pool.counts().refused
                ),
                (Some(80), 1, 1),
                "(value handed back, the table's count, the pool's count)"
            );
            assert_eq!(
                other.bind(7, 71).ok(),
                Some(Some(70)),
                "a held id needs no row"
            );
        }
        {
            let mut table = lent_ids(&mut table, &space);
            assert_eq!(table.find(2), Some(&20));
            assert_eq!(table.unbind(1), Some(10));
        }
        {
            let mut other = lent_ids(&mut other, &space);
            assert!(other.bind(8, 80).is_ok(), "the row table gave back");
            assert_eq!(
                other.entries().collect::<std::vec::Vec<_>>(),
                [(7, &71), (8, &80)],
                "in the order bound"
            );
            other.reset();
        }
        lent_ids(&mut table, &space).reset();
        assert_eq!(pool.counts().used, 0, "a reset gives back every row");
        assert_eq!(
            (table.refusals(), other.refusals()),
            (1, 1),
            "and keeps the counts, read off the heads"
        );
    }

    /// A table split off a pooled one holds its ids in the order they were bound and keeps their
    /// rows in the pool; the table it came from holds none and binds new ids in rows of the same
    /// pool. A table of a span of its own is not split, and keeps what it holds.
    #[test]
    fn a_split_off_table_keeps_its_rows_in_the_pool() {
        let pool = pool_of::<crate::row_pool::Keyed<u32>>(3);
        let space = pool.space();
        let mut table: PooledIdMap<u32, 3> = PooledIdMap::new();
        {
            let mut table = lent_ids(&mut table, &space);
            assert!(table.bind(2, 20).is_ok() && table.bind(1, 10).is_ok());
        }
        let mut owed = table.split_off().expect("a pooled table is split");
        {
            let mut owed = lent_ids(&mut owed, &space);
            assert_eq!(
                owed.entries().collect::<std::vec::Vec<_>>(),
                [(2, &20), (1, &10)],
                "in the order bound"
            );
            assert_eq!(owed.unbind(1), Some(10));
        }
        assert_eq!(table.count(), 0, "the table it came from holds none");
        assert_eq!(pool.counts().used, 1, "the rows stay in the pool");
        assert!(
            lent_ids(&mut table, &space).bind(5, 50).is_ok(),
            "and it binds in the same pool"
        );
        assert_eq!(pool.counts().used, 2);
        lent_ids(&mut owed, &space).reset();
        lent_ids(&mut table, &space).reset();
        assert_eq!(pool.counts().used, 0, "each gives back its own rows");
        let own_space = space_of::<crate::row_pool::Keyed<u32>>(3, true);
        let mut own: PooledIdMap<u32, 3> = PooledIdMap::new();
        assert!(lent_ids(&mut own, &own_space).bind(1, 10).is_ok());
        assert!(own.split_off().is_none(), "a span of its own is not split");
        assert_eq!(
            lent_ids(&mut own, &own_space).find(1),
            Some(&10),
            "and keeps what it holds"
        );
    }

    /// A lent table made by `Default` holds no space and refuses every new id, counted, whatever
    /// space it is lent.
    #[test]
    fn a_pooled_table_handed_no_pool_refuses_and_counts() {
        let pool = pool_of::<crate::row_pool::Keyed<u32>>(2);
        let mut table: PooledIdMap<u32, 4> = PooledIdMap::default();
        for space in [crate::row_pool::RowSpace::none(), pool.space()] {
            // SAFETY: a table attached to no space holds no row in any; it is lent one to be
            // refused.
            assert!(unsafe { table.lend(&space) }.bind(1, 10).is_err());
        }
        assert_eq!(
            (table.count(), table.refusals(), pool.counts().used),
            (0, 2, 0)
        );
    }

    /// The lent backing refuses under a bound as the fixed one does, in a shared pool and in a
    /// span of its own.
    #[test]
    fn a_bound_refuses_a_new_id_on_the_lent_backing() {
        for own in [false, true] {
            let space = space_of::<crate::row_pool::Keyed<u32>>(4, own);
            let mut table: PooledIdMap<u32, 4> = PooledIdMap::new();
            {
                let lent = lent_ids(&mut table, &space);
                a_bound_refuses_a_new_id_as_a_full_table_does_in(move || lent);
            }
        }
    }

    /// A lent table and its rows in a span of its own take no more than the inline table of the
    /// same rows, on every target: the rows are the inline table's `(id, value)`, byte for byte,
    /// and the head is two `u16`s and the `u32` count of refusals the inline table keeps, 8 bytes,
    /// which is the least room the inline table keeps beside its rows (a length and that count,
    /// on i386 System V, where a `u64` aligns to 4). The head holds no pointer: its owner holds the
    /// space once.
    #[cfg(not(feature = "pool-monitor"))]
    #[test]
    fn a_lent_table_of_its_own_span_is_no_larger_than_the_inline_table() {
        use crate::key_arena::KeyRef;
        use crate::row_pool::{Keyed, RowSpace};
        use core::mem::size_of;
        const N: usize = 16;
        assert_eq!(
            size_of::<PooledIdMap<KeyRef, N>>(),
            size_of::<(u16, u16, u32)>(),
            "the head is two counters and the count of refusals"
        );
        assert_eq!(
            RowSpace::<Keyed<KeyRef>>::own_bytes(N),
            Some(N * size_of::<(u64, KeyRef)>()),
            "the rows are the inline table's, byte for byte"
        );
        let lent = size_of::<PooledIdMap<KeyRef, N>>()
            + RowSpace::<Keyed<KeyRef>>::own_bytes(N).expect("fits");
        assert!(
            lent <= size_of::<FixedIdMap<KeyRef, N>>(),
            "{lent} against {}",
            size_of::<FixedIdMap<KeyRef, N>>()
        );
    }

    fn fill(table: &mut FixedIdMap<u32, 3>, from: u64, to: u64) {
        for id in from..to {
            assert!(table.bind(id, id as u32).is_ok(), "id {id} fits");
        }
    }

    #[test]
    fn a_new_id_past_the_capacity_is_refused_counted_and_handed_back() {
        let mut table: FixedIdMap<u32, 3> = FixedIdMap::new();
        fill(&mut table, 1, 4);
        let refused = table.bind(9, 90);
        assert_eq!(
            (refused.err().map(|c| c.0), table.count(), table.refusals()),
            (Some(90), 3, 1),
            "(value handed back, rows held, refusals counted)"
        );
        let again = table.bind(10, 100);
        assert_eq!((again.is_err(), table.refusals()), (true, 2));
        // What it held is untouched by the refusals.
        assert_eq!(
            table
                .entries()
                .map(|(id, _)| id)
                .collect::<heapless::Vec<_, 3>>(),
            heapless::Vec::<u64, 3>::from_slice(&[1, 2, 3]).unwrap()
        );
    }

    #[test]
    fn rebinding_a_held_id_replaces_it_and_needs_no_room() {
        let mut table: FixedIdMap<u32, 3> = FixedIdMap::new();
        fill(&mut table, 1, 4);
        assert_eq!(table.bind(2, 200).ok(), Some(Some(2)));
        assert_eq!(table.find(2), Some(&200));
        assert_eq!((table.count(), table.refusals()), (3, 0));
    }

    #[test]
    fn unbinding_makes_room_and_keeps_the_count_of_what_was_refused() {
        let mut table: FixedIdMap<u32, 2> = FixedIdMap::new();
        assert!(table.bind(1, 1).is_ok() && table.bind(2, 2).is_ok());
        assert!(table.bind(3, 3).is_err());
        assert_eq!(table.unbind(1), Some(1));
        assert_eq!(table.unbind(1), None, "double unbind is a no-op");
        assert!(table.bind(3, 3).is_ok());
        assert_eq!((table.find(2), table.find(3)), (Some(&2), Some(&3)));
        table.reset();
        assert_eq!((table.count(), table.refusals()), (0, 1));
        assert!(!table.is_bound());
    }

    /// The on-use table of a peer's ids takes its rows at its first id, and lent its owner's handle
    /// a NEW id takes a row of the slot's kind from the session's budget: two faces' tables hold
    /// the session's bound together, a refused id takes nothing, a replaced id needs no row, and an
    /// id let go of or a table released gives its row back. Turned red by a bind that asks no row of
    /// the budget, by an unbind, a reset or a release that gives none back, or by a table that takes
    /// its rows when made.
    #[cfg(feature = "alloc")]
    #[test]
    fn an_on_use_table_holds_its_faces_ids_to_the_sessions_bound_together() {
        use crate::limit_binding::{LimitSpec, Quota};
        use crate::limits::SessionLimits;
        use crate::on_use::{BudgetKeys, KeyBudget};
        use crate::row_pool::PeerSlot;

        let mut limits = SessionLimits::defaults();
        if limits
            .select_session_max_remote_decls(Quota::at_most(2))
            .is_err()
        {
            assert!(
                <crate::limits::SessionMaxRemoteDecls as LimitSpec>::DOMAIN.is_singleton(),
                "only a domain of one value refuses a lower bound"
            );
            return;
        }
        let budget =
            KeyBudget::new(0, limits.max_keyexpr_bytes_held()).holding_peer_rows_to(&limits);
        // SAFETY: the budget outlives the handle and every table lent it, all of this test's.
        let keys = unsafe { budget.keys() };
        let slot = PeerSlot::Subscribers;
        let mut first: CountedIdMap<u32, 4> = CountedIdMap::new();
        let mut second: CountedIdMap<u32, 4> = CountedIdMap::new();
        assert!(
            !first.holds_rows() && first.capacity() == 4,
            "CONTROL: a table made takes nothing and is counted to N"
        );
        // SAFETY: each table is lent the one handle and slot it is counted in.
        unsafe {
            let mut lent = PeerIds::<u32, BudgetKeys>::lend(&mut first, &keys, slot);
            assert!(lent.bind(1, 10).is_ok() && lent.bind(2, 20).is_ok());
            assert_eq!(
                lent.bind(1, 11).ok(),
                Some(Some(10)),
                "a replaced id needs no row"
            );
        }
        assert!(first.holds_rows());
        assert_eq!(budget.peer_rows(slot), 2);
        // SAFETY: as above.
        unsafe {
            let mut lent = PeerIds::<u32, BudgetKeys>::lend(&mut second, &keys, slot);
            assert!(
                lent.bind(7, 70).is_err(),
                "the second face's first id is past the session's two"
            );
            assert_eq!(lent.refusals(), 1);
        }
        assert!(!second.holds_rows(), "the refusal took nothing");
        // SAFETY: as above.
        unsafe {
            assert_eq!(
                PeerIds::<u32, BudgetKeys>::lend(&mut first, &keys, slot).unbind(2),
                Some(20)
            );
            assert_eq!(
                budget.peer_rows(slot),
                1,
                "the id let go of gave its row back"
            );
            assert!(PeerIds::<u32, BudgetKeys>::lend(&mut second, &keys, slot)
                .bind(7, 70)
                .is_ok());
            PeerIds::<u32, BudgetKeys>::release(&mut first, &keys, slot);
        }
        assert_eq!(
            budget.peer_rows(slot),
            1,
            "the released table gave its row back, the other's stays"
        );
        // SAFETY: as above.
        let read = unsafe { PeerIds::<u32, BudgetKeys>::lend_ref(&second, &keys, slot) };
        assert_eq!((read.find(7), read.count()), (Some(&70), 1));
        let none = BudgetKeys::default();
        let mut own: CountedIdMap<u32, 1> = CountedIdMap::new();
        // SAFETY: a handle of no budget names no space; the table is lent it alone.
        unsafe {
            let mut lent = PeerIds::<u32, BudgetKeys>::lend(&mut own, &none, slot);
            assert!(lent.bind(1, 1).is_ok());
            assert!(
                lent.bind(2, 2).is_err(),
                "a table is held to its own count too"
            );
        }
    }

    /// The on-use table of a peer's ids is counted anew while it holds no id, giving back the
    /// rows it took, and keeps its count while it holds one. Turned red by a recount of a table
    /// that holds ids (its rows would go with them), or by one that keeps the rows it took.
    #[cfg(feature = "alloc")]
    #[test]
    fn an_on_use_table_is_recounted_only_while_it_holds_no_id() {
        use crate::on_use::BudgetKeys;
        use crate::row_pool::PeerSlot;

        let none = BudgetKeys::default();
        let slot = PeerSlot::Aliases;
        let mut table: CountedIdMap<u32, 2> = CountedIdMap::new();
        assert!(PeerIds::<u32, BudgetKeys>::recount(&mut table, 5));
        assert_eq!(table.capacity(), 5, "counted past the build's N");
        // SAFETY: a handle of no budget names no space; the table is lent it alone.
        unsafe {
            let mut lent = PeerIds::<u32, BudgetKeys>::lend(&mut table, &none, slot);
            for id in 0..5 {
                assert!(lent.bind(id, 0).is_ok());
            }
            assert!(lent.bind(5, 0).is_err());
        }
        assert!(
            !PeerIds::<u32, BudgetKeys>::recount(&mut table, 1),
            "a table that holds ids keeps its count"
        );
        assert_eq!(table.capacity(), 5);
        // SAFETY: as above.
        unsafe { PeerIds::<u32, BudgetKeys>::lend(&mut table, &none, slot).reset() };
        assert!(
            table.holds_rows(),
            "CONTROL: emptied, the rows are still taken"
        );
        assert!(PeerIds::<u32, BudgetKeys>::recount(&mut table, 1));
        assert!(!table.holds_rows(), "a recount gives the rows back");
        assert_eq!(table.capacity(), 1);
        let mut fixed: FixedIdMap<u32, 2> = FixedIdMap::new();
        assert!(
            !PeerIds::<u32, BudgetKeys>::recount(&mut fixed, 5),
            "a table of a fixed capacity has no count to change"
        );
    }

    /// The table answers as a pool: its capacity and holdings, the refusals it counted, and the
    /// most it has held, which stays when ids leave.
    #[test]
    fn the_fixed_table_says_its_state_as_a_pool() {
        use crate::pool_gauge::PoolGauge;
        let mut table: FixedIdMap<u32, 3> = FixedIdMap::new();
        let empty = table.pool_stat("peer-aliases");
        assert_eq!(
            (empty.name, empty.capacity, empty.in_use, empty.refused),
            ("peer-aliases", 3, 0, 0)
        );
        for id in 0..3u64 {
            table.bind(id, 0).unwrap();
        }
        assert!(table.bind(9, 0).is_err());
        table.unbind(0);
        table.unbind(1);
        let stat = table.pool_stat("peer-aliases");
        assert_eq!((stat.in_use, stat.refused), (1, 1));
        let expected_mark = cfg!(feature = "pool-monitor").then_some(3);
        assert_eq!(
            stat.high_water, expected_mark,
            "the mark is the most held, not what is held"
        );
        assert_eq!(
            stat.has_been_full(),
            expected_mark.map(|_| true),
            "it was full once; a build without the mark cannot say so"
        );
    }

    #[test]
    fn a_keyexpr_past_the_text_bound_is_refused_on_the_fixed_backing_only() {
        let long = "k".repeat(caps::MAX_KEYEXPR_BYTES + 1);
        let fits = "k".repeat(caps::MAX_KEYEXPR_BYTES);
        assert!(key_text(&fits).is_ok());
        if crate::bounded::ENFORCES_CAPACITY {
            assert_eq!(key_text(&long).err(), Some(KeyexprTooLong));
        } else {
            assert!(
                key_text(&long).is_ok(),
                "the growable backing refuses nothing"
            );
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn the_growable_backing_refuses_nothing_by_its_room() {
        let mut table: GrowableIdMap<u32> = GrowableIdMap::new();
        for id in 0..64u64 {
            assert!(table.bind(id, 0).is_ok());
        }
        assert_eq!((table.count(), table.refusals()), (64, 0));
        assert_eq!(table.as_map().len(), 64);
    }

    /// Under a bound of two, below the room of either backing: the third NEW id is refused
    /// as a full table refuses one, handed back and counted, and changes nothing held; a held
    /// id is replaced without asking the bound, and a place let go is taken again.
    fn a_bound_refuses_a_new_id_as_a_full_table_does<M: IdMap<u32> + Default>() {
        a_bound_refuses_a_new_id_as_a_full_table_does_in(M::default);
    }

    /// [`a_bound_refuses_a_new_id_as_a_full_table_does`] over the table `make` makes.
    fn a_bound_refuses_a_new_id_as_a_full_table_does_in<M: IdMap<u32>>(make: impl FnOnce() -> M) {
        let mut table = make();
        let two = |count: usize| count <= 2;
        assert!(table.bind_within(1, 10, two).is_ok());
        assert!(table.bind_within(2, 20, two).is_ok());
        let refused = table.bind_within(3, 30, two);
        assert_eq!(
            (refused.err().map(|c| c.0), table.count(), table.refusals()),
            (Some(30), 2, 1),
            "(value handed back, ids held, refusals counted)"
        );
        assert_eq!(table.find(3), None);
        assert_eq!(table.bind_within(2, 200, two).ok(), Some(Some(20)));
        assert_eq!((table.count(), table.refusals()), (2, 1));
        assert_eq!(table.unbind(1), Some(10));
        assert!(table.bind_within(3, 30, two).is_ok());
        assert_eq!((table.count(), table.refusals()), (2, 1));
        table.reset();
        assert_eq!(table.refusals(), 1, "a reset keeps the count");
    }

    #[test]
    fn a_bound_refuses_a_new_id_on_the_fixed_backing() {
        a_bound_refuses_a_new_id_as_a_full_table_does::<FixedIdMap<u32, 4>>();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn a_bound_refuses_a_new_id_on_the_growable_backing() {
        a_bound_refuses_a_new_id_as_a_full_table_does::<GrowableIdMap<u32>>();
    }
}
