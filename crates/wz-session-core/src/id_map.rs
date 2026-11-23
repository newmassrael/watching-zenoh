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
use crate::bounded::{BoundedVec, Static};
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
        if !admits(self.rows.len() + 1) {
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
/// new id until it is handed some ([`Self::keep_rows_in`]). Its refusals are counted in the head
/// of its rows, so the table is a pointer and three counters wherever it lies.
pub struct PooledIdMap<V, const N: usize> {
    rows: crate::row_pool::PooledRows<crate::row_pool::Keyed<V>, N>,
    /// The most ids the table has held: zero-sized unless the build keeps the mark
    /// (`pool-monitor`).
    high: crate::pool_gauge::HighWater,
}

impl<V, const N: usize> PooledIdMap<V, N> {
    /// An empty table with no rows. `const`, as [`FixedIdMap::new`] is.
    pub const fn new() -> Self {
        Self {
            rows: crate::row_pool::PooledRows::new(),
            high: crate::pool_gauge::HighWater::new(),
        }
    }

    /// Bind the ids that come from here on in rows of `space`, the session's. A table that holds
    /// rows of another space forgets them first; the refusals it counted are kept.
    pub fn keep_rows_in(&mut self, space: crate::row_pool::RowSpace<crate::row_pool::Keyed<V>>) {
        self.rows.keep_rows_in(space);
    }

    /// The declared capacity `N`: the most ids the table holds at once, whatever its rows have.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// The ids the table holds, as a table of their own whose rows stay where they lie in the
    /// pool, and this one left holding none and binding ids in rows of the same pool. `None`,
    /// taking nothing, for a table whose rows lie in a span of its own
    /// ([`PooledRows::split_off`](crate::row_pool::PooledRows::split_off)).
    pub fn split_off(&mut self) -> Option<Self> {
        self.rows.split_off().map(|rows| Self {
            rows,
            high: crate::pool_gauge::HighWater::new(),
        })
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
            refused: u64::from(self.rows.refusals()),
        }
    }
}

impl<V, const N: usize> IdMap<V> for PooledIdMap<V, N> {
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
        if let Some(held) = self.find_mut(id) {
            return Ok(Some(core::mem::replace(held, value)));
        }
        if !admits(self.rows.len() + 1) {
            self.rows.count_refused();
            return Err(CapacityFull(value));
        }
        // A refused push is counted by the rows it was refused by.
        match self.rows.push((id, value)) {
            Ok(()) => {
                self.high.note(self.rows.len());
                Ok(None)
            }
            Err(CapacityFull((_, value))) => Err(CapacityFull(value)),
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

    fn entries<'a>(&'a self) -> impl Iterator<Item = (u64, &'a V)>
    where
        V: 'a,
    {
        self.rows.iter()
    }

    fn refusals(&self) -> u32 {
        self.rows.refusals()
    }

    fn count_refused(&mut self) {
        self.rows.count_refused();
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
        if !admits(self.map.len() + 1) {
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
/// sequence of a peer's rows (`Storage::Pooled`), inline on the static policy and in a pool the
/// session's faces share on the lent one, as the peer's id tables are.
#[cfg(feature = "alloc")]
pub struct DeclaredAliases<P: Storage = Profile>(
    <P as Storage>::Pooled<(u64, u64), { caps::MAX_REMOTE_DECLS }>,
);

#[cfg(feature = "alloc")]
impl<P: Storage> Default for DeclaredAliases<P> {
    fn default() -> Self {
        Self(Default::default())
    }
}

#[cfg(all(feature = "alloc", feature = "peer-row-pools"))]
impl DeclaredAliases<crate::bounded::Lent> {
    /// Keep the aliases recorded from here on in rows of `space`, the session's; the ones held go
    /// first, as their rows belong to the space before.
    pub fn keep_rows_in(
        &mut self,
        space: crate::row_pool::RowSpace<crate::row_pool::Seq<(u64, u64)>>,
    ) {
        self.0.keep_rows_in(space);
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
    /// The id the application was told the keyexpr of `id` under, if `id` is an alias.
    pub fn told_as(&self, id: u64) -> Option<u64> {
        RowList::iter(&self.0)
            .find(|(held, _)| *held == id)
            .map(|(_, told)| *told)
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
    /// Forget every alias.
    pub fn clear(&mut self) {
        RowList::clear(&mut self.0);
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
        let ids = caps::MAX_REMOTE_DECLS as u64;
        let mut aliases = DeclaredAliases::<Static>::new_static();
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
        aliases.clear();
        assert_eq!(aliases.told_as(1), None);
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
        let mut aliases = DeclaredAliases::<crate::bounded::Lent>::default();
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
        let mut aliases = DeclaredAliases::<crate::bounded::Lent>::default();
        aliases.keep_rows_in(pool.space());
        aliases.insert(3, 1);
        aliases.insert(3, 2);
        assert_eq!(aliases.told_as(3), Some(2), "a repeat rebinds its row");
        assert_eq!(pool.counts().used, 1, "in one row of the pool");
        assert_eq!(aliases.remove(3), Some(2));
        assert_eq!(pool.counts().used, 0, "the row went back");
    }

    /// A lent table refuses a NEW id as a fixed one of its capacity does, and as one whose pool
    /// has no row left: handed back and counted, by the table and by the pool, what it held kept.
    #[test]
    fn a_pooled_table_refuses_past_its_bound_and_past_its_pool() {
        let pool = pool_of::<crate::row_pool::Keyed<u32>>(3);
        let mut table: PooledIdMap<u32, 2> = PooledIdMap::new();
        table.keep_rows_in(pool.space());
        assert!(table.bind(1, 10).is_ok() && table.bind(2, 20).is_ok());
        assert_eq!(
            (table.bind(3, 30).err().map(|c| c.0), table.refusals()),
            (Some(30), 1),
            "the table's own bound"
        );
        assert_eq!(pool.counts().refused, 0, "the pool had a row left");
        let mut other: PooledIdMap<u32, 2> = PooledIdMap::new();
        other.keep_rows_in(pool.space());
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
        assert_eq!(table.find(2), Some(&20));
        assert_eq!(table.unbind(1), Some(10));
        assert!(other.bind(8, 80).is_ok(), "the row table gave back");
        assert_eq!(
            other.entries().collect::<std::vec::Vec<_>>(),
            [(7, &71), (8, &80)],
            "in the order bound"
        );
        table.reset();
        other.reset();
        assert_eq!(pool.counts().used, 0, "a reset gives back every row");
        assert_eq!(
            (table.refusals(), other.refusals()),
            (1, 1),
            "and keeps the counts"
        );
    }

    /// A table split off a pooled one holds its ids in the order they were bound and keeps their
    /// rows in the pool; the table it came from holds none and binds new ids in rows of the same
    /// pool. A table of a span of its own is not split, and keeps what it holds.
    #[test]
    fn a_split_off_table_keeps_its_rows_in_the_pool() {
        let pool = pool_of::<crate::row_pool::Keyed<u32>>(3);
        let mut table: PooledIdMap<u32, 3> = PooledIdMap::new();
        table.keep_rows_in(pool.space());
        assert!(table.bind(2, 20).is_ok() && table.bind(1, 10).is_ok());
        let mut owed = table.split_off().expect("a pooled table is split");
        assert_eq!(
            owed.entries().collect::<std::vec::Vec<_>>(),
            [(2, &20), (1, &10)],
            "in the order bound"
        );
        assert_eq!(table.count(), 0, "the table it came from holds none");
        assert_eq!(pool.counts().used, 2, "the rows stay in the pool");
        assert!(table.bind(5, 50).is_ok(), "and it binds in the same pool");
        assert_eq!(pool.counts().used, 3);
        assert_eq!(owed.unbind(1), Some(10));
        owed.reset();
        table.reset();
        assert_eq!(pool.counts().used, 0, "each gives back its own rows");
        let mut own: PooledIdMap<u32, 3> = PooledIdMap::new();
        own.keep_rows_in(space_of(3, true));
        assert!(own.bind(1, 10).is_ok());
        assert!(own.split_off().is_none(), "a span of its own is not split");
        assert_eq!(own.find(1), Some(&10), "and keeps what it holds");
    }

    /// A lent table made by `Default` holds no pool and refuses every new id, counted.
    #[test]
    fn a_pooled_table_handed_no_pool_refuses_and_counts() {
        let mut table: PooledIdMap<u32, 4> = PooledIdMap::default();
        assert!(table.bind(1, 10).is_err());
        assert_eq!((table.count(), table.refusals()), (0, 1));
    }

    /// The lent backing refuses under a bound as the fixed one does, in a shared pool and in a
    /// span of its own.
    #[test]
    fn a_bound_refuses_a_new_id_on_the_lent_backing() {
        for own in [false, true] {
            a_bound_refuses_a_new_id_as_a_full_table_does_in(|| {
                let mut table: PooledIdMap<u32, 4> = PooledIdMap::new();
                table.keep_rows_in(space_of(4, own));
                table
            });
        }
    }

    /// A lent table in a span of its own takes no more than the inline table of the same rows:
    /// the rows are the inline table's `(id, value)`, and the head that points at them is the
    /// room the inline table's length and count take.
    #[cfg(not(feature = "pool-monitor"))]
    #[test]
    fn a_lent_table_of_its_own_span_is_no_larger_than_the_inline_table() {
        use crate::key_arena::KeyRef;
        use crate::row_pool::{Keyed, RowSpace};
        const N: usize = 16;
        let lent = core::mem::size_of::<PooledIdMap<KeyRef, N>>()
            + RowSpace::<Keyed<KeyRef>>::own_bytes(N).expect("fits");
        assert!(
            lent <= core::mem::size_of::<FixedIdMap<KeyRef, N>>(),
            "{lent} against {}",
            core::mem::size_of::<FixedIdMap<KeyRef, N>>()
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
