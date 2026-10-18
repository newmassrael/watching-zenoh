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
//! - **growable** (`alloc` on, `bounded-heapless` off: the AP profile) is the
//!   `hashbrown::HashMap` the registries always held.
//!   [`bind`](crate::id_map::IdMap::bind) never refuses and the declared capacity
//!   is advisory.
//! - **fixed** (`alloc` off, or `bounded-heapless` on: the MCU profiles) is a
//!   [`crate::id_map::FixedIdMap`]: `N` rows in an inline array.
//!   [`bind`](crate::id_map::IdMap::bind) of an id the table does not hold, with
//!   the table full, is a typed refusal ([`crate::bounded::CapacityFull`],
//!   carrying the value back), is COUNTED
//!   ([`refusals`](crate::id_map::IdMap::refusals)) and allocates nothing.
//!   Rebinding an id the table already holds replaces it in place and needs no
//!   room, which is what a peer that re-declares an id expects.
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

#[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
use alloc::string::String;
#[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
use hashbrown::HashMap;

#[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
use crate::bounded::BoundedString;
use crate::bounded::CapacityFull;
#[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
use crate::caps;

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

    /// How many NEW ids were refused for want of room since the table was made.
    /// Always zero on the growable backing, where nothing is refused.
    fn refusals(&self) -> u32;

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
}

impl<V, const N: usize> FixedIdMap<V, N> {
    /// An empty table. `const`, so a session slot that holds one can be a
    /// `static`.
    pub const fn new() -> Self {
        Self {
            rows: heapless::Vec::new(),
            refused: 0,
        }
    }

    /// The declared capacity `N`: the most ids the table holds at once.
    pub const fn capacity(&self) -> usize {
        N
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
        if let Some((_, held)) = self.rows.iter_mut().find(|(k, _)| *k == id) {
            return Ok(Some(core::mem::replace(held, value)));
        }
        match self.rows.push((id, value)) {
            Ok(()) => Ok(None),
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
}

#[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
impl<V> IdMap<V> for HashMap<u64, V> {
    fn find(&self, id: u64) -> Option<&V> {
        self.get(&id)
    }

    fn find_mut(&mut self, id: u64) -> Option<&mut V> {
        self.get_mut(&id)
    }

    fn bind(&mut self, id: u64, value: V) -> Result<Option<V>, CapacityFull<V>> {
        Ok(self.insert(id, value))
    }

    fn unbind(&mut self, id: u64) -> Option<V> {
        self.remove(&id)
    }

    fn reset(&mut self) {
        self.clear();
    }

    fn count(&self) -> usize {
        self.len()
    }

    fn entries<'a>(&'a self) -> impl Iterator<Item = (u64, &'a V)>
    where
        V: 'a,
    {
        self.iter().map(|(k, v)| (*k, v))
    }

    fn refusals(&self) -> u32 {
        0
    }
}

/// The text of a keyexpr as a peer's table holds it: a `String` on the growable
/// backing, and a bounded buffer of [`caps::MAX_KEYEXPR_BYTES`] on the fixed one.
#[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
pub type KeyText = String;

/// The text of a keyexpr as a peer's table holds it: a `String` on the growable
/// backing, and a bounded buffer of [`caps::MAX_KEYEXPR_BYTES`] on the fixed one.
#[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
pub type KeyText = BoundedString<{ caps::MAX_KEYEXPR_BYTES }>;

/// A keyexpr the peer named is longer than [`caps::MAX_KEYEXPR_BYTES`], which a
/// fixed table cannot hold. Never answered on the growable backing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyexprTooLong;

/// `literal` as the text a table holds, or [`KeyexprTooLong`] when the fixed
/// backing cannot hold it. The caller drops the declaration, as it drops one the
/// table has no room for.
#[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
pub fn key_text(literal: &str) -> Result<KeyText, KeyexprTooLong> {
    Ok(String::from(literal))
}

/// `literal` as the text a table holds, or [`KeyexprTooLong`] when the fixed
/// backing cannot hold it. The caller drops the declaration, as it drops one the
/// table has no room for.
#[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
pub fn key_text(literal: &str) -> Result<KeyText, KeyexprTooLong> {
    let mut text = KeyText::new();
    text.push_str(literal).map_err(|_| KeyexprTooLong)?;
    Ok(text)
}

/// The peer's keyexpr aliases: `DeclKexpr.id -> keyexpr`, at most
/// [`caps::MAX_PEER_KEYEXPR_ALIASES`] on the fixed backing.
#[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
pub type PeerAliases = HashMap<u64, String>;

/// The peer's keyexpr aliases: `DeclKexpr.id -> keyexpr`, at most
/// [`caps::MAX_PEER_KEYEXPR_ALIASES`] on the fixed backing.
#[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
pub type PeerAliases = FixedIdMap<KeyText, { caps::MAX_PEER_KEYEXPR_ALIASES }>;

/// The keyexprs the peer declared a subscriber, or a token, on: `id -> keyexpr`,
/// at most [`caps::MAX_REMOTE_DECLS`] on the fixed backing.
#[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
pub type DeclaredKeys = HashMap<u64, String>;

/// The keyexprs the peer declared a subscriber, or a token, on: `id -> keyexpr`,
/// at most [`caps::MAX_REMOTE_DECLS`] on the fixed backing.
#[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
pub type DeclaredKeys = FixedIdMap<KeyText, { caps::MAX_REMOTE_DECLS }>;

/// What a peer's `DeclQueryable` is remembered as, in a table that holds one per
/// id: the keyexpr it answers on and whether it answers for it completely.
pub struct DeclaredQueryable {
    /// The keyexpr the peer declared the queryable on, resolved.
    pub keyexpr: KeyText,
    /// Whether the peer declared it `complete`.
    pub complete: bool,
}

/// The queryables the peer declared: `id -> (keyexpr, complete)`, at most
/// [`caps::MAX_REMOTE_DECLS`] on the fixed backing.
#[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
pub type DeclaredQueryables = HashMap<u64, DeclaredQueryable>;

/// The queryables the peer declared: `id -> (keyexpr, complete)`, at most
/// [`caps::MAX_REMOTE_DECLS`] on the fixed backing.
#[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
pub type DeclaredQueryables = FixedIdMap<DeclaredQueryable, { caps::MAX_REMOTE_DECLS }>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps;

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

    #[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
    #[test]
    fn the_growable_backing_refuses_nothing() {
        let mut table: HashMap<u64, u32> = HashMap::new();
        for id in 0..64u64 {
            assert!(table.bind(id, 0).is_ok());
        }
        assert_eq!((table.count(), table.refusals()), (64, 0));
    }
}
