// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A persistent hash map: a hash array mapped trie (Bagwell, "Ideal Hash Trees", 2001) whose nodes
//! are shared between copies, so that a copy costs one count and a write to a copy copies the path
//! from the root to what it changes and nothing else (path copying, Okasaki 1998; Driscoll, Sarnak,
//! Sleator and Tarjan 1989).
//!
//! It exists for the router's tables under the `snapshot` value of the `routing-table-sharing`
//! policy (`docs/router-table-snapshots.md`, phase 6): a writer drafts the next version of the
//! tables from a copy of the published one, and a store held in a `HashMap` is copied whole by the
//! first write that reaches it, which made each declaration cost as much as the store is large. In
//! this map the same write copies at most one node per level, `ceil(64 / 5) = 13` levels at the
//! very most and about `log32(n)` in practice, each node at most 32 counted pointers.
//!
//! The shape:
//!
//! - A node holds a 32-bit occupancy bitmap and one slot per set bit, in bit order; the five bits
//!   of the key's 64-bit hash at the node's depth choose the bit.
//! - A slot is an entry, a deeper node, or a collision bucket (keys whose whole hashes are equal).
//! - Every entry is behind an `Arc` of its own, so copying a node counts its entries and copies
//!   none of their values: a write copies the one value it changes.
//! - The trie stays canonical under removal: a node left with one entry or one bucket is replaced
//!   by that slot, so a removal leaves the trie a sequence of insertions of its keys would build.
//!
//! What it does not offer, deliberately: a mutable iterator. Writing through every entry of a map
//! that another version shares copies every entry, which is the whole cost this map exists to
//! remove, and an iterator would make that the easy thing to write. A writer reads to find what it
//! changes and then writes those keys through [`PersistentMap::get_mut`].
//!
//! Under the `rwlock` value no version is shared, every count is one, and `Arc::make_mut` copies
//! nothing: the map is then an ordinary hash trie written in place.

use std::borrow::Borrow;
use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::Arc;

/// The bits of the hash each level consumes.
const BITS: u32 = 5;

/// The slots of a node.
const MASK: u64 = (1 << BITS) - 1;

/// A key this node gives out itself and no remote chooses: a face's number, a log's sequence
/// number. Only such a key may be hashed by its own bits ([`AssignedKeyHasher`]).
///
/// The bound is the whole contract. A key a remote chooses (a declaration id, a key expression) is
/// hashed by a keyed hasher, [`RandomState`]: hashed by its own bits, a remote could choose keys
/// that share a whole hash and turn every lookup of the map into a scan of one bucket. Do not
/// implement this for a type a remote can name, nor for `u64` or `String`, which both kinds use.
pub(crate) trait AssignedHere: Hash + Eq {}

/// The accept loop numbers the faces in the order they come, and never takes a number from the
/// wire (`accept_loop::FaceId`).
impl AssignedHere for crate::accept_loop::FaceId {}

/// The hasher of a map whose keys are [`AssignedHere`]: the key's own bits, which for a number
/// the node counts up are already spread over the low bits each level of the trie reads. It costs
/// nothing to compute, where a keyed hasher costs a few dozen instructions a lookup.
///
/// Built only by [`HasherFor`], which gives it to a map of [`AssignedHere`] keys and to no other,
/// so it cannot be named into a map whose keys a remote chooses.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AssignedKeyHasher(());

/// The state of [`AssignedKeyHasher`]: the bits written, folded.
pub(crate) struct AssignedKeyBits(u64);

impl Hasher for AssignedKeyBits {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(byte);
        }
    }

    fn write_u64(&mut self, n: u64) {
        // A key of one number hashes to the number itself: the state starts at zero.
        self.0 = self.0.rotate_left(BITS) ^ n;
    }
}

impl BuildHasher for AssignedKeyHasher {
    type Hasher = AssignedKeyBits;

    fn build_hasher(&self) -> AssignedKeyBits {
        AssignedKeyBits(0)
    }
}

/// The hashers a map of keys `K` is built with: [`RandomState`], keyed, for every key, and
/// [`AssignedKeyHasher`] for an [`AssignedHere`] key alone. Every constructor of a map asks for
/// it, so a map of remote keys with the unkeyed hasher does not compile.
pub(crate) trait HasherFor<K: ?Sized>: BuildHasher + Clone {
    /// The hasher of a new map.
    fn for_new_map() -> Self;
}

impl<K: ?Sized> HasherFor<K> for RandomState {
    fn for_new_map() -> Self {
        RandomState::new()
    }
}

impl<K: AssignedHere + ?Sized> HasherFor<K> for AssignedKeyHasher {
    fn for_new_map() -> Self {
        AssignedKeyHasher(())
    }
}

/// A [`PersistentMap`] whose keys this node assigns ([`AssignedHere`]), hashed by their own bits.
pub(crate) type AssignedKeyMap<K, V> = PersistentMap<K, V, AssignedKeyHasher>;

/// A [`PersistentSet`] whose members this node assigns ([`AssignedHere`]). The router's face
/// table's (`routing-router-hat`).
#[cfg(any(test, feature = "routing-router-hat"))]
pub(crate) type AssignedKeySet<T> = PersistentSet<T, AssignedKeyHasher>;

/// A hash map whose copies share their nodes. See the module documentation.
pub(crate) struct PersistentMap<K, V, S = RandomState> {
    root: Arc<Node<K, V>>,
    len: usize,
    hasher: S,
}

/// An entry: the key's whole hash, the key and its value.
struct Entry<K, V> {
    hash: u64,
    key: K,
    value: V,
}

/// An interior node: an occupancy bitmap and one slot per set bit.
struct Node<K, V> {
    bitmap: u32,
    slots: Vec<Slot<K, V>>,
}

enum Slot<K, V> {
    Entry(Arc<Entry<K, V>>),
    Branch(Arc<Node<K, V>>),
    /// Two or more entries whose whole hashes are equal.
    Collision(Arc<Collision<K, V>>),
}

struct Collision<K, V> {
    hash: u64,
    entries: Vec<Arc<Entry<K, V>>>,
}

// Copies of the shape count pointers and copy no key or value, so they ask nothing of `K` or `V`.
impl<K, V> Clone for Slot<K, V> {
    fn clone(&self) -> Self {
        match self {
            Slot::Entry(entry) => Slot::Entry(Arc::clone(entry)),
            Slot::Branch(node) => Slot::Branch(Arc::clone(node)),
            Slot::Collision(bucket) => Slot::Collision(Arc::clone(bucket)),
        }
    }
}

impl<K, V> Clone for Node<K, V> {
    fn clone(&self) -> Self {
        Self {
            bitmap: self.bitmap,
            slots: self.slots.clone(),
        }
    }
}

impl<K, V> Clone for Collision<K, V> {
    fn clone(&self) -> Self {
        Self {
            hash: self.hash,
            entries: self.entries.clone(),
        }
    }
}

impl<K: Clone, V: Clone> Clone for Entry<K, V> {
    fn clone(&self) -> Self {
        Self {
            hash: self.hash,
            key: self.key.clone(),
            value: self.value.clone(),
        }
    }
}

impl<K, V> Node<K, V> {
    const EMPTY: Self = Self {
        bitmap: 0,
        slots: Vec::new(),
    };

    /// The bit of `hash` at `shift`, and the index of its slot.
    fn locate(&self, hash: u64, shift: u32) -> (u32, usize) {
        let bit = 1u32 << ((hash >> shift) & MASK);
        (bit, (self.bitmap & (bit - 1)).count_ones() as usize)
    }

    /// The node at `shift` holding `a`, whose hash is `hash_a`, and the entry `b`, whose hash
    /// differs from `hash_a`.
    fn pair(a: Slot<K, V>, hash_a: u64, b: Arc<Entry<K, V>>, shift: u32) -> Self {
        debug_assert_ne!(
            hash_a, b.hash,
            "two hashes that differ split before the bits run out"
        );
        let at_a = (hash_a >> shift) & MASK;
        let at_b = (b.hash >> shift) & MASK;
        if at_a == at_b {
            let below = Self::pair(a, hash_a, b, shift + BITS);
            return Self {
                bitmap: 1 << at_a,
                slots: vec![Slot::Branch(Arc::new(below))],
            };
        }
        let b = Slot::Entry(b);
        Self {
            bitmap: (1 << at_a) | (1 << at_b),
            slots: if at_a < at_b { vec![a, b] } else { vec![b, a] },
        }
    }
}

impl<K, V> Slot<K, V> {
    /// The whole hash of the keys a slot that is not a branch holds.
    fn leaf_hash(&self) -> Option<u64> {
        match self {
            Slot::Entry(entry) => Some(entry.hash),
            Slot::Collision(bucket) => Some(bucket.hash),
            Slot::Branch(_) => None,
        }
    }
}

/// The value of an entry taken out of the trie: moved when this was its only holder, copied
/// when another version still holds it.
fn into_value<K: Clone, V: Clone>(entry: Arc<Entry<K, V>>) -> V {
    match Arc::try_unwrap(entry) {
        Ok(entry) => entry.value,
        Err(shared) => shared.value.clone(),
    }
}

impl<K, V> PersistentMap<K, V, RandomState> {
    /// An empty map.
    pub(crate) fn new() -> Self {
        Self::with_hasher(RandomState::new())
    }
}

impl<K, V, S: HasherFor<K>> PersistentMap<K, V, S> {
    /// An empty map hashing with `hasher`.
    pub(crate) fn with_hasher(hasher: S) -> Self {
        Self {
            root: Arc::new(Node::EMPTY),
            len: 0,
            hasher,
        }
    }
}

impl<K, V, S> PersistentMap<K, V, S> {
    /// How many keys the map holds.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Whether the map holds no key.
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Every key and its value, in an order fixed by the hashes and not by the insertions.
    pub(crate) fn iter(&self) -> Iter<'_, K, V> {
        Iter {
            stack: vec![self.root.slots.iter()],
            bucket: None,
            remaining: self.len,
        }
    }

    /// Every key, in the order of [`iter`](Self::iter).
    pub(crate) fn keys(&self) -> impl Iterator<Item = &K> + '_ {
        self.iter().map(|(key, _)| key)
    }

    /// Every value, in the order of [`iter`](Self::iter).
    pub(crate) fn values(&self) -> impl Iterator<Item = &V> + '_ {
        self.iter().map(|(_, value)| value)
    }
}

impl<K: Hash + Eq, V, S: BuildHasher> PersistentMap<K, V, S> {
    fn hash_of<Q: Hash + ?Sized>(&self, key: &Q) -> u64 {
        self.hasher.hash_one(key)
    }

    /// The entry of `key`, if the map holds it.
    fn find<Q>(&self, key: &Q) -> Option<&Entry<K, V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.find_hashed(self.hash_of(key), key)
    }

    /// [`find`](Self::find) with the hash of `key` already computed by this map's hasher.
    fn find_hashed<Q>(&self, hash: u64, key: &Q) -> Option<&Entry<K, V>>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        let mut node: &Node<K, V> = &self.root;
        let mut shift = 0;
        loop {
            let (bit, at) = node.locate(hash, shift);
            if node.bitmap & bit == 0 {
                return None;
            }
            match &node.slots[at] {
                Slot::Entry(entry) => {
                    return (entry.hash == hash && entry.key.borrow() == key).then_some(&**entry);
                }
                Slot::Branch(below) => {
                    node = below;
                    shift += BITS;
                }
                Slot::Collision(bucket) => {
                    if bucket.hash != hash {
                        return None;
                    }
                    return bucket
                        .entries
                        .iter()
                        .find(|entry| entry.key.borrow() == key)
                        .map(|entry| &**entry);
                }
            }
        }
    }

    /// The value of `key`.
    pub(crate) fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.find(key).map(|entry| &entry.value)
    }

    /// The key the map holds equal to `key`, and its value.
    ///
    /// Read by the tests and by the forwarder's client stores (`routing-router-hat`); gated for the
    /// dead-code lint of a build of the peer mesh alone, which reads it nowhere.
    #[cfg(any(test, feature = "routing-router-hat"))]
    pub(crate) fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.find(key).map(|entry| (&entry.key, &entry.value))
    }

    /// Whether the map holds `key`.
    pub(crate) fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.find(key).is_some()
    }
}

impl<K: Hash + Eq + Clone, V: Clone, S: BuildHasher> PersistentMap<K, V, S> {
    /// The value of `key`, for writing. The nodes on its path and its entry are copied first where
    /// another version shares them; a key the map does not hold copies nothing.
    pub(crate) fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let hash = self.hash_of(key);
        self.find_hashed(hash, key)?;
        self.walk_mut(hash, key)
    }

    /// [`get_mut`](Self::get_mut), when `wanted` answers `true` of the value as it stands: a value
    /// it refuses is not copied out of the versions that share it. One hash of `key` for the read
    /// and the write, where a [`get`](Self::get) and then a `get_mut` hash it twice.
    ///
    /// Read by the tests and by the forwarder's client stores (`routing-router-hat`).
    #[cfg(any(test, feature = "routing-router-hat"))]
    pub(crate) fn get_mut_if<Q>(
        &mut self,
        key: &Q,
        wanted: impl FnOnce(&V) -> bool,
    ) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let hash = self.hash_of(key);
        if !wanted(&self.find_hashed(hash, key)?.value) {
            return None;
        }
        self.walk_mut(hash, key)
    }

    /// Write the value of `key` through `edit`, and take the key out of the map when `edit` answers
    /// that the value is not to be kept (a set it emptied): one hash of `key` for the write and the
    /// removal. `None` for a key the map does not hold, which copies nothing; else whether the key
    /// was kept.
    ///
    /// Read by the tests and by the forwarder's client stores (`routing-router-hat`).
    #[cfg(any(test, feature = "routing-router-hat"))]
    pub(crate) fn edit_or_remove<Q>(
        &mut self,
        key: &Q,
        edit: impl FnOnce(&mut V) -> bool,
    ) -> Option<bool>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let hash = self.hash_of(key);
        self.find_hashed(hash, key)?;
        let keep = edit(
            self.walk_mut(hash, key)
                .expect("the key was found just before"),
        );
        if !keep {
            let removed = remove_from(Arc::make_mut(&mut self.root), hash, key, 0);
            debug_assert!(removed.is_some(), "the key was found before the removal");
            self.len -= 1;
        }
        Some(keep)
    }

    /// The value of `key`, whose hash is `hash`, for writing: the path to it copied where another
    /// version shares it. Called once the key is known to be held, so a miss copies nothing.
    fn walk_mut<Q>(&mut self, hash: u64, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        let mut node = Arc::make_mut(&mut self.root);
        let mut shift = 0;
        loop {
            let (_, at) = node.locate(hash, shift);
            match &mut node.slots[at] {
                Slot::Entry(entry) => return Some(&mut Arc::make_mut(entry).value),
                Slot::Branch(below) => {
                    node = Arc::make_mut(below);
                    shift += BITS;
                }
                Slot::Collision(bucket) => {
                    return Arc::make_mut(bucket)
                        .entries
                        .iter_mut()
                        .find(|entry| entry.key.borrow() == key)
                        .map(|entry| &mut Arc::make_mut(entry).value);
                }
            }
        }
    }

    /// The value of `key`, for writing, inserted from `default` first if the map does not hold it.
    pub(crate) fn get_mut_or_insert_with(&mut self, key: K, default: impl FnOnce() -> V) -> &mut V {
        self.get_mut_or_insert_by(&key, || key.clone(), default)
    }

    /// The value of the key `key` borrows, for writing, inserted from `default` under the key
    /// `owned` makes if the map does not hold it: `key` is hashed once, and an owned key is made
    /// only for an insertion, so a key the map holds is found by a borrow and allocates nothing.
    pub(crate) fn get_mut_or_insert_by<Q>(
        &mut self,
        key: &Q,
        owned: impl FnOnce() -> K,
        default: impl FnOnce() -> V,
    ) -> &mut V
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let hash = self.hash_of(key);
        if self.find_hashed(hash, key).is_none() {
            let owned = owned();
            debug_assert!(
                <K as Borrow<Q>>::borrow(&owned) == key,
                "the key made is the key asked for"
            );
            self.insert_hashed(hash, owned, default());
        }
        self.walk_mut(hash, key)
            .expect("the key was held or has just been inserted")
    }

    /// The value of `key`, for writing, inserted as `V::default()` first if the map does not hold
    /// it: `HashMap::entry(key).or_default()`.
    pub(crate) fn get_mut_or_default(&mut self, key: K) -> &mut V
    where
        V: Default,
    {
        self.get_mut_or_insert_with(key, V::default)
    }

    /// Hold `value` under `key`, returning the value it replaces.
    pub(crate) fn insert(&mut self, key: K, value: V) -> Option<V> {
        let hash = self.hash_of(&key);
        self.insert_hashed(hash, key, value)
    }

    fn insert_hashed(&mut self, hash: u64, key: K, value: V) -> Option<V> {
        let mut node = Arc::make_mut(&mut self.root);
        let mut shift = 0;
        loop {
            let (bit, at) = node.locate(hash, shift);
            if node.bitmap & bit == 0 {
                node.slots
                    .insert(at, Slot::Entry(Arc::new(Entry { hash, key, value })));
                node.bitmap |= bit;
                self.len += 1;
                return None;
            }
            let slot = &mut node.slots[at];
            match slot {
                Slot::Branch(below) => {
                    node = Arc::make_mut(below);
                    shift += BITS;
                }
                Slot::Entry(entry) if entry.hash == hash && entry.key == key => {
                    return Some(std::mem::replace(&mut Arc::make_mut(entry).value, value));
                }
                Slot::Entry(entry) if entry.hash == hash => {
                    let bucket = Collision {
                        hash,
                        entries: vec![Arc::clone(entry), Arc::new(Entry { hash, key, value })],
                    };
                    *slot = Slot::Collision(Arc::new(bucket));
                    self.len += 1;
                    return None;
                }
                Slot::Collision(bucket) if bucket.hash == hash => {
                    let bucket = Arc::make_mut(bucket);
                    if let Some(entry) = bucket.entries.iter_mut().find(|entry| entry.key == key) {
                        return Some(std::mem::replace(&mut Arc::make_mut(entry).value, value));
                    }
                    bucket.entries.push(Arc::new(Entry { hash, key, value }));
                    self.len += 1;
                    return None;
                }
                _ => {
                    // An entry or a bucket of another hash on the same bits: both go one level
                    // down, into a node that splits them.
                    let here = slot.clone();
                    let hash_here = here.leaf_hash().expect("a branch was matched above");
                    let new = Arc::new(Entry { hash, key, value });
                    *slot = Slot::Branch(Arc::new(Node::pair(here, hash_here, new, shift + BITS)));
                    self.len += 1;
                    return None;
                }
            }
        }
    }

    /// Take `key` out of the map, returning its value. A key the map does not hold copies nothing.
    pub(crate) fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let hash = self.hash_of(key);
        self.find_hashed(hash, key)?;
        let removed = remove_from(Arc::make_mut(&mut self.root), hash, key, 0);
        debug_assert!(removed.is_some(), "the key was found before the removal");
        self.len -= 1;
        removed
    }
}

/// Take the entry of `key`, which `node` at `shift` holds, out of it, and keep the trie canonical
/// on the way back up: a node below left with one entry or one bucket is replaced by that slot,
/// and a node below left empty is taken out.
fn remove_from<K, V, Q>(node: &mut Node<K, V>, hash: u64, key: &Q, shift: u32) -> Option<V>
where
    K: Borrow<Q> + Clone,
    V: Clone,
    Q: Eq + ?Sized,
{
    let (bit, at) = node.locate(hash, shift);
    if node.bitmap & bit == 0 {
        return None;
    }
    match &mut node.slots[at] {
        Slot::Entry(entry) => {
            if entry.hash != hash || entry.key.borrow() != key {
                return None;
            }
            node.bitmap &= !bit;
            match node.slots.remove(at) {
                Slot::Entry(entry) => Some(into_value(entry)),
                _ => unreachable!("the slot was matched as an entry"),
            }
        }
        Slot::Collision(bucket) => {
            if bucket.hash != hash {
                return None;
            }
            let bucket = Arc::make_mut(bucket);
            let index = bucket
                .entries
                .iter()
                .position(|entry| entry.key.borrow() == key)?;
            let removed = into_value(bucket.entries.swap_remove(index));
            if bucket.entries.len() == 1 {
                let last = bucket.entries.pop().expect("one entry is left");
                node.slots[at] = Slot::Entry(last);
            }
            Some(removed)
        }
        Slot::Branch(below) => {
            let below = Arc::make_mut(below);
            let removed = remove_from(below, hash, key, shift + BITS)?;
            match below.slots.len() {
                0 => {
                    node.bitmap &= !bit;
                    node.slots.remove(at);
                }
                1 if !matches!(below.slots[0], Slot::Branch(_)) => {
                    node.slots[at] = below.slots.pop().expect("one slot is left");
                }
                _ => {}
            }
            Some(removed)
        }
    }
}

/// The iterator of [`PersistentMap::iter`].
pub(crate) struct Iter<'a, K, V> {
    stack: Vec<std::slice::Iter<'a, Slot<K, V>>>,
    bucket: Option<std::slice::Iter<'a, Arc<Entry<K, V>>>>,
    remaining: usize,
}

impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(bucket) = &mut self.bucket {
                if let Some(entry) = bucket.next() {
                    self.remaining -= 1;
                    return Some((&entry.key, &entry.value));
                }
                self.bucket = None;
            }
            match self.stack.last_mut()?.next() {
                None => {
                    self.stack.pop();
                }
                Some(Slot::Entry(entry)) => {
                    self.remaining -= 1;
                    return Some((&entry.key, &entry.value));
                }
                Some(Slot::Branch(below)) => self.stack.push(below.slots.iter()),
                Some(Slot::Collision(bucket)) => self.bucket = Some(bucket.entries.iter()),
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K, V> ExactSizeIterator for Iter<'_, K, V> {}

impl<'a, K, V, S> IntoIterator for &'a PersistentMap<K, V, S> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// A copy shares every node: one count, whatever the map holds.
impl<K, V, S: Clone> Clone for PersistentMap<K, V, S> {
    fn clone(&self) -> Self {
        Self {
            root: Arc::clone(&self.root),
            len: self.len,
            hasher: self.hasher.clone(),
        }
    }
}

impl<K, V, S: HasherFor<K>> Default for PersistentMap<K, V, S> {
    fn default() -> Self {
        Self::with_hasher(S::for_new_map())
    }
}

impl<K: fmt::Debug, V: fmt::Debug, S> fmt::Debug for PersistentMap<K, V, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

/// Two maps are equal when they hold the same keys with equal values, whatever their shapes.
impl<K: Hash + Eq, V: PartialEq, S: BuildHasher> PartialEq for PersistentMap<K, V, S> {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len
            && self
                .iter()
                .all(|(key, value)| other.get(key).is_some_and(|theirs| theirs == value))
    }
}

impl<K: Hash + Eq, V: Eq, S: BuildHasher> Eq for PersistentMap<K, V, S> {}

impl<K: Hash + Eq + Clone, V: Clone, S: HasherFor<K>> FromIterator<(K, V)>
    for PersistentMap<K, V, S>
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut map = Self::default();
        for (key, value) in iter {
            map.insert(key, value);
        }
        map
    }
}

/// A persistent set: the keys of a [`PersistentMap`] with no value.
pub(crate) struct PersistentSet<T, S = RandomState>(PersistentMap<T, (), S>);

impl<T, S> PersistentSet<T, S> {
    /// Every member.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        self.0.keys()
    }

    /// Whether the set holds no member.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T: Hash + Eq, S: BuildHasher> PersistentSet<T, S> {
    /// Whether the set holds `member`.
    pub(crate) fn contains<Q>(&self, member: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.contains_key(member)
    }
}

impl<T: Hash + Eq + Clone, S: BuildHasher> PersistentSet<T, S> {
    /// Add `member`, saying whether it was not there.
    pub(crate) fn insert(&mut self, member: T) -> bool {
        self.0.insert(member, ()).is_none()
    }

    /// Take `member` out, saying whether it was there.
    pub(crate) fn remove<Q>(&mut self, member: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.remove(member).is_some()
    }
}

impl<T, S: Clone> Clone for PersistentSet<T, S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T, S: HasherFor<T>> Default for PersistentSet<T, S> {
    fn default() -> Self {
        Self(PersistentMap::default())
    }
}

impl<T: fmt::Debug, S> fmt::Debug for PersistentSet<T, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::hash::Hasher;

    /// A hasher that keeps only the bits `mask` lets through of the key's own value, so that a test
    /// chooses how deep the trie grows and how many keys share a whole hash.
    #[derive(Clone, Default)]
    struct Masked {
        mask: u64,
    }

    struct MaskedHasher {
        mask: u64,
        value: u64,
    }

    impl BuildHasher for Masked {
        type Hasher = MaskedHasher;

        fn build_hasher(&self) -> MaskedHasher {
            MaskedHasher {
                mask: self.mask,
                value: 0,
            }
        }
    }

    impl<K: ?Sized> HasherFor<K> for Masked {
        fn for_new_map() -> Self {
            Self::default()
        }
    }

    impl Hasher for MaskedHasher {
        fn finish(&self) -> u64 {
            self.value & self.mask
        }

        fn write(&mut self, bytes: &[u8]) {
            for byte in bytes {
                self.value = self.value.rotate_left(8) ^ u64::from(*byte);
            }
        }

        fn write_u64(&mut self, value: u64) {
            self.value = value;
        }
    }

    /// A small deterministic generator (xorshift64*), so that a failing sequence replays.
    struct Draw(u64);

    impl Draw {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    /// Every invariant of the shape: the bitmap counts the slots, no branch is empty or holds one
    /// leaf alone (canonical), a bucket holds two or more keys of one whole hash, and the entries
    /// counted are the length.
    fn check_shape<K, V>(node: &Node<K, V>, root: bool) -> usize {
        assert_eq!(node.bitmap.count_ones() as usize, node.slots.len());
        if !root {
            assert!(!node.slots.is_empty(), "an empty node below the root");
            assert!(
                node.slots.len() > 1 || matches!(node.slots[0], Slot::Branch(_)),
                "a node below the root holding one leaf alone"
            );
        }
        node.slots
            .iter()
            .map(|slot| match slot {
                Slot::Entry(_) => 1,
                Slot::Branch(below) => check_shape(below, false),
                Slot::Collision(bucket) => {
                    assert!(bucket.entries.len() >= 2, "a bucket of one");
                    assert!(bucket.entries.iter().all(|entry| entry.hash == bucket.hash));
                    bucket.entries.len()
                }
            })
            .sum()
    }

    /// The map under test, hashing through [`Masked`].
    type Tested = PersistentMap<u64, u64, Masked>;

    /// Drive the map and `HashMap` through the same random operations and require the same answer
    /// from both after each.
    fn agrees_with_a_hash_map(mask: u64, keys: u64, steps: usize, seed: u64) {
        let mut map: Tested = PersistentMap::with_hasher(Masked { mask });
        let mut model: HashMap<u64, u64> = HashMap::new();
        let mut kept: Vec<(Tested, HashMap<u64, u64>)> = Vec::new();
        let mut draw = Draw(seed);
        for step in 0..steps {
            let key = draw.next() % keys;
            let value = draw.next();
            match draw.next() % 9 {
                0 | 1 => assert_eq!(map.insert(key, value), model.insert(key, value)),
                2 => assert_eq!(map.remove(&key), model.remove(&key)),
                3 => {
                    if let Some(v) = map.get_mut(&key) {
                        *v = value;
                    }
                    if let Some(v) = model.get_mut(&key) {
                        *v = value;
                    }
                }
                4 => {
                    *map.get_mut_or_insert_with(key, || value) ^= 1;
                    *model.entry(key).or_insert(value) ^= 1;
                }
                5 => {
                    if let Some(v) = map.get_mut_if(&key, |held| held % 2 == 0) {
                        *v = value;
                    }
                    if let Some(v) = model.get_mut(&key).filter(|held| **held % 2 == 0) {
                        *v = value;
                    }
                }
                6 => {
                    *map.get_mut_or_insert_by(&key, || key, || value) ^= 2;
                    *model.entry(key).or_insert(value) ^= 2;
                }
                7 => {
                    // Kept unless the edit leaves a multiple of three.
                    let edit = |v: &mut u64| {
                        *v ^= 4;
                        *v % 3 != 0
                    };
                    let kept = map.edit_or_remove(&key, edit);
                    let expected = model.get_mut(&key).map(edit);
                    if expected == Some(false) {
                        model.remove(&key);
                    }
                    assert_eq!(kept, expected, "kept or removed, {key} at step {step}");
                }
                _ => {
                    // A copy kept aside must answer, later, what the map answered now.
                    if kept.len() < 8 {
                        kept.push((map.clone(), model.clone()));
                    }
                }
            }
            assert_eq!(map.len(), model.len(), "the length at step {step}");
            assert_eq!(
                map.get(&key),
                model.get(&key),
                "the value of {key} at step {step}"
            );
            assert_eq!(
                map.get_key_value(&key),
                model.get_key_value(&key),
                "the entry of {key} at step {step}"
            );
            assert_eq!(
                check_shape(&map.root, true),
                map.len(),
                "the shape at step {step}"
            );
        }
        let mut listed: Vec<(u64, u64)> = map.iter().map(|(k, v)| (*k, *v)).collect();
        let mut expected: Vec<(u64, u64)> = model.iter().map(|(k, v)| (*k, *v)).collect();
        listed.sort_unstable();
        expected.sort_unstable();
        assert_eq!(listed, expected, "the iteration");
        assert_eq!(map.iter().len(), model.len());
        for (copy, then) in &kept {
            assert_eq!(copy.len(), then.len(), "a copy kept its length");
            for (key, value) in then {
                assert_eq!(copy.get(key), Some(value), "a copy kept {key}");
            }
            assert_eq!(check_shape(&copy.root, true), copy.len());
        }
    }

    #[test]
    fn it_answers_as_a_hash_map_does_with_hashes_spread_over_every_bit() {
        agrees_with_a_hash_map(u64::MAX, 4096, 40_000, 0x9E37_79B9_7F4A_7C15);
    }

    #[test]
    fn it_answers_as_a_hash_map_does_when_many_keys_share_a_whole_hash() {
        // Twelve bits of hash for up to 4096 keys: buckets everywhere, splits of a bucket and an
        // entry, and buckets collapsing back into entries.
        agrees_with_a_hash_map(0x0F0F, 4096, 40_000, 0x1234_5678_9ABC_DEF1);
    }

    #[test]
    fn it_answers_as_a_hash_map_does_when_hashes_differ_only_in_their_last_bits() {
        // Only the top bits differ, so every key goes to the deepest level before splitting.
        agrees_with_a_hash_map(0xF000_0000_0000_0000, 64, 5_000, 0x0BAD_C0DE_DEAD_BEEF);
    }

    #[test]
    fn a_write_to_a_copy_leaves_the_original_as_it_was() {
        let mut original: PersistentMap<String, Vec<u8>> = PersistentMap::new();
        for i in 0..1000 {
            original.insert(format!("k{i}"), vec![i as u8]);
        }
        let mut copy = original.clone();
        copy.insert("k1".to_owned(), vec![9, 9]);
        copy.remove("k2");
        copy.get_mut("k3").expect("k3").push(7);
        copy.insert("new".to_owned(), Vec::new());
        assert_eq!(original.get("k1"), Some(&vec![1]));
        assert_eq!(original.get("k2"), Some(&vec![2]));
        assert_eq!(original.get("k3"), Some(&vec![3]));
        assert!(!original.contains_key("new"));
        assert_eq!(original.len(), 1000);
        assert_eq!(copy.get("k1"), Some(&vec![9, 9]));
        assert_eq!(copy.get("k2"), None);
        assert_eq!(copy.get("k3"), Some(&vec![3, 7]));
        assert_eq!(copy.len(), 1000);
    }

    /// The address of every node, bucket and entry under `node`, the root included.
    fn addresses<K, V>(node: &Arc<Node<K, V>>, into: &mut std::collections::HashSet<usize>) {
        into.insert(Arc::as_ptr(node) as usize);
        for slot in &node.slots {
            match slot {
                Slot::Entry(entry) => {
                    into.insert(Arc::as_ptr(entry) as usize);
                }
                Slot::Collision(bucket) => {
                    into.insert(Arc::as_ptr(bucket) as usize);
                    for entry in &bucket.entries {
                        into.insert(Arc::as_ptr(entry) as usize);
                    }
                }
                Slot::Branch(below) => addresses(below, into),
            }
        }
    }

    /// How many nodes, buckets and entries of `copy` are its own, not shared with `original`.
    fn own<K, V>(copy: &PersistentMap<K, V>, original: &PersistentMap<K, V>) -> usize {
        let (mut theirs, mut ours) = (
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
        );
        addresses(&original.root, &mut theirs);
        addresses(&copy.root, &mut ours);
        ours.difference(&theirs).count()
    }

    #[test]
    fn a_write_to_a_copy_copies_one_path_and_shares_the_rest() {
        let mut original: PersistentMap<u64, u64> = PersistentMap::new();
        for i in 0..100_000 {
            original.insert(i, i);
        }
        let mut copy = original.clone();
        *copy.get_mut(&77).expect("77") += 1;
        // A path is one node per level and the entry: at 100 000 keys, about log32 of that is four
        // levels. Everything else is shared, so the count is that of a path and not of the map.
        let fresh = own(&copy, &original);
        assert!(
            fresh <= 8,
            "a write to one key of a copy made {fresh} nodes and entries of its own"
        );
        assert_eq!(original.get(&77), Some(&77));
        assert_eq!(copy.get(&77), Some(&78));
    }

    #[test]
    fn a_write_to_a_map_no_copy_shares_copies_nothing() {
        let mut map: PersistentMap<u64, u64> = PersistentMap::new();
        for i in 0..10_000 {
            map.insert(i, i);
        }
        let root = Arc::as_ptr(&map.root);
        *map.get_mut(&5).expect("5") += 1;
        map.insert(10_001, 0);
        map.remove(&6);
        assert_eq!(
            Arc::as_ptr(&map.root),
            root,
            "a map that shares nothing is written in place"
        );
    }

    #[test]
    fn a_refused_write_copies_nothing_and_an_accepted_one_copies_one_path() {
        let mut original: PersistentMap<u64, u64> = PersistentMap::new();
        for i in 0..10_000 {
            original.insert(i, i);
        }
        let mut copy = original.clone();
        assert!(copy.get_mut_if(&77, |held| *held != 77).is_none());
        assert!(
            copy.get_mut_if(&20_000, |_| true).is_none(),
            "a key not held"
        );
        assert_eq!(own(&copy, &original), 0, "nothing was copied for a refusal");
        *copy
            .get_mut_if(&77, |held| *held == 77)
            .expect("77 is wanted") += 1;
        assert!(
            own(&copy, &original) > 0,
            "the accepted write copied its path"
        );
        assert_eq!(original.get(&77), Some(&77));
        assert_eq!(copy.get(&77), Some(&78));
    }

    #[test]
    fn a_key_held_is_found_by_its_borrow_and_an_owned_key_is_made_only_to_insert() {
        let mut map: PersistentMap<String, u64> = PersistentMap::new();
        let mut made = 0;
        *map.get_mut_or_insert_by(
            "demo/a",
            || {
                made += 1;
                "demo/a".to_owned()
            },
            || 1,
        ) += 10;
        *map.get_mut_or_insert_by(
            "demo/a",
            || {
                made += 1;
                "demo/a".to_owned()
            },
            || 1,
        ) += 10;
        assert_eq!(made, 1, "the second call found the key by its borrow");
        assert_eq!(map.get("demo/a"), Some(&21));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn a_face_number_is_its_own_hash_and_its_map_answers_as_a_keyed_one() {
        use crate::accept_loop::FaceId;
        let hasher = <AssignedKeyHasher as HasherFor<FaceId>>::for_new_map();
        assert_eq!(hasher.hash_one(FaceId(77)), 77);
        let mut assigned: AssignedKeyMap<FaceId, u64> = AssignedKeyMap::default();
        let mut keyed: PersistentMap<FaceId, u64> = PersistentMap::new();
        for n in 0..5_000 {
            assigned.insert(FaceId(n), n * 3);
            keyed.insert(FaceId(n), n * 3);
        }
        for n in (0..5_000).step_by(3) {
            assert_eq!(assigned.remove(&FaceId(n)), keyed.remove(&FaceId(n)));
        }
        assert_eq!(assigned.len(), keyed.len());
        assert_eq!(check_shape(&assigned.root, true), assigned.len());
        for n in 0..5_001 {
            assert_eq!(assigned.get(&FaceId(n)), keyed.get(&FaceId(n)), "face {n}");
        }
        let mut set: AssignedKeySet<FaceId> = AssignedKeySet::default();
        assert!(set.insert(FaceId(1)));
        assert!(set.contains(&FaceId(1)));
    }

    #[test]
    fn a_set_holds_each_member_once() {
        let mut set: PersistentSet<String> = PersistentSet::default();
        assert!(set.insert("a/*".to_owned()));
        assert!(!set.insert("a/*".to_owned()));
        let copy = set.clone();
        assert!(set.remove("a/*"));
        assert!(!set.remove("a/*"));
        assert_eq!(set.iter().count(), 0);
        assert_eq!(
            copy.iter().collect::<Vec<_>>(),
            ["a/*"],
            "the copy kept its member"
        );
    }
}
