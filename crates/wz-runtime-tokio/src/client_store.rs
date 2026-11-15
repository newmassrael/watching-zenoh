// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The declarations a node's client faces hold on one plane, indexed by key and changed only through
//! methods that say which key moved.
//!
//! One store serves the three planes a broker hat keeps for its clients: subscribers, queryables
//! and liveliness tokens. A declaration is a face's id naming a key, and a queryable also carries
//! the [`QueryableInfo`] it was declared with; the store holds that value beside the id, as `V`
//! ([`Held`]), so the planes differ only in `V`. The subscriber store is the client leg of a data
//! route ([`client_route`](crate::linkstate_forward)), the queryable store the client leg of a query
//! route, and both are cached against it. Three things come with it that a plain
//! `Versioned<HashMap<..>>` did not give:
//!
//! - AN INDEX BY KEY. Every key some client declares is held in a trie of its chunks
//!   ([`KeyexprIndex`]), so the keys a route or an interest's answer needs are found by walking the
//!   branches the asked keyexpr can meet, wildcards on either side included, instead of a scan of
//!   every declaration. What is declared on one exact key, by which faces, under which ids and with
//!   which values, is one lookup: the question every propagation asks of a key it moved.
//! - A CHANGE LOG. Every change records the key it declared or withdrew under the version it produced,
//!   so a cache that was fresh at an earlier version can ask which keys moved since and retire only the
//!   routes those keys intersect ([`changed_since`](ClientStore::changed_since)).
//! - NO UNRECORDED CHANGE. The per-face map is readable through `Deref` and not writable: there is no
//!   `DerefMut`, so a change that did not go through a method here, and so did not record its key, does
//!   not compile. That is the property that let the cache read its freshness from the table instead of
//!   being told (`route_cache`), kept while the invalidation became incremental.
//!
//! The log is bounded. A reader that fell further behind than it reaches is told so
//! (`changed_since` answers `false`) and drops everything, which is the answer the unindexed store gave
//! to every change.
//!
//! Every part of it is a [`PersistentMap`], so that the router's tables, which hold it, can be
//! copied as a version and the copy written: a change copies the path to what it moves and not the
//! store (`docs/router-table-snapshots.md`, phase 6). A store held in `HashMap`s was copied whole by
//! the first change in each version, which made a declaration cost as much as the store is large.

use std::collections::HashSet;
use std::ops::Deref;
use std::sync::Arc;

use wz_session_core::keyexpr_match::keyexpr_intersects_target;
use wz_session_core::queryable_info::QueryableInfo;

use crate::accept_loop::FaceId;
use crate::keyexpr_index::KeyexprIndex;
use crate::persistent_map::{AssignedKeyMap, PersistentMap};

/// How many changed keys the log keeps. A cache consulted by every message is never this far behind;
/// one that is drops its routes instead.
const LOG_CAPACITY: usize = 4096;

/// The entries of one chunk of the log ([`ChangeLog`]).
const LOG_CHUNK: usize = 64;

// An entry's slot is its number modulo the capacity, which stays right across the wrap of the
// numbers only for a power of two; and the chunks tile the ring.
const _: () = assert!(LOG_CAPACITY.is_power_of_two() && LOG_CAPACITY % LOG_CHUNK == 0);

/// One logged change: the version it produced and the key it moved.
type LogEntry = (u64, Arc<str>);

/// The keys changed, each under the version its change produced, by the order they were logged in:
/// the entries numbered from `first` up to before `next`, at most [`LOG_CAPACITY`] of them. A
/// change that drops a face logs several keys under one version, so the log is numbered by entry
/// and not by version.
///
/// A ring: entry `n` sits in slot `n % LOG_CAPACITY`, read and written by its number with nothing
/// hashed. The slots are in chunks of [`LOG_CHUNK`], each behind an `Arc`, and the chunks behind
/// one more, so that a version of the tables copies the log with one count and a write to a
/// shared log copies the chunk table and the one chunk it writes (`docs/router-table-snapshots.md`,
/// phase 6). A log no other version shares is written in place.
#[derive(Debug, Clone, Default)]
struct ChangeLog {
    /// The chunks, filled in order the first time round and overwritten after.
    chunks: Arc<Vec<Arc<Vec<LogEntry>>>>,
    /// The number of the oldest entry held.
    first: u64,
    /// The number the next entry is logged under.
    next: u64,
    /// The version of the newest change whose entry the log has dropped, or 0 while none has been.
    /// A reader that was fresh at this version or later is answered from the log; an earlier one is
    /// not.
    floor: u64,
}

impl ChangeLog {
    /// The chunk and the slot in it of entry `n`.
    fn slot_of(n: u64) -> (usize, usize) {
        let slot = (n % LOG_CAPACITY as u64) as usize;
        (slot / LOG_CHUNK, slot % LOG_CHUNK)
    }

    /// Entry `n`, which the log holds.
    fn entry(&self, n: u64) -> &LogEntry {
        let (chunk, slot) = Self::slot_of(n);
        &self.chunks[chunk][slot]
    }

    /// Log `keyexpr` under `version`, in the slot of the oldest entry once the log is full.
    fn push(&mut self, version: u64, keyexpr: Arc<str>) {
        if self.next.wrapping_sub(self.first) == LOG_CAPACITY as u64 {
            self.floor = self.entry(self.first).0;
            self.first = self.first.wrapping_add(1);
        }
        let (chunk, slot) = Self::slot_of(self.next);
        let chunks = Arc::make_mut(&mut self.chunks);
        debug_assert!(chunk <= chunks.len(), "the chunks are filled in order");
        if chunk == chunks.len() {
            chunks.push(Arc::new(Vec::with_capacity(LOG_CHUNK)));
        }
        let slots = Arc::make_mut(&mut chunks[chunk]);
        debug_assert!(slot <= slots.len(), "a chunk is filled in order");
        if slot == slots.len() {
            slots.push((version, keyexpr));
        } else {
            slots[slot] = (version, keyexpr);
        }
        self.next = self.next.wrapping_add(1);
    }
}

/// What a client declaration carries beside its key, and how the declarations of one face on one key
/// read as one: the face is one holder of the key, whatever number of ids it declared it under.
///
/// `merge` is associative and commutative, so the fold over a face's ids does not depend on the
/// order they were declared in.
pub(crate) trait Held: Clone + PartialEq {
    /// The value two declarations on one key amount to.
    #[must_use]
    fn merge(self, other: Self) -> Self;
}

/// A subscriber and a liveliness token carry nothing beside their key.
impl Held for () {
    fn merge(self, _other: Self) -> Self {}
}

/// A queryable's: complete if any is, at the nearest distance, as the pin merges the queryables of
/// one face (`zenoh/src/net/routing/hat/broker/queries.rs` @ `.reduce(merge_qabl_infos);`).
impl Held for QueryableInfo {
    fn merge(self, other: Self) -> Self {
        QueryableInfo::merge(self, other)
    }
}

/// The declarations on one key: per face, the ids declaring it and the value each carries. The
/// faces are the node's own numbers and the ids the remote's, so only the inner map is keyed.
pub(crate) type Holders<V> = AssignedKeyMap<FaceId, PersistentMap<u64, V>>;

/// The client faces' declarations on one plane: per face, by declaration id; and by key.
///
/// A key is held once, as one `Arc<str>` that the face's ids, the index by key and the log all
/// point at: a declaration of a key some client already declares allocates no text.
#[derive(Debug, Clone)]
pub(crate) struct ClientStore<V> {
    /// Per face, the declaration ids and the key each names.
    by_face: AssignedKeyMap<FaceId, PersistentMap<u64, Arc<str>>>,
    /// Per key some client declares, the faces declaring it, each with its ids on it and their values.
    by_key: PersistentMap<Arc<str>, Holders<V>>,
    /// The keys in `by_key`, each held under itself: the keys an asked keyexpr may intersect, found
    /// without trying every key.
    keys: KeyexprIndex<Arc<str>>,
    /// How many changes the store has seen; wraps.
    version: u64,
    /// The keys the changes moved ([`ChangeLog`]).
    log: ChangeLog,
}

/// The client faces' subscribers.
pub(crate) type ClientSubStore = ClientStore<()>;

/// The client faces' queryables, each with the [`QueryableInfo`] it was declared with.
pub(crate) type ClientQablStore = ClientStore<QueryableInfo>;

/// The client faces' liveliness tokens. A client withdraws a token by its id alone (an
/// `UndeclareToken` carries no keyexpr on the wire), which the store resolves through the face's ids.
#[cfg(feature = "routing-token-tables")]
pub(crate) type ClientTokenStore = ClientStore<()>;

impl<V> Default for ClientStore<V> {
    fn default() -> Self {
        Self {
            by_face: AssignedKeyMap::default(),
            by_key: PersistentMap::default(),
            keys: KeyexprIndex::default(),
            version: 0,
            log: ChangeLog::default(),
        }
    }
}

impl<V> Deref for ClientStore<V> {
    type Target = AssignedKeyMap<FaceId, PersistentMap<u64, Arc<str>>>;

    fn deref(&self) -> &Self::Target {
        &self.by_face
    }
}

impl<V: Held> ClientStore<V> {
    /// An empty store at version 0.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// How many changes the store has seen. A route cached at one value is stale at another unless
    /// [`changed_since`](Self::changed_since) says the keys that moved did not touch it.
    pub(crate) fn version(&self) -> u64 {
        self.version
    }

    /// Whether any client declares exactly `keyexpr`: the resource question every route cache asks
    /// on a miss.
    pub(crate) fn names_key(&self, keyexpr: &str) -> bool {
        self.by_key.contains_key(keyexpr)
    }

    /// The faces declaring exactly `keyexpr`, each with its ids on it and their values; `None` when
    /// no client declares it.
    pub(crate) fn holders(&self, keyexpr: &str) -> Option<&Holders<V>> {
        self.by_key.get(keyexpr)
    }

    /// How many faces declare exactly `keyexpr`, however many ids each holds on it: one lookup,
    /// where counting the faces whose ids name it is a scan of every face.
    pub(crate) fn faces_naming(&self, keyexpr: &str) -> usize {
        self.holders(keyexpr).map_or(0, PersistentMap::len)
    }

    /// How many declarations name exactly `keyexpr`, counting each id of each face.
    #[cfg(feature = "routing-token-tables")]
    pub(crate) fn ids_naming(&self, keyexpr: &str) -> usize {
        self.holders(keyexpr)
            .map_or(0, |holders| holders.values().map(PersistentMap::len).sum())
    }

    /// Whether `face` declares exactly `keyexpr` under any id.
    pub(crate) fn face_names(&self, face: FaceId, keyexpr: &str) -> bool {
        self.holders(keyexpr)
            .is_some_and(|holders| holders.contains_key(&face))
    }

    /// The value `face` holds on exactly `keyexpr`: the merge of its ids on it, `None` when it holds
    /// none.
    pub(crate) fn face_value(&self, face: FaceId, keyexpr: &str) -> Option<V> {
        merged(self.holders(keyexpr)?.get(&face)?)
    }

    /// The value every face together holds on exactly `keyexpr`, `None` when none holds it.
    pub(crate) fn key_value(&self, keyexpr: &str) -> Option<V> {
        key_value(self.holders(keyexpr)?, None)
    }

    /// Declare `id` of `face` on `keyexpr` with `value`, returning the key `id` named before, if it
    /// named one (the same key when the id is declared again).
    pub(crate) fn insert(
        &mut self,
        face: FaceId,
        id: u64,
        keyexpr: &str,
        value: V,
    ) -> Option<Arc<str>> {
        let keyexpr = self.key_of(keyexpr);
        let displaced = self
            .by_face
            .get_mut_or_default(face)
            .insert(id, Arc::clone(&keyexpr));
        // The id leaves the key it named before it is entered under the one it names now, so an id
        // declared again on its own key is held once.
        if let Some(old) = &displaced {
            self.index_remove(face, id, old);
            if **old != *keyexpr {
                self.record(Arc::clone(old));
            }
        }
        self.record(Arc::clone(&keyexpr));
        self.index_add(face, id, &keyexpr, value);
        displaced
    }

    /// `keyexpr` as the store holds it: the one copy the store shares when some client declares
    /// it already, else a new one.
    fn key_of(&self, keyexpr: &str) -> Arc<str> {
        self.by_key
            .get_key_value(keyexpr)
            .map_or_else(|| Arc::from(keyexpr), |(held, _)| Arc::clone(held))
    }

    /// Withdraw `id` of `face`, returning the key it named. A face left with nothing is dropped.
    pub(crate) fn remove_id(&mut self, face: FaceId, id: u64) -> Option<Arc<str>> {
        // Looked up before it is written, so that an id the face does not hold copies nothing.
        let by_id = self
            .by_face
            .get_mut_if(&face, |by_id| by_id.contains_key(&id))?;
        let removed = by_id.remove(&id)?;
        if by_id.is_empty() {
            self.by_face.remove(&face);
        }
        self.record(Arc::clone(&removed));
        self.index_remove(face, id, &removed);
        Some(removed)
    }

    /// Withdraw `id` of `face` and say whether `face` no longer declares the key `id` named, that is
    /// whether no other id of the face names it. `false` when `id` was not held.
    /// The router's broker hat withdraws a subscriber by id and asks this; the peer withdraws by id and
    /// asks which key it named ([`remove_id`](Self::remove_id)).
    #[cfg(feature = "routing-router-hat")]
    pub(crate) fn remove_id_leaving_key(&mut self, face: FaceId, id: u64) -> bool {
        let Some(removed) = self.remove_id(face, id) else {
            return false;
        };
        !self.face_names(face, &removed)
    }

    /// Withdraw every declaration of `face`, returning what it held by id.
    pub(crate) fn remove_face(&mut self, face: FaceId) -> Option<PersistentMap<u64, Arc<str>>> {
        let removed = self.by_face.remove(&face)?;
        // One change for the whole face: the version moves once, and each distinct key it held is
        // logged under it.
        self.version = self.version.wrapping_add(1);
        let mut seen: HashSet<&str> = HashSet::new();
        for (id, keyexpr) in &removed {
            if seen.insert(keyexpr) {
                self.log.push(self.version, Arc::clone(keyexpr));
            }
            self.index_remove(face, *id, keyexpr);
        }
        Some(removed)
    }

    /// The faces with a declaration that intersects `keyexpr`, in face order.
    pub(crate) fn faces_intersecting(&self, keyexpr: &str) -> Vec<FaceId> {
        let mut faces: Vec<FaceId> = self
            .keys_intersecting(keyexpr)
            .into_iter()
            .flat_map(|(_, holders)| holders.keys().copied())
            .collect();
        faces.sort_unstable();
        faces.dedup();
        faces
    }

    /// Every key some client declares that intersects `keyexpr`, with its holders.
    ///
    /// The index finds the keys that may intersect and the intersection test the scan always used
    /// decides each, so the answer is the set a scan of every key gives.
    pub(crate) fn keys_intersecting(&self, keyexpr: &str) -> Vec<(&str, &Holders<V>)> {
        let target: Vec<&str> = keyexpr.split('/').collect();
        self.keys
            .intersecting(keyexpr)
            .into_iter()
            .filter(|key| keyexpr_intersects_target(key, &target))
            .map(|key| {
                let holders = self.by_key.get(&**key).expect("an indexed key has holders");
                (&**key, holders)
            })
            .collect()
    }

    /// Whether some client declares a key that intersects `keyexpr`.
    fn any_intersecting(&self, keyexpr: &str) -> bool {
        let target: Vec<&str> = keyexpr.split('/').collect();
        self.keys
            .intersecting(keyexpr)
            .into_iter()
            .any(|key| keyexpr_intersects_target(key, &target))
    }

    /// Whether some client declaration backs a reply for `keyexpr`: one that intersects it when the
    /// reply is `aggregate` (it stands for everything its keyexpr meets), else one on that very key,
    /// as a resource is one keyexpr and nothing else keeps it declared.
    pub(crate) fn backs(&self, keyexpr: &str, aggregate: bool) -> bool {
        if aggregate {
            self.any_intersecting(keyexpr)
        } else {
            self.names_key(keyexpr)
        }
    }

    /// The keys that back a reply for `keyexpr` ([`backs`](Self::backs)), with their holders.
    pub(crate) fn keys_backing(&self, keyexpr: &str, aggregate: bool) -> Vec<(&str, &Holders<V>)> {
        if aggregate {
            return self.keys_intersecting(keyexpr);
        }
        self.by_key
            .get_key_value(keyexpr)
            .map(|(key, holders)| (&**key, holders))
            .into_iter()
            .collect()
    }

    /// Every key some client declares, with its holders: the answer to an unrestricted interest.
    pub(crate) fn every_key(&self) -> Vec<(&str, &Holders<V>)> {
        self.by_key
            .iter()
            .map(|(key, holders)| (&**key, holders))
            .collect()
    }

    /// Feed `visit` every key changed after `version`, and say whether that was all of them. `false`
    /// means the log no longer reaches back that far, and the caller must treat every key as changed.
    pub(crate) fn changed_since(&self, version: u64, mut visit: impl FnMut(&str)) -> bool {
        let behind = self.version.wrapping_sub(version);
        let reach = self.version.wrapping_sub(self.log.floor);
        if behind > reach {
            return false;
        }
        // Newest first, as far back as the reader is behind.
        let mut entry = self.log.next;
        while entry != self.log.first {
            entry = entry.wrapping_sub(1);
            let (at, keyexpr) = self.log.entry(entry);
            if self.version.wrapping_sub(*at) >= behind {
                break;
            }
            visit(keyexpr);
        }
        true
    }

    /// One change that moved `keyexpr`.
    fn record(&mut self, keyexpr: Arc<str>) {
        self.version = self.version.wrapping_add(1);
        self.log.push(self.version, keyexpr);
    }

    /// Enter `id` of `face` under `keyexpr` in the index by key: one lookup of the key, by its
    /// text, and the key indexed when it is new.
    fn index_add(&mut self, face: FaceId, id: u64, keyexpr: &Arc<str>, value: V) {
        let mut new_key = false;
        self.by_key
            .get_mut_or_insert_by(
                &**keyexpr,
                || Arc::clone(keyexpr),
                || {
                    new_key = true;
                    Holders::default()
                },
            )
            .get_mut_or_default(face)
            .insert(id, value);
        if new_key {
            self.keys.insert(keyexpr, Arc::clone(keyexpr));
        }
    }

    /// Take `id` of `face` out from under `keyexpr` in the index by key: one lookup of the key for
    /// the write and, when it leaves the key with no holder, its removal.
    fn index_remove(&mut self, face: FaceId, id: u64, keyexpr: &Arc<str>) {
        let kept = self.by_key.edit_or_remove(&**keyexpr, |holders| {
            holders.edit_or_remove(&face, |ids| {
                ids.remove(&id);
                !ids.is_empty()
            });
            !holders.is_empty()
        });
        if kept == Some(false) {
            self.keys.remove(keyexpr, keyexpr);
        }
    }
}

/// The value of one face's ids on a key, `None` for no id.
pub(crate) fn merged<V: Held>(ids: &PersistentMap<u64, V>) -> Option<V> {
    ids.values().cloned().reduce(Held::merge)
}

/// The value every face of `holders` but `except` holds on their key together, `None` when none does.
pub(crate) fn key_value<V: Held>(holders: &Holders<V>, except: Option<FaceId>) -> Option<V> {
    holders
        .iter()
        .filter(|(face, _)| Some(**face) != except)
        .filter_map(|(_, ids)| merged(ids))
        .reduce(Held::merge)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn face(n: u64) -> FaceId {
        FaceId(n)
    }

    fn info(complete: bool, distance: u16) -> QueryableInfo {
        QueryableInfo { complete, distance }
    }

    /// The scan the store replaces, as the reference its index must agree with.
    fn scanned<V: Held>(store: &ClientStore<V>, keyexpr: &str) -> Vec<FaceId> {
        let target: Vec<&str> = keyexpr.split('/').collect();
        let mut faces: Vec<FaceId> = store
            .iter()
            .filter(|(_, ids)| {
                ids.values()
                    .any(|sub| keyexpr_intersects_target(sub, &target))
            })
            .map(|(f, _)| *f)
            .collect();
        faces.sort_unstable();
        faces
    }

    /// The keys a scan of every declaration finds intersecting `keyexpr`, in order.
    fn scanned_keys<V: Held>(store: &ClientStore<V>, keyexpr: &str) -> Vec<String> {
        let target: Vec<&str> = keyexpr.split('/').collect();
        let mut keys: Vec<String> = store
            .values()
            .flat_map(|ids| ids.values())
            .filter(|sub| keyexpr_intersects_target(sub, &target))
            .map(|sub| sub.to_string())
            .collect();
        keys.sort_unstable();
        keys.dedup();
        keys
    }

    fn indexed_keys<V: Held>(store: &ClientStore<V>, keyexpr: &str) -> Vec<String> {
        let mut keys: Vec<String> = store
            .keys_intersecting(keyexpr)
            .into_iter()
            .map(|(key, _)| key.to_owned())
            .collect();
        keys.sort_unstable();
        keys
    }

    /// The exact-key answers against a scan of every face's ids: how many faces name `keyexpr`, and
    /// which.
    fn assert_exact_answers<V: Held>(store: &ClientStore<V>, keyexpr: &str) {
        let naming: Vec<FaceId> = store
            .iter()
            .filter(|(_, ids)| ids.values().any(|sub| **sub == *keyexpr))
            .map(|(f, _)| *f)
            .collect();
        assert_eq!(
            store.faces_naming(keyexpr),
            naming.len(),
            "count, {keyexpr}"
        );
        assert_eq!(store.names_key(keyexpr), !naming.is_empty(), "{keyexpr}");
        for n in 0..10 {
            assert_eq!(
                store.face_names(face(n), keyexpr),
                naming.contains(&face(n)),
                "face {n}, {keyexpr}"
            );
        }
    }

    /// Every answer by key against a scan, for `keyexpr` as a probe.
    fn assert_answers<V: Held>(store: &ClientStore<V>, keyexpr: &str) {
        assert_eq!(
            store.faces_intersecting(keyexpr),
            scanned(store, keyexpr),
            "faces, probe {keyexpr}"
        );
        let scanned = scanned_keys(store, keyexpr);
        assert_eq!(
            indexed_keys(store, keyexpr),
            scanned,
            "keys, probe {keyexpr}"
        );
        assert_eq!(
            store.backs(keyexpr, true),
            !scanned.is_empty(),
            "any, probe {keyexpr}"
        );
        assert_eq!(
            store.backs(keyexpr, false),
            store.names_key(keyexpr),
            "exact, probe {keyexpr}"
        );
        let mut backing: Vec<&str> = store
            .keys_backing(keyexpr, true)
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        backing.sort_unstable();
        assert_eq!(backing, scanned, "aggregate backing, probe {keyexpr}");
        let exact: Vec<&str> = store
            .keys_backing(keyexpr, false)
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        let expected: Vec<&str> = if store.names_key(keyexpr) {
            vec![keyexpr]
        } else {
            vec![]
        };
        assert_eq!(exact, expected, "exact backing, probe {keyexpr}");
        assert_exact_answers(store, keyexpr);
    }

    const PROBES: &[&str] = &[
        "demo/a",
        "demo/b",
        "demo/a/b",
        "demo/c/d/e",
        "other/a",
        "demo/*",
        "demo/**",
        "**",
        "demo/a/*",
        "other/**",
        "a//b",
        "demo/a/",
    ];

    #[test]
    fn the_index_finds_the_faces_the_scan_found() {
        let mut store = ClientSubStore::new();
        store.insert(face(1), 1, "demo/a", ());
        store.insert(face(2), 1, "demo/b", ());
        store.insert(face(3), 1, "demo/*", ());
        store.insert(face(4), 1, "demo/**", ());
        store.insert(face(5), 1, "other/a", ());
        store.insert(face(5), 2, "demo/a", ());
        store.insert(face(6), 1, "demo/a/*", ());
        store.insert(face(7), 1, "**", ());
        store.insert(face(8), 1, "demo/c/d/e", ());
        for probe in PROBES {
            assert_answers(&store, probe);
        }
        // Withdraw some, displace one, drop a face: the index follows each.
        store.remove_id(face(5), 2);
        store.insert(face(2), 1, "demo/c/d/e", ());
        store.remove_face(face(3));
        store.remove_id(face(7), 1);
        for probe in PROBES {
            assert_answers(&store, probe);
        }
    }

    #[cfg(feature = "routing-router-hat")]
    #[test]
    fn two_ids_of_one_face_on_one_key_keep_the_key_until_the_last_goes() {
        let mut store = ClientSubStore::new();
        store.insert(face(1), 1, "demo/a", ());
        store.insert(face(1), 2, "demo/a", ());
        assert!(
            !store.remove_id_leaving_key(face(1), 1),
            "id 2 still names it"
        );
        assert!(store.names_key("demo/a"));
        assert!(store.remove_id_leaving_key(face(1), 2), "the last id left");
        assert!(!store.names_key("demo/a"));
        assert!(store.is_empty(), "the emptied face is dropped");
        assert!(
            !store.remove_id_leaving_key(face(1), 2),
            "an unknown id leaves nothing"
        );
    }

    #[test]
    fn an_id_declared_again_on_its_own_key_is_held_once() {
        let mut store = ClientQablStore::new();
        store.insert(face(1), 1, "demo/q", info(false, 0));
        let displaced = store.insert(face(1), 1, "demo/q", info(true, 0));
        assert_eq!(displaced.as_deref(), Some("demo/q"));
        let holders = store.holders("demo/q").expect("still declared");
        assert_eq!(holders.get(&face(1)).map(PersistentMap::len), Some(1));
        assert_eq!(
            store.face_value(face(1), "demo/q"),
            Some(info(true, 0)),
            "the newer value replaced the older"
        );
        assert_eq!(
            store.keys_intersecting("demo/**").len(),
            1,
            "the key is indexed once, after the id left it and came back"
        );
        assert_eq!(store.remove_id(face(1), 1).as_deref(), Some("demo/q"));
        assert!(!store.names_key("demo/q"), "one withdrawal leaves nothing");
        assert!(
            store.keys_intersecting("demo/**").is_empty(),
            "and the index let go of the key"
        );
    }

    #[test]
    fn a_face_value_is_the_merge_of_its_ids_and_a_key_value_of_its_faces() {
        let mut store = ClientQablStore::new();
        store.insert(face(1), 1, "demo/q", info(false, 3));
        store.insert(face(1), 2, "demo/q", info(true, 5));
        store.insert(face(2), 1, "demo/q", info(false, 1));
        store.insert(face(2), 2, "demo/r", info(true, 0));
        assert_eq!(store.face_value(face(1), "demo/q"), Some(info(true, 3)));
        assert_eq!(store.face_value(face(2), "demo/q"), Some(info(false, 1)));
        assert_eq!(store.face_value(face(3), "demo/q"), None);
        assert_eq!(store.key_value("demo/q"), Some(info(true, 1)));
        let holders = store.holders("demo/q").expect("declared");
        assert_eq!(key_value(holders, Some(face(1))), Some(info(false, 1)));
        assert_eq!(key_value(holders, Some(face(2))), Some(info(true, 3)));
        // The complete id leaves: the face's value falls back to what its other id declared.
        store.remove_id(face(1), 2);
        assert_eq!(store.face_value(face(1), "demo/q"), Some(info(false, 3)));
        // Moving an id to another key takes its value with it.
        store.insert(face(2), 1, "demo/r", info(false, 4));
        assert_eq!(store.face_value(face(2), "demo/q"), None);
        assert_eq!(store.face_value(face(2), "demo/r"), Some(info(true, 0)));
        assert_eq!(store.key_value("demo/q"), Some(info(false, 3)));
    }

    #[test]
    fn a_change_logs_the_key_it_moved_and_a_read_logs_nothing() {
        let mut store = ClientSubStore::new();
        let v0 = store.version();
        store.insert(face(1), 1, "demo/a", ());
        let v1 = store.version();
        let _ = store.faces_intersecting("demo/a");
        let _ = store.names_key("demo/a");
        assert_eq!(store.version(), v1, "a read does not move the version");
        store.remove_id(face(1), 1);
        let mut since_v0 = Vec::new();
        assert!(store.changed_since(v0, |k| since_v0.push(k.to_owned())));
        assert_eq!(since_v0, ["demo/a", "demo/a"], "declared, then withdrawn");
        let mut since_v1 = Vec::new();
        assert!(store.changed_since(v1, |k| since_v1.push(k.to_owned())));
        assert_eq!(since_v1, ["demo/a"], "only the withdrawal is after v1");
        assert!(store.changed_since(store.version(), |_| panic!("nothing is after now")));
    }

    #[test]
    fn moving_an_id_logs_both_keys() {
        let mut store = ClientSubStore::new();
        store.insert(face(1), 1, "demo/a", ());
        let before = store.version();
        store.insert(face(1), 1, "demo/b", ());
        let mut moved = Vec::new();
        assert!(store.changed_since(before, |k| moved.push(k.to_owned())));
        moved.sort();
        assert_eq!(moved, ["demo/a", "demo/b"]);
    }

    #[test]
    fn dropping_a_face_moves_the_version_once_and_logs_each_distinct_key() {
        let mut store = ClientSubStore::new();
        store.insert(face(1), 1, "demo/a", ());
        store.insert(face(1), 2, "demo/a", ());
        store.insert(face(1), 3, "demo/b", ());
        let before = store.version();
        store.remove_face(face(1));
        assert_eq!(store.version(), before + 1);
        let mut moved = Vec::new();
        assert!(store.changed_since(before, |k| moved.push(k.to_owned())));
        moved.sort();
        assert_eq!(moved, ["demo/a", "demo/b"]);
        assert!(store.every_key().is_empty(), "the index let go of both");
    }

    #[test]
    fn a_reader_the_log_no_longer_reaches_is_told_so() {
        let mut store = ClientSubStore::new();
        let start = store.version();
        for i in 0..(LOG_CAPACITY as u64 + 10) {
            store.insert(face(1), i, &format!("demo/{i}"), ());
        }
        assert!(
            !store.changed_since(start, |_| {}),
            "the first changes fell out of the log"
        );
        let recent = store.version() - 5;
        let mut n = 0;
        assert!(store.changed_since(recent, |_| n += 1));
        assert_eq!(n, 5, "a reader within reach is answered");
    }

    /// The ring keeps the last [`LOG_CAPACITY`] changes across several rounds of its slots, in
    /// order, and a copy of the store taken between rounds keeps the log it had.
    #[test]
    fn the_log_keeps_the_last_changes_across_its_rounds_and_a_copy_keeps_its_own() {
        let mut store = ClientSubStore::new();
        let mut copy = None;
        let total = 3 * LOG_CAPACITY as u64 + 17;
        for i in 0..total {
            store.insert(face(1), 1, &format!("demo/{i}"), ());
            if i == LOG_CAPACITY as u64 + 5 {
                copy = Some((store.clone(), store.version()));
            }
        }
        // A move of an id logs the key it left and the key it took, so each insertion after the
        // first is two changes; the reader asks for the last ten.
        let mut moved = Vec::new();
        assert!(store.changed_since(store.version() - 10, |k| moved.push(k.to_owned())));
        let expected: Vec<String> = (total - 5..total)
            .rev()
            .flat_map(|i| [format!("demo/{i}"), format!("demo/{}", i - 1)])
            .collect();
        assert_eq!(moved, expected, "newest first, both keys of each move");
        let reach = store.version() - LOG_CAPACITY as u64;
        assert!(
            store.changed_since(reach, |_| {}),
            "the capacity is reached"
        );
        assert!(
            !store.changed_since(reach - 1, |_| {}),
            "one change past the capacity is not"
        );
        let (copy, at) = copy.expect("a copy was taken");
        let mut kept = Vec::new();
        assert!(copy.changed_since(at - 2, |k| kept.push(k.to_owned())));
        let i = LOG_CAPACITY as u64 + 5;
        assert_eq!(
            kept,
            [format!("demo/{i}"), format!("demo/{}", i - 1)],
            "the copy's log is as it was when it was taken"
        );
    }

    /// A key is held once: every face declaring it and the log point at the one copy.
    #[test]
    fn a_key_declared_by_two_faces_is_held_once() {
        let mut store = ClientSubStore::new();
        store.insert(face(1), 1, "demo/a", ());
        store.insert(face(2), 7, "demo/a", ());
        let first = store.get(&face(1)).and_then(|ids| ids.get(&1)).expect("1");
        let second = store.get(&face(2)).and_then(|ids| ids.get(&7)).expect("7");
        assert!(Arc::ptr_eq(first, second), "the second face shares the key");
        let logged = &store.log.entry(store.log.next - 1).1;
        assert!(Arc::ptr_eq(first, logged), "and so does the log");
    }
}
