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

use wz_session_core::keyexpr_match::keyexpr_intersects_target;
use wz_session_core::queryable_info::QueryableInfo;

use crate::accept_loop::FaceId;
use crate::keyexpr_index::KeyexprIndex;
use crate::persistent_map::PersistentMap;

/// How many changed keys the log keeps. A cache consulted by every message is never this far behind;
/// one that is drops its routes instead.
const LOG_CAPACITY: usize = 4096;

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

/// The declarations on one key: per face, the ids declaring it and the value each carries.
pub(crate) type Holders<V> = PersistentMap<FaceId, PersistentMap<u64, V>>;

/// The client faces' declarations on one plane: per face, by declaration id; and by key.
#[derive(Debug, Clone)]
pub(crate) struct ClientStore<V> {
    /// Per face, the declaration ids and the key each names.
    by_face: PersistentMap<FaceId, PersistentMap<u64, String>>,
    /// Per key some client declares, the faces declaring it, each with its ids on it and their values.
    by_key: PersistentMap<String, Holders<V>>,
    /// The keys in `by_key`, each held under itself: the keys an asked keyexpr may intersect, found
    /// without trying every key.
    keys: KeyexprIndex<String>,
    /// How many changes the store has seen; wraps.
    version: u64,
    /// The keys changed, each under the version its change produced, by the order they were logged
    /// in: the entries numbered from `log_first` up to before `log_next`. A change that drops a face
    /// logs several keys under one version, so the log is numbered by entry and not by version.
    log: PersistentMap<u64, (u64, String)>,
    /// The number of the oldest entry the log holds.
    log_first: u64,
    /// The number the next entry is logged under.
    log_next: u64,
    /// The version of the newest change whose entries the log has dropped, or 0 while none has been.
    /// A reader that was fresh at this version or later is answered from the log; an earlier one is not.
    log_floor: u64,
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
            by_face: PersistentMap::default(),
            by_key: PersistentMap::default(),
            keys: KeyexprIndex::default(),
            version: 0,
            log: PersistentMap::default(),
            log_first: 0,
            log_next: 0,
            log_floor: 0,
        }
    }
}

impl<V> Deref for ClientStore<V> {
    type Target = PersistentMap<FaceId, PersistentMap<u64, String>>;

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
        keyexpr: String,
        value: V,
    ) -> Option<String> {
        let displaced = self
            .by_face
            .get_mut_or_default(face)
            .insert(id, keyexpr.clone());
        // The id leaves the key it named before it is entered under the one it names now, so an id
        // declared again on its own key is held once.
        if let Some(old) = &displaced {
            self.index_remove(face, id, old);
            if *old != keyexpr {
                self.record(old);
            }
        }
        self.record(&keyexpr);
        self.index_add(face, id, &keyexpr, value);
        displaced
    }

    /// Withdraw `id` of `face`, returning the key it named. A face left with nothing is dropped.
    pub(crate) fn remove_id(&mut self, face: FaceId, id: u64) -> Option<String> {
        // Looked up before it is written, so that an id the face does not hold copies nothing.
        if !self.by_face.get(&face)?.contains_key(&id) {
            return None;
        }
        let by_id = self.by_face.get_mut(&face)?;
        let removed = by_id.remove(&id)?;
        if by_id.is_empty() {
            self.by_face.remove(&face);
        }
        self.record(&removed);
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
    pub(crate) fn remove_face(&mut self, face: FaceId) -> Option<PersistentMap<u64, String>> {
        let removed = self.by_face.remove(&face)?;
        // One change for the whole face: the version moves once, and each distinct key it held is
        // logged under it.
        self.version = self.version.wrapping_add(1);
        let mut seen: HashSet<&str> = HashSet::new();
        for (id, keyexpr) in &removed {
            if seen.insert(keyexpr) {
                self.log_key(keyexpr);
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
                let holders = self
                    .by_key
                    .get(key.as_str())
                    .expect("an indexed key has holders");
                (key.as_str(), holders)
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
            .map(|(key, holders)| (key.as_str(), holders))
            .into_iter()
            .collect()
    }

    /// Every key some client declares, with its holders: the answer to an unrestricted interest.
    pub(crate) fn every_key(&self) -> Vec<(&str, &Holders<V>)> {
        self.by_key
            .iter()
            .map(|(key, holders)| (key.as_str(), holders))
            .collect()
    }

    /// Feed `visit` every key changed after `version`, and say whether that was all of them. `false`
    /// means the log no longer reaches back that far, and the caller must treat every key as changed.
    pub(crate) fn changed_since(&self, version: u64, mut visit: impl FnMut(&str)) -> bool {
        let behind = self.version.wrapping_sub(version);
        let reach = self.version.wrapping_sub(self.log_floor);
        if behind > reach {
            return false;
        }
        // Newest first, as far back as the reader is behind.
        let mut entry = self.log_next;
        while entry != self.log_first {
            entry = entry.wrapping_sub(1);
            let (at, keyexpr) = self
                .log
                .get(&entry)
                .expect("the log holds every entry from the first to before the next");
            if self.version.wrapping_sub(*at) >= behind {
                break;
            }
            visit(keyexpr);
        }
        true
    }

    /// One change that moved `keyexpr`.
    fn record(&mut self, keyexpr: &str) {
        self.version = self.version.wrapping_add(1);
        self.log_key(keyexpr);
    }

    /// Log `keyexpr` under the current version, dropping the oldest entry past the capacity.
    fn log_key(&mut self, keyexpr: &str) {
        self.log
            .insert(self.log_next, (self.version, keyexpr.to_owned()));
        self.log_next = self.log_next.wrapping_add(1);
        while self.log.len() > LOG_CAPACITY {
            if let Some((at, _)) = self.log.remove(&self.log_first) {
                self.log_floor = at;
            }
            self.log_first = self.log_first.wrapping_add(1);
        }
    }

    fn index_add(&mut self, face: FaceId, id: u64, keyexpr: &str, value: V) {
        if !self.by_key.contains_key(keyexpr) {
            self.keys.insert(keyexpr, keyexpr.to_owned());
        }
        self.by_key
            .get_mut_or_default(keyexpr.to_owned())
            .get_mut_or_default(face)
            .insert(id, value);
    }

    fn index_remove(&mut self, face: FaceId, id: u64, keyexpr: &str) {
        let Some(holders) = self.by_key.get_mut(keyexpr) else {
            return;
        };
        if let Some(ids) = holders.get_mut(&face) {
            ids.remove(&id);
            if ids.is_empty() {
                holders.remove(&face);
            }
        }
        if holders.is_empty() {
            self.by_key.remove(keyexpr);
            self.keys.remove(keyexpr, &keyexpr.to_owned());
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
            .cloned()
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
            .filter(|(_, ids)| ids.values().any(|sub| sub == keyexpr))
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
        store.insert(face(1), 1, "demo/a".into(), ());
        store.insert(face(2), 1, "demo/b".into(), ());
        store.insert(face(3), 1, "demo/*".into(), ());
        store.insert(face(4), 1, "demo/**".into(), ());
        store.insert(face(5), 1, "other/a".into(), ());
        store.insert(face(5), 2, "demo/a".into(), ());
        store.insert(face(6), 1, "demo/a/*".into(), ());
        store.insert(face(7), 1, "**".into(), ());
        store.insert(face(8), 1, "demo/c/d/e".into(), ());
        for probe in PROBES {
            assert_answers(&store, probe);
        }
        // Withdraw some, displace one, drop a face: the index follows each.
        store.remove_id(face(5), 2);
        store.insert(face(2), 1, "demo/c/d/e".into(), ());
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
        store.insert(face(1), 1, "demo/a".into(), ());
        store.insert(face(1), 2, "demo/a".into(), ());
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
        store.insert(face(1), 1, "demo/q".into(), info(false, 0));
        let displaced = store.insert(face(1), 1, "demo/q".into(), info(true, 0));
        assert_eq!(displaced.as_deref(), Some("demo/q"));
        let holders = store.holders("demo/q").expect("still declared");
        assert_eq!(holders.get(&face(1)).map(PersistentMap::len), Some(1));
        assert_eq!(
            store.face_value(face(1), "demo/q"),
            Some(info(true, 0)),
            "the newer value replaced the older"
        );
        assert_eq!(store.remove_id(face(1), 1).as_deref(), Some("demo/q"));
        assert!(!store.names_key("demo/q"), "one withdrawal leaves nothing");
    }

    #[test]
    fn a_face_value_is_the_merge_of_its_ids_and_a_key_value_of_its_faces() {
        let mut store = ClientQablStore::new();
        store.insert(face(1), 1, "demo/q".into(), info(false, 3));
        store.insert(face(1), 2, "demo/q".into(), info(true, 5));
        store.insert(face(2), 1, "demo/q".into(), info(false, 1));
        store.insert(face(2), 2, "demo/r".into(), info(true, 0));
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
        store.insert(face(2), 1, "demo/r".into(), info(false, 4));
        assert_eq!(store.face_value(face(2), "demo/q"), None);
        assert_eq!(store.face_value(face(2), "demo/r"), Some(info(true, 0)));
        assert_eq!(store.key_value("demo/q"), Some(info(false, 3)));
    }

    #[test]
    fn a_change_logs_the_key_it_moved_and_a_read_logs_nothing() {
        let mut store = ClientSubStore::new();
        let v0 = store.version();
        store.insert(face(1), 1, "demo/a".into(), ());
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
        store.insert(face(1), 1, "demo/a".into(), ());
        let before = store.version();
        store.insert(face(1), 1, "demo/b".into(), ());
        let mut moved = Vec::new();
        assert!(store.changed_since(before, |k| moved.push(k.to_owned())));
        moved.sort();
        assert_eq!(moved, ["demo/a", "demo/b"]);
    }

    #[test]
    fn dropping_a_face_moves_the_version_once_and_logs_each_distinct_key() {
        let mut store = ClientSubStore::new();
        store.insert(face(1), 1, "demo/a".into(), ());
        store.insert(face(1), 2, "demo/a".into(), ());
        store.insert(face(1), 3, "demo/b".into(), ());
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
            store.insert(face(1), i, format!("demo/{i}"), ());
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
}
