// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The subscriptions a node's client faces hold, indexed by key and changed only through methods
//! that say which key moved.
//!
//! This is the store the client leg of a data route is computed from and cached against
//! ([`client_route`](crate::linkstate_forward)). Three things come with it that a plain
//! `Versioned<HashMap<..>>` did not give:
//!
//! - AN INDEX BY KEY. A route for a literal key is found by one lookup of that key, plus a scan of the
//!   subscriptions that have a wildcard in them, instead of a scan of every subscription. Whether a key
//!   is declared by any client at all (the question every route cache asks on a miss) is one lookup too.
//! - A CHANGE LOG. Every change records the key it declared or withdrew under the version it produced,
//!   so a cache that was fresh at an earlier version can ask which keys moved since and retire only the
//!   routes those keys intersect ([`changed_since`](ClientSubStore::changed_since)).
//! - NO UNRECORDED CHANGE. The per-face map is readable through `Deref` and not writable: there is no
//!   `DerefMut`, so a change that did not go through a method here, and so did not record its key, does
//!   not compile. That is the property that let the cache read its freshness from the table instead of
//!   being told (`route_cache`), kept while the invalidation became incremental.
//!
//! The log is bounded. A reader that fell further behind than it reaches is told so
//! (`changed_since` answers `false`) and drops everything, which is the answer the unindexed store gave
//! to every change.

use std::collections::{HashMap, HashSet, VecDeque};
use std::ops::Deref;

use wz_session_core::keyexpr_match::keyexpr_intersects_target;

use crate::accept_loop::FaceId;

/// How many changed keys the log keeps. A cache consulted by every message is never this far behind;
/// one that is drops its routes instead.
const LOG_CAPACITY: usize = 4096;

/// The client faces' subscriptions: per face, by declaration id; and by key.
#[derive(Debug, Default)]
pub(crate) struct ClientSubStore {
    /// Per face, the subscription ids and the key each names.
    by_face: HashMap<FaceId, HashMap<u64, String>>,
    /// Per key some client subscribes to, the faces subscribing it and how many ids each holds on it.
    by_key: HashMap<String, HashMap<FaceId, usize>>,
    /// The keys in `by_key` that contain a wildcard: the only ones a literal key can intersect without
    /// being equal to.
    wild: HashSet<String>,
    /// How many changes the store has seen; wraps.
    version: u64,
    /// The keys changed, each under the version its change produced, oldest first.
    log: VecDeque<(u64, String)>,
    /// The version of the newest change whose entries the log has dropped, or 0 while none has been.
    /// A reader that was fresh at this version or later is answered from the log; an earlier one is not.
    log_floor: u64,
}

impl Deref for ClientSubStore {
    type Target = HashMap<FaceId, HashMap<u64, String>>;

    fn deref(&self) -> &Self::Target {
        &self.by_face
    }
}

/// Whether `keyexpr` has a wildcard chunk. A zenoh key expression spells its wildcards `*`, `**` and
/// `$*`, and every one contains a `*`.
fn has_wildcard(keyexpr: &str) -> bool {
    keyexpr.contains('*')
}

impl ClientSubStore {
    /// An empty store at version 0.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// How many changes the store has seen. A route cached at one value is stale at another unless
    /// [`changed_since`](Self::changed_since) says the keys that moved did not touch it.
    pub(crate) fn version(&self) -> u64 {
        self.version
    }

    /// Whether any client subscribes to exactly `keyexpr`: the resource question every route cache
    /// asks on a miss.
    pub(crate) fn names_key(&self, keyexpr: &str) -> bool {
        self.by_key.contains_key(keyexpr)
    }

    /// Subscribe `id` of `face` to `keyexpr`, returning the key `id` named before, if it named one.
    pub(crate) fn insert(&mut self, face: FaceId, id: u64, keyexpr: String) -> Option<String> {
        self.record(&keyexpr);
        self.index_add(face, &keyexpr);
        let displaced = self
            .by_face
            .entry(face)
            .or_default()
            .insert(id, keyexpr.clone());
        if let Some(old) = &displaced {
            self.record(old);
            self.index_remove(face, old);
        }
        displaced
    }

    /// Withdraw `id` of `face`, returning the key it named. A face left with nothing is dropped.
    pub(crate) fn remove_id(&mut self, face: FaceId, id: u64) -> Option<String> {
        let by_id = self.by_face.get_mut(&face)?;
        let removed = by_id.remove(&id)?;
        if by_id.is_empty() {
            self.by_face.remove(&face);
        }
        self.record(&removed);
        self.index_remove(face, &removed);
        Some(removed)
    }

    /// Withdraw `id` of `face` and say whether `face` no longer subscribes to the key `id` named, that
    /// is whether no other id of the face names it. `false` when `id` was not held.
    /// The router's broker hat withdraws by id and asks this; the peer withdraws by id and asks which
    /// key it named ([`remove_id`](Self::remove_id)).
    #[cfg(feature = "routing-router-hat")]
    pub(crate) fn remove_id_leaving_key(&mut self, face: FaceId, id: u64) -> bool {
        let Some(removed) = self.remove_id(face, id) else {
            return false;
        };
        !self
            .by_face
            .get(&face)
            .is_some_and(|by_id| by_id.values().any(|k| *k == removed))
    }

    /// Withdraw every subscription of `face`, returning what it held by id.
    pub(crate) fn remove_face(&mut self, face: FaceId) -> Option<HashMap<u64, String>> {
        let removed = self.by_face.remove(&face)?;
        // One change for the whole face: the version moves once, and each distinct key it held is
        // logged under it.
        self.version = self.version.wrapping_add(1);
        let mut seen: HashSet<&str> = HashSet::new();
        for keyexpr in removed.values() {
            if seen.insert(keyexpr) {
                self.log_key(keyexpr);
            }
            self.index_remove(face, keyexpr);
        }
        Some(removed)
    }

    /// The faces with a subscription that intersects `keyexpr`, in face order.
    ///
    /// A literal `keyexpr` finds its literal subscribers by one lookup and the wildcard subscriptions by
    /// a scan of only those; a `keyexpr` with a wildcard of its own is matched against every key, as
    /// there is nothing to look up. The intersection test is the one the scan always used, so the
    /// answer is the same set.
    pub(crate) fn faces_intersecting(&self, keyexpr: &str) -> Vec<FaceId> {
        let target: Vec<&str> = keyexpr.split('/').collect();
        let mut faces: Vec<FaceId> = Vec::new();
        let mut take = |key: &str, holders: &HashMap<FaceId, usize>| {
            if keyexpr_intersects_target(key, &target) {
                faces.extend(holders.keys().copied());
            }
        };
        if has_wildcard(keyexpr) {
            for (key, holders) in &self.by_key {
                take(key, holders);
            }
        } else {
            if let Some((key, holders)) = self.by_key.get_key_value(keyexpr) {
                take(key, holders);
            }
            for key in &self.wild {
                if let Some(holders) = self.by_key.get(key) {
                    take(key, holders);
                }
            }
        }
        faces.sort_unstable();
        faces.dedup();
        faces
    }

    /// Feed `visit` every key changed after `version`, and say whether that was all of them. `false`
    /// means the log no longer reaches back that far, and the caller must treat every key as changed.
    pub(crate) fn changed_since(&self, version: u64, mut visit: impl FnMut(&str)) -> bool {
        let behind = self.version.wrapping_sub(version);
        let reach = self.version.wrapping_sub(self.log_floor);
        if behind > reach {
            return false;
        }
        for (at, keyexpr) in self.log.iter().rev() {
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
        self.log.push_back((self.version, keyexpr.to_owned()));
        while self.log.len() > LOG_CAPACITY {
            if let Some((at, _)) = self.log.pop_front() {
                self.log_floor = at;
            }
        }
    }

    fn index_add(&mut self, face: FaceId, keyexpr: &str) {
        if !self.by_key.contains_key(keyexpr) && has_wildcard(keyexpr) {
            self.wild.insert(keyexpr.to_owned());
        }
        *self
            .by_key
            .entry(keyexpr.to_owned())
            .or_default()
            .entry(face)
            .or_insert(0) += 1;
    }

    fn index_remove(&mut self, face: FaceId, keyexpr: &str) {
        let Some(holders) = self.by_key.get_mut(keyexpr) else {
            return;
        };
        if let Some(count) = holders.get_mut(&face) {
            *count -= 1;
            if *count == 0 {
                holders.remove(&face);
            }
        }
        if holders.is_empty() {
            self.by_key.remove(keyexpr);
            self.wild.remove(keyexpr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn face(n: u64) -> FaceId {
        FaceId(n)
    }

    /// The scan the store replaces, as the reference its index must agree with.
    fn scanned(store: &ClientSubStore, keyexpr: &str) -> Vec<FaceId> {
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
        store.insert(face(1), 1, "demo/a".into());
        store.insert(face(2), 1, "demo/b".into());
        store.insert(face(3), 1, "demo/*".into());
        store.insert(face(4), 1, "demo/**".into());
        store.insert(face(5), 1, "other/a".into());
        store.insert(face(5), 2, "demo/a".into());
        store.insert(face(6), 1, "demo/a/*".into());
        store.insert(face(7), 1, "**".into());
        store.insert(face(8), 1, "demo/c/d/e".into());
        for probe in PROBES {
            assert_eq!(
                store.faces_intersecting(probe),
                scanned(&store, probe),
                "probe {probe}"
            );
        }
        // Withdraw some, displace one, drop a face: the index follows each.
        store.remove_id(face(5), 2);
        store.insert(face(2), 1, "demo/c/d/e".into());
        store.remove_face(face(3));
        store.remove_id(face(7), 1);
        for probe in PROBES {
            assert_eq!(
                store.faces_intersecting(probe),
                scanned(&store, probe),
                "after changes, probe {probe}"
            );
        }
    }

    #[cfg(feature = "routing-router-hat")]
    #[test]
    fn two_ids_of_one_face_on_one_key_keep_the_key_until_the_last_goes() {
        let mut store = ClientSubStore::new();
        store.insert(face(1), 1, "demo/a".into());
        store.insert(face(1), 2, "demo/a".into());
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
    fn a_change_logs_the_key_it_moved_and_a_read_logs_nothing() {
        let mut store = ClientSubStore::new();
        let v0 = store.version();
        store.insert(face(1), 1, "demo/a".into());
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
    fn dropping_a_face_moves_the_version_once_and_logs_each_distinct_key() {
        let mut store = ClientSubStore::new();
        store.insert(face(1), 1, "demo/a".into());
        store.insert(face(1), 2, "demo/a".into());
        store.insert(face(1), 3, "demo/b".into());
        let before = store.version();
        store.remove_face(face(1));
        assert_eq!(store.version(), before + 1);
        let mut moved = Vec::new();
        assert!(store.changed_since(before, |k| moved.push(k.to_owned())));
        moved.sort();
        assert_eq!(moved, ["demo/a", "demo/b"]);
    }

    #[test]
    fn a_reader_the_log_no_longer_reaches_is_told_so() {
        let mut store = ClientSubStore::new();
        let start = store.version();
        for i in 0..(LOG_CAPACITY as u64 + 10) {
            store.insert(face(1), i, format!("demo/{i}"));
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
