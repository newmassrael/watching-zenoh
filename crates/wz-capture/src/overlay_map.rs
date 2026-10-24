// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A MAP THAT IS CHEAP TO COPY WHILE IT IS BEING GROWN.
//!
//! # What it is for
//!
//! The census planes keep a verdict for every record they have judged, so the map
//! grows with the capture. A plane that is kept between calls (see
//! `crate::ordered_fold`) is read by copying it: a plane's state is a fold that
//! goes on, and a reading that finishes the fold (judging what is still open) must
//! not finish the one that is kept. Copying a map of every record is the whole cost
//! of the call, and it grows with the capture.
//!
//! # How
//!
//! Two layers. `base` is shared (reference counted) and is never written while a
//! copy of it is alive; `delta` is the recent writes, owned by each copy. Reading
//! looks in `delta` first. Writing a key puts it in `delta`, seeded from the value
//! in `base`, so what is read back is exactly what a single map would hold. A copy
//! costs one pointer and the size of `delta`.
//!
//! When `delta` has grown past a fraction of `base`, the next write folds it into
//! `base` — but only if nothing else shares `base`, so a copy that is alive (a
//! reading in progress) never makes the fold copy the whole map, and the writes a
//! reading makes (the verdicts of exchanges it judges unclosed) land in the
//! reading's own `delta` and are gone with it.
//!
//! The amortised cost of a write is the cost of one insertion into a sorted chunk
//! (`wz_session_core::sorted_chunks`), and the cost of a copy no longer depends on
//! how many keys the map holds. Both layers are sorted chunks and not B-trees so
//! that the bytes they hold are the capacities of what they allocated, which a
//! memory report can state exactly.

use alloc::sync::Arc;

use wz_session_core::sorted_chunks::SortedChunks;

/// A map whose copies share what was written before them. See the module docs.
#[derive(Debug, Clone)]
pub(crate) struct OverlayMap<K: Ord, V> {
    base: Arc<SortedChunks<K, V>>,
    delta: SortedChunks<K, V>,
}

impl<K: Ord, V> Default for OverlayMap<K, V> {
    fn default() -> Self {
        Self {
            base: Arc::new(SortedChunks::new()),
            delta: SortedChunks::new(),
        }
    }
}

impl<K: Ord + Clone, V: Clone + Default> OverlayMap<K, V> {
    /// The value at `key`: the recent write if there is one, otherwise the shared
    /// one.
    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        self.delta.get(key).or_else(|| self.base.get(key))
    }

    /// The value at `key` for writing, made from the shared one (or the default)
    /// the first time this copy writes the key. This is `entry(key).or_default()`
    /// of a single map, and what it returns is the one value under that key.
    pub(crate) fn entry_or_default(&mut self, key: K) -> &mut V {
        self.fold_into_base_if_due();
        if !self.delta.contains_key(&key) {
            let seed = self.base.get(&key).cloned().unwrap_or_default();
            self.delta.insert(key.clone(), seed);
        }
        self.delta
            .get_mut(&key)
            .expect("the key was put in `delta` just above")
    }

    /// How many keys the map holds.
    #[cfg(any(test, all(feature = "dissect", feature = "network-codecs")))]
    pub(crate) fn len(&self) -> usize {
        let fresh = self
            .delta
            .iter()
            .filter(|(key, _)| !self.base.contains_key(key))
            .count();
        self.base.len() + fresh
    }

    /// Bytes the two layers hold, as their chunks' capacities say, and what
    /// `owned` says each value holds beyond its slot. It reads every value, so its
    /// cost follows the map; it is asked for on a report, not on a walk.
    #[cfg(all(feature = "dissect", feature = "network-codecs"))]
    pub(crate) fn memory(&self, owned: impl Fn(&V) -> usize) -> usize {
        self.base.allocated_bytes()
            + self.delta.allocated_bytes()
            + self
                .base
                .values()
                .chain(self.delta.values())
                .map(owned)
                .sum::<usize>()
    }

    /// Fold `delta` into `base` when it has grown past a fraction of it, and when
    /// nothing else holds `base`, which is what keeps this from copying it.
    fn fold_into_base_if_due(&mut self) {
        if self.delta.len() <= 64 + self.base.len() / 8 {
            return;
        }
        if let Some(base) = Arc::get_mut(&mut self.base) {
            base.append(&mut self.delta);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    /// A map and a plain one given the same writes read the same, through folds
    /// into the base and through copies that were written to and dropped.
    #[test]
    fn it_reads_back_exactly_what_a_single_map_holds() {
        let mut overlay: OverlayMap<u32, u32> = OverlayMap::default();
        let mut plain: BTreeMap<u32, u32> = BTreeMap::new();
        for step in 0..2000u32 {
            let key = (step * 7919) % 500;
            *overlay.entry_or_default(key) += step;
            *plain.entry(key).or_default() += step;
            if step % 37 == 0 {
                // A reading: a copy that is written to and dropped.
                let mut reading = overlay.clone();
                *reading.entry_or_default(10_000 + step) += 1;
                assert_eq!(reading.get(&(10_000 + step)), Some(&1));
            }
            if step % 101 == 0 {
                for (key, value) in &plain {
                    assert_eq!(overlay.get(key), Some(value), "step {step}, key {key}");
                }
                assert_eq!(overlay.len(), plain.len());
            }
        }
        assert_eq!(overlay.get(&10_000), None, "a reading's write is not kept");
    }

    /// The point of it: a copy shares the shared layer and does not copy it.
    #[test]
    fn a_copy_shares_the_base_and_a_reading_never_makes_a_fold_copy_it() {
        let mut overlay: OverlayMap<u32, u32> = OverlayMap::default();
        for key in 0..5000u32 {
            *overlay.entry_or_default(key) += 1;
        }
        let reading = overlay.clone();
        assert!(
            Arc::ptr_eq(&overlay.base, &reading.base),
            "a copy must share the base"
        );
        // Writes while the reading is alive do not fold (the base is shared), so
        // they cannot copy it.
        for key in 0..2000u32 {
            *overlay.entry_or_default(key) += 1;
        }
        assert!(
            Arc::ptr_eq(&overlay.base, &reading.base),
            "a fold must not copy a base another copy holds"
        );
        drop(reading);
        // With the reading gone the next write folds in place.
        let before = Arc::as_ptr(&overlay.base);
        *overlay.entry_or_default(0) += 1;
        assert_eq!(Arc::as_ptr(&overlay.base), before, "the fold is in place");
    }
}
