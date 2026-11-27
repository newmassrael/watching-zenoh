//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-shm 1.10.2, file
// src/reader.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2): the reader's table of
// mapped segments (`ensure_data_segment`), which the metadata subscription repeats, made one
// table that holds a segment only while it is used.

//! The segments a reader mapped, held as long as something reads them.
//!
//! A segment a reader maps is owned by the buffers that point into it: each holds it by an
//! `Arc` (`PtrInSegment`, `OwnedMetadataDescriptor`). The table here only finds a mapping
//! again, by a `Weak`, so it keeps no segment alive by itself. Without more, a subscriber that
//! drops each sample before the next would unmap and map the provider's segment on every
//! message, so the table also keeps the most recently used segments by a strong reference, at
//! most a fixed number of them: the working set of a reader is the providers it reads from at
//! once, and one past that bound is let go of, least recently used first.
//!
//! So a reader maps a segment while a buffer of it is held, and otherwise only while it is among
//! the last ones used; a provider that is gone, whose segment no buffer holds, takes no memory
//! once readers of others have pushed it out. Upstream's tables keep every segment they ever
//! mapped for their whole life, a process-long table for the global storage, which is a mapping
//! (and the memory of an unlinked segment) for every provider a process ever read from.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock, Weak,
    },
};

use zenoh_core::{zread, zwrite};
use zenoh_result::ZResult;

/// How many segments a table keeps mapped with no buffer of theirs held, by default.
pub(crate) const RETAINED_SEGMENTS: usize = 16;

/// One segment the table knows.
struct Entry<V: ?Sized> {
    segment: Weak<V>,
    /// When it was last found, on the table's clock: what the least recently used is chosen by.
    used: AtomicU64,
}

struct Table<K, V: ?Sized> {
    entries: BTreeMap<K, Entry<V>>,
    /// The segments kept with no buffer of theirs held: at most the cache's capacity.
    kept: BTreeMap<K, Arc<V>>,
}

/// A table of mapped segments by id, holding each by a `Weak` and the most recently used ones,
/// up to `capacity`, by an `Arc`.
pub(crate) struct SegmentCache<K, V: ?Sized> {
    table: RwLock<Table<K, V>>,
    capacity: usize,
    clock: AtomicU64,
}

impl<K: Ord + Copy, V: ?Sized> SegmentCache<K, V> {
    /// An empty table that keeps at most `capacity` segments no buffer holds.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            table: RwLock::new(Table {
                entries: BTreeMap::new(),
                kept: BTreeMap::new(),
            }),
            capacity,
            clock: AtomicU64::new(0),
        }
    }

    fn tick(&self) -> u64 {
        self.clock.fetch_add(1, Ordering::Relaxed)
    }

    /// The segment `id`: the one mapped now, or the one `map` maps, which the table then knows.
    pub(crate) fn get_or_map(
        &self,
        id: K,
        map: impl FnOnce() -> ZResult<Arc<V>>,
    ) -> ZResult<Arc<V>> {
        // The common case, under the shared lock: a segment some buffer or the kept set holds.
        {
            let table = zread!(self.table);
            if let Some(found) = Self::live(&table, id, self.tick()) {
                return Ok(found);
            }
        }
        let mut table = zwrite!(self.table);
        // Another reader may have mapped it between the two locks.
        if let Some(found) = Self::live(&table, id, self.tick()) {
            return Ok(found);
        }
        let segment = map()?;
        // What no buffer and no kept slot holds any more is forgotten with the miss that finds
        // it, so the table is as long as what is mapped and not as long as what ever was.
        table
            .entries
            .retain(|_, entry| entry.segment.strong_count() > 0);
        table.entries.insert(
            id,
            Entry {
                segment: Arc::downgrade(&segment),
                used: AtomicU64::new(self.tick()),
            },
        );
        self.keep(&mut table, id, &segment);
        Ok(segment)
    }

    /// The segment `id` if it is still mapped, marked used at `now`.
    fn live(table: &Table<K, V>, id: K, now: u64) -> Option<Arc<V>> {
        let entry = table.entries.get(&id)?;
        let segment = entry.segment.upgrade()?;
        entry.used.store(now, Ordering::Relaxed);
        Some(segment)
    }

    /// Keep `segment` among the last ones used, letting go of the least recently used one kept
    /// when the set is full.
    fn keep(&self, table: &mut Table<K, V>, id: K, segment: &Arc<V>) {
        if self.capacity == 0 {
            return;
        }
        if table.kept.len() >= self.capacity {
            let oldest = table.kept.keys().copied().min_by_key(|key| {
                table
                    .entries
                    .get(key)
                    .map_or(0, |entry| entry.used.load(Ordering::Relaxed))
            });
            if let Some(oldest) = oldest {
                table.kept.remove(&oldest);
            }
        }
        table.kept.insert(id, Arc::clone(segment));
    }

    /// How many segments the table holds mapped now, by a buffer or by its kept set.
    pub(crate) fn mapped(&self) -> usize {
        zread!(self.table)
            .entries
            .values()
            .filter(|entry| entry.segment.strong_count() > 0)
            .count()
    }
}

impl<K, V: ?Sized> std::fmt::Debug for SegmentCache<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("SegmentCache");
        debug.field("capacity", &self.capacity);
        match self.table.try_read() {
            Ok(table) => debug
                .field("known", &table.entries.len())
                .field("kept", &table.kept.len()),
            Err(_) => debug.field("table", &"<locked>"),
        };
        debug.finish()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    /// A segment that counts how often it is mapped and how many are mapped now.
    struct Fake {
        alive: Arc<AtomicUsize>,
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            self.alive.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct Mapper {
        alive: Arc<AtomicUsize>,
        maps: AtomicUsize,
    }

    impl Mapper {
        fn new() -> Self {
            Self {
                alive: Arc::new(AtomicUsize::new(0)),
                maps: AtomicUsize::new(0),
            }
        }

        fn map(&self) -> ZResult<Arc<Fake>> {
            self.maps.fetch_add(1, Ordering::SeqCst);
            self.alive.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(Fake {
                alive: Arc::clone(&self.alive),
            }))
        }
    }

    /// With no kept set, a segment is mapped exactly while a buffer holds it: the second read
    /// while the first buffer lives finds the same mapping, and once no buffer holds it the
    /// mapping is gone and the next read maps it again. Turned red by a table that keeps what it
    /// maps (upstream's), or by one that maps a segment a buffer still holds a second time.
    #[test]
    fn a_segment_lives_exactly_while_a_buffer_holds_it() {
        let cache = SegmentCache::<u32, Fake>::new(0);
        let mapper = Mapper::new();
        let first = cache.get_or_map(7, || mapper.map()).unwrap();
        let second = cache.get_or_map(7, || mapper.map()).unwrap();
        assert!(
            Arc::ptr_eq(&first, &second),
            "a held segment is found, not mapped again"
        );
        assert_eq!(mapper.maps.load(Ordering::SeqCst), 1);
        assert_eq!(cache.mapped(), 1);
        drop((first, second));
        assert_eq!(
            mapper.alive.load(Ordering::SeqCst),
            0,
            "no buffer holds it: unmapped"
        );
        assert_eq!(cache.mapped(), 0);
        let _again = cache.get_or_map(7, || mapper.map()).unwrap();
        assert_eq!(mapper.maps.load(Ordering::SeqCst), 2);
    }

    /// The kept set holds the last segments used and no more: a reader that drops each buffer
    /// before the next reads its provider's segment through one mapping, and a segment pushed out
    /// of the set by others, with no buffer of it held, is unmapped. Turned red by a set that
    /// grows past its capacity, or by one that lets go of the most recently used segment first.
    #[test]
    fn the_kept_set_holds_the_least_recently_used_segments_out() {
        let cache = SegmentCache::<u32, Fake>::new(2);
        let mapper = Mapper::new();
        for _ in 0..3 {
            drop(cache.get_or_map(1, || mapper.map()).unwrap());
        }
        assert_eq!(
            mapper.maps.load(Ordering::SeqCst),
            1,
            "a kept segment is not mapped again"
        );
        drop(cache.get_or_map(2, || mapper.map()).unwrap());
        // 1 is used again, so 2 is the least recently used when 3 comes.
        drop(cache.get_or_map(1, || mapper.map()).unwrap());
        drop(cache.get_or_map(3, || mapper.map()).unwrap());
        assert_eq!(mapper.alive.load(Ordering::SeqCst), 2, "the set holds two");
        assert_eq!(cache.mapped(), 2);
        let maps = mapper.maps.load(Ordering::SeqCst);
        drop(cache.get_or_map(1, || mapper.map()).unwrap());
        assert_eq!(mapper.maps.load(Ordering::SeqCst), maps, "1 stayed");
        drop(cache.get_or_map(2, || mapper.map()).unwrap());
        assert_eq!(
            mapper.maps.load(Ordering::SeqCst),
            maps + 1,
            "2 went and is mapped again"
        );
    }

    /// A segment a buffer holds stays mapped however many others push it out of the kept set,
    /// and a failed map leaves the table as it was.
    #[test]
    fn a_held_segment_outlives_the_kept_set_and_a_failed_map_changes_nothing() {
        let cache = SegmentCache::<u32, Fake>::new(1);
        let mapper = Mapper::new();
        let held = cache.get_or_map(1, || mapper.map()).unwrap();
        for id in 2..6 {
            drop(cache.get_or_map(id, || mapper.map()).unwrap());
        }
        assert_eq!(cache.mapped(), 2, "the held one and the last one kept");
        let found = cache.get_or_map(1, || mapper.map()).unwrap();
        assert!(Arc::ptr_eq(&held, &found));
        assert!(cache
            .get_or_map(9, || zenoh_result::bail!("no such segment"))
            .is_err());
        assert_eq!(cache.mapped(), 2);
    }
}
