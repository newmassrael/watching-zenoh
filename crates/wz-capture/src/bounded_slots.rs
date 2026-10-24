// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A FEW VALUES KEPT BY WHAT THEY WERE MADE FOR, the least recently used given up
//! first.
//!
//! # What this is for
//!
//! A fold or a set of remembered words is a fact about ONE selector, so a handle
//! that is asked under several needs a value per selector. Keeping one for each
//! selector ever seen would grow without bound, so the count is held, and when
//! more are in use than there are slots the one asked longest ago is given up and
//! made again, from nothing, the next time its selector is asked. That costs what
//! it always cost and is never a wrong answer.
//!
//! One place owns this so the census memory and the selection memory cannot part
//! on what "least recently used" means, and so the count given up is tallied in
//! one place: a removal here is a loss of folded work, and the gate that reads
//! every removal in this crate wants it counted beside the removal.

use alloc::vec::Vec;

/// The most selector memories one handle may keep. A memory is a set of folded
/// tables, not a copy of the capture, but it is not free either, and an unbounded
/// count would let a caller that never repeats a selector grow without limit.
pub const MAX_SELECTOR_MEMORIES: usize = 64;

/// What the slots have given up.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SlotStats {
    /// Values given up to make room, or because the count was lowered.
    pub evicted: u64,
}

/// At most `capacity` values, each under its key, the most recently used last.
#[derive(Debug, Clone)]
pub(crate) struct BoundedSlots<K, V> {
    entries: Vec<(K, V)>,
    capacity: usize,
    stats: SlotStats,
}

impl<K, V> Default for BoundedSlots<K, V> {
    /// One slot, which is what a handle kept before there could be several.
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            capacity: 1,
            stats: SlotStats::default(),
        }
    }
}

impl<K: PartialEq, V> BoundedSlots<K, V> {
    /// How many values are kept at once.
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    /// Keep up to `n` values, `n` held to `1..=`[`MAX_SELECTOR_MEMORIES`], and
    /// return the count in effect. Lowering it gives up the least recently used
    /// first.
    pub(crate) fn set_capacity(&mut self, n: usize) -> usize {
        self.capacity = n.clamp(1, MAX_SELECTOR_MEMORIES);
        self.trim();
        self.capacity
    }

    /// How many keys hold a value now.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no key holds a value.
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Values given up since these slots were made.
    pub(crate) fn evicted(&self) -> u64 {
        self.stats.evicted
    }

    /// Give up the least recently used values beyond the capacity, counting them.
    fn trim(&mut self) {
        let excess = self.entries.len().saturating_sub(self.capacity);
        self.stats.evicted += excess as u64;
        self.entries.drain(..excess);
    }

    /// The value under `key`, made by `make` when there is none, and marked the
    /// most recently used. Making one may give up the least recently used.
    pub(crate) fn touch(&mut self, key: &K, make: impl FnOnce() -> V) -> &mut V
    where
        K: Clone,
    {
        match self.entries.iter().position(|(k, _)| k == key) {
            // Move it to the end by rotating, not by taking it out and putting it
            // back: nothing is removed, so nothing is lost.
            Some(at) => self.entries[at..].rotate_left(1),
            None => {
                self.entries.push((key.clone(), make()));
                self.trim();
            }
        }
        &mut self
            .entries
            .last_mut()
            .expect("an entry was made or moved last above")
            .1
    }

    /// Every memory held, oldest first.
    #[cfg(feature = "dissect")]
    pub(crate) fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.iter().map(|(_, v)| v)
    }

    /// The key and value last touched, if any.
    pub(crate) fn newest_mut(&mut self) -> Option<(&K, &mut V)> {
        self.entries.last_mut().map(|(k, v)| (&*k, v))
    }
}
