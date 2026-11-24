// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The table one kind of an advanced subscriber's sources lies in: a row for each source, as
//! many as the build states ([`caps::MAX_ADVANCED_SOURCES`]), kept with the subscriber, so
//! meeting a new source takes no memory.
//!
//! A source met while every row is taken takes the row of the one met longest ago, among those
//! the caller lets go, as upstream's timestamped table lets its least recently used entry go. A
//! row the caller keeps (one with samples held or a get in flight) is never taken, so when every
//! row is kept the new source has none and is not ordered.

use wz_session_core::caps;

/// A source's row: its key, its state, and when it was last met, in its table's own count.
struct Row<K, V> {
    key: K,
    value: V,
    met: u64,
}

/// The sources of one kind a subscriber orders at once.
pub(super) struct Sources<K, V> {
    rows: [Option<Row<K, V>>; caps::MAX_ADVANCED_SOURCES],
    /// How many times a source was met, which orders the rows by when each was last met.
    met: u64,
}

impl<K: PartialEq + Clone, V> Sources<K, V> {
    /// A table with no source.
    pub(super) fn new() -> Self {
        Self {
            rows: core::array::from_fn(|_| None),
            met: 0,
        }
    }

    fn slot_of(&self, key: &K) -> Option<usize> {
        self.rows
            .iter()
            .position(|row| row.as_ref().is_some_and(|row| row.key == *key))
    }

    /// Whether `key` has a row.
    #[cfg(feature = "advanced-recovery")]
    pub(super) fn contains_key(&self, key: &K) -> bool {
        self.slot_of(key).is_some()
    }

    /// The row of `key` and its slot, if it has one, not counted as met.
    #[cfg(feature = "advanced-recovery")]
    pub(super) fn get_mut(&mut self, key: &K) -> Option<(usize, &mut V)> {
        let slot = self.slot_of(key)?;
        let row = self.rows.get_mut(slot)?.as_mut()?;
        Some((slot, &mut row.value))
    }

    /// The row of `key` and its slot, met now: made with `make` when `key` has none, in a free
    /// row or else in the one met longest ago of those `may_go(slot, state)` lets go. `None`
    /// when every row is taken and none may go.
    pub(super) fn entry(
        &mut self,
        key: &K,
        make: impl FnOnce() -> V,
        mut may_go: impl FnMut(usize, &V) -> bool,
    ) -> Option<(usize, &mut V)> {
        self.met = self.met.wrapping_add(1);
        let met = self.met;
        let slot = match self.slot_of(key) {
            Some(slot) => slot,
            None => {
                let slot = match self.rows.iter().position(Option::is_none) {
                    Some(free) => free,
                    None => self
                        .rows
                        .iter()
                        .enumerate()
                        .filter_map(|(slot, row)| row.as_ref().map(|row| (slot, row)))
                        .filter(|(slot, row)| may_go(*slot, &row.value))
                        .min_by_key(|(_, row)| row.met)
                        .map(|(slot, _)| slot)?,
                };
                *self.rows.get_mut(slot)? = Some(Row {
                    key: key.clone(),
                    value: make(),
                    met,
                });
                slot
            }
        };
        let row = self.rows.get_mut(slot)?.as_mut()?;
        row.met = met;
        Some((slot, &mut row.value))
    }

    /// Every row, with its slot and key, in the order of the slots.
    #[cfg(feature = "advanced-recovery")]
    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = (usize, &K, &mut V)> + '_ {
        self.rows
            .iter_mut()
            .enumerate()
            .filter_map(|(slot, row)| row.as_mut().map(|row| (slot, &row.key, &mut row.value)))
    }

    /// Keep the rows `keep(slot, state)` says to and let the others go; the answer is how many
    /// went.
    #[cfg(feature = "advanced-recovery")]
    pub(super) fn retain(&mut self, mut keep: impl FnMut(usize, &mut V) -> bool) -> usize {
        let mut gone = 0;
        for (slot, row) in self.rows.iter_mut().enumerate() {
            let goes = match row.as_mut() {
                Some(held) => !keep(slot, &mut held.value),
                None => false,
            };
            if goes {
                *row = None;
                gone += 1;
            }
        }
        gone
    }

    /// Put `value` in the row of `key`, or in a free row; a test's way to set a table up.
    #[cfg(all(test, feature = "advanced-recovery"))]
    pub(super) fn insert(&mut self, key: K, value: V) {
        let slot = self
            .slot_of(&key)
            .or_else(|| self.rows.iter().position(Option::is_none))
            .expect("a test fills no more rows than the table has");
        self.met = self.met.wrapping_add(1);
        self.rows[slot] = Some(Row {
            key,
            value,
            met: self.met,
        });
    }
}

#[cfg(all(test, feature = "advanced-recovery"))]
impl<K: PartialEq + Clone, V> core::ops::Index<&K> for Sources<K, V> {
    type Output = V;

    fn index(&self, key: &K) -> &V {
        let slot = self.slot_of(key).expect("the source has a row");
        &self.rows[slot]
            .as_ref()
            .expect("a row's slot holds it")
            .value
    }
}
