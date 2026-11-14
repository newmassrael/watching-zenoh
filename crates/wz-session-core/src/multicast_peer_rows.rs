// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The rows of a multicast group's member table
//! ([`MulticastDispatcher`](crate::multicast_dispatch::MulticastDispatcher)): the fixed rows the
//! dispatcher is built with and, in a build with an allocator, the rows it adds past them when its
//! host lets the table grow (`MulticastConfig::growing`).
//!
//! A row keeps its index for as long as the table is in use: the index is the member's key for its
//! reassembly chains (`multicast_chain_key`), which are aborted when the member leaves, and only
//! then is the index given to another. So a row is freed and reused, never removed; the grown rows
//! are let go together, when the whole table is reset with its link.

use core::mem::MaybeUninit;
use core::ops::{Index, IndexMut};
use core::ptr::addr_of_mut;

/// The rows of a member table: `N` fixed ones, then those grown past them. Row `N + i` is the
/// `i`-th grown row.
pub(crate) struct PeerRows<T, const N: usize> {
    fixed: [T; N],
    #[cfg(feature = "alloc")]
    grown: alloc::vec::Vec<T>,
}

impl<T, const N: usize> PeerRows<T, N> {
    /// Build the table in `slot` with no grown row, each fixed row written in its own cell by
    /// `init`, so that no row, and no array of them, is a value in the frame of the function that
    /// builds the table. Whatever `slot` held is not dropped.
    ///
    /// # Safety
    ///
    /// `init` writes a whole `T` into the cell it is given.
    pub(crate) unsafe fn init_in(
        slot: &mut MaybeUninit<Self>,
        mut init: impl FnMut(&mut MaybeUninit<T>),
    ) -> &mut Self {
        let at = slot.as_mut_ptr();
        // SAFETY: `at` is storage for one table that holds no value. Each fixed row is written by
        // `init`, which is the caller's contract, and the grown rows are an empty vector;
        // `fields_are_written_by_init_in` names every field, so one added to the struct stops that
        // from compiling until it is written here too. With all written the table is whole.
        unsafe {
            let fixed = addr_of_mut!((*at).fixed).cast::<MaybeUninit<T>>();
            for index in 0..N {
                init(&mut *fixed.add(index));
            }
            #[cfg(feature = "alloc")]
            addr_of_mut!((*at).grown).write(alloc::vec::Vec::new());
            &mut *at
        }
    }

    /// Names every field of the table, so that [`Self::init_in`], which writes each by its
    /// address, cannot miss one that is added.
    #[allow(dead_code)]
    fn fields_are_written_by_init_in(self) {
        let Self {
            fixed: _,
            #[cfg(feature = "alloc")]
                grown: _,
        } = self;
    }

    /// How many rows the table has: the fixed ones and those grown past them.
    pub(crate) fn len(&self) -> usize {
        #[cfg(feature = "alloc")]
        {
            N + self.grown.len()
        }
        #[cfg(not(feature = "alloc"))]
        {
            N
        }
    }

    /// Row `index`, or `None` past the last.
    pub(crate) fn get(&self, index: usize) -> Option<&T> {
        match index.checked_sub(N) {
            None => self.fixed.get(index),
            #[cfg(feature = "alloc")]
            Some(grown) => self.grown.get(grown),
            #[cfg(not(feature = "alloc"))]
            Some(_) => None,
        }
    }

    /// Row `index` to change, or `None` past the last.
    pub(crate) fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        match index.checked_sub(N) {
            None => self.fixed.get_mut(index),
            #[cfg(feature = "alloc")]
            Some(grown) => self.grown.get_mut(grown),
            #[cfg(not(feature = "alloc"))]
            Some(_) => None,
        }
    }

    /// Every row in index order: the fixed ones, then the grown ones.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        #[cfg(feature = "alloc")]
        {
            self.fixed.iter().chain(self.grown.iter())
        }
        #[cfg(not(feature = "alloc"))]
        {
            self.fixed.iter()
        }
    }

    /// Every row in index order, to change.
    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> + '_ {
        #[cfg(feature = "alloc")]
        {
            self.fixed.iter_mut().chain(self.grown.iter_mut())
        }
        #[cfg(not(feature = "alloc"))]
        {
            self.fixed.iter_mut()
        }
    }

    /// Add a row past the last, written in its own cell by `init`, and return its index. The
    /// vector's storage is where the row is written, so a row is not a value in this frame either.
    ///
    /// # Safety
    ///
    /// `init` writes a whole `T` into the cell it is given.
    #[cfg(feature = "alloc")]
    pub(crate) unsafe fn grow_with(&mut self, init: impl FnOnce(&mut MaybeUninit<T>)) -> usize {
        self.grown.reserve(1);
        let at = self.grown.len();
        // SAFETY: `reserve` left room for at least one row past the length, which is the first
        // cell of the spare capacity; `init` writes a whole row there (the caller's contract), so
        // the length may count it. An `init` that unwinds leaves the length as it was.
        unsafe {
            init(&mut self.grown.spare_capacity_mut()[0]);
            self.grown.set_len(at + 1);
        }
        N + at
    }

    /// Let the grown rows go and keep the fixed ones: what a reset of the whole table does, since
    /// no member is left to hold an index past them.
    #[cfg(feature = "alloc")]
    pub(crate) fn shed_grown(&mut self) {
        self.grown = alloc::vec::Vec::new();
    }
}

/// The rows of a table that grows, found by a key without walking them: the member a datagram
/// came from is looked up for every datagram, and a table that grows to a configuration's cap
/// (a thousand members by upstream's default) cannot answer that by a scan. A table that does
/// not grow keeps no index, and allocates nothing for one: its rows are few, and its host may
/// have no heap.
///
/// The index is exact, not a hint: the table enters a key when a row takes a member
/// ([`Self::admitted`]), leaves it when the member leaves ([`Self::left`]) and empties it when the
/// whole table is reset ([`Self::cleared`]), so [`Self::lookup`] answers what a scan of the rows
/// would.
#[cfg(feature = "alloc")]
pub(crate) struct RowIndex<K> {
    by_key: Option<hashbrown::HashMap<K, usize>>,
}

#[cfg(feature = "alloc")]
impl<K: core::hash::Hash + Eq> RowIndex<K> {
    /// An index for a table that grows, or none for one that does not.
    pub(crate) fn for_table(grows: bool) -> Self {
        Self {
            by_key: grows.then(hashbrown::HashMap::new),
        }
    }

    /// Row `row` took the member keyed `key`.
    pub(crate) fn admitted(&mut self, key: K, row: usize) {
        if let Some(by_key) = &mut self.by_key {
            by_key.insert(key, row);
        }
    }

    /// The member keyed `key` left its row.
    pub(crate) fn left(&mut self, key: &K) {
        if let Some(by_key) = &mut self.by_key {
            by_key.remove(key);
        }
    }

    /// Every member left with the table's reset, and the storage goes with them.
    pub(crate) fn cleared(&mut self) {
        if let Some(by_key) = &mut self.by_key {
            *by_key = hashbrown::HashMap::new();
        }
    }

    /// `None` when the table keeps no index and must be scanned; otherwise the row of the member
    /// keyed `key`, or `Some(None)` when no member is.
    pub(crate) fn lookup(&self, key: &K) -> Option<Option<usize>> {
        self.by_key.as_ref().map(|by_key| by_key.get(key).copied())
    }

    /// How many members the index holds, `None` when it keeps none.
    pub(crate) fn members(&self) -> Option<usize> {
        self.by_key.as_ref().map(hashbrown::HashMap::len)
    }
}

impl<T, const N: usize> Index<usize> for PeerRows<T, N> {
    type Output = T;

    fn index(&self, index: usize) -> &T {
        let rows = self.len();
        match self.get(index) {
            Some(row) => row,
            None => panic!("row {index} of a member table of {rows} rows"),
        }
    }
}

impl<T, const N: usize> IndexMut<usize> for PeerRows<T, N> {
    fn index_mut(&mut self, index: usize) -> &mut T {
        let rows = self.len();
        match self.get_mut(index) {
            Some(row) => row,
            None => panic!("row {index} of a member table of {rows} rows"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A table of `N` rows of `u32`, the fixed ones numbered from 10.
    fn table<const N: usize>(slot: &mut MaybeUninit<PeerRows<u32, N>>) -> &mut PeerRows<u32, N> {
        let mut next = 10;
        // SAFETY: the closure writes a whole `u32` into each cell.
        unsafe {
            PeerRows::init_in(slot, |cell| {
                cell.write(next);
                next += 1;
            })
        }
    }

    #[test]
    fn the_fixed_rows_are_written_in_index_order_and_read_back_by_index() {
        let mut slot = MaybeUninit::uninit();
        let rows = table::<3>(&mut slot);
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().copied().eq([10, 11, 12]));
        assert_eq!(rows[1], 11);
        rows[1] = 21;
        assert_eq!(rows.get(1), Some(&21));
        assert_eq!(rows.get(3), None, "no row past the last");
        for row in rows.iter_mut() {
            *row += 1;
        }
        assert!(rows.iter().copied().eq([11, 22, 13]));
    }

    #[test]
    #[should_panic(expected = "row 2 of a member table of 2 rows")]
    fn an_index_past_the_last_row_names_the_table() {
        let mut slot = MaybeUninit::uninit();
        let rows = table::<2>(&mut slot);
        let _ = rows[2];
    }

    /// A grown row takes the index after the last, keeps it while later ones are added, and is let
    /// go with the others when the table sheds them; the fixed rows stay.
    #[cfg(feature = "alloc")]
    #[test]
    fn grown_rows_follow_the_fixed_ones_and_are_shed_together() {
        let mut slot = MaybeUninit::uninit();
        let rows = table::<2>(&mut slot);
        // SAFETY: each closure writes a whole `u32`.
        let first = unsafe {
            rows.grow_with(|cell| {
                cell.write(30);
            })
        };
        let second = unsafe {
            rows.grow_with(|cell| {
                cell.write(31);
            })
        };
        assert_eq!((first, second), (2, 3));
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[2], 30);
        rows[3] = 41;
        assert_eq!(rows.get_mut(3).copied(), Some(41));
        assert!(rows.iter().copied().eq([10, 11, 30, 41]));

        rows.shed_grown();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows.get(2), None);
        assert!(rows.iter().copied().eq([10, 11]));
    }

    /// A table that does not grow keeps no index and is told to scan; one that grows answers by
    /// key, through admission, departure and reset.
    #[cfg(feature = "alloc")]
    #[test]
    fn an_index_answers_only_for_a_table_that_grows() {
        let mut none = RowIndex::<u16>::for_table(false);
        none.admitted(7, 0);
        assert_eq!(none.lookup(&7), None, "no index: the caller scans");
        assert_eq!(none.members(), None);

        let mut index = RowIndex::<u16>::for_table(true);
        index.admitted(7, 2);
        index.admitted(9, 3);
        assert_eq!(index.lookup(&7), Some(Some(2)));
        assert_eq!(index.lookup(&8), Some(None));
        index.left(&7);
        assert_eq!(index.lookup(&7), Some(None));
        assert_eq!(index.members(), Some(1));
        index.cleared();
        assert_eq!(index.lookup(&9), Some(None));
        assert_eq!(index.members(), Some(0));
    }
}
