// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The rows of a multicast group's member table
//! ([`MulticastDispatcher`](crate::multicast_dispatch::MulticastDispatcher)): the fixed rows the
//! dispatcher is built with and, for a table that grows (`GrowingTable`, a build with an
//! allocator), the rows it adds past them.
//!
//! A row keeps its index for as long as the table is in use: the index is the member's key for its
//! reassembly chains (`multicast_chain_key`), which are aborted when the member leaves, and only
//! then is the index given to another. So a row is freed and reused, never removed; the grown rows
//! are let go together, when the whole table is reset with its link.
//!
//! # A type, not a value
//!
//! Growth changes the shape of the table, not a number in it: a table that grows holds a vector
//! of rows past its fixed ones and an index of its members by address, and one that does not
//! holds neither. So it is a strategy type the table is built with ([`TableGrowth`]), chosen
//! where the table is built, and not a flag both kinds carry (a choice that changes the shape of
//! the code is a type parameter): a flag is read at run time, so an image whose table never grows
//! would still link the vector, the hash index and its hasher's seed. [`FixedTable`]'s grown rows
//! and index are empty types whose every operation is a constant, so an image that names it links
//! none of that.

use core::hash::Hash;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;

/// Whether a member table grows past its fixed rows, as the types of what it holds for growth.
pub trait TableGrowth {
    /// Whether the table adds rows past its fixed ones, so that a stated cap above them is held
    /// rather than refused.
    const GROWS: bool;

    /// The rows past the fixed ones.
    type Rows<T>: GrownRows<T>;

    /// The rows of the members by a key, kept so a member is found without a scan.
    type Index<K: Hash + Eq>: RowIndex<K>;
}

/// A table of its fixed rows only: no row is added and no index is kept, so a member is found by a
/// scan of the few rows. What a host without an allocator builds, and any host whose group is not
/// let grow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FixedTable;

impl TableGrowth for FixedTable {
    const GROWS: bool = false;
    type Rows<T> = [T; 0];
    type Index<K: Hash + Eq> = NoIndex<K>;
}

/// A table that adds rows past its fixed ones, up to a stated cap, and finds its members by an
/// index of their addresses: a group may be as large as its configuration says (a thousand members
/// by upstream's default), and the member a datagram came from is looked up for every datagram,
/// which a scan of that many rows cannot answer.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GrowingTable;

#[cfg(feature = "alloc")]
impl TableGrowth for GrowingTable {
    const GROWS: bool = true;
    type Rows<T> = alloc::vec::Vec<T>;
    type Index<K: Hash + Eq> = hashbrown::HashMap<K, usize>;
}

/// The rows a table holds past its fixed ones ([`TableGrowth::Rows`]).
pub trait GrownRows<T> {
    /// No grown row.
    fn empty() -> Self;

    /// The grown rows in index order.
    fn rows(&self) -> &[T];

    /// The grown rows in index order, to change.
    fn rows_mut(&mut self) -> &mut [T];

    /// Add a row past the last, written in its own cell by `init`, and return its index among
    /// the grown rows; `None`, without calling `init`, when no row can be added.
    ///
    /// # Safety
    ///
    /// `init` writes a whole `T` into the cell it is given.
    unsafe fn grow_with(&mut self, init: impl FnOnce(&mut MaybeUninit<T>)) -> Option<usize>;

    /// Let every grown row go.
    fn shed(&mut self);
}

impl<T> GrownRows<T> for [T; 0] {
    #[inline]
    fn empty() -> Self {
        []
    }

    #[inline]
    fn rows(&self) -> &[T] {
        self
    }

    #[inline]
    fn rows_mut(&mut self) -> &mut [T] {
        self
    }

    #[inline]
    unsafe fn grow_with(&mut self, _init: impl FnOnce(&mut MaybeUninit<T>)) -> Option<usize> {
        None
    }

    #[inline]
    fn shed(&mut self) {}
}

#[cfg(feature = "alloc")]
impl<T> GrownRows<T> for alloc::vec::Vec<T> {
    fn empty() -> Self {
        alloc::vec::Vec::new()
    }

    fn rows(&self) -> &[T] {
        self
    }

    fn rows_mut(&mut self) -> &mut [T] {
        self
    }

    /// The vector's storage is where the row is written, so a row is not a value in this frame.
    unsafe fn grow_with(&mut self, init: impl FnOnce(&mut MaybeUninit<T>)) -> Option<usize> {
        self.reserve(1);
        let at = self.len();
        // `reserve` left room for at least one row past the length: the first spare cell.
        let cell = self.spare_capacity_mut().first_mut()?;
        // SAFETY: `init` writes a whole row into the first cell past the length (the caller's
        // contract), so the length may count it. An `init` that unwinds leaves the length as it was.
        unsafe {
            init(cell);
            self.set_len(at.saturating_add(1));
        }
        Some(at)
    }

    fn shed(&mut self) {
        *self = alloc::vec::Vec::new();
    }
}

/// The rows of a table's members found by a key without walking them ([`TableGrowth::Index`]).
///
/// The index is exact, not a hint: the table enters a key when a row takes a member
/// ([`Self::admitted`]), leaves it when the member leaves ([`Self::left`]) and empties it when the
/// whole table is reset ([`Self::cleared`]), so [`Self::lookup`] answers what a scan of the rows
/// would. A table that keeps none ([`NoIndex`]) answers that it must be scanned.
pub trait RowIndex<K> {
    /// An index that holds no member.
    fn empty() -> Self;

    /// Row `row` took the member keyed `key`.
    fn admitted(&mut self, key: K, row: usize);

    /// The member keyed `key` left its row.
    fn left(&mut self, key: &K);

    /// Every member left with the table's reset, and the storage goes with them.
    fn cleared(&mut self);

    /// `None` when the table keeps no index and must be scanned; otherwise the row of the member
    /// keyed `key`, or `Some(None)` when no member is.
    fn lookup(&self, key: &K) -> Option<Option<usize>>;

    /// How many members the index holds, `None` when it keeps none.
    fn members(&self) -> Option<usize>;
}

/// The index of a table that keeps none: an empty type, so a table of its fixed rows holds no
/// map and allocates nothing for one.
pub struct NoIndex<K>(PhantomData<K>);

impl<K> RowIndex<K> for NoIndex<K> {
    #[inline]
    fn empty() -> Self {
        Self(PhantomData)
    }

    #[inline]
    fn admitted(&mut self, _key: K, _row: usize) {}

    #[inline]
    fn left(&mut self, _key: &K) {}

    #[inline]
    fn cleared(&mut self) {}

    #[inline]
    fn lookup(&self, _key: &K) -> Option<Option<usize>> {
        None
    }

    #[inline]
    fn members(&self) -> Option<usize> {
        None
    }
}

#[cfg(feature = "alloc")]
impl<K: Hash + Eq> RowIndex<K> for hashbrown::HashMap<K, usize> {
    fn empty() -> Self {
        hashbrown::HashMap::new()
    }

    fn admitted(&mut self, key: K, row: usize) {
        self.insert(key, row);
    }

    fn left(&mut self, key: &K) {
        self.remove(key);
    }

    fn cleared(&mut self) {
        *self = hashbrown::HashMap::new();
    }

    fn lookup(&self, key: &K) -> Option<Option<usize>> {
        Some(self.get(key).copied())
    }

    fn members(&self) -> Option<usize> {
        Some(self.len())
    }
}

/// The rows of a member table: `N` fixed ones, then those grown past them by `G`. Row `N + i` is
/// the `i`-th grown row.
pub(crate) struct PeerRows<T, const N: usize, G: TableGrowth> {
    fixed: [T; N],
    grown: G::Rows<T>,
}

impl<T, const N: usize, G: TableGrowth> PeerRows<T, N, G> {
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
        // `init`, which is the caller's contract, and the grown rows are written empty;
        // `fields_are_written_by_init_in` names every field, so one added to the struct stops that
        // from compiling until it is written here too. With all written the table is whole.
        unsafe {
            let fixed = addr_of_mut!((*at).fixed).cast::<MaybeUninit<T>>();
            for index in 0..N {
                init(&mut *fixed.add(index));
            }
            addr_of_mut!((*at).grown).write(<G::Rows<T> as GrownRows<T>>::empty());
            &mut *at
        }
    }

    /// Names every field of the table, so that [`Self::init_in`], which writes each by its
    /// address, cannot miss one that is added.
    #[allow(dead_code)]
    fn fields_are_written_by_init_in(self) {
        let Self { fixed: _, grown: _ } = self;
    }

    /// How many rows the table has: the fixed ones and those grown past them. Read where a
    /// dispatcher retires every member with what it declared, and by the tests.
    #[cfg(any(test, all(feature = "alloc", feature = "codec-declare")))]
    pub(crate) fn len(&self) -> usize {
        self.grown.rows().len().saturating_add(N)
    }

    /// Row `index`, or `None` past the last.
    pub(crate) fn get(&self, index: usize) -> Option<&T> {
        match index.checked_sub(N) {
            None => self.fixed.get(index),
            Some(grown) => self.grown.rows().get(grown),
        }
    }

    /// Row `index` to change, or `None` past the last.
    pub(crate) fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        match index.checked_sub(N) {
            None => self.fixed.get_mut(index),
            Some(grown) => self.grown.rows_mut().get_mut(grown),
        }
    }

    /// Every row in index order: the fixed ones, then the grown ones.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        self.fixed.iter().chain(self.grown.rows().iter())
    }

    /// Every row in index order, to change.
    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> + '_ {
        self.fixed
            .iter_mut()
            .chain(self.grown.rows_mut().iter_mut())
    }

    /// Add a row past the last, written in its own cell by `init`, and return its index; `None`,
    /// without calling `init`, when the table does not grow.
    ///
    /// # Safety
    ///
    /// `init` writes a whole `T` into the cell it is given.
    pub(crate) unsafe fn grow_with(
        &mut self,
        init: impl FnOnce(&mut MaybeUninit<T>),
    ) -> Option<usize> {
        // SAFETY: `init` writes a whole row, the caller's contract.
        unsafe { self.grown.grow_with(init) }.map(|at| at.saturating_add(N))
    }

    /// Let the grown rows go and keep the fixed ones: what a reset of the whole table does, since
    /// no member is left to hold an index past them.
    pub(crate) fn shed_grown(&mut self) {
        self.grown.shed();
    }
}

// Indexing that panics past the last row is for the tests alone: the table answers `get`.
#[cfg(test)]
impl<T, const N: usize, G: TableGrowth> core::ops::Index<usize> for PeerRows<T, N, G> {
    type Output = T;

    fn index(&self, index: usize) -> &T {
        let rows = self.len();
        match self.get(index) {
            Some(row) => row,
            None => panic!("row {index} of a member table of {rows} rows"),
        }
    }
}

#[cfg(test)]
impl<T, const N: usize, G: TableGrowth> core::ops::IndexMut<usize> for PeerRows<T, N, G> {
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

    /// A table of `N` rows of `u32` growing by `G`, the fixed ones numbered from 10.
    fn table<const N: usize, G: TableGrowth>(
        slot: &mut MaybeUninit<PeerRows<u32, N, G>>,
    ) -> &mut PeerRows<u32, N, G> {
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
        let rows = table::<3, FixedTable>(&mut slot);
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
        let rows = table::<2, FixedTable>(&mut slot);
        let _ = rows[2];
    }

    /// A table of its fixed rows only holds nothing for growth: its grown rows and its index are
    /// empty types, so the table is the size of its fixed rows and no vector or map is in it.
    #[test]
    fn a_fixed_table_holds_no_grown_row_and_no_index() {
        use core::mem::size_of as size;
        assert_eq!(size::<<FixedTable as TableGrowth>::Rows<u64>>(), 0);
        assert_eq!(size::<<FixedTable as TableGrowth>::Index<u64>>(), 0);
        assert_eq!(size::<PeerRows<u64, 3, FixedTable>>(), size::<[u64; 3]>());
    }

    /// A table that does not grow refuses a row past its fixed ones without calling the row's
    /// initialiser, and its shed keeps the fixed rows.
    #[test]
    fn a_fixed_table_adds_no_row() {
        let mut slot = MaybeUninit::uninit();
        let rows = table::<2, FixedTable>(&mut slot);
        let mut called = false;
        // SAFETY: the closure writes a whole `u32`.
        let added = unsafe {
            rows.grow_with(|cell| {
                called = true;
                cell.write(30);
            })
        };
        assert_eq!(added, None);
        assert!(!called, "no cell to initialise");
        rows.shed_grown();
        assert!(rows.iter().copied().eq([10, 11]));
    }

    /// A grown row takes the index after the last, keeps it while later ones are added, and is let
    /// go with the others when the table sheds them; the fixed rows stay.
    #[cfg(feature = "alloc")]
    #[test]
    fn grown_rows_follow_the_fixed_ones_and_are_shed_together() {
        let mut slot = MaybeUninit::uninit();
        let rows = table::<2, GrowingTable>(&mut slot);
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
        assert_eq!((first, second), (Some(2), Some(3)));
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
        let mut none: <FixedTable as TableGrowth>::Index<u16> = RowIndex::empty();
        none.admitted(7, 0);
        assert_eq!(none.lookup(&7), None, "no index: the caller scans");
        assert_eq!(none.members(), None);

        let mut index: <GrowingTable as TableGrowth>::Index<u16> = RowIndex::empty();
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
