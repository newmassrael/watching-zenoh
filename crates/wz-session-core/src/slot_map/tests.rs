// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

use super::*;
use crate::bounded::{Static, ARENA_ALIGN};
use core::cell::Cell;
use core::ptr::NonNull;

/// The marker of the tables these tests make.
enum Test {}

type Map<const N: usize> = SlotMap<Test, u32, N, Static>;

/// One block of an arena's memory, aligned as an arena's spans start.
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct Block([u8; ARENA_ALIGN]);

/// An arena over `bytes` bytes the test process leaks, so it outlives every table lent from it.
fn arena(bytes: usize) -> Arena {
    let blocks = bytes.div_ceil(ARENA_ALIGN).max(1);
    let region: &'static mut [Block] = std::vec![Block([0; ARENA_ALIGN]); blocks].leak();
    // SAFETY: the region is aligned to `ARENA_ALIGN`, as its blocks are, holds at least `bytes`
    // bytes, and is leaked, so nothing else uses it and it outlives every lent table.
    unsafe { Arena::over(NonNull::from(region).cast::<u8>(), bytes) }
}

#[test]
fn an_absent_handle_costs_no_word_of_its_own() {
    assert_eq!(core::mem::size_of::<Handle<Test>>(), 4);
    assert_eq!(core::mem::size_of::<Option<Handle<Test>>>(), 4);
}

#[test]
fn a_row_is_found_by_the_handle_its_insert_answered() {
    let mut map = Map::<4>::new();
    let a = map.insert(10).unwrap();
    let b = map.insert(20).unwrap();
    assert_ne!(a, b);
    assert_eq!(map.get(a), Some(&10));
    assert_eq!(map.get(b), Some(&20));
    assert_eq!(map.len(), 2);
    *map.get_mut(b).unwrap() = 21;
    assert_eq!(map.get(b), Some(&21));
}

#[test]
fn a_full_table_refuses_and_hands_the_value_back() {
    let mut map = Map::<2>::new();
    map.insert(1).unwrap();
    map.insert(2).unwrap();
    assert!(map.is_full());
    match map.insert(3) {
        Err(CapacityFull(back)) => assert_eq!(back, 3),
        Ok(_) => panic!("a third row went into a table of two"),
    }
    assert_eq!(map.len(), 2);
}

#[test]
fn a_limit_under_the_build_bound_refuses_at_the_limit() {
    let mut map = Map::<4>::new();
    map.limit_to(1);
    assert_eq!(map.capacity(), 1);
    map.insert(1).unwrap();
    assert!(map.is_full());
    assert!(map.insert(2).is_err());
}

#[test]
fn a_handle_kept_past_its_row_names_nothing() {
    let mut map = Map::<2>::new();
    let old = map.insert(1).unwrap();
    assert_eq!(map.remove(old), Some(Removal::Taken(1)));
    assert_eq!(map.get(old), None);
    assert_eq!(map.remove(old), None);
    // The slot is taken again, at the next generation: the old handle does not reach the new row.
    let new = map.insert(2).unwrap();
    assert_eq!(new.place(), old.place());
    assert_ne!(new, old);
    assert_eq!(map.get(old), None);
    assert_eq!(map.get(new), Some(&2));
    assert_eq!(map.len(), 1);
}

#[test]
fn a_pinned_row_removed_leaves_every_lookup_and_comes_back_at_its_last_unpin() {
    let mut map = Map::<2>::new();
    let h = map.insert(7).unwrap();
    let first = map.pin(h).unwrap();
    let second = map.pin(h).unwrap();
    assert_eq!(map.remove(h), Some(Removal::AfterCalls));
    // Gone to every lookup, kept for the calls that run.
    assert_eq!(map.get(h), None);
    assert_eq!(map.iter().count(), 0);
    assert!(map.pin(h).is_none());
    assert_eq!(map.pinned(&first), Some(&7));
    // It still holds its slot until the last pin is given back.
    assert_eq!(map.len(), 1);
    assert!(map.holds_slot(h));
    assert_eq!(map.unpin(first), None);
    assert_eq!(map.len(), 1);
    assert!(map.holds_slot(h));
    assert_eq!(map.unpin(second), Some(7));
    assert_eq!(map.len(), 0);
    assert!(!map.holds_slot(h));
    // The slot is free again, at a generation the old handle does not name.
    let next = map.insert(8).unwrap();
    assert_ne!(next, h);
    assert_eq!(map.get(h), None);
}

#[test]
fn an_unpin_of_a_live_row_hands_nothing_back() {
    let mut map = Map::<2>::new();
    let h = map.insert(5).unwrap();
    let pinned = map.pin(h).unwrap();
    assert_eq!(pinned.handle(), h);
    assert_eq!(map.unpin(pinned), None);
    assert_eq!(map.get(h), Some(&5));
    assert_eq!(map.remove(h), Some(Removal::Taken(5)));
}

#[test]
fn a_removed_row_is_not_pinned() {
    let mut map = Map::<2>::new();
    let h = map.insert(5).unwrap();
    let _ = map.remove(h);
    assert!(map.pin(h).is_none());
}

#[test]
fn a_cursor_walks_the_live_rows_while_the_table_changes() {
    let mut map = Map::<4>::new();
    let a = map.insert(1).unwrap();
    let b = map.insert(2).unwrap();
    let c = map.insert(3).unwrap();
    let _ = map.remove(b);
    let mut cursor = 0;
    let mut seen = std::vec::Vec::new();
    while let Some((handle, row)) = map.next_from(&mut cursor) {
        seen.push((handle, *row));
    }
    assert_eq!(seen, std::vec![(a, 1), (c, 3)]);
    // A walk that removes what it finds reaches every row once.
    let mut cursor = 0;
    let mut taken = 0;
    while let Some(handle) = map.next_from(&mut cursor).map(|(handle, _)| handle) {
        assert!(map.remove(handle).is_some());
        taken += 1;
    }
    assert_eq!(taken, 2);
    assert!(map.is_empty());
}

#[test]
fn iter_mut_changes_the_live_rows_only() {
    let mut map = Map::<4>::new();
    let a = map.insert(1).unwrap();
    let b = map.insert(2).unwrap();
    let pinned = map.pin(b).unwrap();
    let _ = map.remove(b);
    for (_, row) in map.iter_mut() {
        *row += 10;
    }
    assert_eq!(map.get(a), Some(&11));
    assert_eq!(map.unpin(pinned), Some(2));
}

#[test]
fn a_handle_survives_its_word() {
    let mut map = Map::<4>::new();
    let a = map.insert(1).unwrap();
    let _ = map.remove(a);
    let b = map.insert(2).unwrap();
    assert_eq!(Handle::<Test>::from_bits(b.to_bits()), Some(b));
    // A word whose index half is zero is no handle.
    assert_eq!(
        Handle::<Test>::from_bits(NonZeroU32::new(0x0001_0000).unwrap()),
        None
    );
}

#[test]
fn a_lent_table_holds_the_rows_it_was_lent() {
    let bytes = SlotMap::<Test, u32, 4, Lent>::arena_bytes(2).unwrap();
    let mut arena = arena(bytes);
    let mut map = SlotMap::<Test, u32, 4, Lent>::lent(&mut arena, 2).unwrap();
    assert_eq!(arena.high_water(), bytes);
    assert_eq!(map.capacity(), 2);
    let a = map.insert(1).unwrap();
    map.insert(2).unwrap();
    assert!(map.is_full());
    assert!(map.insert(3).is_err());
    let _ = map.remove(a);
    let c = map.insert(4).unwrap();
    assert_eq!(map.get(c), Some(&4));
}

#[test]
fn a_lent_table_past_its_build_bound_is_refused() {
    let mut arena = arena(1024);
    assert!(matches!(
        SlotMap::<Test, u32, 4, Lent>::lent(&mut arena, 5),
        Err(LendRefused::OverCeiling {
            rows: 5,
            ceiling: 4
        })
    ));
}

#[test]
fn a_table_made_without_rows_on_the_lent_policy_refuses_every_insert() {
    let mut map = SlotMap::<Test, u32, 4, Lent>::new();
    assert!(map.is_full());
    assert!(map.insert(1).is_err());
}

#[cfg(feature = "alloc")]
#[test]
fn a_growable_table_takes_its_bound_from_its_limit_not_from_the_build() {
    let mut map = SlotMap::<Test, u32, 2, crate::bounded::Heap>::new();
    for value in 0..3 {
        map.insert(value).unwrap();
    }
    assert_eq!(map.len(), 3);
    map.limit_to(4);
    assert_eq!(map.capacity(), 4);
    map.insert(3).unwrap();
    assert!(map.is_full());
    assert!(map.insert(4).is_err());
}

/// A row that counts its drops in `drops`.
struct Counted<'a>(&'a Cell<u32>);

impl Drop for Counted<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get().saturating_add(1));
    }
}

/// Fill `map` with a live row, a row removed at once and a row removed while pinned, and drop
/// it: each of the three is dropped once, the removed one when it is handed back, the other two
/// with the table.
fn drops_each_row_once<'a, const N: usize, P: Storage>(
    mut map: SlotMap<Test, Counted<'a>, N, P>,
    drops: &'a Cell<u32>,
) {
    let (Ok(_live), Ok(removed), Ok(pinned)) = (
        map.insert(Counted(drops)),
        map.insert(Counted(drops)),
        map.insert(Counted(drops)),
    ) else {
        panic!("a table of four rows refused one of three");
    };
    let _pin = map.pin(pinned).expect("a live row is pinned");
    assert!(matches!(map.remove(pinned), Some(Removal::AfterCalls)));
    drop(map.remove(removed));
    assert_eq!(drops.get(), 1);
    drop(map);
    assert_eq!(drops.get(), 3);
}

#[test]
fn dropping_a_lent_table_drops_its_live_and_retired_rows_once() {
    let drops = Cell::new(0);
    let bytes = SlotMap::<Test, Counted<'_>, 4, Lent>::arena_bytes(4).unwrap();
    let mut arena = arena(bytes);
    let map = SlotMap::<Test, Counted<'_>, 4, Lent>::lent(&mut arena, 4).unwrap();
    drops_each_row_once(map, &drops);
}

#[test]
fn dropping_a_fixed_table_drops_its_live_and_retired_rows_once() {
    let drops = Cell::new(0);
    drops_each_row_once(SlotMap::<Test, Counted<'_>, 4, Static>::new(), &drops);
}
