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

/// A walk of the retired rows finds a row removed while pinned, and no live one; once its last pin
/// is given back it is found no more. The CONTROL is the live walk, which never finds it.
#[test]
fn a_cursor_walks_the_retired_rows_alone() {
    let mut map = Map::<4>::new();
    let live = map.insert(1).unwrap();
    let held = map.insert(2).unwrap();
    let _pinned = map.pin(held).unwrap();
    assert!(matches!(map.remove(held), Some(Removal::AfterCalls)));
    let mut cursor = 0;
    assert_eq!(map.next_retired_from(&mut cursor), Some((held, &2)));
    assert_eq!(
        map.next_retired_from(&mut cursor),
        None,
        "the live row is not"
    );
    let mut cursor = 0;
    assert_eq!(
        map.next_from(&mut cursor),
        Some((live, &1)),
        "CONTROL: the live walk"
    );
    assert_eq!(map.next_from(&mut cursor), None);
    assert_eq!(map.release(held), Some(2));
    assert_eq!(
        map.next_retired_from(&mut 0),
        None,
        "given back, it is gone"
    );
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

/// Tables of two row types, both lent by the one body that lends every table's columns, each take
/// the span their own rows count, the second laid after the first, and each holds its own rows.
#[test]
fn tables_of_two_row_types_each_take_the_span_of_their_rows() {
    let small = SlotMap::<Test, u8, 4, Lent>::arena_bytes(3).unwrap();
    let large = SlotMap::<Test, [u64; 4], 4, Lent>::arena_bytes(3).unwrap();
    let mut arena = arena(small + large);
    let mut bytes = SlotMap::<Test, u8, 4, Lent>::lent(&mut arena, 3).unwrap();
    assert_eq!(arena.high_water(), small);
    let mut words = SlotMap::<Test, [u64; 4], 4, Lent>::lent(&mut arena, 3).unwrap();
    assert_eq!(arena.high_water(), small + large);
    assert_eq!((bytes.capacity(), words.capacity()), (3, 3));
    let a = bytes.insert(7).unwrap();
    let b = words.insert([1, 2, 3, 4]).unwrap();
    assert_eq!(bytes.get(a), Some(&7));
    assert_eq!(words.get(b), Some(&[1, 2, 3, 4]));
}

/// A table whose rows find no room once its metadata column was lent is refused, and the
/// metadata's span stays lent: the arena keeps what was lent before a refusal.
#[test]
fn a_lent_table_whose_rows_find_no_room_is_refused() {
    let meta = Arena::table_bytes::<Meta>(2).unwrap();
    let rows = Arena::table_bytes::<Option<[u64; 4]>>(2).unwrap();
    let mut arena = arena(meta + rows - ARENA_ALIGN);
    assert!(matches!(
        SlotMap::<Test, [u64; 4], 4, Lent>::lent(&mut arena, 2),
        Err(LendRefused::Exhausted { .. })
    ));
    assert_eq!(arena.high_water(), meta);
}

/// A lender keeps its first refusal: a table asked after it is lent no rows, takes nothing of the
/// arena and refuses every insert, though the arena has the room for it, and `finish` hands the
/// first refusal back. The CONTROL is the table lent before the refusal, which holds its rows.
#[test]
fn a_lender_lends_nothing_after_its_first_refusal() {
    let fits = SlotMap::<Test, u32, 4, Lent>::arena_bytes(2).unwrap();
    let mut arena = arena(fits * 2);
    let mut lend = TableLender::new(&mut arena);
    let mut first = SlotMap::<Test, u32, 4, Lent>::lent_from(&mut lend, 2);
    let mut past = SlotMap::<Test, u32, 4, Lent>::lent_from(&mut lend, 5);
    let mut after = SlotMap::<Test, u32, 4, Lent>::lent_from(&mut lend, 2);
    assert_eq!(
        lend.finish(),
        Err(LendRefused::OverCeiling {
            rows: 5,
            ceiling: 4
        })
    );
    assert_eq!(arena.high_water(), fits);
    assert_eq!((past.capacity(), after.capacity()), (0, 0));
    assert!(past.insert(1).is_err());
    assert!(after.insert(1).is_err());
    assert!(
        first.insert(1).is_ok(),
        "CONTROL: the table lent before holds its rows"
    );
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

/// A row taken into a freed slot and one taken into a slot the table adds are each written once,
/// over an empty place: no insert drops a row, the freed slot is taken before the table grows, and
/// each row is dropped once, with the table. Turned red by an insert that takes a new slot while
/// one is free, or that drops what it writes over.
#[test]
fn an_insert_writes_its_row_once_into_a_freed_or_an_added_slot() {
    let drops = Cell::new(0);
    let mut map = SlotMap::<Test, Counted<'_>, 4, Static>::new();
    let freed = map
        .insert(Counted(&drops))
        .expect("a table of four takes a row");
    drop(map.remove(freed));
    assert_eq!(drops.get(), 1);
    let reused = map.insert(Counted(&drops)).expect("the freed slot is free");
    assert_eq!(reused.place(), freed.place());
    assert_ne!(reused, freed);
    let added = map
        .insert(Counted(&drops))
        .expect("a table of four takes a second row");
    assert_eq!(added.place(), freed.place() + 1);
    assert_eq!(drops.get(), 1, "an insert drops nothing");
    assert_eq!(map.len(), 2);
    drop(map);
    assert_eq!(drops.get(), 3);
}

/// The core adds a slot only where both columns have a place for it: refused, the count stays as
/// it was; given one, the slot after the last is counted; and a freed slot is taken again, at its
/// next generation, before any is added. Turned red by a core that adds a slot with no place for
/// it, or adds one while a slot is free.
#[test]
fn the_core_adds_a_slot_only_where_its_row_has_a_place() {
    let mut meta = BoundedVec::<Meta, 4, Static>::default();
    let mut slots = Core::new(4);
    assert!(slots.take_slot(&mut meta, false).is_none());
    assert_eq!(slots.held, 0, "nothing is taken");
    let added = slots
        .take_slot(&mut meta, true)
        .expect("a place for the row");
    assert_eq!((added.at, added.generation, added.grown), (0, 0, true));
    assert_eq!(slots.held, 1);
    assert!(
        meta.push(Meta::ADDED).is_ok(),
        "the place the core was told of"
    );
    slots.free(&mut meta, added.at);
    let reused = slots
        .take_slot(&mut meta, false)
        .expect("the freed slot needs no new place");
    assert_eq!((reused.at, reused.generation, reused.grown), (0, 1, false));
    assert_eq!((meta.len(), slots.held), (1, 1));
}

/// A row's rank and the row at a rank are read off the slots, in the order the table's walk hands
/// its rows: a freed slot and a row removed while pinned hold no rank. Turned red by a rank that
/// counts a slot that holds no live row, or a walk to a rank that skips none.
#[test]
fn a_rows_rank_is_its_place_in_the_tables_walk() {
    let mut map = Map::<5>::new();
    let first = map.insert(10).unwrap();
    let freed = map.insert(20).unwrap();
    let retired = map.insert(30).unwrap();
    let last = map.insert(40).unwrap();
    assert!(matches!(map.remove(freed), Some(Removal::Taken(20))));
    let _pinned = map.pin(retired).unwrap();
    assert!(matches!(map.remove(retired), Some(Removal::AfterCalls)));
    let walked: std::vec::Vec<Handle<Test>> = map.iter().map(|(handle, _)| handle).collect();
    assert_eq!(walked, [first, last]);
    for (rank, handle) in walked.iter().enumerate() {
        assert_eq!(map.rank_of(*handle), Some(rank));
        assert_eq!(map.nth_live(rank).map(|(at, _)| at), Some(*handle));
    }
    assert_eq!(map.nth_live(1).map(|(_, row)| *row), Some(40));
    assert_eq!(map.rank_of(freed), None);
    assert_eq!(map.rank_of(retired), None);
    assert!(map.nth_live(2).is_none());
}

/// A table's slots name a row by its handle's bits with the rank the table's walk gives it, and
/// count a row removed while pinned as the table does. Turned red by a rank read off the bits
/// that is not the typed one, or by slots that count only the live rows.
#[test]
fn the_slots_rank_a_row_by_its_handles_bits_as_the_table_does() {
    let mut map = Map::<4>::new();
    let first = map.insert(1).unwrap();
    let freed = map.insert(2).unwrap();
    let last = map.insert(3).unwrap();
    assert!(matches!(map.remove(freed), Some(Removal::Taken(2))));
    assert_eq!(map.slots().len(), 2);
    assert_eq!(map.slots().rank_of(first.to_bits()), Some(0));
    assert_eq!(map.slots().rank_of(last.to_bits()), Some(1));
    assert_eq!(map.slots().rank_of(freed.to_bits()), None);
    assert_eq!(map.slots().nth_live(0), Some(first.to_bits()));
    assert_eq!(map.slots().nth_live(1), Some(last.to_bits()));
    assert_eq!(map.slots().nth_live(2), None);
    let _pinned = map.pin(last).unwrap();
    assert!(matches!(map.remove(last), Some(Removal::AfterCalls)));
    assert_eq!(map.slots().len(), map.len(), "a retired row keeps its slot");
    assert_eq!(map.slots().len(), 2);
    assert_eq!(map.slots().rank_of(last.to_bits()), None);
    assert_eq!(map.slots().nth_live(1), None);
    assert!(Slots::NONE.is_empty());
    assert_eq!(Slots::NONE.nth_live(0), None);
}

/// A row found once by its entry is read, changed and removed through it, and its handle names
/// nothing after: the one look the entry made still tells a handle kept past its row.
#[test]
fn an_entry_reads_changes_and_removes_the_row_its_handle_names() {
    let mut map = Map::<4>::new();
    let a = map.insert(10).unwrap();
    let b = map.insert(20).unwrap();
    let mut entry = map.entry(a).expect("a live row");
    assert_eq!(entry.get(), Some(&10));
    *entry.get_mut().expect("the row") = 11;
    assert_eq!(entry.get(), Some(&11));
    assert!(matches!(entry.remove(), Some(Removal::Taken(11))));
    assert!(map.get(a).is_none());
    assert!(
        map.entry(a).is_none(),
        "a handle kept past its row finds no entry"
    );
    assert_eq!(map.get(b), Some(&20), "the other row is untouched");
    assert_eq!(map.len(), 1);
}

/// A handle whose slot was freed and taken by a new row names no entry: the new row is at the
/// same place under a new generation.
#[test]
fn a_handle_of_a_reused_slot_finds_no_entry() {
    let mut map = Map::<1>::new();
    let old = map.insert(1).unwrap();
    assert!(map.remove(old).is_some());
    let new = map.insert(2).unwrap();
    assert!(map.entry(old).is_none());
    assert_eq!(
        map.entry(new).and_then(|entry| entry.get().copied()),
        Some(2)
    );
}

/// An entry pinned and then removed retires its row: it leaves every lookup and is handed back by
/// the release of its pin, as a pin taken by the handle is.
#[test]
fn an_entry_pinned_then_removed_waits_for_its_release() {
    let mut map = Map::<2>::new();
    let a = map.insert(7).unwrap();
    let mut entry = map.entry(a).expect("a live row");
    assert!(entry.pin());
    assert!(matches!(entry.remove(), Some(Removal::AfterCalls)));
    assert!(map.get(a).is_none());
    assert!(map.entry(a).is_none());
    assert_eq!(map.release(a), Some(7));
    assert!(map.is_empty());
}
