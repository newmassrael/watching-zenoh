// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

use super::*;
use crate::bounded::{Region, SeqPlace, Static, ZeroEmpty, ARENA_ALIGN};
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

/// A row built of its parts is built only once its slot was found: a full table hands the parts
/// back whole and never builds it; a table with room builds it once, where its handle finds it.
/// Turned red by an `insert_with` that builds the row before it finds a slot, or hands back
/// anything but the parts it was given.
#[test]
fn a_row_built_in_its_slot_is_not_built_when_the_table_is_full() {
    let built = Cell::new(0);
    let mut map = Map::<2>::new();
    let make = |(a, b): (u32, u32)| {
        built.set(built.get() + 1);
        a + b
    };
    let first = map
        .insert_with((1, 2), make)
        .expect("a table of two takes a row");
    assert_eq!(map.get(first), Some(&3));
    assert_eq!(built.get(), 1);
    map.insert_with((3, 4), make)
        .expect("a table of two takes a second row");
    assert!(map.is_full());
    assert_eq!(map.insert_with((5, 6), make), Err((5, 6)));
    assert_eq!(built.get(), 2, "a refused row is not built");
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

/// A lent table adds each free slot through the one body every row type shares, its rows
/// `STRIDE` apart: rows of a wide type and of a narrow type read back as they were written, and
/// a table adds no slot past the rows it was lent or past its limit. Turned red by a stride other
/// than the row's place in its column, a slot added past the rows lent, or one past the limit.
#[test]
fn a_lent_table_adds_its_free_slots_by_its_rows_stride() {
    let wide = SlotMap::<Test, [u64; 4], 4, Lent>::arena_bytes(3).unwrap();
    let narrow = SlotMap::<Test, u8, 4, Lent>::arena_bytes(3).unwrap();
    let mut arena = arena(wide + 2 * narrow);
    let mut words = SlotMap::<Test, [u64; 4], 4, Lent>::lent(&mut arena, 3).unwrap();
    let mut bytes = SlotMap::<Test, u8, 4, Lent>::lent(&mut arena, 3).unwrap();
    let mut held = std::vec::Vec::new();
    for n in 0..3u8 {
        let word = words.insert([u64::from(n) + 1; 4]).expect("a row lent");
        let byte = bytes.insert(n + 1).expect("a row lent");
        held.push((n, word, byte));
    }
    for (n, word, byte) in held {
        assert_eq!(words.get(word), Some(&[u64::from(n) + 1; 4]));
        assert_eq!(bytes.get(byte), Some(&(n + 1)));
    }
    assert_eq!(
        (words.meta.len(), words.rows.len()),
        (3, 3),
        "a slot and a row's place for each row lent"
    );
    assert!(words.insert([9; 4]).is_err(), "no slot past the rows lent");
    assert_eq!((words.meta.len(), words.rows.len()), (3, 3));

    let mut limited = SlotMap::<Test, u8, 4, Lent>::lent(&mut arena, 3).unwrap();
    limited.limit_to(1);
    assert!(limited.insert(1).is_ok());
    assert!(limited.insert(2).is_err(), "the limit is held");
    assert_eq!(
        (limited.meta.len(), limited.rows.len()),
        (1, 1),
        "no slot was added past the limit"
    );
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

/// The growable policy drops each of its rows once too, from the chunks it made them in. Turned red
/// by a drop of `Chunked` that skips a written row, drops a retired row twice, or drops a place no
/// row was written to.
#[cfg(feature = "alloc")]
#[test]
fn dropping_a_growable_table_drops_its_live_and_retired_rows_once() {
    let drops = Cell::new(0);
    drops_each_row_once(
        SlotMap::<Test, Counted<'_>, 4, crate::bounded::Heap>::new(),
        &drops,
    );
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

/// A row discarded is dropped once, where it lies, and leaves its slot free for the next row at a
/// generation its handle does not name; a handle past its row discards nothing. Turned red by a
/// discard that leaves the row standing, drops it a second time with the table, or frees the slot
/// without dropping the row.
#[test]
fn a_discarded_row_is_dropped_once_where_it_lies() {
    let drops = Cell::new(0);
    let mut map = SlotMap::<Test, Counted<'_>, 4, Static>::new();
    let gone = map
        .insert(Counted(&drops))
        .expect("a table of four takes a row");
    let kept = map
        .insert(Counted(&drops))
        .expect("a table of four takes a second row");
    assert_eq!(map.discard(gone), Some(Discarded::Now));
    assert_eq!(drops.get(), 1);
    assert!(map.get(gone).is_none());
    assert!(!map.holds_slot(gone));
    assert_eq!(map.len(), 1);
    assert_eq!(
        map.discard(gone),
        None,
        "a handle past its row discards nothing"
    );
    assert_eq!(drops.get(), 1);
    let next = map.insert(Counted(&drops)).expect("the freed slot is free");
    assert_eq!(next.place(), gone.place());
    assert_ne!(next, gone);
    assert!(map.get(kept).is_some());
    drop(map);
    assert_eq!(
        drops.get(),
        3,
        "the two rows left go with the table, once each"
    );
}

/// A pinned row discarded is retired, not dropped: it leaves every lookup, keeps its slot, and is
/// handed back by its last unpin, as a pinned row removed is. Turned red by a discard that drops a
/// row a call still reads.
#[test]
fn a_pinned_row_discarded_waits_for_its_last_unpin() {
    let drops = Cell::new(0);
    let mut map = SlotMap::<Test, Counted<'_>, 2, Static>::new();
    let row = map
        .insert(Counted(&drops))
        .expect("a table of two takes a row");
    let pin = map.pin(row).expect("a live row is pinned");
    assert_eq!(map.discard(row), Some(Discarded::AfterCalls));
    assert_eq!(drops.get(), 0, "a call still reads it");
    assert!(map.get(row).is_none());
    assert!(map.holds_slot(row));
    let back = map.unpin(pin);
    assert!(back.is_some(), "the last unpin hands the row back");
    drop(back);
    assert_eq!(drops.get(), 1);
    assert!(!map.holds_slot(row));
}

/// A row found by its entry is discarded through it as by its handle: dropped where it lies, or
/// retired while pinned. Turned red by an entry's discard that frees no slot, or drops a row a
/// call still reads.
#[test]
fn an_entry_discards_its_row_as_its_handle_does() {
    let drops = Cell::new(0);
    let mut map = SlotMap::<Test, Counted<'_>, 2, Static>::new();
    let free = map
        .insert(Counted(&drops))
        .expect("a table of two takes a row");
    let pinned = map
        .insert(Counted(&drops))
        .expect("a table of two takes a second row");
    let pin = map.pin(pinned).expect("a live row is pinned");
    let entry = map.entry(free).expect("a live row has an entry");
    assert_eq!(entry.discard(), Some(Discarded::Now));
    assert_eq!(drops.get(), 1);
    assert!(!map.holds_slot(free));
    let entry = map.entry(pinned).expect("a live row has an entry");
    assert_eq!(entry.discard(), Some(Discarded::AfterCalls));
    assert_eq!(drops.get(), 1, "a call still reads it");
    assert!(map.entry(pinned).is_none(), "a retired row has no entry");
    drop(map.unpin(pin));
    assert_eq!(drops.get(), 2);
    assert_eq!(map.len(), 0);
}

/// A slot is taken only off the free list, and is put there only once it was added after every
/// slot there was: taken, it is live at the generation it was added at; freed, it is taken again
/// at its next. Turned red by a take that makes a slot live that was never added, or an added slot
/// that `adopt` counts as holding a row.
#[test]
fn the_core_takes_a_slot_only_off_its_free_list() {
    let mut meta = BoundedVec::<Meta, 4, Static>::default();
    let mut slots = Core::new(4);
    assert!(slots.take_free(&mut meta).is_none(), "no slot was added");
    assert!(meta.push(Meta::FREED).is_ok());
    slots.adopt(&mut meta, 0);
    assert_eq!(slots.held, 0, "an added slot holds no row");
    assert_eq!(slots.take_free(&mut meta), Some((0, 0)));
    assert_eq!(slots.held, 1);
    assert!(
        slots.take_free(&mut meta).is_none(),
        "the one slot is taken"
    );
    slots.free(&mut meta, 0);
    assert_eq!(
        slots.take_free(&mut meta),
        Some((0, 1)),
        "a freed slot is taken again at its next generation"
    );
    assert_eq!((meta.len(), slots.held), (1, 1));
}

/// A table at its bound adds no slot to its columns: the refused insert leaves both as they were.
/// Turned red by a table that grows its columns before it reads its bound.
#[test]
fn a_table_at_its_bound_adds_no_slot() {
    let mut map = Map::<4>::new();
    map.limit_to(1);
    assert!(map.insert(1).is_ok());
    assert!(map.insert(2).is_err());
    assert_eq!(map.meta.len(), 1, "no slot was added past the bound");
    assert_eq!(map.rows.len(), 1, "nor a place for its row");
}

/// The untyped take hands the handle and the place of a free slot's row, which the caller writes
/// the row at; a table with no free slot takes none until its typed face adds one. Turned red by a
/// take that adds a slot itself, or answers a place other than the one the table reads the row at.
#[test]
fn a_raw_take_answers_a_free_slot_and_the_place_its_row_is_read_at() {
    let mut map = Map::<4>::new();
    assert!(map.raw().take().is_none(), "no slot was added");
    assert_eq!(map.len(), 0);
    let (handle, place) = map
        .raw_for_insert()
        .take()
        .expect("a slot was added for the take");
    // SAFETY: the place of the row of the slot just taken, which holds `None`.
    unsafe { place.cast::<Option<u32>>().as_ptr().write(Some(7)) };
    let handle = handle.tag::<Test>();
    assert_eq!(map.get(handle), Some(&7));
    assert_eq!(map.len(), 1);
    let stride = map.raw().stride();
    assert_eq!(stride, core::mem::size_of::<Option<u32>>());
    let found = map
        .raw()
        .get(handle.erase())
        .expect("the live row is found");
    assert_eq!(found, place, "found where it was written");
}

/// A removal through the untyped core frees the slot and leaves the row at its place for the
/// caller to take out; a pinned row is retired and found by no lookup. Turned red by a removal
/// that drops the row itself, or one that frees a pinned row's slot.
#[test]
fn a_raw_removal_leaves_the_row_for_its_caller_and_retires_a_pinned_one() {
    let drops = Cell::new(0);
    let mut map = SlotMap::<Test, Counted<'_>, 4, Static>::new();
    let (Ok(freed), Ok(pinned)) = (map.insert(Counted(&drops)), map.insert(Counted(&drops))) else {
        panic!("a table of four refused one of two rows");
    };
    let Some(RawRemoval::Freed(place)) = map.raw().remove(freed.erase()) else {
        panic!("a live row that is not pinned is freed");
    };
    assert_eq!(drops.get(), 0, "the removal drops nothing");
    assert!(
        map.get(freed).is_none(),
        "the freed row is found by no lookup"
    );
    // SAFETY: the place of the row whose slot was just freed; taken out once, leaving `None`.
    drop(unsafe { place.cast::<Option<Counted<'_>>>().as_ptr().replace(None) });
    assert_eq!(drops.get(), 1);
    let pin = map.pin(pinned).expect("a live row is pinned");
    assert_eq!(
        map.raw().remove(pinned.erase()),
        Some(RawRemoval::AfterCalls)
    );
    assert!(
        map.raw().get(pinned.erase()).is_none(),
        "a retired row is not live"
    );
    assert!(map.holds_slot(pinned), "the retired row keeps its slot");
    drop(map.unpin(pin));
    assert_eq!(drops.get(), 2, "the last unpin hands the row back");
}

/// Two tables of two strides, each reached through its untyped core alone: a row removed from
/// either and a row taken again land in that table's own freed slot, at its own stride, and a
/// handle kept across the removal reads nothing. Turned red by a core that reads one table's
/// stride for another's rows, or a removal that leaves the slot's generation where it was.
#[test]
fn two_tables_of_two_strides_each_take_again_their_own_freed_slot() {
    let mut narrow = SlotMap::<Test, u8, 4, Static>::new();
    let mut wide = SlotMap::<Test, [u64; 3], 4, Static>::new();
    let (Ok(narrow_first), Ok(_)) = (narrow.insert(1), narrow.insert(2)) else {
        panic!("a table of four refused one of two rows");
    };
    let (Ok(wide_first), Ok(wide_second)) = (wide.insert([1; 3]), wide.insert([2; 3])) else {
        panic!("a table of four refused one of two rows");
    };
    let stride = wide.raw().stride();
    assert_ne!(narrow.raw().stride(), stride);
    let first_place = wide.raw().get(wide_first.erase()).expect("a live row");
    let second_place = wide.raw().get(wide_second.erase()).expect("a live row");
    assert_eq!(
        (second_place.as_ptr() as usize) - (first_place.as_ptr() as usize),
        stride,
        "the second row lies one stride of its own table past the first"
    );

    let Some(RawRemoval::Freed(place)) = narrow.raw().remove(narrow_first.erase()) else {
        panic!("a live row that is not pinned is freed");
    };
    // SAFETY: the place of the row whose slot was just freed; taken out once, leaving `None`.
    assert_eq!(
        unsafe { place.cast::<Option<u8>>().as_ptr().replace(None) },
        Some(1)
    );
    let Some(RawRemoval::Freed(place)) = wide.raw().remove(wide_second.erase()) else {
        panic!("a live row that is not pinned is freed");
    };
    assert_eq!(place, second_place);
    // SAFETY: as above.
    assert_eq!(
        unsafe { place.cast::<Option<[u64; 3]>>().as_ptr().replace(None) },
        Some([2; 3])
    );

    let (narrow_again, at) = narrow.raw().take().expect("the freed slot is free");
    assert_eq!(narrow_again.place(), narrow_first.place());
    // SAFETY: the place of the row of the slot just taken, which holds `None`.
    unsafe { at.cast::<Option<u8>>().as_ptr().write(Some(9)) };
    let (wide_again, at) = wide.raw().take().expect("the freed slot is free");
    assert_eq!(wide_again.place(), wide_second.place());
    assert_eq!(at, second_place, "taken again at its own table's stride");
    // SAFETY: as above.
    unsafe { at.cast::<Option<[u64; 3]>>().as_ptr().write(Some([9; 3])) };

    assert!(
        narrow.get(narrow_first).is_none(),
        "a handle kept across the removal"
    );
    assert!(
        wide.get(wide_second).is_none(),
        "a handle kept across the removal"
    );
    assert_eq!(narrow.get(narrow_again.tag::<Test>()), Some(&9));
    assert_eq!(wide.get(wide_again.tag::<Test>()), Some(&[9; 3]));
    assert_eq!(
        wide.get(wide_first),
        Some(&[1; 3]),
        "the other row is untouched"
    );
}

/// The untyped walk hands each live row once, in slot order, at the place the table reads it at,
/// and passes over a retired row and a free slot; its pin is the table's. Turned red by a walk
/// that hands a retired row, or that finds a row at another place than its handle's.
#[test]
fn a_raw_walk_hands_each_live_row_where_its_handle_finds_it() {
    let mut map = Map::<4>::new();
    let (Ok(first), Ok(freed), Ok(retired), Ok(last)) =
        (map.insert(1), map.insert(2), map.insert(3), map.insert(4))
    else {
        panic!("a table of four refused one of four rows");
    };
    assert!(matches!(map.remove(freed), Some(Removal::Taken(2))));
    assert!(map.raw().pin(retired.erase()), "a live row is pinned");
    assert!(matches!(map.remove(retired), Some(Removal::AfterCalls)));
    assert!(!map.raw().pin(freed.erase()), "a freed row is not pinned");

    let raw = map.raw();
    let mut cursor = 0;
    let mut walked = std::vec::Vec::new();
    while let Some((handle, place)) = raw.next_live(&mut cursor) {
        assert_eq!(raw.get(handle), Some(place));
        // SAFETY: the place of a live row of this table, read while it is borrowed.
        walked.push(unsafe { *place.cast::<Option<u32>>().as_ref() });
    }
    assert_eq!(walked, [Some(1), Some(4)]);
    let mut cursor = 0;
    let typed: std::vec::Vec<_> = core::iter::from_fn(|| map.next_from(&mut cursor)).collect();
    assert_eq!(
        typed,
        [(first, &1), (last, &4)],
        "the typed walk is the same walk"
    );
    let mut cursor = 0;
    assert_eq!(map.next_retired_from(&mut cursor), Some((retired, &3)));
    assert_eq!(map.release(retired), Some(3), "its last pin hands it back");
}

/// Rows of a growable table past its first chunk are found by their handle where they were put,
/// and stay there as more rows come: the untyped core finds a row through the list of the chunks'
/// places. Turned red by a row found in another chunk than the one it was written in, or a chunk
/// that moves when one is added.
#[cfg(feature = "alloc")]
#[test]
fn a_growable_tables_rows_are_found_where_they_were_put_past_its_first_chunk() {
    let mut map = SlotMap::<Test, u32, 2, crate::bounded::Heap>::new();
    let count = 2 * CHUNK_ROWS + 3;
    let mut handles = std::vec::Vec::new();
    for value in 0..count {
        handles.push(
            map.insert(value as u32)
                .expect("a growable table takes a row"),
        );
    }
    let first = map.get(handles[0]).map(core::ptr::from_ref);
    for (value, handle) in handles.iter().enumerate() {
        assert_eq!(map.get(*handle), Some(&(value as u32)));
        let place = map.raw().get(handle.erase()).expect("a live row");
        // SAFETY: the place of a live row of this table, read while the table is borrowed.
        let read = unsafe { *place.cast::<Option<u32>>().as_ptr() };
        assert_eq!(
            read,
            Some(value as u32),
            "the untyped core finds the same row"
        );
    }
    assert_eq!(map.iter().count(), count);
    assert_eq!(
        map.get(handles[0]).map(core::ptr::from_ref),
        first,
        "the first row did not move"
    );
    let last = *handles.last().expect("rows were put");
    assert!(matches!(map.remove(last), Some(Removal::Taken(_))));
    assert!(map.get(last).is_none());
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

/// A table of the region policy lies in a region of zero bytes with its rows beside it: empty
/// there and with no slot, and placed by its two lines of the region's description it takes its
/// `N` rows, names each, refuses the next, and gives a freed slot to the next insert. Turned red by
/// a `Core` whose zero bytes are not an empty free list (a `NIL` other than zero, or a link not
/// counted from one), or by `places` naming one column's rows for the other.
#[test]
fn a_region_table_of_zero_bytes_placed_by_its_lines_holds_n_rows() {
    #[repr(C)]
    struct OneTable {
        table: SlotMap<Test, u32, 3, Region>,
        rows: SlotRows<u32, 3>,
    }
    // SAFETY: both fields are `ZeroEmpty`.
    unsafe impl ZeroEmpty for OneTable {}
    const LINES: [SeqPlace; 2] = SlotMap::<Test, u32, 3, Region>::places(
        core::mem::offset_of!(OneTable, table),
        core::mem::offset_of!(OneTable, rows),
    );
    let layout = std::alloc::Layout::new::<OneTable>();
    // SAFETY: the layout is of a type of some bytes.
    let block = unsafe { std::alloc::alloc_zeroed(layout) };
    let region = NonNull::new(block).expect("the test allocator answers");
    // SAFETY: the zeroed block is a `OneTable`, every field of which is empty at zero bytes.
    let one = unsafe { &mut *block.cast::<OneTable>() };
    assert!(one.table.is_empty());
    assert!(one.table.is_full(), "a table placed no rows has no slot");
    // SAFETY: the lines name the table's two columns and the rows beside it, aligned, which
    // nothing but the table reaches.
    unsafe { crate::bounded::place_seqs(region, &LINES) };
    assert_eq!(one.table.capacity(), 3);
    let first = one.table.insert(10).expect("a slot");
    let second = one.table.insert(11).expect("a slot");
    let third = one.table.insert(12).expect("a slot");
    assert!(
        one.table.insert(13).is_err(),
        "three rows are all it was placed"
    );
    assert_eq!(one.table.get(second), Some(&11));
    assert!(one.table.remove(second).is_some());
    assert_eq!(one.table.get(second), None);
    let again = one.table.insert(14).expect("the freed slot");
    assert_eq!(one.table.get(again), Some(&14));
    assert_eq!(
        (one.table.get(first), one.table.get(third)),
        (Some(&10), Some(&12))
    );
    assert!(
        one.table.insert(15).is_err(),
        "the freed slot was the only one"
    );
    // SAFETY: the rows hold nothing that drops; the block goes back with its layout.
    unsafe { std::alloc::dealloc(block, layout) };
}

/// A table keyed by a peer's ids, of all zero bytes, holds no id and takes one.
#[test]
fn a_fixed_id_map_of_zero_bytes_is_empty() {
    use crate::id_map::{FixedIdMap, IdMap};
    // SAFETY: `FixedIdMap` is `ZeroEmpty`.
    let mut ids: FixedIdMap<u32, 2> = unsafe { core::mem::zeroed() };
    assert!(ids.find(7).is_none());
    assert!(matches!(ids.bind(7, 70), Ok(None)));
    assert_eq!(ids.find(7), Some(&70));
    assert_eq!(ids.unbind(7), Some(70));
}

/// The rows a table the contract is read on is made to hold: past one chunk of the growable
/// policy's column, so the clause that a row stays where it was put spans the insert that makes a
/// second chunk there.
const CONTRACT_ROWS: usize = 40;

#[cfg(feature = "alloc")]
const _: () = assert!(CONTRACT_ROWS > CHUNK_ROWS);

/// A table made to hold `CONTRACT_ROWS` rows.
type ContractMap<P> = SlotMap<Test, u32, CONTRACT_ROWS, P>;

/// Hold `map`, made empty to hold `CONTRACT_ROWS` rows, to what a table answers whatever its
/// storage policy, the shape a policy gives its rows being the only thing a policy changes
/// (`docs/c-abi-migration/heap-native.md`, section 2.3): its count bounds it and a refusal hands
/// the value back and takes nothing; a row stays where it was put while it stands; a handle names
/// nothing once its row left, before and after its slot is taken again; a row removed while pinned
/// leaves every lookup at once and holds its slot until its last unpin hands it back; a limit
/// lowered under the rows held refuses every insert until enough leave, though slots are free.
///
/// Turned red by a policy's column that moves a row when it grows, by `Core::free` leaving a
/// slot's generation, by `Core::take_free` taking a slot past the limit, or by a retired row that a
/// lookup or a walk still finds or whose slot an insert takes before its last unpin.
fn keeps_the_table_contract<P: Storage>(map: &mut ContractMap<P>) {
    assert!(map.is_empty());
    assert_eq!(map.capacity(), CONTRACT_ROWS);

    let first = map.insert(0).expect("a row under the count");
    let first_at: *const u32 = map.get(first).expect("the row just put");
    let mut held = std::vec![first];
    for value in 1..CONTRACT_ROWS {
        let value = u32::try_from(value).expect("a count a u32 holds");
        held.push(map.insert(value).expect("a row under the count"));
    }
    assert!(map.is_full());
    match map.insert(u32::MAX) {
        Err(CapacityFull(back)) => assert_eq!(back, u32::MAX),
        Ok(_) => panic!("a row went in past the count"),
    }
    assert_eq!(map.len(), CONTRACT_ROWS);

    assert!(
        core::ptr::eq(map.get(first).expect("the first row stands"), first_at),
        "a row stays where it was put"
    );
    for (at, handle) in held.iter().enumerate() {
        assert_eq!(map.get(*handle).copied(), u32::try_from(at).ok());
    }

    let gone = held[1];
    assert_eq!(map.remove(gone), Some(Removal::Taken(1)));
    assert_eq!(map.get(gone), None);
    assert!(!map.contains(gone));
    assert!(map.pin(gone).is_none());
    assert_eq!(map.remove(gone), None);
    let again = map.insert(100).expect("the slot the removal freed");
    assert_eq!(again.place(), gone.place());
    assert_ne!(again, gone, "the slot's generation moved");
    assert_eq!(map.get(gone), None);
    assert_eq!(map.get(again), Some(&100));
    assert_eq!(Handle::<Test>::from_bits(again.to_bits()), Some(again));

    let busy = held[2];
    let pin = map.pin(busy).expect("a live row is pinned");
    assert_eq!(map.remove(busy), Some(Removal::AfterCalls));
    assert_eq!(map.get(busy), None);
    assert!(map.iter().all(|(handle, _)| handle != busy));
    assert_eq!(map.pinned(&pin), Some(&2));
    assert!(map.holds_slot(busy));
    assert_eq!(map.len(), CONTRACT_ROWS);
    assert!(
        map.insert(u32::MAX).is_err(),
        "a retired row holds its slot"
    );
    assert_eq!(map.unpin(pin), Some(2));
    assert!(!map.holds_slot(busy));
    let next = map.insert(200).expect("the slot the last unpin freed");
    assert_eq!(next.place(), busy.place());
    assert_eq!(map.get(busy), None);

    map.limit_to(CONTRACT_ROWS - 2);
    assert_eq!(map.capacity(), CONTRACT_ROWS - 2);
    assert!(map.remove(held[3]).is_some());
    assert!(map.remove(held[4]).is_some());
    assert_eq!(map.len(), CONTRACT_ROWS - 2);
    assert!(
        map.insert(300).is_err(),
        "two slots are free and the lowered limit holds"
    );
    assert!(map.remove(held[5]).is_some());
    assert!(map.insert(300).is_ok(), "one row under the limit");
}

/// The fixed policy keeps the table contract, its rows inline in the table at its build count.
#[test]
fn a_fixed_table_keeps_the_table_contract() {
    keeps_the_table_contract(&mut ContractMap::<Static>::new());
}

/// The lent policy keeps the table contract, its rows lent from an arena at the count asked.
#[test]
fn a_lent_table_keeps_the_table_contract() {
    let bytes = ContractMap::<Lent>::arena_bytes(CONTRACT_ROWS).expect("a table's bytes");
    let mut arena = arena(bytes);
    let mut map = ContractMap::<Lent>::lent(&mut arena, CONTRACT_ROWS).expect("the rows lent");
    keeps_the_table_contract(&mut map);
}

/// The region policy keeps the table contract, its rows laid out beside the table in a block of
/// zero bytes and placed by the table's lines.
#[test]
fn a_region_table_keeps_the_table_contract() {
    #[repr(C)]
    struct OneTable {
        table: ContractMap<Region>,
        rows: SlotRows<u32, CONTRACT_ROWS>,
    }
    // SAFETY: both fields are `ZeroEmpty`.
    unsafe impl ZeroEmpty for OneTable {}
    const LINES: [SeqPlace; 2] = ContractMap::<Region>::places(
        core::mem::offset_of!(OneTable, table),
        core::mem::offset_of!(OneTable, rows),
    );
    let layout = std::alloc::Layout::new::<OneTable>();
    // SAFETY: the layout is of a type of some bytes.
    let block = unsafe { std::alloc::alloc_zeroed(layout) };
    let region = NonNull::new(block).expect("the test allocator answers");
    // SAFETY: the lines name the table's two columns and the rows beside it, aligned, which
    // nothing but the table reaches.
    unsafe { crate::bounded::place_seqs(region, &LINES) };
    // SAFETY: the zeroed block is a `OneTable`, its table placed over its rows just above, and
    // nothing else reaches it until it goes back below.
    let one = unsafe { &mut *block.cast::<OneTable>() };
    keeps_the_table_contract(&mut one.table);
    // SAFETY: the rows hold nothing that drops; the block goes back with its layout.
    unsafe { std::alloc::dealloc(block, layout) };
}

/// The growable policy keeps the table contract once a limit holds it to the count, its rows in
/// chunks made as they are needed. Turned red by a column of that policy that moves its rows when
/// it grows, or that a limit does not bound.
#[cfg(feature = "alloc")]
#[test]
fn a_growable_table_held_to_a_count_keeps_the_table_contract() {
    let mut map = ContractMap::<crate::bounded::Heap>::new();
    map.limit_to(CONTRACT_ROWS);
    keeps_the_table_contract(&mut map);
}
