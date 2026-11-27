// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

use super::GetLegs;
use crate::bounded::{Arena, Lent, ARENA_ALIGN};
use crate::reply_sink::{BorrowedReply, ReplyKind};
use crate::wire_id::{request_id_at, RequestId};
use core::ptr::NonNull;

/// One block of an arena's memory, aligned as an arena's spans start.
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct Block([u8; ARENA_ALIGN]);

/// An arena of at least `bytes` bytes over memory the test process leaks, so it outlives the
/// table it lends.
fn arena(bytes: usize) -> Arena {
    let blocks = bytes.div_ceil(ARENA_ALIGN).max(1);
    let region: &'static mut [Block] = std::vec![Block([0; ARENA_ALIGN]); blocks].leak();
    // SAFETY: the region is aligned to `ARENA_ALIGN`, as its blocks are, holds `blocks` whole
    // blocks, and is leaked, so nothing else uses it and it outlives the lent table.
    unsafe { Arena::over(NonNull::from(region).cast::<u8>(), blocks * ARENA_ALIGN) }
}

fn reply(rid: RequestId, keyexpr: &str, kind: ReplyKind) -> BorrowedReply<'_> {
    BorrowedReply {
        rid,
        keyexpr,
        kind,
        payload: b"v",
        err_encoding: None,
        attachment: None,
        put_encoding: None,
    }
}

/// A reply finds the get its id names, and the Final of that leg ends it once, handing the get
/// back. Turned red by a reply handed to another leg's get, or a Final that ends a leg twice.
#[test]
fn a_reply_finds_the_get_its_id_names_and_its_final_ends_the_leg_once() {
    let mut legs = GetLegs::<u8>::default();
    let first = request_id_at(1, legs.next_row());
    assert!(legs.hold(first, 7));
    let second = request_id_at(1, legs.next_row());
    assert!(legs.hold(second, 9));
    assert_eq!(
        legs.reply_to(&reply(second, "demo/a", ReplyKind::Put)),
        Some(9)
    );
    assert_eq!(legs.reply_to(&reply(first, "", ReplyKind::Err)), Some(7));
    assert_eq!(legs.end_leg(second), Some(9));
    assert_eq!(legs.end_leg(second), None, "its Final was taken");
    assert_eq!(legs.get_of(second), None);
    assert_eq!(legs.get_of(first), Some(7), "CONTROL: the other leg stands");
    assert_eq!(legs.len(), 1);
}

/// A row held again is not named by the id of the leg it held before, and a leg an earlier end
/// moved toward the front is still found by its id. Turned red by a carried row taken without the
/// whole id compared, or by a find that reads only the carried row.
#[test]
fn a_leg_is_found_by_its_whole_id_wherever_an_earlier_end_moved_it() {
    let mut legs = GetLegs::<u8>::default();
    let earlier = request_id_at(1, legs.next_row());
    assert!(legs.hold(earlier, 3));
    assert_eq!(legs.end_leg(earlier), Some(3));
    let again = request_id_at(2, legs.next_row());
    assert_eq!(again & 0xff, earlier & 0xff, "the same row");
    assert!(legs.hold(again, 4));
    assert_eq!(legs.get_of(earlier), None);
    assert_eq!(legs.get_of(again), Some(4));
    let moved = request_id_at(2, legs.next_row());
    assert!(legs.hold(moved, 5));
    assert_eq!(legs.end_leg(again), Some(4));
    assert_eq!(legs.get_of(moved), Some(5), "found past the row it carries");
}

/// A get its row retired lets go of its legs and no other's, and a face lost ends every leg it
/// holds, each handed back once. Turned red by a forget that takes another get's leg, or a loss
/// that leaves a leg held or hands one twice.
#[test]
fn a_retired_get_is_forgotten_and_a_lost_face_ends_every_leg() {
    let mut legs = GetLegs::<u8>::default();
    assert!(legs.hold(request_id_at(1, 0), 3));
    assert!(legs.hold(request_id_at(1, 1), 4));
    assert!(legs.hold(request_id_at(1, 2), 3));
    assert_eq!(legs.forget(3), 2);
    assert_eq!(legs.forget(3), 0, "nothing of it is left");
    assert_eq!(legs.get_of(request_id_at(1, 1)), Some(4));
    assert!(legs.hold(request_id_at(2, 1), 6));
    let mut ended = std::vec::Vec::new();
    legs.end_every_leg(|get| ended.push(get));
    assert_eq!(ended, [4, 6]);
    assert!(legs.is_empty());
    assert_eq!(legs.end_leg(request_id_at(1, 1)), None);
}

/// A table lent one row holds one leg and refuses the next, which takes the row once it is free.
/// Turned red by a table that holds past its rows or keeps a row its leg left.
#[test]
fn a_table_lent_one_row_refuses_a_second_leg_until_the_first_ends() {
    let mut arena = arena(GetLegs::<u8, Lent>::arena_bytes(1).expect("one row"));
    let mut legs = GetLegs::<u8, Lent>::lent(&mut arena, 1).expect("one row");
    assert!(legs.has_room());
    assert!(legs.hold(request_id_at(1, 0), 1));
    assert!(!legs.has_room());
    assert!(!legs.hold(request_id_at(1, 1), 2), "no row is free");
    assert_eq!(legs.end_leg(request_id_at(1, 0)), Some(1));
    assert!(legs.hold(request_id_at(2, 0), 2), "the row is free again");
}

/// A face whose key set is closed hands a get no reply its peer sent on a key outside the set,
/// counted, though the leg is held; an Err, which names no key, is handed on. Turned red by a
/// reply that skips the face's key gate.
#[cfg(feature = "key-set-closed")]
#[test]
fn a_closed_key_set_keeps_a_reply_outside_it_from_its_get() {
    use crate::key_catalogue::tests::TABLE;
    let mut legs = GetLegs::<u8>::default();
    legs.receive_mut()
        .set_key_gate(crate::key_gate::KeyGate::closed(&TABLE));
    let id = request_id_at(1, 0);
    assert!(legs.hold(id, 8));
    assert_eq!(legs.reply_to(&reply(id, "a/b", ReplyKind::Put)), Some(8));
    assert_eq!(legs.reply_to(&reply(id, "a/c", ReplyKind::Put)), None);
    assert_eq!(legs.reply_to(&reply(id, "", ReplyKind::Err)), Some(8));
    assert_eq!(legs.receive().key_gate_refused().outside_set, 1);
}
