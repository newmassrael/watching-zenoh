// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The rows of the legs' callbacks, the ends and the held replies of the get plane, each lent by an
//! arena, and the sink and the hold a leg's entry owns.

use super::*;
use crate::bounded::{Arena, Lent, OnUse, ARENA_ALIGN};
use crate::caps;
use crate::placed::Placed;
use crate::plane_lock::StdLocks;
use crate::reply_sink::ReplyKind;
use crate::round::{RoundCalls, RoundRowCounts, RoundRows};
use crate::session_tables::{Absent, Present};
use alloc::sync::Arc;
use core::convert::Infallible;
use core::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::AtomicUsize;

/// What a test's leg callback was handed, and how often it was let go of.
#[derive(Default)]
struct Seen {
    calls: AtomicUsize,
    drops: AtomicUsize,
}

impl Seen {
    fn calls(&self) -> usize {
        self.calls.load(SeqCst)
    }

    fn drops(&self) -> usize {
        self.drops.load(SeqCst)
    }
}

/// A leg's callback, which counts its calls and its drop in what it sees.
struct Counted(Arc<Seen>);

impl Drop for Counted {
    fn drop(&mut self) {
        self.0.drops.fetch_add(1, SeqCst);
    }
}

/// A session whose own queryables answer its gets: its plane captures.
enum Asking {}

impl RoundCalls for Asking {
    type Subscriber = Infallible;
    type Liveliness = Infallible;
    type Queryable = Infallible;
    type Watch = core::convert::Infallible;
    type Leg = LegId;
    type ReplyCallback = Counted;
    type Tokens = Absent;
    type Replies = Present;
    type Queries = Absent;
    type Watches = Absent;
    type Capture = Absent;
    type Group = Absent;
    type Locks = StdLocks;
    type Tally = ();
    type Form = crate::row_callback::Threads;
    type TablePolicy = Lent;
}

impl PlaneCalls for Asking {
    type LocalAnswers = Present;
    type Captures = Present;
    type Queues = StdLocks;
}

impl GetCalls for Asking {
    type Fan = u8;

    fn call(callback: &Counted, _reply: &dyn ReplyView) {
        callback.0.calls.fetch_add(1, SeqCst);
    }

    fn holds_a_session() -> bool {
        false
    }
}

/// A session whose gets only its links answer: its plane captures nothing.
enum Remote {}

impl RoundCalls for Remote {
    type Subscriber = Infallible;
    type Liveliness = Infallible;
    type Queryable = Infallible;
    type Watch = core::convert::Infallible;
    type Leg = LegId;
    type ReplyCallback = Counted;
    type Tokens = Absent;
    type Replies = Present;
    type Queries = Absent;
    type Watches = Absent;
    type Capture = Absent;
    type Group = Absent;
    type Locks = StdLocks;
    type Tally = ();
    type Form = crate::row_callback::Threads;
    type TablePolicy = Lent;
}

impl PlaneCalls for Remote {
    type LocalAnswers = Absent;
    type Captures = Absent;
    type Queues = StdLocks;
}

impl GetCalls for Remote {
    type Fan = u8;

    fn call(callback: &Counted, _reply: &dyn ReplyView) {
        callback.0.calls.fetch_add(1, SeqCst);
    }

    fn holds_a_session() -> bool {
        false
    }
}

/// A session whose gets only its links answer, whose read hands each record out as it is read: its
/// plane captures the peer's reply for the read.
enum Stepped {}

impl RoundCalls for Stepped {
    type Subscriber = Infallible;
    type Liveliness = Infallible;
    type Queryable = Infallible;
    type Watch = core::convert::Infallible;
    type Leg = LegId;
    type ReplyCallback = Counted;
    type Tokens = Absent;
    type Replies = Present;
    type Queries = Absent;
    type Watches = Absent;
    type Capture = Absent;
    type Group = Absent;
    type Locks = StdLocks;
    type Tally = ();
    type Form = crate::row_callback::Threads;
    type TablePolicy = Lent;
}

impl PlaneCalls for Stepped {
    type LocalAnswers = Absent;
    type Captures = Present;
    type Queues = StdLocks;
}

impl GetCalls for Stepped {
    type Fan = u8;

    fn call(callback: &Counted, _reply: &dyn ReplyView) {
        callback.0.calls.fetch_add(1, SeqCst);
    }

    fn holds_a_session() -> bool {
        false
    }
}

/// [`Remote`] in a session whose tables take their rows at their first value.
enum RemoteOnUse {}

impl RoundCalls for RemoteOnUse {
    type Subscriber = Infallible;
    type Liveliness = Infallible;
    type Queryable = Infallible;
    type Watch = core::convert::Infallible;
    type Leg = LegId;
    type ReplyCallback = Counted;
    type Tokens = Absent;
    type Replies = Present;
    type Queries = Absent;
    type Watches = Absent;
    type Capture = Absent;
    type Group = Absent;
    type Locks = StdLocks;
    type Tally = ();
    type Form = crate::row_callback::Threads;
    type TablePolicy = OnUse;
}

impl PlaneCalls for RemoteOnUse {
    type LocalAnswers = Absent;
    type Captures = Absent;
    type Queues = StdLocks;
}

impl GetCalls for RemoteOnUse {
    type Fan = u8;

    fn call(callback: &Counted, _reply: &dyn ReplyView) {
        callback.0.calls.fetch_add(1, SeqCst);
    }

    fn holds_a_session() -> bool {
        false
    }
}

/// One block of an arena's memory, aligned as an arena's spans start.
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct Block([u8; ARENA_ALIGN]);

/// An arena of at least `bytes` bytes over memory the test process leaks, so it outlives every
/// table it lends.
fn arena(bytes: usize) -> Arena {
    let blocks = bytes.div_ceil(ARENA_ALIGN).max(1);
    let region: &'static mut [Block] = std::vec![Block([0; ARENA_ALIGN]); blocks].leak();
    // SAFETY: the region is aligned to `ARENA_ALIGN`, as its blocks are, holds `blocks` whole
    // blocks, and is leaked, so nothing else uses it and it outlives every lent table.
    unsafe { Arena::over(NonNull::from(region).cast::<u8>(), blocks * ARENA_ALIGN) }
}

/// A plane whose legs' callbacks and ends have `rows` rows and whose gets hold `held` replies.
fn plane<C: GetCalls<TablePolicy = Lent>>(rows: usize, held: usize) -> Placed<GetPlane<C>> {
    let mut arena = arena(1 << 17);
    let ends = arena.lend(rows).expect("the arena has the rows");
    let legs = arena.lend(rows).expect("the arena has the rows");
    let replies = HeldReplies::lent(&mut arena, held).expect("the arena has the rows");
    // SAFETY: the arena hands a place aligned for the plane and valid for writes of one, where it
    // stays.
    unsafe {
        arena.place_with(|at| {
            GetPlane::init_at(
                NonNull::new_unchecked(at),
                EndedLegs::over(ends),
                replies,
                LegRows::over(legs),
            )
        })
    }
    .expect("the arena has the plane's place")
}

/// A plane of a session whose tables take their rows at their first value: its legs' callbacks and
/// ends counted `rows` rows, its gets `held` replies, none of them taken yet. The plane itself is
/// placed in an arena over leaked memory.
fn plane_on_use<C: GetCalls<TablePolicy = OnUse>>(rows: usize, held: usize) -> Placed<GetPlane<C>> {
    let mut arena = arena(1 << 14);
    // SAFETY: the arena hands a place aligned for the plane and valid for writes of one, where it
    // stays.
    unsafe {
        arena.place_with(|at| {
            GetPlane::init_at(
                NonNull::new_unchecked(at),
                EndedLegs::over(BoundedVec::counted(rows)),
                HeldReplies::counted(held),
                LegRows::over(BoundedVec::counted(rows)),
            )
        })
    }
    .expect("the arena has the plane's place")
}

/// A round of a few records, placed with its tables in an arena over leaked memory.
fn round<C: RoundCalls<TablePolicy = Lent>>() -> Placed<Round<C>> {
    let counts = RoundRowCounts {
        records: caps::DELIVERY_LANE_EVENTS.min(4),
        callbacks: caps::DELIVERY_LANE_CALLBACKS.min(4),
        longest_key: caps::MAX_KEYEXPR_BYTES,
    };
    // Each table on a span of its own, rounded up to the next start of one.
    let bytes = counts.records * RoundRows::<C>::RECORD_BYTES
        + counts.callbacks * RoundRows::<C>::CALLBACK_BYTES
        + counts.key_bytes::<C::Form>()
        + core::mem::size_of::<Round<C>>()
        + 4 * ARENA_ALIGN;
    let mut arena = arena(bytes);
    let rows = RoundRows::lent(&mut arena, counts).expect("the arena has the rows");
    Round::placed_over(&mut arena, rows).expect("the arena has the round")
}

/// A reply of key `key` and payload `payload`.
struct Answer {
    key: &'static str,
    payload: &'static [u8],
}

impl ReplyView for Answer {
    fn rid(&self) -> RequestId {
        4
    }

    fn keyexpr(&self) -> &str {
        self.key
    }

    fn kind(&self) -> ReplyKind {
        ReplyKind::Put
    }

    fn payload(&self) -> &[u8] {
        self.payload
    }

    fn err_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
        None
    }
}

/// A reply a test hands a leg. A static, so its payload lies in one place a round can be lent
/// ([`lend_reply`]).
static REPLY: Answer = Answer {
    key: "demo/a",
    payload: b"a",
};

/// Lend `round` the bytes [`REPLY`]'s payload lies in, as a link lends the step the datagram a
/// reply was read in: the round copies no part, so a reply whose payload lies nowhere it was lent
/// is refused as unplaced.
fn lend_reply<C: RoundCalls>(round: &Round<C>) {
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is, and the
    // payload is static, so it lies where it is while the round reads it.
    unsafe { round.set_lending(Some(REPLY.payload)) };
}

/// The end of the get in row `at`, which the timeout of `rid` ended when there is one.
fn ended_by(at: u32, timed_out: Option<RequestId>) -> Ended {
    Ended {
        timed_out,
        row: LegId(at),
    }
}

/// What an end says: its get's row and the timeout that ended it.
fn said(ended: Option<Ended>) -> Option<(u32, Option<RequestId>)> {
    ended.map(|ended| (ended.row().0, ended.timed_out()))
}

/// The row of a get of one leg asked of `plane`, its asker let go of once that leg is held: what
/// stands of the get is the leg alone, which holds the one count of the row. `None`, nothing
/// minted, when the plane has no room for the get.
fn opened<C: GetCalls>(
    plane: &GetPlane<C>,
    mint: &mut dyn FnMut() -> C::ReplyCallback,
    shows_timestamp: bool,
    fan: Option<C::Fan>,
) -> Option<LegId> {
    let mut asked = AskedGet::new(plane);
    asked.leg(mint, shows_timestamp, fan)
}

/// A table of `rows` ends over an arena of its own.
fn ends(rows: usize) -> EndedLegs<Lent> {
    EndedLegs::over(arena(1 << 12).lend(rows).expect("the arena has the rows"))
}

/// Each get's hold keeps its replies in the plane's rows apart from another get's, refuses one past
/// the rows, and lets go of nothing at a leg's Final or at its drop: what a get holds waits for its
/// end, which takes it out, or for the session to let it go.
#[test]
fn a_gets_hold_keeps_its_replies_in_the_planes_rows_until_its_end() {
    let plane = plane::<Remote>(4, 2);
    // SAFETY: the holds, declared after the plane, are dropped before it.
    let shared = unsafe { plane.share() };
    let (mut one, mut two) = (
        LegHold::new(LegId(1), shared),
        LegHold::new(LegId(2), shared),
    );
    let first = Answer {
        key: "demo/a",
        payload: b"first",
    };
    assert_eq!(one.hold(&first, true), Ok(()));
    let other = Answer {
        key: "demo/a",
        payload: b"other",
    };
    assert_eq!(two.hold(&other, true), Ok(()));
    let past = Answer {
        key: "demo/b",
        payload: b"past",
    };
    assert_eq!(
        one.hold(&past, true),
        Err(HoldRefused::Full),
        "two rows hold two replies"
    );
    let mut drained = std::vec::Vec::new();
    one.drain(&mut |reply| drained.push(reply.payload().to_vec()));
    assert!(
        drained.is_empty(),
        "a leg's Final hands nothing on: what the get held waits in its rows"
    );
    drop(one);
    drop(two);
    assert_eq!(
        StdLocks::with(&plane.replies, |replies| replies.len()),
        2,
        "a leg's hold lets go of nothing as it goes"
    );
    let due = plane.take_due(LegId(1)).expect("the get's reply");
    assert_eq!(due.payload(), b"first", "a get is handed its own");
    assert!(plane.take_due(LegId(1)).is_none());
    plane.forget_due(LegId(2));
    assert!(StdLocks::with(&plane.replies, |replies| replies.is_empty()));
}

/// A leg's row holds its callback, called through it, until the last count is given back, which
/// hands the callback out to be dropped by the one that gave it back; a row given back is held
/// and called by none.
#[test]
fn a_legs_row_holds_its_callback_until_its_last_count() {
    let plane = plane::<Remote>(2, 1);
    let seen = Arc::new(Seen::default());
    let row = opened(&plane, &mut || Counted(seen.clone()), true, None).expect("a row is free");
    assert!(plane.hold(row), "a record's count of it");
    plane.call(row, &REPLY);
    assert_eq!(seen.calls(), 1);
    assert!(
        plane.release(row).is_none(),
        "the entry's count is still held"
    );
    assert_eq!(seen.drops(), 0);
    let last = plane.release(row);
    assert!(last.is_some(), "the last count hands the callback out");
    assert_eq!(seen.drops(), 0, "handed out, not dropped in the row");
    drop(last);
    assert_eq!(seen.drops(), 1);
    assert!(!plane.hold(row), "a row given back is held by none");
    plane.call(row, &REPLY);
    assert_eq!(seen.calls(), 1, "a row given back calls nothing");
}

/// A get's row names the fan it was asked under and no other, read through the sink of a leg's
/// entry; a get asked under no fan is in none, and a row given back is in none. Turned red by a row
/// that keeps no fan, or one that keeps it past its last count.
#[test]
fn a_legs_row_names_the_fan_its_get_was_asked_under() {
    let plane = plane::<Remote>(2, 1);
    let seen = Arc::new(Seen::default());
    let fanned =
        opened(&plane, &mut || Counted(seen.clone()), true, Some(7)).expect("a row is free");
    let alone =
        opened(&plane, &mut || Counted(seen.clone()), true, None).expect("a second row is free");
    // SAFETY: the test hands the sink nothing, and the sink is dropped before the plane.
    let sink = unsafe { LegSink::new(fanned, plane.share(), EveryReplyCaptured) };
    assert_eq!(sink.row(), fanned);
    assert!(plane.in_fan(sink.row(), 7));
    assert!(!plane.in_fan(sink.row(), 8), "another fan's");
    assert!(!plane.in_fan(alone, 7), "a get asked under no fan");
    drop(sink);
    let ended = plane
        .take_end()
        .expect("the leg that stood last wrote the get's end");
    drop(plane.release(ended.row()));
    assert!(!plane.in_fan(fanned, 7), "a row given back is in no fan");
    drop(plane.release(alone));
    assert_eq!(seen.drops(), 2);
}

/// A get that finds every row held is refused before its callback is minted, and the row its end
/// gives back is the next get's.
#[test]
fn a_leg_past_the_rows_mints_no_callback_and_a_row_given_back_is_reused() {
    let plane = plane::<Remote>(1, 1);
    let (first, second) = (Arc::new(Seen::default()), Arc::new(Seen::default()));
    let row = opened(&plane, &mut || Counted(first.clone()), true, None).expect("one row");
    let mut minted = 0;
    let refused = opened(
        &plane,
        &mut || {
            minted += 1;
            Counted(second.clone())
        },
        true,
        None,
    );
    assert_eq!(refused, None, "one row holds one get");
    assert_eq!(minted, 0, "refused before its callback is minted");
    // SAFETY: the test hands the sink nothing, and the sink is dropped before the plane.
    drop(unsafe { LegSink::new(row, plane.share(), EveryReplyCaptured) });
    let end = plane
        .take_end()
        .expect("the sink's drop, its leg standing last, is the get's end");
    drop(plane.release(end.row()));
    assert_eq!(first.drops(), 1);
    let again = opened(&plane, &mut || Counted(second.clone()), true, None);
    assert_eq!(again, Some(row), "the row given back is the next get's");
    drop(plane.release(row));
    assert_eq!(second.drops(), 1);
}

/// Every leg of one get hands its replies to the one callback the first leg minted, and the get's
/// end is written by what of it stands last, its legs and its asker in either order: a leg that
/// ends while another stands writes no end. Turned red by a later leg that mints a callback of its
/// own (`AskedGet::leg` opening a row each leg), by an asker that does not stand (the first leg's
/// end ending the get while it still issues its legs), or by an end written for each leg.
#[test]
fn a_gets_legs_share_the_callback_its_first_leg_minted() {
    let plane = plane::<Remote>(4, 1);
    let seen = Arc::new(Seen::default());
    let mut minted = 0;
    let mut asked = AskedGet::<Remote>::new(&plane);
    let mut mint = || {
        minted += 1;
        Counted(seen.clone())
    };
    let one = asked.leg(&mut mint, true, Some(3)).expect("a row");
    let two = asked.leg(&mut mint, true, Some(3)).expect("the same row");
    assert_eq!(one, two, "both legs name the get's one row");
    assert_eq!(minted, 1, "one callback for the get");
    assert!(plane.in_fan(two, 3), "the row names the fan of the get");
    // SAFETY: the test hands the sinks nothing, and they are dropped before the plane.
    let (first, second) = unsafe {
        (
            LegSink::new(one, plane.share(), EveryReplyCaptured),
            LegSink::new(two, plane.share(), EveryReplyCaptured),
        )
    };
    plane.call(first.row(), &REPLY);
    plane.call(second.row(), &REPLY);
    assert_eq!(seen.calls(), 2, "each leg's reply reaches the one callback");
    drop(first);
    assert!(
        plane.take_end().is_none(),
        "the second leg and the asker stand"
    );
    drop(asked);
    assert!(plane.take_end().is_none(), "the second leg stands");
    assert_eq!(seen.drops(), 0);
    drop(second);
    let end = plane.take_end().expect("the last leg writes the get's end");
    assert!(plane.take_end().is_none(), "one end for the get");
    drop(plane.release(end.row()));
    assert_eq!(seen.drops(), 1, "the end's count was the last");
    // A get whose one leg ended while it was issued: the asker stands last and writes the end.
    let mut asked = AskedGet::<Remote>::new(&plane);
    let row = asked
        .leg(&mut || Counted(seen.clone()), true, None)
        .expect("a row");
    // SAFETY: as above.
    drop(unsafe { LegSink::new(row, plane.share(), EveryReplyCaptured) });
    assert!(plane.take_end().is_none(), "the asker stands");
    drop(asked);
    let end = plane.take_end().expect("the asker writes the get's end");
    assert_eq!((end.row(), end.timed_out()), (row, None));
    assert_eq!(seen.drops(), 1, "the end holds the callback");
    drop(plane.release(end.row()));
    assert_eq!(seen.drops(), 2);
}

/// The ends bound the gets held at once, a row set aside for each at its first leg, whatever number
/// of legs each issues: a get past them is refused with nothing minted, and the row an end gives
/// back once handed out is the next get's. Turned red by a get held with no row of the ends set
/// aside (`EndedLegs::set_aside` left out of `GetPlane::open_leg`), whose end would find none, or by
/// a row set aside for each leg, which would refuse the third leg of the first get.
#[test]
fn the_ends_bound_the_gets_held_at_once_whatever_their_legs() {
    let plane = plane::<Remote>(2, 1);
    let seen = Arc::new(Seen::default());
    let mut mint = || Counted(seen.clone());
    let mut first = AskedGet::<Remote>::new(&plane);
    let row = first.leg(&mut mint, true, None).expect("a row");
    for _ in 0..3 {
        assert_eq!(
            first.leg(&mut mint, true, None),
            Some(row),
            "a later leg sets no row aside"
        );
    }
    let mut second = AskedGet::<Remote>::new(&plane);
    assert!(second.leg(&mut mint, true, None).is_some(), "a second get");
    let mut minted = 0;
    let mut third = AskedGet::<Remote>::new(&plane);
    let mut counting = || {
        minted += 1;
        Counted(seen.clone())
    };
    assert_eq!(
        third.leg(&mut counting, true, None),
        None,
        "two ends bound two gets"
    );
    assert_eq!(minted, 0, "refused before its callback is minted");
    // The first get ends: its four legs' entries, then its asker.
    for _ in 0..4 {
        // SAFETY: the test hands the sink nothing, and drops it before the plane.
        drop(unsafe { LegSink::new(row, plane.share(), EveryReplyCaptured) });
    }
    drop(first);
    assert!(
        third.leg(&mut mint, true, None).is_none(),
        "an end waiting holds its row until it is handed out"
    );
    let end = plane.take_end().expect("the first get's end");
    drop(plane.release(end.row()));
    assert!(
        third.leg(&mut mint, true, None).is_some(),
        "its row is free"
    );
    drop((second, third));
    while let Some(end) = plane.take_end() {
        drop(plane.release(end.row()));
    }
}

/// The plane let go of before its arena gives back the count an end waiting holds and drops every
/// callback a row still holds, and holds no row and no end after.
#[test]
fn a_plane_let_go_drops_the_callbacks_its_rows_and_ends_still_hold() {
    let plane = plane::<Remote>(2, 1);
    let (ended, open) = (Arc::new(Seen::default()), Arc::new(Seen::default()));
    let one = opened(&plane, &mut || Counted(ended.clone()), true, None).expect("a row");
    let two = opened(&plane, &mut || Counted(open.clone()), true, None).expect("a row");
    plane.ended.with(|ends| {
        ends.note(Ended {
            timed_out: None,
            row: one,
        })
    });
    plane.let_go();
    assert_eq!((ended.drops(), open.drops()), (1, 1));
    assert!(!plane.hold(two), "the rows are let go of");
    assert!(plane.take_end().is_none());
    assert!(!plane.ends_pending());
}

/// A reply the session's own queryables answer while the plane captures hands the capturing thread
/// the first leg it reached with a count of its row, which keeps the callback past the entry's
/// count until the thread gives it back; nothing is offered to the round.
#[test]
fn a_captured_leg_keeps_a_count_of_its_row_for_the_capturing_thread() {
    let plane = plane::<Asking>(2, 1);
    let mut round = round::<Asking>();
    let legs: NonNull<dyn LegHolders<Asking>> = NonNull::from(&*plane);
    // SAFETY: the plane is dropped after the round, which is declared after it.
    unsafe { round.get_mut().calls_legs_of(legs) };
    let seen = Arc::new(Seen::default());
    let row = opened(&plane, &mut || Counted(seen.clone()), true, None).expect("a row");
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is, and the
    // sink, made after the round, is dropped before it.
    let mut sink = unsafe { LegSink::new(row, plane.share(), round.share()) };
    lend_reply(&round);
    plane.capture();
    sink.on_reply(&REPLY);
    assert!(!plane.captures(row), "one leg for each capture");
    assert_eq!(plane.captured(), Some(row));
    assert_eq!(plane.captured(), None, "a capture is taken once");
    // SAFETY: as above.
    unsafe { round.seal() };
    assert!(!round.deliver(), "the captured reply was not held");
    assert!(plane.release(row).is_none(), "the capture's count");
    drop(sink);
    let end = plane.take_end().expect("the sink's drop is the leg's end");
    drop(plane.release(end.row()));
    assert_eq!(
        seen.drops(),
        1,
        "the entry's count, held by the end, was the last"
    );
}

/// A plane whose session answers none of its own gets captures nothing: the reply is held in the
/// round for the leg's callback as any other.
#[test]
fn a_plane_whose_session_answers_none_of_its_gets_captures_nothing() {
    let plane = plane::<Remote>(2, 1);
    let mut round = round::<Remote>();
    let legs: NonNull<dyn LegHolders<Remote>> = NonNull::from(&*plane);
    // SAFETY: the plane is dropped after the round, which is declared after it.
    unsafe { round.get_mut().calls_legs_of(legs) };
    let seen = Arc::new(Seen::default());
    let row = opened(&plane, &mut || Counted(seen.clone()), true, None).expect("a row");
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is, and the
    // sink, made after the round, is dropped before it.
    let mut sink = unsafe { LegSink::new(row, plane.share(), round.share()) };
    lend_reply(&round);
    plane.capture();
    sink.on_reply(&REPLY);
    assert_eq!(plane.captured(), None);
    // SAFETY: as above.
    unsafe { round.seal() };
    assert!(round.deliver(), "the reply was held for the leg");
    assert_eq!(seen.calls(), 1);
    assert_eq!(
        round.counts().unplaced,
        0,
        "the payload was read where it lies"
    );
}

/// A plane that keeps a capture though its session answers none of its own gets captures a peer's
/// reply for the read that hands it out: the leg comes back with a count of its row, and nothing is
/// held in the round.
#[test]
fn a_plane_whose_read_hands_each_record_captures_a_peers_reply() {
    let plane = plane::<Stepped>(2, 1);
    let mut round = round::<Stepped>();
    let legs: NonNull<dyn LegHolders<Stepped>> = NonNull::from(&*plane);
    // SAFETY: the plane is dropped after the round, which is declared after it.
    unsafe { round.get_mut().calls_legs_of(legs) };
    let seen = Arc::new(Seen::default());
    let row = opened(&plane, &mut || Counted(seen.clone()), true, None).expect("a row");
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is, and the
    // sink, made after the round, is dropped before it.
    let mut sink = unsafe { LegSink::new(row, plane.share(), round.share()) };
    lend_reply(&round);
    plane.capture();
    sink.on_reply(&REPLY);
    assert_eq!(plane.captured(), Some(row));
    // SAFETY: as above.
    unsafe { round.seal() };
    assert!(!round.deliver(), "the captured reply was not held");
    plane.call(row, &REPLY);
    assert_eq!(seen.calls(), 1, "the reader hands it once");
    assert!(plane.release(row).is_none(), "the capture's count");
    drop(sink);
    let end = plane.take_end().expect("the sink's drop is the leg's end");
    drop(plane.release(end.row()));
    assert_eq!(seen.drops(), 1);
}

/// A sink that keeps no round ([`EveryReplyCaptured`]) hands each reply it is handed under a
/// capture to the capturing thread, one capture each, and holds no handle of a round: no round is
/// made here at all. Its drop is the leg's one end. Turned red by a sink of that form that holds a
/// round's handle again, or that hands a captured reply anywhere but to its capture.
#[test]
fn a_sink_that_keeps_no_round_hands_each_reply_to_its_capture() {
    assert!(
        core::mem::size_of::<LegSink<Stepped, EveryReplyCaptured>>()
            < core::mem::size_of::<LegSink<Stepped>>(),
        "the sink holds no handle of a round"
    );
    let plane = plane::<Stepped>(2, 1);
    let seen = Arc::new(Seen::default());
    let row = opened(&plane, &mut || Counted(seen.clone()), true, None).expect("a row");
    // SAFETY: the test hands the sink its replies alone, as the holder of the session's lock
    // does, and the sink, made after the plane, is dropped before it.
    let mut sink = unsafe { LegSink::new(row, plane.share(), EveryReplyCaptured) };
    for handed in 1..=2 {
        plane.capture();
        sink.on_reply(&REPLY);
        assert_eq!(plane.captured(), Some(row), "reply {handed} is captured");
        plane.call(row, &REPLY);
        assert_eq!(
            seen.calls(),
            handed,
            "each reply is handed once, in its turn"
        );
        assert!(plane.release(row).is_none(), "the capture's count");
    }
    drop(sink);
    let end = plane.take_end().expect("the sink's drop is the leg's end");
    assert!(plane.take_end().is_none(), "one end");
    drop(plane.release(end.row()));
    assert_eq!(seen.drops(), 1);
}

/// A reply handed to a sink that keeps no round outside a capture is the defect of an engine that
/// promised to capture each: nothing is called, nothing is captured, and a debug build stops there.
/// The CONTROL is the sink's leg, whose row is still held.
#[test]
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "a reply reached a leg's sink outside a capture")
)]
fn a_reply_outside_a_capture_reaches_no_round_and_is_a_defect() {
    let plane = plane::<Stepped>(2, 1);
    let seen = Arc::new(Seen::default());
    let row = opened(&plane, &mut || Counted(seen.clone()), true, None).expect("a row");
    // SAFETY: as above.
    let mut sink = unsafe { LegSink::new(row, plane.share(), EveryReplyCaptured) };
    sink.on_reply(&REPLY);
    assert_eq!(plane.captured(), None, "no capture was asked");
    assert_eq!(seen.calls(), 0, "nothing is called");
    assert!(plane.hold(row), "CONTROL: the leg's row is held");
    assert!(plane.release(row).is_none());
    drop(sink);
}

/// A sink's drop is its leg's end, with the timeout it was told of; while the sink lives no end
/// waits, and the end of the get it stood last in holds the entry's count of the row past the sink.
#[test]
fn a_sinks_drop_is_its_legs_end_with_the_timeout_it_was_told() {
    let plane = plane::<Remote>(2, 1);
    let round = round::<Remote>();
    let seen = Arc::new(Seen::default());
    let row = opened(&plane, &mut || Counted(seen.clone()), true, None).expect("a row");
    // SAFETY: the test hands the sink nothing; it is the round's one writer, and the sink, made
    // after the round, is dropped before it.
    let mut sink = unsafe { LegSink::new(row, plane.share(), round.share()) };
    sink.on_final(5);
    sink.on_timeout(9);
    assert!(!plane.ends_pending(), "no end while the sink lives");
    drop(sink);
    assert!(plane.ends_pending());
    let end = plane.take_end().expect("the get's end");
    assert_eq!((end.timed_out(), end.row()), (Some(9), row));
    assert_eq!(seen.drops(), 0, "the end holds the entry's count");
    drop(plane.release(end.row()));
    assert_eq!(seen.drops(), 1);
}

/// The get's end says the timeout of the leg that stood last, and a leg that timed out while
/// another stood writes nothing: the legs of a get share its deadline and time out in one sweep, so
/// the last of them says the get timed out, once. Turned red by an end written for each leg, or by
/// the timeout of a leg that did not stand last.
#[test]
fn a_gets_end_says_the_timeout_of_the_leg_that_stood_last() {
    let plane = plane::<Remote>(2, 1);
    let seen = Arc::new(Seen::default());
    let mut asked = AskedGet::<Remote>::new(&plane);
    let mut mint = || Counted(seen.clone());
    let row = asked.leg(&mut mint, true, None).expect("a row");
    assert_eq!(asked.leg(&mut mint, true, None), Some(row));
    drop(asked);
    // SAFETY: the test hands the sinks nothing, and drops them before the plane.
    let (mut first, mut second) = unsafe {
        (
            LegSink::new(row, plane.share(), EveryReplyCaptured),
            LegSink::new(row, plane.share(), EveryReplyCaptured),
        )
    };
    first.on_timeout(4);
    drop(first);
    assert!(!plane.ends_pending(), "the second leg stands");
    second.on_timeout(6);
    drop(second);
    assert_eq!(said(plane.take_end()), Some((row.0, Some(6))));
    assert!(plane.take_end().is_none(), "one end for the get");
}

/// A get of two legs, each consolidating `Latest`, holds back one reply of a key over both: a leg's
/// Final hands nothing on, and the get's end finds the latest reply of the key in its rows, once, as
/// zenoh flushes a query at its last Final. Turned red by a hold of each leg's own (two replies of
/// the key at the end), or by a Final that flushes the leg's hold before the get's end.
#[test]
fn a_gets_legs_hold_back_into_one_consolidation() {
    let plane = plane::<Remote>(2, 2);
    let seen = Arc::new(Seen::default());
    let mut asked = AskedGet::<Remote>::new(&plane);
    let mut mint = || Counted(seen.clone());
    let row = asked.leg(&mut mint, true, None).expect("a row");
    assert_eq!(asked.leg(&mut mint, true, None), Some(row));
    drop(asked);
    // SAFETY: the test hands the sinks their replies alone, as the holder of the session's lock
    // does, and drops them before the plane.
    let (mut first, mut second) = unsafe {
        (
            crate::reply_sink::ConsolidatingSink::with_hold(
                crate::query_mode::ConsolidationMode::Latest,
                LegSink::new(row, plane.share(), EveryReplyCaptured),
                LegHold::new(row, plane.share()),
            ),
            crate::reply_sink::ConsolidatingSink::with_hold(
                crate::query_mode::ConsolidationMode::Latest,
                LegSink::new(row, plane.share(), EveryReplyCaptured),
                LegHold::new(row, plane.share()),
            ),
        )
    };
    first.on_reply(&Answer {
        key: "demo/a",
        payload: b"first",
    });
    first.on_final(1);
    drop(first);
    assert_eq!(seen.calls(), 0, "a leg's Final hands nothing on");
    second.on_reply(&Answer {
        key: "demo/a",
        payload: b"second",
    });
    second.on_final(2);
    drop(second);
    let end = plane.take_end().expect("the get's end");
    let held = plane.take_due(end.row()).expect("the key's one reply");
    assert_eq!(held.payload(), b"second", "the latest of the key");
    assert!(
        plane.take_due(end.row()).is_none(),
        "one reply of the key over both legs"
    );
    drop(plane.release(end.row()));
    assert_eq!(seen.drops(), 1);
}

/// An end the session decided itself is taken out by it once, and left for no delivery.
#[test]
fn an_end_forgotten_by_its_maker_is_left_for_no_delivery() {
    let plane = plane::<Remote>(2, 1);
    plane.ended.with(|ends| ends.note(ended_by(4, None)));
    assert_eq!(said(plane.forget_end(LegId(4))), Some((4, None)));
    assert!(plane.forget_end(LegId(4)).is_none(), "and only once");
    assert!(!plane.ends_pending(), "nothing is left for a delivery");
}

/// Each end noted is taken once, and an end its get's maker handled itself is taken out by that
/// maker, once, and not by the deliveries.
#[test]
fn each_end_is_taken_once_and_a_forgotten_one_never() {
    let mut ends = ends(3);
    ends.note(ended_by(1, None));
    ends.note(ended_by(2, None));
    ends.note(ended_by(3, None));
    assert_eq!(
        said(ends.forget(LegId(2))),
        Some((2, None)),
        "taken out by its maker"
    );
    assert!(ends.forget(LegId(2)).is_none(), "and only once");
    let mut taken = [ends.take(), ends.take(), ends.take()].map(|e| e.map(|e| e.row().0));
    taken.sort();
    assert_eq!(taken, [None, Some(1), Some(3)]);
}

/// The end of a get a timeout ended keeps the timeout's request id to its delivery, and one that
/// ended otherwise keeps none.
#[test]
fn an_end_keeps_the_timeout_that_ended_its_get() {
    let mut ends = ends(2);
    ends.note(ended_by(5, Some(9)));
    assert_eq!(said(ends.take()), Some((5, Some(9))));
    ends.note(ended_by(6, None));
    assert_eq!(
        said(ends.take()),
        Some((6, None)),
        "CONTROL: a final ends with none"
    );
}

/// A leg of a plane whose tables take their rows on use is refused at its open, its callback not
/// minted, while the heap has no room for the rows its end will be written in, though the legs'
/// rows are had already; with room, the next open keeps it. The refusal is a value its caller
/// answers (a get with no row), where the end, written by the drop of its leg's entry, could
/// answer none. Turned red by an open that keeps a leg before the ends took their rows
/// (`EndedLegs::set_aside` left out of `GetPlane::open_leg`).
#[test]
fn a_leg_whose_ends_rows_the_heap_refuses_is_refused_at_its_open() {
    let plane = plane_on_use::<RemoteOnUse>(2, 1);
    assert!(
        StdLocks::with(&plane.legs, |legs| legs.rows.make_room()),
        "the legs' rows are had: a refusal is the ends' alone"
    );
    let seen = Arc::new(Seen::default());
    let mut minted = 0;
    let refused = crate::test_heap::refused(|| {
        opened(
            &plane,
            &mut || {
                minted += 1;
                Counted(seen.clone())
            },
            true,
            None,
        )
    });
    assert_eq!(
        refused, None,
        "no row for the leg's end: the leg is refused"
    );
    assert_eq!(minted, 0, "refused before its callback is minted");
    let row =
        opened(&plane, &mut || Counted(seen.clone()), true, None).expect("the heap has room again");
    drop(plane.release(row));
    assert_eq!(seen.drops(), 1);
}

/// The end of a get of a plane whose tables take their rows on use is written in a row its first leg
/// had the ends take, whatever the heap holds when the last leg's entry goes, and handed out once.
/// Turned red by an open that does not have the ends take their rows (`EndedLegs::set_aside` left
/// out of `GetPlane::open_leg`): the end then asks the heap at the entry's drop, which answers no
/// one.
#[test]
fn a_gets_end_finds_the_row_its_first_leg_had_taken_whatever_the_heap_holds() {
    let plane = plane_on_use::<RemoteOnUse>(2, 1);
    let seen = Arc::new(Seen::default());
    let row = opened(&plane, &mut || Counted(seen.clone()), true, None).expect("a row");
    // SAFETY: the test hands the sink nothing, and the sink, made after the plane, is dropped
    // before it.
    let sink = unsafe { LegSink::new(row, plane.share(), EveryReplyCaptured) };
    crate::test_heap::refused(|| drop(sink));
    let end = plane
        .take_end()
        .expect("the end was written with the heap full");
    assert_eq!(end.row(), row);
    assert!(plane.take_end().is_none(), "one end");
    drop(plane.release(end.row()));
    assert_eq!(seen.drops(), 1);
}

/// A table lent no rows is the defect the plane's making rules out (a row of the ends set aside at
/// each leg's open): the end is not kept, and a debug build stops there.
#[test]
#[cfg_attr(debug_assertions, should_panic(expected = "an end finds the row"))]
fn an_end_past_the_rows_is_a_defect() {
    let mut ends = ends(0);
    ends.note(ended_by(1, None));
    assert!(ends.take().is_none());
}
