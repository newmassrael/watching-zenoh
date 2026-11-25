// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The rows of the legs' callbacks, the ends and the held replies of the get plane, each lent by an
//! arena, and the sink and the hold a leg's entry owns.

use super::*;
use crate::bounded::{Arena, ARENA_ALIGN};
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
}

impl PlaneCalls for Asking {
    type LocalAnswers = Present;
    type Captures = Present;
    type Queues = StdLocks;
}

impl GetCalls for Asking {
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
}

impl PlaneCalls for Remote {
    type LocalAnswers = Absent;
    type Captures = Absent;
    type Queues = StdLocks;
}

impl GetCalls for Remote {
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
}

impl PlaneCalls for Stepped {
    type LocalAnswers = Absent;
    type Captures = Present;
    type Queues = StdLocks;
}

impl GetCalls for Stepped {
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
fn plane<C: GetCalls>(rows: usize, held: usize) -> Placed<GetPlane<C>> {
    let mut arena = arena(1 << 17);
    let ends = arena.lend(rows).expect("the arena has the rows");
    let legs = arena.lend(rows).expect("the arena has the rows");
    let replies = HeldReplies::lent(&mut arena, held).expect("the arena has the rows");
    arena
        .place(GetPlane::new(
            EndedLegs::over(ends),
            replies,
            LegRows::over(legs),
        ))
        .expect("the arena has the plane's place")
}

/// A round of a few records, placed with its tables in an arena over leaked memory.
fn round<C: RoundCalls>() -> Placed<Round<C>> {
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

/// The end of leg `leg`, which the timeout of `rid` ended when there is one.
fn ended_by(leg: u64, timed_out: Option<RequestId>) -> Ended {
    Ended {
        leg,
        timed_out,
        row: LegId::FIRST,
    }
}

/// What an end says: its leg and the timeout that ended it.
fn said(ended: Option<Ended>) -> Option<(u64, Option<RequestId>)> {
    ended.map(|ended| (ended.leg(), ended.timed_out()))
}

/// A table of `rows` ends over an arena of its own.
fn ends(rows: usize) -> EndedLegs {
    EndedLegs::over(arena(1 << 12).lend(rows).expect("the arena has the rows"))
}

/// Each leg's hold keeps its replies in the plane's rows apart from another leg's, refuses one past
/// the rows, keeps what it held due at its drain, and lets go of what it still holds when it goes
/// with nothing due.
#[test]
fn a_legs_hold_keeps_its_replies_in_the_planes_rows() {
    let plane = plane::<Remote>(4, 2);
    // SAFETY: the holds, declared after the plane, are dropped before it.
    let shared = unsafe { plane.share() };
    let (mut one, mut two) = (LegHold::new(1, shared), LegHold::new(2, shared));
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
        "the end hands nothing on: what it held is due in its rows"
    );
    drop(one);
    drop(two);
    assert_eq!(
        StdLocks::with(&plane.replies, |replies| replies.len()),
        1,
        "a leg that goes with nothing due lets go of what it held; a due one keeps it"
    );
    let due = plane.take_due(1).expect("the due reply");
    assert_eq!(due.payload(), b"first", "a leg is handed its own");
    assert!(plane.take_due(1).is_none());
    assert!(StdLocks::with(&plane.replies, |replies| replies.is_empty()));
}

/// A leg's row holds its callback, called through it, until the last count is given back, which
/// hands the callback out to be dropped by the one that gave it back; a row given back is held
/// and called by none.
#[test]
fn a_legs_row_holds_its_callback_until_its_last_count() {
    let plane = plane::<Remote>(2, 1);
    let seen = Arc::new(Seen::default());
    let row = plane
        .open_leg(&mut || Counted(seen.clone()), true)
        .expect("a row is free");
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

/// A leg that finds every row held is refused before its callback is minted, and a row given back
/// is the next leg's.
#[test]
fn a_leg_past_the_rows_mints_no_callback_and_a_row_given_back_is_reused() {
    let plane = plane::<Remote>(1, 1);
    let (first, second) = (Arc::new(Seen::default()), Arc::new(Seen::default()));
    let row = plane
        .open_leg(&mut || Counted(first.clone()), true)
        .expect("one row");
    let mut minted = 0;
    let refused = plane.open_leg(
        &mut || {
            minted += 1;
            Counted(second.clone())
        },
        true,
    );
    assert_eq!(refused, None, "one row holds one leg");
    assert_eq!(minted, 0, "refused before its callback is minted");
    drop(plane.release(row));
    assert_eq!(first.drops(), 1);
    let again = plane.open_leg(&mut || Counted(second.clone()), true);
    assert_eq!(again, Some(row), "the row given back is the next leg's");
    drop(plane.release(row));
    assert_eq!(second.drops(), 1);
}

/// The plane let go of before its arena gives back the count an end waiting holds and drops every
/// callback a row still holds, and holds no row and no end after.
#[test]
fn a_plane_let_go_drops_the_callbacks_its_rows_and_ends_still_hold() {
    let plane = plane::<Remote>(2, 1);
    let (ended, open) = (Arc::new(Seen::default()), Arc::new(Seen::default()));
    let one = plane
        .open_leg(&mut || Counted(ended.clone()), true)
        .expect("a row");
    let two = plane
        .open_leg(&mut || Counted(open.clone()), true)
        .expect("a row");
    plane.ended.with(|ends| {
        ends.note(Ended {
            leg: 1,
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
    let row = plane
        .open_leg(&mut || Counted(seen.clone()), true)
        .expect("a row");
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is, and the
    // sink, made after the round, is dropped before it.
    let mut sink = unsafe { LegSink::new(3, row, plane.share(), round.share()) };
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
    let row = plane
        .open_leg(&mut || Counted(seen.clone()), true)
        .expect("a row");
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is, and the
    // sink, made after the round, is dropped before it.
    let mut sink = unsafe { LegSink::new(3, row, plane.share(), round.share()) };
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
    let row = plane
        .open_leg(&mut || Counted(seen.clone()), true)
        .expect("a row");
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is, and the
    // sink, made after the round, is dropped before it.
    let mut sink = unsafe { LegSink::new(3, row, plane.share(), round.share()) };
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

/// A sink's drop is its leg's end, with the timeout it was told of; while the sink lives no end
/// waits, and the end holds the entry's count of the row past the sink.
#[test]
fn a_sinks_drop_is_its_legs_end_with_the_timeout_it_was_told() {
    let plane = plane::<Remote>(2, 1);
    let round = round::<Remote>();
    let seen = Arc::new(Seen::default());
    let row = plane
        .open_leg(&mut || Counted(seen.clone()), true)
        .expect("a row");
    // SAFETY: the test hands the sink nothing; it is the round's one writer, and the sink, made
    // after the round, is dropped before it.
    let mut sink = unsafe { LegSink::new(7, row, plane.share(), round.share()) };
    sink.on_final(5);
    sink.on_timeout(9);
    assert!(!plane.ends_pending(), "no end while the sink lives");
    drop(sink);
    assert!(plane.ends_pending());
    let end = plane.take_end().expect("the leg's end");
    assert_eq!((end.leg(), end.timed_out(), end.row()), (7, Some(9), row));
    assert_eq!(seen.drops(), 0, "the end holds the entry's count");
    drop(plane.release(end.row()));
    assert_eq!(seen.drops(), 1);
}

/// An end the session decided itself is taken out by it once, and left for no delivery.
#[test]
fn an_end_forgotten_by_its_maker_is_left_for_no_delivery() {
    let plane = plane::<Remote>(2, 1);
    plane.ended.with(|ends| ends.note(ended_by(4, None)));
    assert_eq!(said(plane.forget_end(4)), Some((4, None)));
    assert!(plane.forget_end(4).is_none(), "and only once");
    assert!(!plane.ends_pending(), "nothing is left for a delivery");
}

/// Each end noted is taken once, and an end its leg's maker handled itself is taken out by that
/// maker, once, and not by the deliveries.
#[test]
fn each_end_is_taken_once_and_a_forgotten_one_never() {
    let mut ends = ends(3);
    ends.note(ended_by(1, None));
    ends.note(ended_by(2, None));
    ends.note(ended_by(3, None));
    assert_eq!(
        said(ends.forget(2)),
        Some((2, None)),
        "taken out by its maker"
    );
    assert!(ends.forget(2).is_none(), "and only once");
    let mut taken = [ends.take(), ends.take(), ends.take()].map(|e| e.map(|e| e.leg()));
    taken.sort();
    assert_eq!(taken, [None, Some(1), Some(3)]);
}

/// The end of a leg a timeout ended keeps the timeout's request id to its delivery, and one that
/// ended otherwise keeps none.
#[test]
fn an_end_keeps_the_timeout_that_ended_its_leg() {
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

/// A table lent no rows is the defect the plan rules out: the end is not kept, and a debug build
/// stops there.
#[test]
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "the ends waiting outnumber")
)]
fn an_end_past_the_rows_is_a_defect() {
    let mut ends = ends(0);
    ends.note(ended_by(1, None));
    assert!(ends.take().is_none());
}
