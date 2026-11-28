// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Finals the query plane holds, lent by an arena, and what a query that reaches a queryable
//! does with them: held, refused, or noted for the session's own get.

use super::*;
use crate::bounded::{Arena, Lent, OnUse, ARENA_ALIGN};
use crate::plane_lock::StdLocks;
use crate::round::RoundCall;
use crate::session_tables::{Absent, Present};
use core::convert::Infallible;
use core::ptr::NonNull;
use core::sync::atomic::AtomicUsize;
use std::sync::{mpsc, Arc};
use std::time::Duration;

/// One block of an arena's memory, aligned as an arena's spans start.
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct Block([u8; ARENA_ALIGN]);

/// Room for the Finals of `rows` queries, in rows lent from an arena over memory the test
/// process leaks, so it outlives the rows.
fn holds(rows: usize) -> FinalHolds<Lent> {
    let held = Arena::table_bytes::<FinalHold>(rows).expect("rows the address space holds");
    let refused = Arena::table_bytes::<RefusedFinal>(rows).expect("rows the address space holds");
    let blocks = (held + refused).div_ceil(ARENA_ALIGN) + 2;
    let region: &'static mut [Block] = std::vec![Block([0; ARENA_ALIGN]); blocks].leak();
    // SAFETY: the region is aligned to `ARENA_ALIGN`, as its blocks are, holds `blocks` whole
    // blocks, and is leaked, so nothing else uses it and it outlives every lent table.
    let mut arena =
        unsafe { Arena::over(NonNull::from(region).cast::<u8>(), blocks * ARENA_ALIGN) };
    FinalHolds::over(
        arena.lend(rows).expect("the arena has the rows"),
        arena.lend(rows).expect("the arena has the rows"),
    )
}

/// A plane over `holds`, made in a box of its own.
fn plane<C: PlaneCalls>(holds: FinalHolds<C::TablePolicy>) -> alloc::boxed::Box<QueryPlane<C>> {
    // SAFETY: the box's place is valid for writes of the plane, which stays there.
    crate::plane_lock::boxed_at(|at| unsafe { QueryPlane::init_at(at, holds) })
}

/// A call begun on a test's queryable row, which counts its end.
struct Begun(Arc<AtomicUsize>);

impl RoundCall for Begun {
    fn end(self) -> bool {
        self.0.fetch_add(1, Ordering::SeqCst);
        false
    }
}

/// A session whose own queryables answer its gets: its plane notes the calls its get begins.
enum Local {}

impl RoundCalls for Local {
    type Subscriber = Infallible;
    type Liveliness = Infallible;
    type Queryable = Begun;
    type Watch = core::convert::Infallible;
    type Get = Infallible;
    type Tokens = Absent;
    type Replies = Absent;
    type Queries = Absent;
    type Watches = Absent;
    type Capture = Absent;
    type Group = Absent;
    type Locks = StdLocks;
    type Tally = ();
    type Form = crate::row_callback::Threads;
    type TablePolicy = Lent;
}

impl PlaneCalls for Local {
    type LocalAnswers = Present;
    type Queues = StdLocks;
}

/// A session whose queries only its links ask: its plane notes no call of its own.
enum Linked {}

impl RoundCalls for Linked {
    type Subscriber = Infallible;
    type Liveliness = Infallible;
    type Queryable = Begun;
    type Watch = core::convert::Infallible;
    type Get = Infallible;
    type Tokens = Absent;
    type Replies = Absent;
    type Queries = Absent;
    type Watches = Absent;
    type Capture = Absent;
    type Group = Absent;
    type Locks = StdLocks;
    type Tally = ();
    type Form = crate::row_callback::Threads;
    type TablePolicy = Lent;
}

impl PlaneCalls for Linked {
    type LocalAnswers = Absent;
    type Queues = StdLocks;
}

/// [`Linked`] in a session whose tables take their rows at their first value.
enum LinkedOnUse {}

impl RoundCalls for LinkedOnUse {
    type Subscriber = Infallible;
    type Liveliness = Infallible;
    type Queryable = Begun;
    type Watch = core::convert::Infallible;
    type Get = Infallible;
    type Tokens = Absent;
    type Replies = Absent;
    type Queries = Absent;
    type Watches = Absent;
    type Capture = Absent;
    type Group = Absent;
    type Locks = StdLocks;
    type Tally = ();
    type Form = crate::row_callback::Threads;
    type TablePolicy = OnUse;
}

impl PlaneCalls for LinkedOnUse {
    type LocalAnswers = Absent;
    type Queues = StdLocks;
}

/// A query of request id `.0`, with no part but its key.
struct Query(RequestId);

impl QueryView for Query {
    fn keyexpr(&self) -> &str {
        "demo/q"
    }

    fn parameters(&self) -> Option<&[u8]> {
        None
    }

    fn attachment(&self) -> Option<&[u8]> {
        None
    }

    fn rid(&self) -> RequestId {
        self.0
    }

    fn qos(&self) -> QosLevel {
        QosLevel::DEFAULT
    }
}

/// What a test's arrivals began and ended.
#[derive(Default)]
struct Calls {
    begun: AtomicUsize,
    ended: Arc<AtomicUsize>,
}

impl Calls {
    /// Begin a call, counted.
    fn begin(&self) -> Option<Begun> {
        self.begun.fetch_add(1, Ordering::SeqCst);
        Some(Begun(Arc::clone(&self.ended)))
    }

    fn begun(&self) -> usize {
        self.begun.load(Ordering::SeqCst)
    }

    fn ended(&self) -> usize {
        self.ended.load(Ordering::SeqCst)
    }
}

/// Run `body` on a thread of its own and wait at most five seconds for what it returns: a take
/// that waits on the lock it holds fails here by name instead of holding the run for ever.
fn within_five_seconds<R: Send + 'static>(
    what: &str,
    body: impl FnOnce() -> R + Send + 'static,
) -> R {
    let (done, outcome) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(body());
    });
    outcome
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| panic!("{what} did not return within five seconds"))
}

/// A table of one row refuses a second get's row and returns at once, leaving the first row
/// held; once the first is let go of, the row takes the next. The CONTROL is the first take.
/// Turned red by a refused take that hands back a hold, whose drop gives back the row the first
/// holds.
#[test]
fn a_full_table_refuses_the_row_and_keeps_the_one_held() {
    let (first, refused, still_full, next) = within_five_seconds("a refused take", || {
        let plane = plane::<Local>(holds(1));
        let first = OwnFinalHold::take(&plane, 1);
        let refused = OwnFinalHold::take(&plane, 2).is_none();
        let still_full = OwnFinalHold::take(&plane, 3).is_none();
        let held = first.is_some();
        drop(first);
        let next = OwnFinalHold::take(&plane, 4).is_some();
        (held, refused, still_full, next)
    });
    assert!(first, "CONTROL: the one row is taken");
    assert!(refused, "every row taken: refused");
    assert!(still_full, "the refusal gave back no row it never took");
    assert!(next, "the row the first let go of takes the next");
}

/// With its one row taken, the table refuses a second request, which stays refused for the rest
/// of its dispatch though a row comes free, and whose Final the dispatch does not send; that Final
/// spends the refusal, so the request is weighed afresh after. The CONTROL is the first request,
/// held, whose Final waits for its hold.
#[test]
fn a_request_no_row_holds_is_refused_with_its_final() {
    let mut holds = holds(1);
    assert_eq!(
        holds.admit(1, 7),
        Admitted::Held,
        "CONTROL: the one row holds the first request"
    );
    assert_eq!(holds.admit(1, 8), Admitted::Refused, "every row taken");
    assert!(
        !holds.owe(1, 7, QosLevel::DEFAULT),
        "CONTROL: the held request's Final waits for its hold"
    );
    assert!(
        holds.release(1, 7).is_some(),
        "CONTROL: the last hold let go sends the Final owed"
    );
    assert_eq!(
        holds.admit(1, 8),
        Admitted::Refused,
        "refused for the rest of its dispatch, though a row is free"
    );
    assert!(
        !holds.owe(1, 8, QosLevel::DEFAULT),
        "the refused request's Final is not sent"
    );
    assert_eq!(
        holds.admit(1, 8),
        Admitted::Held,
        "the refusal spent, the free row holds it"
    );
    assert!(
        holds.release(1, 8).is_none(),
        "nothing owed yet for the request held afresh"
    );
}

/// A hold past the most a count holds is refused, and the holds already counted keep the Final
/// held: a release lets go of one of them, not of the row.
///
/// # Control
///
/// A `take` that wraps or saturates the count reds the refusal or the release.
#[test]
fn a_hold_past_the_counts_bound_is_refused_and_the_final_stays_held() {
    let mut holds = holds(1);
    assert!(holds.take(1, 7), "CONTROL: the one row is taken");
    for hold in holds.holds.iter_mut() {
        hold.holds = usize::MAX;
    }
    assert!(!holds.take(1, 7), "no count past the bound");
    assert!(
        !holds.owe(1, 7, QosLevel::DEFAULT),
        "the Final waits for the holds counted"
    );
    assert!(
        holds.release(1, 7).is_none(),
        "one release lets go of one hold, not the row"
    );
    assert_eq!(holds.holds.len(), 1, "the row is still held");
}

/// A query kept past its callback holds its Final, and what its replies are built from, until its
/// last keep is let go of: a second keep answers what the first kept, the callback's own hold
/// ending leaves the Final held, and the last keep sends the Final owed and forgets the query. The
/// CONTROL is the first release, which lets go of a keep and nothing else. Turned red by a release
/// that sends the Final before the last keep, or that leaves the query kept.
#[test]
fn a_kept_query_holds_its_final_until_its_last_keep() {
    let mut holds = holds(1);
    assert_eq!(holds.admit(1, 7), Admitted::Held, "the callback's hold");
    assert_eq!(holds.keep_again(1, 7), None, "not kept yet");
    let answer = (ReplyKeyExpr::Any, QosLevel::DEFAULT);
    assert!(holds.keep(1, 7, answer), "the first keep");
    assert!(!holds.keep(1, 7, answer), "a first keep of a kept query");
    assert_eq!(holds.keep_again(1, 7), Some(Ok(answer)), "a second keep");
    assert!(holds.release(1, 7).is_none(), "the callback returned");
    assert!(
        !holds.owe(1, 7, QosLevel::DEFAULT),
        "the keeps hold the Final"
    );
    assert_eq!(holds.release_kept(1, 7), None, "CONTROL: one keep is left");
    assert_eq!(
        holds.release_kept(1, 7),
        Some(QosLevel::DEFAULT),
        "the Final owed goes out with the last keep"
    );
    assert_eq!(holds.keep_again(1, 7), None, "nothing is kept");
    assert!(holds.holds.is_empty(), "the row went with the last hold");
}

/// A keep of a query no row holds keeps nothing, a keep past the most a count holds is refused and
/// keeps the holds counted, and a query nothing keeps lets go of nothing at a release of a keep.
#[test]
fn a_keep_no_row_holds_is_refused_and_a_query_not_kept_releases_nothing() {
    let mut holds = holds(1);
    let answer = (ReplyKeyExpr::MatchingQuery, QosLevel::DEFAULT);
    assert!(!holds.keep(1, 7, answer), "no row holds the query");
    assert_eq!(
        holds.admit(1, 7),
        Admitted::Held,
        "CONTROL: the callback's hold"
    );
    assert_eq!(holds.release_kept(1, 7), None);
    assert!(
        !holds.owe(1, 7, QosLevel::DEFAULT),
        "the callback's hold still holds the Final"
    );
    assert!(holds.keep(1, 7, answer), "kept");
    for hold in holds.holds.iter_mut() {
        hold.holds = usize::MAX;
    }
    assert_eq!(
        holds.keep_again(1, 7),
        Some(Err(HoldsFull)),
        "no count past the bound"
    );
}

/// A hold taken outside a dispatch (a get of the session's own) and refused notes no refusal: the
/// Final of that request id is not withheld from the dispatch that owes it.
#[test]
fn a_refused_take_withholds_no_final() {
    let mut holds = holds(1);
    assert!(holds.take(0, 1), "CONTROL: the one row is taken");
    assert!(!holds.take(0, 2), "every row taken: refused");
    assert!(
        holds.owe(0, 2, QosLevel::DEFAULT),
        "a refused take noted nothing, so the Final goes out"
    );
}

/// A link's generation is the counter's next value, and where the counter wraps the session's own
/// queries' generation is stepped over.
///
/// # Control
///
/// Returning the wrapped value without the step over `LOCAL_QUERY` reds the second assertion.
#[test]
fn a_links_generation_is_never_the_sessions_own() {
    let plane = plane::<Linked>(FinalHolds::default());
    assert_eq!(plane.next_generation(), 1);
    plane
        .generation
        .store(LOCAL_QUERY.wrapping_sub(1), Ordering::Relaxed);
    let after = LOCAL_QUERY.wrapping_add(1);
    assert_eq!(
        plane.next_generation(),
        after,
        "LOCAL_QUERY is stepped over"
    );
    assert_eq!(plane.generation.load(Ordering::Relaxed), after);
}

/// A query that reaches a queryable with a row free for its Final begins a call and is offered to
/// the round under its link's generation; a round that keeps no query ends the call and the hold
/// goes back. With the one row held, the next query is refused before any call is begun, counted,
/// and its Final withheld from the dispatch. The CONTROL is the first query, begun. Turned red by
/// an arrival that begins its call before its Final is admitted, or that counts no refusal.
#[test]
fn a_query_no_row_holds_is_refused_before_its_call_begins() {
    let plane = plane::<Linked>(holds(1));
    let round = crate::round::tests::round::<Linked>();
    let calls = Calls::default();
    plane.set_arriving(5);
    // SAFETY (each call): this thread is the round's one writer.
    unsafe { plane.arrive(&round, || calls.begin(), &Query(7)) };
    assert_eq!(calls.begun(), 1, "CONTROL: a call is begun");
    assert_eq!(calls.ended(), 1, "the round that keeps no query ended it");
    assert!(
        plane.with_holds(|holds| holds.owe(5, 7, QosLevel::DEFAULT)),
        "the hold went back, so the Final goes out"
    );
    assert!(
        plane.with_holds(|holds| holds.take(5, 1)),
        "the one row held"
    );
    unsafe { plane.arrive(&round, || calls.begin(), &Query(8)) };
    assert_eq!(calls.begun(), 1, "no call is begun for a refused query");
    assert_eq!(plane.refused(), 1, "the refusal is counted");
    assert!(
        !plane.with_holds(|holds| holds.owe(5, 8, QosLevel::DEFAULT)),
        "the refused query's Final is withheld"
    );
}

/// A query whose queryable begins no call (its row past the most calls its latch counts) gives
/// its hold back, and is no refusal.
#[test]
fn a_query_no_call_begins_for_gives_its_hold_back() {
    let plane = plane::<Linked>(holds(1));
    let round = crate::round::tests::round::<Linked>();
    plane.set_arriving(5);
    // SAFETY: this thread is the round's one writer.
    unsafe { plane.arrive(&round, || None, &Query(7)) };
    assert_eq!(plane.refused(), 0, "no refusal");
    assert!(
        plane.with_holds(|holds| holds.owe(5, 7, QosLevel::DEFAULT)),
        "the hold went back, so the Final goes out"
    );
}

/// A query that arrives while the session asks its own get is the get's: the call begun is noted
/// for the get to hand, under the session's own generation, and not offered to the round; once
/// taken, the list is empty. The CONTROL is a query that arrives outside the get, offered to the
/// round, which ends its call. Turned red by an arrival that offers the get's query to the round.
#[test]
fn the_sessions_own_get_notes_the_calls_it_begins() {
    let plane = plane::<Local>(holds(2));
    let round = crate::round::tests::round::<Local>();
    let calls = Calls::default();
    plane.set_arriving(5);
    // SAFETY (each call): this thread is the round's one writer.
    unsafe { plane.arrive(&round, || calls.begin(), &Query(7)) };
    assert_eq!(
        calls.ended(),
        1,
        "CONTROL: the link's query went to the round"
    );
    assert!(plane.take_asked().is_empty(), "CONTROL: nothing noted");
    plane.asking_locally(|| unsafe { plane.arrive(&round, || calls.begin(), &Query(9)) });
    let asked = plane.take_asked();
    assert_eq!(asked.len(), 1, "the get's call is noted");
    assert_eq!(calls.ended(), 1, "and not offered to the round");
    assert!(
        !plane.with_holds(|holds| holds.owe(LOCAL_QUERY, 9, QosLevel::DEFAULT)),
        "its Final is held under the session's own generation"
    );
    assert!(plane.take_asked().is_empty(), "the list was left empty");
    for call in asked {
        call.end();
    }
    assert_eq!(calls.ended(), 2);
}

/// A session whose own queryables answer none of its gets notes no call: `asking_locally` runs
/// what it is handed, and a query that arrives meanwhile is the link's, offered to the round.
/// Turned red by a plane of such a session that takes the query as its own get's.
#[test]
fn a_session_whose_own_queryables_answer_none_notes_no_call() {
    let plane = plane::<Linked>(holds(1));
    let round = crate::round::tests::round::<Linked>();
    let calls = Calls::default();
    plane.set_arriving(5);
    let ran = plane.asking_locally(|| {
        // SAFETY: this thread is the round's one writer.
        unsafe { plane.arrive(&round, || calls.begin(), &Query(9)) };
        true
    });
    assert!(ran, "the get was asked");
    assert!(plane.take_asked().is_empty(), "no call is noted");
    assert_eq!(calls.ended(), 1, "the query went to the round");
    assert!(
        plane.with_holds(|holds| holds.owe(5, 9, QosLevel::DEFAULT)),
        "held and let go of under the link's generation"
    );
}

/// A session whose read takes each query of its links notes only its own get's calls: a query
/// that arrives outside the get takes no hold and begins no call, so its Final goes out as one no
/// queryable was reached by; one that arrives while the get is asked is noted for the get under
/// the session's own generation, its call not ended. A plane of a session whose own queryables
/// answer none of its gets begins no call either. The CONTROL is the get's call, noted. Turned red
/// by an `arrive_own` that begins a call outside the get, or that leaves the get's call unnoted.
#[test]
fn a_read_that_takes_its_links_queries_notes_only_its_own_gets_calls() {
    let plane = plane::<Local>(holds(2));
    let calls = Calls::default();
    plane.set_arriving(5);
    plane.arrive_own(|| calls.begin(), &Query(7));
    assert_eq!(calls.begun(), 0, "a link's query begins no call here");
    assert!(plane.take_asked().is_empty(), "nothing is noted for it");
    assert!(
        plane.with_holds(|holds| holds.owe(5, 7, QosLevel::DEFAULT)),
        "no hold is taken, so its Final goes out"
    );
    plane.asking_locally(|| plane.arrive_own(|| calls.begin(), &Query(9)));
    let asked = plane.take_asked();
    assert_eq!(asked.len(), 1, "CONTROL: the get's call is noted");
    assert_eq!(calls.ended(), 0, "and left for the get to end");
    assert!(
        !plane.with_holds(|holds| holds.owe(LOCAL_QUERY, 9, QosLevel::DEFAULT)),
        "its Final is held under the session's own generation"
    );
    for call in asked {
        call.end();
    }
    assert_eq!(calls.ended(), 1);

    // The local `plane` shadows the helper here.
    let linked = self::plane::<Linked>(holds(1));
    linked.asking_locally(|| linked.arrive_own(|| calls.begin(), &Query(11)));
    assert_eq!(
        calls.begun(),
        1,
        "a plane that answers no get of its own begins no call"
    );
    assert!(linked.take_asked().is_empty());
}

/// A request refused with no row left to note its refusal in is answered as such: it runs no
/// callback, and with nothing noted its Final goes out as one no queryable was reached by, where a
/// noted refusal withholds it. The CONTROL is the first request, held. Turned red by an `admit`
/// that answers a refusal it could not note as noted (`Admitted::Refused` for the push's `Err`),
/// which would leave the dispatch withholding a Final no row remembers.
#[test]
fn a_refusal_with_no_row_to_be_noted_in_is_unnoted_and_owes_its_final() {
    let mut holds = FinalHolds::<OnUse>::over(BoundedVec::counted(1), BoundedVec::counted(0));
    assert_eq!(
        holds.admit(1, 7),
        Admitted::Held,
        "CONTROL: the one row holds the first request"
    );
    assert_eq!(
        holds.admit(1, 8),
        Admitted::Unnoted,
        "no row for the refusal"
    );
    assert!(
        holds.owe(1, 8, QosLevel::DEFAULT),
        "nothing noted: the Final goes out"
    );
    assert!(
        !holds.owe(1, 7, QosLevel::DEFAULT),
        "CONTROL: the held request's Final waits for its hold"
    );
}

/// On a policy that takes a table's rows at its first value, the first request held has the list
/// of refusals take its rows too, so a later refusal is noted with the heap full and its Final
/// withheld. Turned red by an `admit` that asks no row for its refusals before a hold
/// (`FinalHolds::rows_for_refusals` left out): the refusal then asks the heap, which refuses it.
#[test]
fn a_refusal_finds_the_row_the_first_hold_had_taken_whatever_the_heap_holds() {
    let mut holds = FinalHolds::<OnUse>::over(BoundedVec::counted(1), BoundedVec::counted(1));
    assert_eq!(holds.admit(1, 7), Admitted::Held);
    assert!(
        holds.refused.holds_rows(),
        "the first hold had the refusals' rows taken"
    );
    let second = crate::test_heap::refused(|| holds.admit(1, 8));
    assert_eq!(second, Admitted::Refused, "noted with the heap full");
    assert!(
        !holds.owe(1, 8, QosLevel::DEFAULT),
        "the noted refusal's Final is withheld"
    );
}

/// A request whose refusals' rows the heap refuses at the session's first query is refused before
/// any hold is asked, its Final owed as one no queryable was reached by; with room, it is held.
/// Turned red by an `admit` that holds a request while no refusal of it could be noted, or that
/// answers the heap's refusal as noted.
#[test]
fn a_request_whose_refusals_rows_the_heap_refuses_is_refused_unnoted() {
    let mut holds = FinalHolds::<OnUse>::over(BoundedVec::counted(1), BoundedVec::counted(1));
    let first = crate::test_heap::refused(|| holds.admit(1, 7));
    assert_eq!(first, Admitted::Unnoted);
    assert!(!holds.holds.holds_rows(), "no hold was asked");
    assert!(
        holds.owe(1, 7, QosLevel::DEFAULT),
        "nothing noted or held: the Final goes out"
    );
    assert_eq!(holds.admit(1, 9), Admitted::Held, "the heap has room again");
}

/// A query the plane refuses with no row to note the refusal in begins no call and is counted as a
/// refusal, and its dispatch owes its Final. Turned red by an `admit_call` that begins a call for
/// an unnoted refusal, or counts none.
#[test]
fn a_query_refused_unnoted_begins_no_call_and_is_counted() {
    let plane = plane::<LinkedOnUse>(FinalHolds::over(
        BoundedVec::counted(0),
        BoundedVec::counted(0),
    ));
    let calls = Calls::default();
    assert!(plane.admit_call(5, 7, || calls.begin()).is_none());
    assert_eq!(calls.begun(), 0, "no call is begun");
    assert_eq!(plane.refused(), 1, "the refusal is counted");
    assert!(
        plane.with_holds(|holds| holds.owe(5, 7, QosLevel::DEFAULT)),
        "nothing noted: the Final goes out"
    );
}
