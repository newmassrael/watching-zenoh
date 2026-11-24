// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

use super::*;
use crate::bounded::ARENA_ALIGN;
use crate::session_tables::{Absent, Present};
use crate::wire_id::RequestId;
use core::ptr::NonNull;
use std::format;
use std::string::String;
use std::sync::Mutex;
use std::vec::Vec;

/// What a test's calls were handed, and how many calls and counts of legs were ended.
#[derive(Default)]
struct Log {
    handed: Mutex<Vec<String>>,
    ended: std::sync::atomic::AtomicUsize,
}

impl Log {
    fn note(&self, what: String) {
        self.handed.lock().unwrap().push(what);
    }

    fn handed(&self) -> Vec<String> {
        self.handed.lock().unwrap().clone()
    }

    fn ended(&self) -> usize {
        self.ended.load(Ordering::SeqCst)
    }

    fn end(&self) {
        self.ended.fetch_add(1, Ordering::SeqCst);
    }
}

/// A call of the test's row `row`, which notes what it is handed and its end in `log`.
struct Call {
    row: u32,
    log: Arc<Log>,
}

impl RoundCall for Call {
    fn end(self) -> bool {
        self.log.end();
        false
    }
}

impl SampleCall for Call {
    fn same_row(&self, other: &Self) -> bool {
        self.row == other.row
    }

    fn hand(&self, sample: &dyn SampleView) {
        self.log
            .note(format!("{} sample {}", self.row, sample.keyexpr()));
    }
}

impl TokenCall for Call {
    fn same_row(&self, other: &Self) -> bool {
        self.row == other.row
    }

    fn hand(&self, sample: LivelinessSample<'_>) {
        self.log
            .note(format!("{} token {}", self.row, sample.keyexpr));
    }
}

/// The host's mutex, as the lock the round keeps what answers its queries under.
enum StdLocks {}

impl LockFamily for StdLocks {
    type Lock<T> = Mutex<T>;

    fn new<T>(value: T) -> Mutex<T> {
        Mutex::new(value)
    }

    fn with<T, R>(lock: &Mutex<T>, f: impl FnOnce(&mut T) -> R) -> R {
        f(&mut lock.lock().unwrap())
    }
}

/// A tally that keeps the rounds handed out and the samples they held.
#[derive(Default)]
struct Counted {
    rounds: std::sync::atomic::AtomicUsize,
    samples: std::sync::atomic::AtomicUsize,
}

impl RoundTally for Counted {
    fn handed(&self, count: impl FnOnce() -> (usize, usize)) {
        let (samples, _lent) = count();
        self.rounds.fetch_add(1, Ordering::SeqCst);
        self.samples.fetch_add(samples, Ordering::SeqCst);
    }
}

/// A round that keeps every kind of record.
enum Kept {}

impl RoundCalls for Kept {
    type Subscriber = Call;
    type Liveliness = Call;
    type Queryable = Call;
    type Leg = u32;
    type ReplyCallback = ();
    type Tokens = Present;
    type Replies = Present;
    type Queries = Present;
    type Capture = Present;
    type Group = Present;
    type Locks = StdLocks;
    type Tally = Counted;
}

/// A round that keeps samples alone, offered calls of every other kind all the same.
enum Lean {}

impl RoundCalls for Lean {
    type Subscriber = Call;
    type Liveliness = Call;
    type Queryable = Call;
    type Leg = u32;
    type ReplyCallback = ();
    type Tokens = Absent;
    type Replies = Absent;
    type Queries = Absent;
    type Capture = Absent;
    type Group = Absent;
    type Locks = StdLocks;
    type Tally = ();
}

/// One block of an arena's memory, aligned as an arena's spans start.
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct Block([u8; ARENA_ALIGN]);

/// A round of a few records, its tables lent from an arena over memory the test process leaks,
/// so it outlives the round.
fn round<C: RoundCalls>() -> Arc<Round<C>> {
    let counts = RoundRowCounts {
        records: caps::DELIVERY_LANE_EVENTS.min(4),
        callbacks: caps::DELIVERY_LANE_CALLBACKS.min(4),
        longest_key: caps::MAX_KEYEXPR_BYTES,
    };
    let bytes: usize = [
        Arena::table_bytes::<Entry<C>>(counts.records),
        Arena::table_bytes::<Owed<C>>(counts.callbacks),
        Arena::table_bytes::<u8>(counts.key_bytes()),
    ]
    .into_iter()
    .map(|bytes| bytes.expect("in the address space"))
    .sum();
    let blocks = bytes.div_ceil(ARENA_ALIGN).max(1);
    let region: &'static mut [Block] = std::vec![Block([0; ARENA_ALIGN]); blocks].leak();
    // SAFETY: the region is aligned to `ARENA_ALIGN`, as its blocks are, holds at least `bytes`
    // bytes, and is leaked, so nothing else uses it and it outlives every lent table.
    let mut arena = unsafe { Arena::over(NonNull::from(region).cast::<u8>(), bytes) };
    Round::shared_over(RoundRows::lent(&mut arena, counts).expect("the arena has the rows"))
}

/// A sample on `key` with no payload.
struct Sample(&'static str);

impl SampleView for Sample {
    fn keyexpr(&self) -> &str {
        self.0
    }

    fn payload(&self) -> &[u8] {
        &[]
    }

    fn kind(&self) -> SampleKind {
        SampleKind::Put
    }

    fn reliability(&self) -> Reliability {
        Reliability::BestEffort
    }
}

/// A query on `key` with no parameters.
struct Query(&'static str);

impl QueryView for Query {
    fn keyexpr(&self) -> &str {
        self.0
    }

    fn parameters(&self) -> Option<&[u8]> {
        None
    }

    fn attachment(&self) -> Option<&[u8]> {
        None
    }

    fn rid(&self) -> RequestId {
        5
    }

    fn qos(&self) -> QosLevel {
        QosLevel::DEFAULT
    }
}

/// A reply on `key` with no payload.
struct Reply(&'static str);

impl ReplyView for Reply {
    fn rid(&self) -> RequestId {
        5
    }

    fn keyexpr(&self) -> &str {
        self.0
    }

    fn kind(&self) -> ReplyKind {
        ReplyKind::Put
    }

    fn payload(&self) -> &[u8] {
        &[]
    }

    fn err_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
        None
    }
}

/// The holder of the one leg 4, which notes the replies its callback is handed and the counts of
/// it given back.
struct OneLeg(Arc<Log>);

impl<C: RoundCalls<Leg = u32, ReplyCallback = ()>> LegHolders<C> for OneLeg {
    fn hold(&self, leg: u32) -> bool {
        leg == 4
    }

    fn call(&self, leg: u32, reply: &dyn ReplyView) {
        self.0.note(format!("{leg} reply {}", reply.keyexpr()));
    }

    fn release(&self, _leg: u32) -> Option<()> {
        self.0.end();
        None
    }
}

/// What answers the queries a round hands out: it notes each one's key and generation.
struct Answers(Arc<Log>);

impl AnswersQueries<Kept> for Answers {
    fn answer_query(&self, call: &Call, query: &dyn QueryView, generation: u64) {
        self.0.note(format!(
            "{} query {} {generation}",
            call.row,
            query.keyexpr()
        ));
    }
}

/// A record of a round that keeps samples alone takes less room than one of a round that keeps
/// every kind: a kind it keeps none of is a variant of no size.
#[test]
fn a_round_that_keeps_samples_alone_has_smaller_records() {
    assert!(RoundRows::<Lean>::RECORD_BYTES < RoundRows::<Kept>::RECORD_BYTES);
    assert_eq!(
        RoundRows::<Lean>::CALLBACK_BYTES,
        RoundRows::<Kept>::CALLBACK_BYTES,
        "the calls are the same in both"
    );
}

/// A token is held and handed where the round keeps tokens; where it keeps none it is refused,
/// counted with the records that hold their sender, and its call ended.
#[test]
fn a_token_is_held_where_tokens_are_kept_and_refused_where_they_are_not() {
    let log = Arc::new(Log::default());
    let token = LivelinessSample {
        kind: LivelinessSampleKind::Put,
        keyexpr: "t/1",
        token_id: 7,
    };
    let kept = round::<Kept>();
    let call = Call {
        row: 1,
        log: log.clone(),
    };
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    unsafe {
        kept.offer_liveliness(call, &token, None);
        kept.seal();
    }
    assert!(kept.deliver());
    assert_eq!(log.handed(), ["1 token t/1"]);
    assert_eq!(log.ended(), 1);

    let lean = round::<Lean>();
    let call = Call {
        row: 2,
        log: log.clone(),
    };
    // SAFETY: as above.
    unsafe {
        lean.offer_liveliness(call, &token, None);
        lean.seal();
    }
    assert!(!lean.deliver(), "nothing was held");
    assert_eq!(
        log.handed(),
        ["1 token t/1"],
        "the refused token is handed to none"
    );
    assert_eq!(log.ended(), 2, "the refused token's call is ended");
    assert_eq!(
        lean.counts(),
        RoundCounts {
            dropped: 0,
            held_over: 1,
            unplaced: 0
        }
    );
}

/// The session's own put is handed the calls of the subscribers it reaches where the round hands
/// them out; where it does not, the sample is held for them as any other.
#[test]
fn a_capture_hands_out_the_calls_only_where_the_round_keeps_captures() {
    let log = Arc::new(Log::default());
    let kept = round::<Kept>();
    let call = Call {
        row: 1,
        log: log.clone(),
    };
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    let mut captured = unsafe {
        kept.capture();
        kept.offer_sample(call, &Sample("k/1"), true);
        kept.captured()
    };
    assert_eq!(captured.len(), 1, "the put is handed the call");
    // SAFETY: as above.
    unsafe { kept.seal() };
    assert!(!kept.deliver(), "nothing was held");
    while let Some(call) = captured.pop() {
        kept.end_call(call);
    }
    assert_eq!(log.ended(), 1);
    assert!(log.handed().is_empty(), "the put hands the sample itself");

    let lean = round::<Lean>();
    let call = Call {
        row: 2,
        log: log.clone(),
    };
    // SAFETY: as above.
    let captured = unsafe {
        lean.capture();
        lean.offer_sample(call, &Sample("k/2"), true);
        lean.captured()
    };
    assert!(captured.is_empty(), "the put is handed no call");
    // SAFETY: as above.
    unsafe { lean.seal() };
    assert!(lean.deliver());
    assert_eq!(log.handed(), ["2 sample k/2"]);
    assert_eq!(log.ended(), 2);
}

/// A tally that keeps counts is told of each round handed out and the samples it held.
#[test]
fn a_round_handed_out_is_told_to_its_tally() {
    let log = Arc::new(Log::default());
    let kept = round::<Kept>();
    let call = Call { row: 1, log };
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    unsafe {
        kept.offer_sample(call, &Sample("k/1"), true);
        kept.seal();
    }
    assert!(kept.deliver());
    assert!(!kept.deliver(), "a round is handed out once");
    let tally = kept.tally();
    assert_eq!(
        (
            tally.rounds.load(Ordering::SeqCst),
            tally.samples.load(Ordering::SeqCst)
        ),
        (1, 1)
    );
}

/// A reply is held for its leg's callback where the round keeps replies, and the record's count of
/// the leg given back once it was handed; where it keeps none it is refused, the legs it was told
/// of held by none.
#[test]
fn a_reply_is_held_where_replies_are_kept_and_refused_where_they_are_not() {
    let log = Arc::new(Log::default());
    let mut kept = round::<Kept>();
    Arc::get_mut(&mut kept)
        .expect("not shared yet")
        .calls_legs_of(Arc::new(OneLeg(log.clone())));
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    unsafe {
        kept.offer_reply(4, &Reply("r/1"));
        kept.seal();
    }
    assert!(kept.deliver());
    assert_eq!(log.handed(), ["4 reply r/1"]);
    assert_eq!(
        log.ended(),
        1,
        "the record's count of the leg is given back"
    );

    let mut lean = round::<Lean>();
    Arc::get_mut(&mut lean)
        .expect("not shared yet")
        .calls_legs_of(Arc::new(OneLeg(log.clone())));
    // SAFETY: as above.
    unsafe {
        lean.offer_reply(4, &Reply("r/2"));
        lean.seal();
    }
    assert!(!lean.deliver(), "nothing was held");
    assert_eq!(log.handed(), ["4 reply r/1"]);
    assert_eq!(lean.counts().held_over, 1);
}

/// A query is held for its queryable and answered through what the round was told answers it
/// where the round keeps queries; where it keeps none it is refused and its call ended.
#[test]
fn a_query_is_held_where_queries_are_kept_and_refused_where_they_are_not() {
    let log = Arc::new(Log::default());
    let kept = round::<Kept>();
    let answers: Arc<dyn AnswersQueries<Kept>> = Arc::new(Answers(log.clone()));
    kept.answer_queries_with(Arc::downgrade(&answers));
    let call = Call {
        row: 3,
        log: log.clone(),
    };
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    let taken = unsafe {
        let taken = kept.offer_query(call, &Query("q/1"), 9);
        kept.seal();
        taken
    };
    assert!(taken);
    assert!(kept.deliver());
    assert_eq!(log.handed(), ["3 query q/1 9"]);
    assert_eq!(log.ended(), 1, "the queryable's call is ended by the round");

    let lean = round::<Lean>();
    let call = Call {
        row: 4,
        log: log.clone(),
    };
    // SAFETY: as above.
    let taken = unsafe { lean.offer_query(call, &Query("q/2"), 9) };
    assert!(!taken);
    assert_eq!(log.ended(), 2, "the refused query's call is ended");
    assert_eq!(lean.counts().held_over, 1);
    assert_eq!(log.handed(), ["3 query q/1 9"]);
}
