// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

use super::*;
use crate::bounded::ARENA_ALIGN;
use crate::plane_lock::StdLocks;
use crate::session_tables::{Absent, Present};
use crate::wire_id::RequestId;
use alloc::sync::Arc;
use core::ptr::NonNull;
use std::format;
use std::string::String;
use std::sync::Mutex;
use std::vec::Vec;

/// What a test's calls were handed, and how many calls and counts of legs were ended.
#[derive(Default)]
pub(crate) struct Log {
    handed: Mutex<Vec<String>>,
    ended: std::sync::atomic::AtomicUsize,
}

impl Log {
    fn note(&self, what: String) {
        self.handed.lock().unwrap().push(what);
    }

    pub(crate) fn handed(&self) -> Vec<String> {
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
pub(crate) struct Call {
    pub(crate) row: u32,
    pub(crate) log: Arc<Log>,
}

impl RoundCall for Call {
    fn end(self) -> bool {
        self.log.end();
        false
    }
}

impl SampleCall for Call {
    fn hand(&self, sample: &SampleRef<'_>) {
        self.log
            .note(format!("{} sample {}", self.row, sample.keyexpr));
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

impl WatchCall for Call {
    fn same_row(&self, other: &Self) -> bool {
        self.row == other.row
    }

    fn hand(&self, event: DeclEvent<'_>) {
        self.log.note(format!(
            "{} watch {:?} {} {} {:?}",
            self.row, event.kind, event.id, event.keyexpr, event.peer
        ));
    }
}

/// A tally that keeps the rounds handed out and the samples they held.
#[derive(Default)]
pub(crate) struct Counted {
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
pub(crate) enum Kept {}

impl RoundCalls for Kept {
    type Subscriber = Call;
    type Liveliness = Call;
    type Queryable = Call;
    type Watch = Call;
    type Leg = u32;
    type ReplyCallback = ();
    type Tokens = Present;
    type Replies = Present;
    type Queries = Present;
    type Watches = Present;
    type Capture = Present;
    type Group = Present;
    type Locks = StdLocks;
    type Tally = Counted;
    type Form = crate::row_callback::Threads;
    type TablePolicy = Lent;
}

/// A round that keeps samples alone, offered calls of every other kind all the same.
enum Lean {}

impl RoundCalls for Lean {
    type Subscriber = Call;
    type Liveliness = Call;
    type Queryable = Call;
    type Watch = Call;
    type Leg = u32;
    type ReplyCallback = ();
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

/// [`Lean`] in a build whose calls all run on the thread that steps the session.
enum Single {}

impl RoundCalls for Single {
    type Subscriber = Call;
    type Liveliness = Call;
    type Queryable = Call;
    type Watch = Call;
    type Leg = u32;
    type ReplyCallback = ();
    type Tokens = Absent;
    type Replies = Absent;
    type Queries = Absent;
    type Watches = Absent;
    type Capture = Absent;
    type Group = Absent;
    type Locks = StdLocks;
    type Tally = ();
    type Form = crate::row_callback::OneThread;
    type TablePolicy = Lent;
}

/// [`Kept`] in a build whose calls all run on the thread that steps the session.
enum KeptSingle {}

impl RoundCalls for KeptSingle {
    type Subscriber = Call;
    type Liveliness = Call;
    type Queryable = Call;
    type Watch = Call;
    type Leg = u32;
    type ReplyCallback = ();
    type Tokens = Present;
    type Replies = Present;
    type Queries = Present;
    type Watches = Present;
    type Capture = Present;
    type Group = Present;
    type Locks = StdLocks;
    type Tally = Counted;
    type Form = crate::row_callback::OneThread;
    type TablePolicy = Lent;
}

/// [`Kept`] in a session whose tables take their rows at their first value.
enum KeptOnUse {}

impl RoundCalls for KeptOnUse {
    type Subscriber = Call;
    type Liveliness = Call;
    type Queryable = Call;
    type Watch = Call;
    type Leg = u32;
    type ReplyCallback = ();
    type Tokens = Present;
    type Replies = Present;
    type Queries = Present;
    type Watches = Present;
    type Capture = Present;
    type Group = Present;
    type Locks = StdLocks;
    type Tally = Counted;
    type Form = crate::row_callback::Threads;
    type TablePolicy = crate::bounded::OnUse;
}

/// One block of an arena's memory, aligned as an arena's spans start.
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct Block([u8; ARENA_ALIGN]);

/// A round of a few records, placed with its tables in an arena over memory the test process
/// leaks, so the memory outlives the round, which its owner drops.
pub(crate) fn round<C: RoundCalls<TablePolicy = Lent>>() -> Placed<Round<C>> {
    round_of(4, 4)
}

/// A round of `records` records owing `callbacks` callbacks at most, each no more than the build's
/// bound, as [`round`] makes one.
fn round_of<C: RoundCalls<TablePolicy = Lent>>(
    records: usize,
    callbacks: usize,
) -> Placed<Round<C>> {
    let counts = RoundRowCounts {
        records: caps::DELIVERY_LANE_EVENTS.min(records),
        callbacks: caps::DELIVERY_LANE_CALLBACKS.min(callbacks),
        longest_key: caps::MAX_KEYEXPR_BYTES,
    };
    let bytes: usize = [
        Arena::table_bytes::<Entry<C>>(counts.records),
        Arena::table_bytes::<Owed<C>>(counts.callbacks),
        Arena::table_bytes::<u8>(counts.key_bytes::<C::Form>()),
        Arena::table_bytes::<Round<C>>(1),
    ]
    .into_iter()
    .map(|bytes| bytes.expect("in the address space"))
    .sum();
    let blocks = bytes.div_ceil(ARENA_ALIGN).max(1);
    let region: &'static mut [Block] = std::vec![Block([0; ARENA_ALIGN]); blocks].leak();
    // SAFETY: the region is aligned to `ARENA_ALIGN`, as its blocks are, holds at least `bytes`
    // bytes, and is leaked, so nothing else uses it and it outlives the round and its tables.
    let mut arena = unsafe { Arena::over(NonNull::from(region).cast::<u8>(), bytes) };
    let rows = RoundRows::lent(&mut arena, counts).expect("the arena has the rows");
    Round::placed_over(&mut arena, rows).expect("the arena has the round")
}

/// A round placed in its session's arena is built there whole: nothing owed and no datagram lent,
/// beside the rows it reads. Turned red by a placed round whose fields are not all written, or one
/// placed past what the arena has.
#[test]
fn a_round_placed_in_an_arena_is_built_there_whole() {
    let counts = RoundRowCounts {
        records: caps::DELIVERY_LANE_EVENTS.min(4),
        callbacks: caps::DELIVERY_LANE_CALLBACKS.min(4),
        longest_key: caps::MAX_KEYEXPR_BYTES,
    };
    let bytes: usize = [
        Arena::table_bytes::<Entry<Kept>>(counts.records),
        Arena::table_bytes::<Owed<Kept>>(counts.callbacks),
        Arena::table_bytes::<u8>(counts.key_bytes::<<Kept as RoundCalls>::Form>()),
        Arena::table_bytes::<Round<Kept>>(1),
    ]
    .into_iter()
    .map(|bytes| bytes.expect("in the address space"))
    .sum();
    let blocks = bytes.div_ceil(ARENA_ALIGN).max(1);
    let region: &'static mut [Block] = std::vec![Block([0; ARENA_ALIGN]); blocks].leak();
    let base = NonNull::from(region).cast::<u8>();
    // SAFETY: the region is aligned to `ARENA_ALIGN`, as its blocks are, holds at least `bytes`
    // bytes, and is leaked, so nothing else uses it and it outlives the round and its rows.
    let mut arena = unsafe { Arena::over(base, bytes) };
    let rows = RoundRows::lent(&mut arena, counts).expect("the arena has the rows");
    let round = Round::<Kept>::placed_over(&mut arena, rows).expect("the arena has the round");
    assert!(!round.owes(), "nothing owed");
    assert!(!round.lends_a_datagram(), "no datagram lent");
    let start = base.as_ptr() as usize;
    let at = core::ptr::from_ref::<Round<Kept>>(&round) as usize;
    assert!(
        (start..start + bytes).contains(&at),
        "the round lies in the session's arena"
    );
}

/// The tables of a round placed over a region's rows take the rows the counts state, at most the
/// build's bound of each, and lie in those rows: records only where the form lends them, keys of as
/// many of the longest as the form holds. Turned red by a table placed over more rows than the
/// region keeps (`BoundedVec::placed_over`), or keys sized by the other form's count.
#[test]
fn a_rounds_tables_placed_in_a_region_take_its_rows_at_most() {
    fn check<C: RoundCalls<TablePolicy = Lent>>() {
        let mut places = std::boxed::Box::new(MaybeUninit::<RoundRowPlaces<C>>::uninit());
        let at = NonNull::from(&mut *places).cast::<RoundRowPlaces<C>>();
        let start = at.as_ptr() as usize;
        let size = core::mem::size_of::<RoundRowPlaces<C>>();
        let past = RoundRowCounts {
            records: caps::DELIVERY_LANE_EVENTS + 5,
            callbacks: caps::DELIVERY_LANE_CALLBACKS + 5,
            longest_key: caps::MAX_KEYEXPR_BYTES,
        };
        // SAFETY: the rows are this frame's box, holding no value, reached by the tables alone,
        // which are dropped before it.
        let rows = unsafe { RoundRows::<C>::placed_in(at, past) };
        let records = if <C::Form as RecordForm>::LENT {
            caps::DELIVERY_LANE_EVENTS
        } else {
            ONE_THREAD_RECORDS
        };
        assert_eq!(rows.records.free_slots(), records);
        assert_eq!(
            rows.callbacks.free_slots(),
            caps::DELIVERY_LANE_CALLBACKS,
            "held to the build's bound"
        );
        assert_eq!(
            rows.keys.free_slots(),
            caps::MAX_KEYEXPR_BYTES * <C::Form as RecordForm>::KEYS,
            "the form's keys, no more"
        );
        for table in [
            rows.callbacks.as_ptr() as usize,
            rows.keys.as_ptr() as usize,
        ] {
            assert!(
                (start..start + size).contains(&table),
                "the rows are the region's"
            );
        }
        drop(rows);
        let fewer = RoundRowCounts {
            records: 1,
            callbacks: 2,
            longest_key: 3,
        };
        // SAFETY: as above; the tables before are gone.
        let rows = unsafe { RoundRows::<C>::placed_in(at, fewer) };
        assert_eq!(rows.callbacks.free_slots(), 2);
        assert_eq!(rows.keys.free_slots(), 3 * <C::Form as RecordForm>::KEYS);
        assert_eq!(rows.longest_key, 3);
        drop(rows);
        drop(places);
    }
    check::<Kept>();
    check::<KeptSingle>();
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

/// A sample on `key` with no payload that holds its sender: sent reliably, with `block`.
struct Blocking(&'static str);

impl SampleView for Blocking {
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
        Reliability::Reliable
    }

    fn qos(&self) -> Option<QosLevel> {
        // The data priority, with the `nodrop` bit: congestion control `block`.
        Some(QosLevel::from_raw(0x05 | 0x08))
    }
}

/// Offer `sample` to the rows `rows` as one fan-out of the session's dispatch hands it to them,
/// in that order: each a call of its row that notes in `log`.
///
/// # Safety
/// The caller is the round's one writer, as a holder of the session's lock is.
unsafe fn fan_out<C: RoundCalls<Subscriber = Call>>(
    round: &Round<C>,
    rows: &[u32],
    sample: &dyn SampleView,
    log: &Arc<Log>,
) {
    for (at, row) in rows.iter().enumerate() {
        let call = Call {
            row: *row,
            log: log.clone(),
        };
        // SAFETY: the caller's contract.
        unsafe { round.offer_sample(call, sample, at == 0) };
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

// A record of a round that keeps samples alone takes less room than one of a round that keeps
// every kind: a kind it keeps none of is a variant of no size. The calls are the same in both.
const _: () = assert!(RoundRows::<Lean>::RECORD_BYTES < RoundRows::<Kept>::RECORD_BYTES);
const _: () = assert!(RoundRows::<Lean>::CALLBACK_BYTES == RoundRows::<Kept>::CALLBACK_BYTES);

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

/// A round of one thread holds one record at a time: once a record is written the gate reads
/// nothing more until it was handed out, so what the peer sent after it is read after its
/// callbacks returned. The CONTROL is the round of threads, which takes the next record while it
/// has the room; both take one again once handed out.
#[test]
fn a_round_of_one_thread_takes_one_record_at_a_time() {
    let room = ReadRoom { callbacks: 1 };
    let log = Arc::new(Log::default());
    let threads = round::<Lean>();
    let single = round::<Single>();
    // SAFETY (each block): the test is each round's one writer, as a holder of the session's lock
    // is.
    unsafe {
        assert!(single.has_room(room), "an empty round takes a record");
        fan_out(&threads, &[1], &Sample("k/1"), &log);
        fan_out(&single, &[2], &Sample("k/2"), &log);
        assert!(
            threads.has_room(room),
            "CONTROL: a round of threads takes the next while it has room"
        );
        assert!(
            !single.has_room(room),
            "a round of one thread holds one record"
        );
        threads.seal();
        single.seal();
    }
    assert!(threads.deliver() && single.deliver());
    assert_eq!(log.handed(), ["1 sample k/1", "2 sample k/2"]);
    // SAFETY: as above.
    assert!(
        unsafe { single.has_room(room) },
        "handed out, the next is read"
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

/// A sample the round keeps no record of is refused, counted and its call ended, in each way it
/// can be: a key longer than the round's keys hold is counted unplaced as well, a sample past the
/// records the table holds and one offered to a sealed round are counted dropped alone, and the
/// samples the table took are handed out all the same. Turned red by a refusal that ends no call,
/// counts none, or counts a sample past the room as unplaced.
#[test]
fn a_sample_with_no_room_or_no_place_is_refused_and_its_call_ended() {
    let log = Arc::new(Log::default());
    let call = |row| Call {
        row,
        log: log.clone(),
    };
    let unplaced = round::<Lean>();
    let long: &'static str = "k".repeat(2 * caps::MAX_KEYEXPR_BYTES + 1).leak();
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    unsafe { unplaced.offer_sample(call(1), &Sample(long), true) };
    assert_eq!(
        unplaced.counts(),
        RoundCounts {
            dropped: 1,
            held_over: 0,
            unplaced: 1
        }
    );
    assert_eq!(log.ended(), 1);

    let full = round::<Lean>();
    let room = caps::DELIVERY_LANE_EVENTS
        .min(caps::DELIVERY_LANE_CALLBACKS)
        .min(4);
    // SAFETY: as above.
    unsafe {
        for row in 0..room {
            let key: &'static str = format!("k/{row}").leak();
            full.offer_sample(call(2), &Sample(key), true);
        }
        full.offer_sample(call(3), &Sample("k/past"), true);
        full.seal();
        full.offer_sample(call(4), &Sample("k/sealed"), true);
    }
    assert_eq!(
        full.counts(),
        RoundCounts {
            dropped: 2,
            held_over: 0,
            unplaced: 0
        }
    );
    assert_eq!(log.ended(), 3, "the refused calls are ended at once");
    assert!(full.deliver());
    assert_eq!(log.handed().len(), room);
    assert_eq!(log.ended(), 3 + room);
}

/// A record a link's gate let through that holds its sender and has a part lying nowhere the round
/// reads it (a key longer than the round's keys hold) is refused, counted with the records that
/// hold their sender and apart, and its call ended; a debug build goes on, since where a peer's
/// parts lie is no bound the gate asks for. Turned red by a refusal of a part that stops at the
/// check of the gate's bound, or that counts it with the drops.
#[test]
fn a_gated_record_with_a_part_past_the_rounds_keys_is_counted_and_not_a_defect() {
    let log = Arc::new(Log::default());
    let lean = round::<Lean>();
    let long: &'static str = "k".repeat(2 * caps::MAX_KEYEXPR_BYTES + 1).leak();
    let call = Call {
        row: 1,
        log: log.clone(),
    };
    #[cfg(debug_assertions)]
    lean.offering_gated(true);
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    unsafe { lean.offer_sample(call, &Blocking(long), true) };
    #[cfg(debug_assertions)]
    lean.offering_gated(false);
    assert_eq!(
        lean.counts(),
        RoundCounts {
            dropped: 0,
            held_over: 1,
            unplaced: 1
        }
    );
    assert_eq!(log.ended(), 1, "the refused call is ended at once");
    assert!(log.handed().is_empty(), "nothing is handed");
}

/// A reply is held for its leg's callback where the round keeps replies, and the record's count of
/// the leg given back once it was handed; where it keeps none it is refused, the legs it was told
/// of held by none.
#[test]
fn a_reply_is_held_where_replies_are_kept_and_refused_where_they_are_not() {
    let log = Arc::new(Log::default());
    // Declared before the rounds, so dropped after them.
    let (kept_leg, lean_leg) = (OneLeg(log.clone()), OneLeg(log.clone()));
    let mut kept = round::<Kept>();
    let legs: NonNull<dyn LegHolders<Kept>> = NonNull::from(&kept_leg);
    // SAFETY: the leg outlives the round.
    unsafe { kept.get_mut().calls_legs_of(legs) };
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
    let legs: NonNull<dyn LegHolders<Lean>> = NonNull::from(&lean_leg);
    // SAFETY: the leg outlives the round.
    unsafe { lean.get_mut().calls_legs_of(legs) };
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
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
    // SAFETY: the stand-in stands past the round's last delivery, below.
    unsafe { kept.answer_queries_with(NonNull::from(&*answers)) };
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

/// A round told to answer no more hands the query it holds after to none and ends its call all
/// the same, as an engine's drop tells it first. Turned red by an `answer_no_queries` that leaves
/// the engine named, which would hand the query to an engine being let go of.
#[test]
fn a_round_told_to_answer_no_more_hands_its_query_to_none() {
    let log = Arc::new(Log::default());
    let answers: Arc<dyn AnswersQueries<Kept>> = Arc::new(Answers(log.clone()));
    let kept = round::<Kept>();
    // SAFETY: the stand-in stands past the round, which is told to answer no more at once.
    unsafe { kept.answer_queries_with(NonNull::from(&*answers)) };
    kept.answer_no_queries();
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
    assert!(taken, "CONTROL: the round still keeps queries");
    assert!(kept.deliver());
    assert!(log.handed().is_empty(), "handed to no engine");
    assert_eq!(log.ended(), 1, "its call ended all the same");
}

/// A round let go of while it still names the engine that answers its queries is a defect a debug
/// build stops at: the engine tells the round to answer no more before it lets it go. Turned red
/// by a `let_go` that no longer checks it.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "the engine that answers the round's queries is let go of before")]
fn a_round_let_go_of_while_it_names_its_engine_is_a_defect() {
    let log = Arc::new(Log::default());
    let answers: Arc<dyn AnswersQueries<Kept>> = Arc::new(Answers(log));
    let kept = round::<Kept>();
    // SAFETY: the stand-in stands past the round; no delivery runs.
    unsafe { kept.answer_queries_with(NonNull::from(&*answers)) };
    // SAFETY: no delivery runs and none starts.
    unsafe { kept.let_go() };
}

/// A peer's declaration is written once for the watches it reaches one after the other and handed
/// to each with its key and its peer; a round that keeps no watch refuses it, counted as dropped.
#[test]
fn a_declaration_is_held_once_for_its_watches_and_refused_where_watches_are_not() {
    let log = Arc::new(Log::default());
    let peer: &[u8] = &[0xa1, 0x02];
    let event = DeclEvent {
        kind: DeclEventKind::Declared,
        id: 9,
        keyexpr: "w/1",
        peer: Some(peer),
    };
    let kept = round::<Kept>();
    let (first, second) = (
        Call {
            row: 1,
            log: log.clone(),
        },
        Call {
            row: 2,
            log: log.clone(),
        },
    );
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    unsafe {
        assert!(kept.offer_decl_watch(first, event, None));
        assert!(kept.offer_decl_watch(second, event, None));
        assert!(
            kept.has_room_for(3, 2),
            "the second watch joined the first one's record"
        );
        assert!(!kept.has_room_for(4, 0), "one record was written");
        kept.seal();
    }
    assert!(kept.deliver());
    assert_eq!(
        log.handed(),
        [
            "1 watch Declared 9 w/1 Some([161, 2])",
            "2 watch Declared 9 w/1 Some([161, 2])"
        ]
    );
    assert_eq!(log.ended(), 2);

    let lean = round::<Lean>();
    let call = Call {
        row: 3,
        log: log.clone(),
    };
    // SAFETY: as above.
    unsafe {
        assert!(!lean.offer_decl_watch(call, event, None));
        lean.seal();
    }
    assert!(!lean.deliver(), "nothing was held");
    assert_eq!(log.handed().len(), 2, "the refused event is handed to none");
    assert_eq!(log.ended(), 3, "the refused event's call is ended");
    assert_eq!(
        lean.counts(),
        RoundCounts {
            dropped: 1,
            held_over: 0,
            unplaced: 0
        }
    );
}

/// A retraction names no key and a loss counts its events, each a record of its own; an event
/// naming a peer longer than a zenoh id has nowhere the record holds it, and is refused as unplaced.
#[test]
fn a_retraction_and_a_loss_are_held_and_a_peer_past_a_zid_is_unplaced() {
    let log = Arc::new(Log::default());
    let call = |row| Call {
        row,
        log: log.clone(),
    };
    let long = [1u8; ZID_MAX + 1];
    let kept = round::<Kept>();
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    unsafe {
        let undeclared = DeclEvent {
            kind: DeclEventKind::Undeclared,
            id: 4,
            keyexpr: "",
            peer: None,
        };
        assert!(kept.offer_decl_watch(call(1), undeclared, None));
        let lost = DeclEvent {
            kind: DeclEventKind::Lost,
            id: 3,
            ..undeclared
        };
        assert!(kept.offer_decl_watch(call(1), lost, None));
        let past = DeclEvent {
            kind: DeclEventKind::Declared,
            id: 5,
            keyexpr: "w/2",
            peer: Some(&long),
        };
        assert!(!kept.offer_decl_watch(call(1), past, None));
        kept.seal();
    }
    assert!(kept.deliver());
    assert_eq!(
        log.handed(),
        ["1 watch Undeclared 4  None", "1 watch Lost 3  None"]
    );
    assert_eq!(log.ended(), 3);
    assert_eq!(
        kept.counts(),
        RoundCounts {
            dropped: 1,
            held_over: 0,
            unplaced: 1
        }
    );
}

/// A sealed round takes no record, so a source that writes several at once is told there is no
/// room before it writes the first.
#[test]
fn a_sealed_round_has_no_room() {
    let log = Arc::new(Log::default());
    let kept = round::<Kept>();
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    unsafe {
        assert!(kept.has_room_for(1, 1), "an empty round has room");
        let event = DeclEvent {
            kind: DeclEventKind::Synced,
            id: 0,
            keyexpr: "",
            peer: None,
        };
        let call = Call {
            row: 1,
            log: log.clone(),
        };
        assert!(kept.offer_decl_watch(call, event, None));
        kept.seal();
        assert!(!kept.has_room_for(1, 0), "a sealed round takes nothing");
    }
    assert!(kept.deliver());
    // SAFETY: as above.
    assert!(
        unsafe { kept.has_room_for(1, 1) },
        "a delivered round has room again"
    );
}

/// A build that keeps no watch gives the record of one no room in the round's rows.
#[test]
fn a_round_that_keeps_no_watch_gives_its_record_no_size() {
    type Record = <<Lean as RoundCalls>::Watches as Presence>::Record<HeldWatch>;
    assert_eq!(core::mem::size_of::<Record>(), 0);
}

/// A round that keeps tokens and declaration watches asks a link for the room of two records
/// before each message, since a token's appearance is held for the liveliness subscribers and for
/// the watches apart; one that keeps either alone asks for one.
#[test]
fn a_round_of_tokens_and_watches_asks_for_two_records_a_message() {
    assert_eq!(Round::<Kept>::MESSAGE_RECORDS, 2);
    assert_eq!(Round::<Lean>::MESSAGE_RECORDS, 1);
    let log = Arc::new(Log::default());
    let kept = round::<Kept>();
    let one = crate::round::ReadRoom { callbacks: 1 };
    let event = |id| DeclEvent {
        kind: DeclEventKind::Undeclared,
        id,
        keyexpr: "",
        peer: None,
    };
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    unsafe {
        for id in 1..=2 {
            let call = Call {
                row: 1,
                log: log.clone(),
            };
            assert!(kept.offer_decl_watch(call, event(id), None));
        }
        assert!(kept.has_room(one), "two of four records are free");
        let call = Call {
            row: 1,
            log: log.clone(),
        };
        assert!(kept.offer_decl_watch(call, event(3), None));
        assert!(
            !kept.has_room(one),
            "one record is free, and a message may make two"
        );
        kept.seal();
    }
    assert!(kept.deliver());
}

/// A fan-out that reaches more rows than the round has callbacks left is held once, for the rows
/// that found room, handed to them in the order the fan-out reached them; each row past the room is
/// refused on its own, counted with the drops and its call ended at once. Turned red by a refusal
/// counted once for the fan-out rather than once for each call, a call past the room left running
/// until the delivery, or a second record written for the sample.
#[test]
fn a_fan_out_past_the_callbacks_left_counts_and_ends_each_call_past_them() {
    let log = Arc::new(Log::default());
    let room = caps::DELIVERY_LANE_CALLBACKS.min(4);
    let round = round_of::<Kept>(4, room);
    let rows: Vec<u32> = (1..=room as u32 + 2).collect();
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    unsafe {
        fan_out(&round, &rows, &Sample("k/a"), &log);
        round.seal();
    }
    assert_eq!(
        round.counts(),
        RoundCounts {
            dropped: 2,
            held_over: 0,
            unplaced: 0
        }
    );
    assert_eq!(log.ended(), 2, "the calls past the room are ended at once");
    assert!(round.deliver());
    let handed: Vec<String> = (1..=room).map(|row| format!("{row} sample k/a")).collect();
    assert_eq!(log.handed(), handed);
    assert_eq!(log.ended(), room + 2, "every call is ended");
    assert_eq!(
        round.tally().samples.load(Ordering::SeqCst),
        1,
        "one record for the sample"
    );
}

/// A fan-out that finds no record left is refused for every row it reaches, each call counted and
/// ended at once: with the drops for a sample that may be dropped, held over for one that holds its
/// sender. The record the round held is handed out untouched. Turned red by a fan-out counted once,
/// counted by another sample's congestion control, or a refused call left running.
#[test]
fn a_fan_out_with_no_record_left_counts_every_call() {
    let log = Arc::new(Log::default());
    let round = round_of::<Kept>(1, 4);
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    unsafe {
        fan_out(&round, &[1], &Sample("k/a"), &log);
        fan_out(&round, &[2, 3, 4], &Sample("k/b"), &log);
        fan_out(&round, &[5, 6], &Blocking("k/c"), &log);
        round.seal();
    }
    assert_eq!(
        round.counts(),
        RoundCounts {
            dropped: 3,
            held_over: 2,
            unplaced: 0
        }
    );
    assert_eq!(log.ended(), 5, "each refused call is ended at once");
    assert!(round.deliver());
    assert_eq!(log.handed(), ["1 sample k/a"]);
    assert_eq!(log.ended(), 6);
}

/// A fan-out offered to a sealed round is refused for every row, each call counted by the
/// sample's congestion control and ended at once; what came before the seal is handed out alone.
/// Turned red by a sealed round that takes a later row of a fan-out, or counts a fan-out once.
#[test]
fn a_fan_out_offered_to_a_sealed_round_counts_every_call() {
    let log = Arc::new(Log::default());
    let round = round_of::<Lean>(4, 4);
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    unsafe {
        fan_out(&round, &[1], &Sample("k/a"), &log);
        round.seal();
        fan_out(&round, &[2, 3], &Sample("k/b"), &log);
        fan_out(&round, &[4, 5, 6], &Blocking("k/c"), &log);
    }
    assert_eq!(
        round.counts(),
        RoundCounts {
            dropped: 2,
            held_over: 3,
            unplaced: 0
        }
    );
    assert_eq!(log.ended(), 5);
    assert!(round.deliver());
    assert_eq!(log.handed(), ["1 sample k/a"]);
}

/// A fan-out of a sample with a part that lies nowhere the round reads it is refused for every
/// row, each call counted unplaced and with the drops, and ended at once; nothing is held. Turned
/// red by a later row of the fan-out that is counted otherwise than the first.
#[test]
fn a_fan_out_of_a_sample_with_no_place_counts_every_call_unplaced() {
    let log = Arc::new(Log::default());
    let round = round_of::<Lean>(4, 4);
    let long: &'static str = "k".repeat(2 * caps::MAX_KEYEXPR_BYTES + 1).leak();
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    unsafe {
        fan_out(&round, &[1, 2, 3], &Sample(long), &log);
        round.seal();
    }
    assert_eq!(
        round.counts(),
        RoundCounts {
            dropped: 3,
            held_over: 0,
            unplaced: 3
        }
    );
    assert_eq!(log.ended(), 3);
    assert!(!round.deliver(), "nothing was held");
    assert!(log.handed().is_empty());
}

/// Each fan-out is one record, handed to its rows in the order the fan-out reached them, and each
/// record after the one before it; a fan-out of the same bytes as an earlier one is a record of
/// its own. Turned red by rows handed out of their fan-out's order, a record handed before the one
/// written before it, or two fan-outs joined into one record.
#[test]
fn each_fan_out_is_one_record_handed_in_the_order_its_rows_came() {
    let log = Arc::new(Log::default());
    let round = round_of::<Kept>(4, 8);
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    unsafe {
        fan_out(&round, &[1, 2], &Sample("k/a"), &log);
        fan_out(&round, &[2, 1], &Sample("k/b"), &log);
        fan_out(&round, &[3], &Sample("k/a"), &log);
        round.seal();
    }
    assert!(round.deliver());
    assert_eq!(
        log.handed(),
        [
            "1 sample k/a",
            "2 sample k/a",
            "2 sample k/b",
            "1 sample k/b",
            "3 sample k/a"
        ]
    );
    assert_eq!(log.ended(), 5);
    assert_eq!(round.counts(), RoundCounts::default(), "nothing refused");
    assert_eq!(
        round.tally().samples.load(Ordering::SeqCst),
        3,
        "three records"
    );
}

/// While the round captures, every row of a fan-out hands its call to the session's own put, in
/// the order the fan-out reached them, and the round holds nothing. Turned red by a later row of a
/// fan-out held in the round, or calls handed out of order.
#[test]
fn a_captured_fan_out_hands_every_call_in_order() {
    let log = Arc::new(Log::default());
    let round = round_of::<Kept>(4, 4);
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    let mut captured = unsafe {
        round.capture();
        fan_out(&round, &[3, 1, 2], &Sample("k/a"), &log);
        round.captured()
    };
    let rows: Vec<u32> = captured.iter().map(|call| call.row).collect();
    assert_eq!(rows, [3, 1, 2]);
    // SAFETY: as above.
    unsafe { round.seal() };
    assert!(!round.deliver(), "nothing was held");
    while let Some(call) = captured.pop() {
        round.end_call(call);
    }
    assert_eq!(log.ended(), 3);
    assert!(log.handed().is_empty(), "the put hands the sample itself");
}

// The arena lends a round of one thread no record, and a round of threads its records: the
// two rounds the test below compares.
const _: () = assert!(
    RoundRows::<Single>::RECORD_BYTES == 0,
    "the arena lends a round of one thread no record"
);
const _: () = assert!(
    RoundRows::<Lean>::RECORD_BYTES > 0,
    "CONTROL: a round of threads is lent its records"
);

/// A round of one thread keeps the records of one message in itself: two, as a token held for its
/// liveliness subscribers and for the declaration watches makes, and a third finds no room and is
/// counted; its arena lends it no row of records (held at compile time above). The CONTROL is the
/// round of threads, whose lent rows take the third. Turned red by a round of one thread that
/// keeps its records in lent rows.
#[test]
fn a_round_of_one_thread_keeps_two_records_in_itself_and_refuses_a_third() {
    let log = Arc::new(Log::default());
    let threads = round::<Lean>();
    let single = round::<Single>();
    // SAFETY (each block): the test is each round's one writer, as a holder of the session's lock
    // is.
    unsafe {
        assert!(single.has_room_for(ONE_THREAD_RECORDS, 1));
        assert!(
            !single.has_room_for(ONE_THREAD_RECORDS + 1, 0),
            "no room for more records than one message makes"
        );
        for (row, key) in [(1, "k/1"), (2, "k/2"), (3, "k/3")] {
            fan_out(&threads, &[row], &Sample(key), &log);
            fan_out(&single, &[row + 10], &Sample(key), &log);
        }
        threads.seal();
        single.seal();
    }
    assert_eq!(
        threads.counts(),
        RoundCounts::default(),
        "CONTROL: the round of threads took all three"
    );
    assert_eq!(single.counts().dropped, 1, "the third found no room");
    assert!(threads.deliver() && single.deliver());
    assert_eq!(
        log.handed(),
        [
            "1 sample k/1",
            "2 sample k/2",
            "3 sample k/3",
            "11 sample k/1",
            "12 sample k/2"
        ]
    );
}

/// A round of one thread is lent one of the session's longest keys, a round of threads two. The
/// records of the one message a round of one thread takes share its key, as a token held for its
/// liveliness subscribers and for the declaration watches does, so both are held; a second key of
/// that length finds no place, where the round of threads (the CONTROL) places it. Turned red by a
/// round of one thread lent a key for each record it holds.
#[test]
fn a_round_of_one_thread_holds_one_longest_key_its_records_share() {
    use crate::row_callback::{OneThread, Threads};

    let counts = RoundRowCounts {
        records: 0,
        callbacks: 0,
        longest_key: 40,
    };
    assert_eq!(counts.key_bytes::<OneThread>(), 40);
    assert_eq!(counts.key_bytes::<Threads>(), 80, "CONTROL: two keys");
    let (first_key, second_key) = (
        "a".repeat(caps::MAX_KEYEXPR_BYTES),
        "b".repeat(caps::MAX_KEYEXPR_BYTES),
    );
    let (first, second) = (first_key.as_str(), second_key.as_str());
    let log = Arc::new(Log::default());
    let call = |row: u32| Call {
        row,
        log: log.clone(),
    };
    let declared = |keyexpr| DeclEvent {
        kind: DeclEventKind::Declared,
        id: 7,
        keyexpr,
        peer: None,
    };
    let token = LivelinessSample {
        kind: LivelinessSampleKind::Put,
        keyexpr: first,
        token_id: 7,
    };
    let shared = round::<KeptSingle>();
    let single = round::<KeptSingle>();
    let threads = round::<Kept>();
    // SAFETY (each block): the test is each round's one writer, as a holder of the session's lock
    // is.
    unsafe {
        shared.offer_liveliness(call(1), &token, None);
        assert!(
            shared.offer_decl_watch(call(2), declared(first), None),
            "the watch's record shares the token's key"
        );
        assert!(single.offer_decl_watch(call(3), declared(first), None));
        assert!(
            !single.offer_decl_watch(call(4), declared(second), None),
            "a second longest key finds no place"
        );
        assert!(threads.offer_decl_watch(call(5), declared(first), None));
        assert!(
            threads.offer_decl_watch(call(6), declared(second), None),
            "CONTROL: a round of threads places a second longest key"
        );
        shared.seal();
        single.seal();
        threads.seal();
    }
    assert_eq!(shared.counts(), RoundCounts::default());
    assert_eq!(
        single.counts(),
        RoundCounts {
            dropped: 1,
            held_over: 0,
            unplaced: 1
        },
        "refused as unplaced, which is counted with what was dropped"
    );
    assert_eq!(threads.counts(), RoundCounts::default());
    assert!(shared.deliver() && single.deliver() && threads.deliver());
    let rows: Vec<u32> = log
        .handed()
        .iter()
        .map(|what| what.split(' ').next().unwrap().parse().unwrap())
        .collect();
    assert_eq!(rows, [1, 2, 3, 5, 6]);
    assert_eq!(log.ended(), 6, "the refused event's call is ended too");
}

/// The queryables one query reaches owe calls of one record, in the order they were reached: a
/// round of one record holds the query for both, and refuses the next query, which is another
/// record. Turned red by a query written as a record for each queryable.
#[test]
fn a_query_for_two_queryables_is_one_record_owing_both() {
    let log = Arc::new(Log::default());
    let kept = round_of::<Kept>(1, 4);
    let answers: Arc<dyn AnswersQueries<Kept>> = Arc::new(Answers(log.clone()));
    // SAFETY: the stand-in stands past the round's last delivery, below.
    unsafe { kept.answer_queries_with(NonNull::from(&*answers)) };
    let call = |row| Call {
        row,
        log: log.clone(),
    };
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    let taken = unsafe {
        let taken = [
            kept.offer_query(call(3), &Query("q/1"), 9),
            kept.offer_query(call(4), &Query("q/1"), 9),
            kept.offer_query(call(5), &Query("q/1"), 8),
        ];
        kept.seal();
        taken
    };
    assert_eq!(
        taken,
        [true, true, false],
        "the second queryable joins the record; another link's query is a record of its own"
    );
    assert_eq!(kept.counts().held_over, 1);
    assert!(kept.deliver());
    assert_eq!(log.handed(), ["3 query q/1 9", "4 query q/1 9"]);
    assert_eq!(
        log.ended(),
        3,
        "every call is ended, the refused one at once"
    );
}

/// Each source the gate does not hold back owes apart: one that no longer owes leaves the links
/// held while the other still does. Turned red by one flag both sources write.
#[test]
fn a_source_that_owes_no_more_leaves_the_links_held_while_another_owes() {
    let round = round::<Lean>();
    assert!(!round.owes());
    round.owe(Owing::Retractions, true);
    round.owe(Owing::CatchUp, true);
    round.owe(Owing::Retractions, false);
    assert!(round.owes(), "the catch-up still owes");
    round.owe(Owing::CatchUp, false);
    assert!(!round.owes(), "CONTROL: none owes");
}

/// The row releases an engine keeps where nothing is put in the round read as the round's do: a
/// mark is taken once and cleared, and each drop under way is counted until its count is given
/// back. Turned red by a mark that survives its taking, or a drop count that settles early.
#[test]
fn the_row_releases_take_a_mark_once_and_count_each_drop() {
    let releases = RowReleases::new();
    assert!(!releases.take_marked(), "CONTROL: no row waits");
    releases.mark();
    assert!(releases.take_marked());
    assert!(!releases.take_marked(), "taking the mark clears it");
    assert!(releases.settled(), "CONTROL: no drop under way");
    let (one, two) = (releases.releasing(), releases.releasing());
    drop(one);
    assert!(!releases.settled(), "the other drop is still under way");
    drop(two);
    assert!(releases.settled());
}

/// What [`At`] calls note of each sample they are handed: the row, the payload's first byte and
/// where the payload lies.
type Seen = Arc<Mutex<Vec<(u32, u8, usize)>>>;

/// A call of subscriber row `row` that notes in `seen` where the payload it is handed lies.
struct At {
    row: u32,
    seen: Seen,
}

impl RoundCall for At {
    fn end(self) -> bool {
        false
    }
}

impl SampleCall for At {
    fn hand(&self, sample: &SampleRef<'_>) {
        self.seen.lock().unwrap().push((
            self.row,
            sample.payload.first().copied().unwrap_or(0),
            sample.payload.as_ptr() as usize,
        ));
    }
}

/// A round that reads a group's datagrams and keeps samples alone, its subscribers' calls noting
/// where each payload lies.
enum Grouped {}

impl RoundCalls for Grouped {
    type Subscriber = At;
    type Liveliness = Call;
    type Queryable = Call;
    type Watch = Call;
    type Leg = u32;
    type ReplyCallback = ();
    type Tokens = Absent;
    type Replies = Absent;
    type Queries = Absent;
    type Watches = Absent;
    type Capture = Absent;
    type Group = Present;
    type Locks = StdLocks;
    type Tally = ();
    type Form = crate::row_callback::Threads;
    type TablePolicy = Lent;
}

/// A group's receive buffer given back while a record of the round reads a datagram in it is
/// kept, the round sealed and handed out meanwhile, and goes back to its table once the lock
/// holder settles the round after the delivery; one in which no record reads goes back at once.
/// Turned red by a round that lets go of the buffer a delivery reads, or keeps one it reads
/// nothing in.
#[test]
fn a_given_back_group_buffer_is_kept_while_a_record_reads_in_it() {
    use crate::byte_cells::{ByteCells, ByteSource};
    use crate::sink::BorrowedSample;

    static RX: ByteCells<16, 2> = ByteCells::new();
    let round = round::<Grouped>();
    let seen: Seen = Arc::default();
    let mut buf = RX.claim().expect("a group's buffer");
    buf.as_mut_slice()[..2].copy_from_slice(&[7, 7]);
    let (base, _) = buf.raw();
    // SAFETY: the first two bytes of the buffer, which the claim holds until it is given back and
    // the round, which keeps it, lets go of it after the delivery read them.
    let datagram = unsafe { core::slice::from_raw_parts(base.cast_const(), 2) };
    let sample = BorrowedSample {
        keyexpr: "demo/round",
        payload: datagram,
        kind: SampleKind::Put,
        reliability: Reliability::BestEffort,
    };
    let call = At {
        row: 1,
        seen: seen.clone(),
    };
    // SAFETY: the test is the round's one writer, as a holder of the session's lock is.
    unsafe {
        round.set_lending(Some(datagram));
        round.offer_sample(call, &sample, true);
        round.set_lending(None);
        round.seal();
        round.keep_rx(buf);
    }
    assert_eq!(RX.in_use(), 1, "a sealed record reads in it, so it is kept");
    let other = RX.claim().expect("the other buffer");
    // SAFETY: as above.
    unsafe { round.keep_rx(other) };
    assert_eq!(
        RX.in_use(),
        1,
        "CONTROL: nothing reads in the other, so it went back"
    );
    assert!(round.deliver());
    assert_eq!(
        *seen.lock().unwrap(),
        [(1, 7, base as usize)],
        "read where it lies"
    );
    assert_eq!(
        RX.in_use(),
        1,
        "handed out with no lock held, it waits for the lock holder"
    );
    // SAFETY: as above.
    unsafe { round.settle() };
    assert_eq!(RX.in_use(), 0, "settled, the buffer is its table's again");
}

/// A round of `records` records owing `callbacks` callbacks at most, each no more than the
/// build's bound, whose tables take their rows at its first record; the round itself is placed in
/// an arena over memory the test process leaks.
fn counted_round<C: RoundCalls<TablePolicy = crate::bounded::OnUse>>(
    records: usize,
    callbacks: usize,
) -> Placed<Round<C>> {
    let counts = RoundRowCounts {
        records: caps::DELIVERY_LANE_EVENTS.min(records),
        callbacks: caps::DELIVERY_LANE_CALLBACKS.min(callbacks),
        longest_key: caps::MAX_KEYEXPR_BYTES,
    };
    let bytes = Arena::table_bytes::<Round<C>>(1).expect("in the address space");
    let blocks = bytes.div_ceil(ARENA_ALIGN).max(1);
    let region: &'static mut [Block] = std::vec![Block([0; ARENA_ALIGN]); blocks].leak();
    // SAFETY: the region is aligned to `ARENA_ALIGN`, as its blocks are, holds `blocks` whole
    // blocks, and is leaked, so nothing else uses it and it outlives the round.
    let mut arena =
        unsafe { Arena::over(NonNull::from(region).cast::<u8>(), blocks * ARENA_ALIGN) };
    Round::placed_over(&mut arena, RoundRows::counted(counts)).expect("the arena has the round")
}

/// Whether the round's records and its callbacks have taken their rows.
fn rows_taken(round: &Round<KeptOnUse>) -> (bool, bool) {
    // SAFETY: the test is the round's one writer and holds no other borrow of its table.
    let table = unsafe { &*round.table.get() };
    (table.entries.holds_rows(), table.callbacks.holds_rows())
}

/// A round of a session whose tables take their rows on use holds no row until its first record,
/// which has its records and its callbacks take theirs, and holds its records to the count its
/// session resolved: a record past it is refused for want of room. Turned red by
/// `RoundRows::counted` making tables that take their rows when made, or that hold the build's
/// bound in place of the count.
#[test]
fn a_round_counted_on_use_takes_its_rows_at_its_first_record() {
    let round = counted_round::<KeptOnUse>(1, 1);
    assert_eq!(rows_taken(&round), (false, false), "no record, no row");
    let log = Arc::new(Log::default());
    // SAFETY (each block): the test is the round's one writer, as a holder of the session's lock
    // is.
    unsafe { fan_out(&round, &[1], &Sample("k/1"), &log) };
    assert_eq!(
        rows_taken(&round),
        (true, true),
        "the first record took the rows"
    );
    unsafe { fan_out(&round, &[2], &Sample("k/2"), &log) };
    assert_eq!(
        round.counts(),
        RoundCounts {
            dropped: 1,
            held_over: 0,
            unplaced: 0
        },
        "the record past the count is refused for want of room"
    );
    unsafe { round.seal() };
    assert!(round.deliver());
    assert_eq!(log.handed(), ["1 sample k/1"]);
}

/// The key of a sample a test lends the round where it lies, so the round asks the heap for no
/// part of the sample: its tables' rows are the only memory a record of it takes.
static LENT_KEY: &str = "k/lent";

/// A record offered to a round counted on use while the heap has no room for its tables' rows is
/// refused as one with a part that found no place, counted with the records that hold their
/// sender, and its call ended; with room again, the next record takes the rows and is handed out.
/// Turned red by an offer that writes a record before its rows are had (`Round::take_rows` left
/// out): the record is then lost uncounted, or a debug build stops at the round's check of its
/// room.
#[test]
fn a_record_whose_rows_the_heap_refuses_is_counted_unplaced() {
    let round = counted_round::<KeptOnUse>(2, 2);
    let log = Arc::new(Log::default());
    let first = Call {
        row: 1,
        log: log.clone(),
    };
    // SAFETY (each block): the test is the round's one writer, as a holder of the session's lock
    // is, and the key is static, so it lies where it is while the round reads it.
    unsafe { round.set_lending(Some(LENT_KEY.as_bytes())) };
    crate::test_heap::refused(|| unsafe { round.offer_sample(first, &Blocking(LENT_KEY), true) });
    assert_eq!(
        round.counts(),
        RoundCounts {
            dropped: 0,
            held_over: 1,
            unplaced: 1
        }
    );
    assert_eq!(log.ended(), 1, "the refused call is ended");
    assert_eq!(rows_taken(&round), (false, false), "nothing was taken");
    let second = Call {
        row: 2,
        log: log.clone(),
    };
    unsafe {
        round.offer_sample(second, &Blocking(LENT_KEY), true);
        round.seal();
    }
    assert!(round.deliver());
    assert_eq!(log.handed(), ["2 sample k/lent"]);
}
