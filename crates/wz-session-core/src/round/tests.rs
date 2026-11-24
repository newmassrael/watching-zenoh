// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

use super::*;
use crate::bounded::ARENA_ALIGN;
use crate::plane_lock::StdLocks;
use crate::session_tables::{Absent, Present};
use crate::wire_id::RequestId;
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
}

/// One block of an arena's memory, aligned as an arena's spans start.
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct Block([u8; ARENA_ALIGN]);

/// A round of a few records, its tables lent from an arena over memory the test process leaks,
/// so it outlives the round.
pub(crate) fn round<C: RoundCalls>() -> Arc<Round<C>> {
    round_of(4, 4)
}

/// A round of `records` records owing `callbacks` callbacks at most, each no more than the build's
/// bound, as [`round`] makes one.
fn round_of<C: RoundCalls>(records: usize, callbacks: usize) -> Arc<Round<C>> {
    let counts = RoundRowCounts {
        records: caps::DELIVERY_LANE_EVENTS.min(records),
        callbacks: caps::DELIVERY_LANE_CALLBACKS.min(callbacks),
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

/// A round placed in its session's arena is built there whole, as a shared one is: nothing owed
/// and no datagram lent, beside the rows it reads. Turned red by a placed round whose fields are
/// not all written, or one placed past what the arena has.
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
        Arena::table_bytes::<u8>(counts.key_bytes()),
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
