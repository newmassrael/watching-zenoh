// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session's round of deliveries: a record is handed to its callbacks as it was offered, read
//! where it lies in a lent datagram or from the round's own bytes; a sealed round refuses and
//! counts by the record's congestion control; the gate reads a link only while the round has the
//! room of a record and no record lies in the datagram the link lent.

use alloc::sync::Arc;
use core::ptr::NonNull;
use std::sync::Mutex;

use wz_session_core::bounded::ARENA_ALIGN;
use wz_session_core::caps;
use wz_session_core::limit_binding::Quota;
use wz_session_core::limits::SessionLimits;
use wz_session_core::reliability::Reliability;
use wz_session_core::sample::{
    EncodingHint, QosLevel, Sample, SampleKind, SourceInfo, TimestampHint,
};
use wz_session_core::sink::{BorrowedSample, SampleView};

use super::entity_tables::lowered;
use crate::arena::{AllocatorMemory, SessionArena};
use crate::engine::{LiveCallback, SubscriberCallback};
use crate::round::{
    ReadRoom, Round, RoundCounts, RoundGate, RoundRowCounts, RoundRows, CALLBACK_BYTES,
    RECORD_BYTES,
};

/// The QoS byte of a sample sent at the data priority whose congestion control holds its sender.
const BLOCK: u8 = 0x05 | 0x08;

/// A round over an area of `bytes` the test leaks, holding `events` records at once, its tables
/// lent from an arena the test leaks too, so both outlive the round.
fn round(bytes: usize, events: usize) -> Arc<Round> {
    let counts = RoundRowCounts {
        records: events,
        callbacks: caps::DELIVERY_LANE_CALLBACKS,
        longest_key: caps::MAX_KEYEXPR_BYTES,
    };
    // Each table on a span of its own, rounded up to the next start of one.
    let bytes_of_rows = events * RECORD_BYTES
        + counts.callbacks * CALLBACK_BYTES
        + counts.key_bytes()
        + 3 * ARENA_ALIGN;
    let arena: &'static mut SessionArena = Box::leak(Box::new(
        SessionArena::of_bytes(bytes_of_rows, &AllocatorMemory).expect("the host has the memory"),
    ));
    let rows = RoundRows::lent(arena.arena_mut(), counts).expect("the arena has the rows");
    let area: &'static mut [u8] = vec![0u8; bytes].leak();
    // SAFETY: the area is leaked, so it outlives the round, and nothing else uses it.
    unsafe { Round::shared_over(NonNull::from(area).cast::<u8>(), bytes, rows) }
}

/// The room of a record of `bytes` bytes for one subscriber.
fn room(bytes: usize) -> ReadRoom {
    ReadRoom {
        bytes,
        callbacks: 1,
    }
}

/// A best-effort put of `len` bytes of `byte` on `demo/round`.
fn filled(len: usize, byte: u8) -> Sample {
    Sample::new_put("demo/round", vec![byte; len]).with_reliability(Reliability::BestEffort)
}

/// A best-effort put on `demo/round` whose payload is borrowed where it lies, as a sample read in
/// place is.
fn borrowed(payload: &[u8]) -> BorrowedSample<'_> {
    BorrowedSample {
        keyexpr: "demo/round",
        payload,
        kind: SampleKind::Put,
        reliability: Reliability::BestEffort,
    }
}

/// A link that has nothing to give: what a gate over it holds back is the gate's alone.
struct Quiet;

impl wz_runtime_coop::session_drive::SessionDatagramLink for Quiet {
    fn service(&self) {}

    fn try_recv(&self) -> Option<wz_session_core::link::RxFrame> {
        None
    }
}

/// What [`noting`] callbacks write: the tag, the payload's first byte and where it lies.
type Noted = Arc<Mutex<Vec<(u8, u8, usize)>>>;

/// A callback the tests count the samples of: each is noted with `tag`, its payload's first byte
/// and where its payload lies.
fn noting(tag: u8, seen: &Noted) -> SubscriberCallback {
    let seen = seen.clone();
    Arc::new(LiveCallback::new(
        wz_capi_port::SubscriberSink::shared(move |sample: &dyn SampleView| {
            let payload = sample.payload();
            seen.lock().unwrap().push((
                tag,
                payload.first().copied().unwrap_or(0),
                payload.as_ptr() as usize,
            ));
        }),
        true,
    ))
}

/// A sample with every part, offered with no datagram lent, is written into the round and handed
/// to its subscriber with every part as it was offered; the round is empty once it is handed.
#[test]
fn a_written_sample_is_handed_with_every_part_as_it_was_offered() {
    type Seen = (
        String,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<(u32, Option<Vec<u8>>)>,
    );
    let round = round(1024, 4);
    let source = SourceInfo::new(&[9, 9], 3, 4);
    let sample = Sample::new_put("demo/a", b"payload".to_vec())
        .with_attachment(b"att".to_vec())
        .with_encoding(EncodingHint {
            packed_id: 7,
            schema: Some(b"text".to_vec()),
        })
        .with_timestamp(TimestampHint {
            time: 42,
            zid: vec![1, 2, 3],
        })
        .with_qos(QosLevel::from_raw(5))
        .with_source_info(source.clone())
        .with_reliability(Reliability::BestEffort);
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let rest: Arc<Mutex<Vec<String>>> = Arc::default();
    let callback: SubscriberCallback = {
        let (seen, rest, source) = (seen.clone(), rest.clone(), source.clone());
        Arc::new(LiveCallback::new(
            wz_capi_port::SubscriberSink::shared(move |view: &dyn SampleView| {
                seen.lock().unwrap().push((
                    view.keyexpr().to_owned(),
                    view.payload().to_vec(),
                    view.attachment().map(<[u8]>::to_vec),
                    view.encoding_parts()
                        .map(|(id, schema)| (id, schema.map(<[u8]>::to_vec))),
                ));
                let mut rest = rest.lock().unwrap();
                if view.kind() != SampleKind::Put {
                    rest.push("kind".to_owned());
                }
                if view.reliability() != Reliability::BestEffort {
                    rest.push("reliability".to_owned());
                }
                if view.qos() != Some(QosLevel::from_raw(5)) {
                    rest.push("qos".to_owned());
                }
                if view.timestamp_parts() != Some((42, &[1u8, 2, 3][..])) {
                    rest.push("timestamp".to_owned());
                }
                if view.source_info() != Some(&source) {
                    rest.push("source info".to_owned());
                }
            }),
            true,
        ))
    };
    // SAFETY (each call): this thread is the round's one writer, as a session's step is.
    unsafe { round.offer_sample(7, Some(&callback), &sample) };
    unsafe { round.seal() };
    assert!(round.deliver(), "the sealed round is handed out");
    assert_eq!(
        *seen.lock().unwrap(),
        [(
            "demo/a".to_owned(),
            b"payload".to_vec(),
            Some(b"att".to_vec()),
            Some((7, Some(b"text".to_vec())))
        )]
    );
    assert_eq!(
        *rest.lock().unwrap(),
        Vec::<String>::new(),
        "every part as offered"
    );
    assert!(!round.deliver(), "nothing is left");
    assert_eq!(round.counts(), RoundCounts::default());
    assert_eq!(round.samples_lent(), 0, "nothing was lent");
}

/// The samples of a datagram a link lends are read where they lie: one record for a sample
/// however many subscribers it reaches, the link held back from the next datagram until they are
/// handed out, and each handed to its callbacks in the order it came.
#[test]
fn the_samples_of_a_lent_datagram_are_handed_where_they_lie() {
    use wz_runtime_coop::session_drive::SessionDatagramLink;

    let round = round(1024, 4);
    // SAFETY (every call on the round and the gate here): this thread is the round's one writer,
    // as a session's step is under its lock, and the datagram outlives every use below.
    let gate = unsafe { RoundGate::new(Quiet, round.clone(), room(32)) };
    let seen: Noted = Arc::default();
    let (first, second) = (noting(1, &seen), noting(2, &seen));
    let datagram = [1u8, 1, 2, 2];
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_sample(1, Some(&first), &borrowed(&datagram[..2])) };
    unsafe { round.offer_sample(2, Some(&second), &borrowed(&datagram[..2])) };
    unsafe { round.offer_sample(1, Some(&first), &borrowed(&datagram[2..])) };
    assert!(
        gate.takes_input(),
        "the round takes the datagram's next record"
    );
    unsafe { round.set_lending(None) };
    assert!(round.lends_a_datagram(), "the round holds the link back");
    unsafe { round.seal() };
    assert!(!gate.takes_input(), "sealed, no further record is read");
    assert!(round.deliver());
    let at = datagram.as_ptr() as usize;
    assert_eq!(
        *seen.lock().unwrap(),
        [(1, 1, at), (2, 1, at), (1, 2, at + 2)],
        "each sample handed where it lies, to each of its subscribers, in the order they came"
    );
    assert!(
        !round.lends_a_datagram(),
        "handed out, the link is read again"
    );
    assert!(gate.takes_input(), "CONTROL: an empty round takes a record");
    assert_eq!(
        (
            round.rounds_handed(),
            round.samples_handed(),
            round.samples_lent()
        ),
        (1, 2, 2),
        "one round of two samples, both read where they lie"
    );
}

/// A rejoined message's records are read where its chain lies while the round lends nothing else,
/// and the datagram lent before the message is lent again after it; the round lends one source,
/// so the datagram's record that follows is copied. The CONTROL is its payload's place.
#[test]
fn a_rejoined_message_is_read_where_its_chain_lies() {
    let round = round(1024, 4);
    let seen: Noted = Arc::default();
    let first = noting(1, &seen);
    let datagram = [1u8, 1];
    let chain = [2u8, 2];
    // SAFETY (each call): this thread is the round's one writer, and both buffers outlive it.
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.lend_rejoined(Some(&chain[..])) };
    unsafe { round.offer_sample(1, Some(&first), &borrowed(&chain[..])) };
    unsafe { round.lend_rejoined(None) };
    unsafe { round.offer_sample(1, Some(&first), &borrowed(&datagram[..])) };
    unsafe { round.set_lending(None) };
    assert!(round.lends_a_datagram(), "the chain is held where it lies");
    unsafe { round.seal() };
    assert!(round.deliver());
    let places: Vec<usize> = seen.lock().unwrap().iter().map(|(_, _, at)| *at).collect();
    assert_eq!(places.len(), 2);
    assert_eq!(
        places[0],
        chain.as_ptr() as usize,
        "read where the chain lies"
    );
    assert_ne!(
        places[1],
        datagram.as_ptr() as usize,
        "CONTROL: the round lent the chain, so the datagram's record was copied"
    );
    assert_eq!(round.samples_lent(), 1);
}

/// A round let go of at its session's end lets go of the callbacks its records owe, before the
/// arena that lent its tables, and hands nothing after; the subscriber's row is its callback's
/// one holder again. The CONTROL is the count while the record waits.
#[test]
fn a_round_let_go_of_lets_go_of_the_callbacks_its_records_owe() {
    let round = round(1024, 4);
    let seen: Noted = Arc::default();
    let first = noting(1, &seen);
    // SAFETY (each call): this thread is the round's one writer, and no delivery runs.
    unsafe { round.offer_sample(1, Some(&first), &filled(4, 1)) };
    unsafe { round.seal() };
    assert_eq!(
        Arc::strong_count(&first),
        2,
        "CONTROL: the waiting record owes it"
    );
    unsafe { round.let_go() };
    assert_eq!(
        Arc::strong_count(&first),
        1,
        "let go of with the round's tables"
    );
    assert!(!round.deliver(), "nothing is left to hand");
    assert!(seen.lock().unwrap().is_empty(), "and nothing was handed");
}

/// A round is handed to one delivery at a time: a delivery asked for from inside a callback of
/// the one running hands nothing, and each record is handed once. The CONTROL is the delivery
/// after it, which finds the round emptied.
#[test]
fn a_round_is_handed_to_one_delivery_at_a_time() {
    let round = round(1024, 4);
    let inner: Arc<Mutex<Vec<bool>>> = Arc::default();
    let again = Arc::downgrade(&round);
    let noted = inner.clone();
    let callback: SubscriberCallback = Arc::new(LiveCallback::new(
        wz_capi_port::SubscriberSink::shared(move |_: &dyn SampleView| {
            let handed = again.upgrade().is_some_and(|round| round.deliver());
            noted.lock().unwrap().push(handed);
        }),
        true,
    ));
    // SAFETY (each call): this thread is the round's one writer, and no delivery runs.
    unsafe { round.offer_sample(1, Some(&callback), &filled(4, 1)) };
    unsafe { round.offer_sample(1, Some(&callback), &filled(4, 2)) };
    unsafe { round.seal() };
    assert!(round.deliver(), "the sealed round is handed out");
    assert_eq!(
        *inner.lock().unwrap(),
        [false, false],
        "each record handed once, and no delivery inside the one running"
    );
    assert!(!round.deliver(), "CONTROL: the round was emptied");
    assert_eq!(
        Arc::strong_count(&callback),
        1,
        "the row holds its callback alone"
    );
}

/// A sample offered again for a subscriber it is for already is a record of its own, handed to
/// that subscriber twice.
#[test]
fn a_sample_offered_again_to_its_subscriber_is_a_record_of_its_own() {
    let round = round(1024, 4);
    let seen: Noted = Arc::default();
    let first = noting(1, &seen);
    let sample = filled(4, 3);
    // SAFETY (each call): this thread is the round's one writer.
    unsafe { round.offer_sample(1, Some(&first), &sample) };
    unsafe { round.offer_sample(1, Some(&first), &sample) };
    unsafe { round.seal() };
    assert!(round.deliver());
    let tags: Vec<(u8, u8)> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|(t, b, _)| (*t, *b))
        .collect();
    assert_eq!(tags, [(1, 3), (1, 3)]);
    assert_eq!(round.samples_handed(), 2, "two records");
}

/// A sealed round refuses what is offered until it is handed out, and counts it by its congestion
/// control: apart when it holds its sender (reliable, `block`), and as a drop otherwise, a
/// reliable sample with no QoS having zenoh's default, `drop`.
#[test]
fn a_sealed_round_refuses_and_counts_by_congestion_control() {
    let round = round(1024, 4);
    let seen: Noted = Arc::default();
    let first = noting(1, &seen);
    // SAFETY (each call): this thread is the round's one writer.
    unsafe { round.offer_sample(1, Some(&first), &filled(4, 1)) };
    unsafe { round.seal() };
    unsafe { round.offer_sample(1, Some(&first), &filled(4, 2)) };
    let held = filled(4, 3)
        .with_reliability(Reliability::Reliable)
        .with_qos(QosLevel::from_raw(BLOCK));
    unsafe { round.offer_sample(1, Some(&first), &held) };
    let reliable = filled(4, 4).with_reliability(Reliability::Reliable);
    unsafe { round.offer_sample(1, Some(&first), &reliable) };
    assert_eq!(
        round.counts(),
        RoundCounts {
            dropped: 2,
            held_over: 1
        }
    );
    assert!(round.deliver());
    let bytes: Vec<u8> = seen.lock().unwrap().iter().map(|(_, b, _)| *b).collect();
    assert_eq!(bytes, [1], "only what came before the seal");
    unsafe { round.offer_sample(1, Some(&first), &filled(4, 5)) };
    unsafe { round.seal() };
    assert!(
        round.deliver(),
        "CONTROL: handed out, the round takes records again"
    );
}

/// The gate reads a link while the round has the room of a record, and not once what was written
/// leaves less than that room or the round holds as many records as it may; an empty round takes
/// a record whatever its room, so a link is never stopped for good.
#[test]
fn the_gate_reads_a_link_only_while_the_round_has_a_records_room() {
    use wz_runtime_coop::session_drive::SessionDatagramLink;

    let round = round(64, 4);
    // SAFETY (each call): this thread is the round's one writer.
    let gate = unsafe { RoundGate::new(Quiet, round.clone(), room(32)) };
    let seen: Noted = Arc::default();
    let first = noting(1, &seen);
    assert!(gate.takes_input(), "an empty round");
    unsafe { round.offer_sample(1, Some(&first), &filled(24, 1)) };
    assert!(
        gate.takes_input(),
        "40 bytes left of 64, a record's 32 among them"
    );
    unsafe { round.offer_sample(1, Some(&first), &filled(16, 2)) };
    assert!(!gate.takes_input(), "24 bytes left, short of a record");
    unsafe { round.seal() };
    assert!(round.deliver());
    assert!(gate.takes_input(), "handed out, the room is back");

    let one = self::round(1024, 1);
    // SAFETY: as above.
    let gate = unsafe { RoundGate::new(Quiet, one.clone(), room(32)) };
    unsafe { one.offer_sample(1, Some(&first), &filled(4, 1)) };
    assert!(!gate.takes_input(), "a round of one record holds one");
    let huge = unsafe { RoundGate::new(Quiet, self::round(64, 4), room(4096)) };
    assert!(
        huge.takes_input(),
        "an empty round takes a record longer than its area"
    );
}

/// While a source the gate does not hold back owes the round records (a lost face's tokens), the
/// gate reads no link, an empty round's included, so what that source owes comes first. The
/// CONTROL is the same round once nothing is owed.
#[cfg(feature = "liveliness")]
#[test]
fn the_gate_reads_no_link_while_retractions_are_owed() {
    use wz_runtime_coop::session_drive::SessionDatagramLink;

    let round = round(1024, 4);
    // SAFETY: this thread is the round's one writer.
    let gate = unsafe { RoundGate::new(Quiet, round.clone(), room(32)) };
    round.owe(true);
    assert!(!gate.takes_input(), "owed, no link is read");
    round.owe(false);
    assert!(gate.takes_input(), "CONTROL: nothing owed");
}

/// A record the gate let through that holds its sender and finds no room is a defect: a debug
/// build stops there, and a release build counts it apart.
#[test]
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "a record the gate let through found no room")
)]
fn a_gated_record_that_finds_no_room_is_a_defect() {
    let round = round(1024, 4);
    let seen: Noted = Arc::default();
    let first = noting(1, &seen);
    // SAFETY (each call): this thread is the round's one writer.
    unsafe { round.offer_sample(1, Some(&first), &filled(4, 1)) };
    unsafe { round.seal() };
    #[cfg(debug_assertions)]
    round.offering_gated(true);
    let held = filled(4, 2)
        .with_reliability(Reliability::Reliable)
        .with_qos(QosLevel::from_raw(BLOCK));
    unsafe { round.offer_sample(1, Some(&first), &held) };
    assert_eq!(round.counts().held_over, 1);
}

/// While the round captures, an offer copies out its subscriber and the callback that subscriber's
/// row holds, in the order they came, and holds nothing; a row with no callback is passed over.
/// Once the capture is taken, what is offered is held again.
#[cfg(feature = "local-subscriber")]
#[test]
fn a_captured_offer_copies_the_rows_callback_and_holds_nothing() {
    use wz_capi_port::SubId;

    let round = round(1024, 4);
    let seen: Noted = Arc::default();
    let callback = noting(1, &seen);
    // SAFETY (each call): this thread is the round's one writer.
    unsafe { round.capture() };
    unsafe { round.offer_sample(3, Some(&callback), &filled(8, 1)) };
    unsafe { round.offer_sample(2, None, &filled(8, 1)) };
    unsafe { round.offer_sample(1, Some(&callback), &filled(8, 1)) };
    let captured = unsafe { round.captured() };
    let ids: Vec<SubId> = captured.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, [3, 1]);
    assert!(
        captured
            .iter()
            .all(|(_, held)| Arc::ptr_eq(held, &callback)),
        "each the callback its row holds"
    );
    unsafe { round.seal() };
    assert!(!round.deliver(), "nothing was held");
    unsafe { round.offer_sample(1, Some(&callback), &filled(8, 1)) };
    unsafe { round.seal() };
    assert!(round.deliver(), "CONTROL: once taken, an offer is held");
}

/// The changes a liveliness callback a test holds is handed: its tag, the key and the token.
#[cfg(feature = "liveliness")]
type Heard = Arc<Mutex<Vec<(u8, String, u64)>>>;

/// A liveliness subscriber's callback that notes each change it is handed with `tag`.
#[cfg(feature = "liveliness")]
fn hearing(tag: u8, heard: &Heard) -> crate::engine::LivelinessCallback {
    use wz_session_core::declare::liveliness_sample::LivelinessSample;
    let heard = heard.clone();
    Arc::new(crate::engine::LiveLiveliness::new(
        wz_capi_port::LivelinessSink::shared(move |sample: LivelinessSample<'_>| {
            heard
                .lock()
                .unwrap()
                .push((tag, sample.keyexpr.to_owned(), sample.token_id));
        }),
    ))
}

/// A token is one record however many liveliness subscribers it reaches, its key read where it
/// lies in the lent datagram or written into the round when it lies elsewhere, and each is handed
/// to its callbacks in the order it came.
#[cfg(feature = "liveliness")]
#[test]
fn the_tokens_of_a_round_are_handed_in_order() {
    use wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleKind};

    let round = round(1024, 4);
    let heard: Heard = Arc::default();
    let (first, second) = (hearing(1, &heard), hearing(2, &heard));
    let datagram = *b"demo/t/1";
    let lying = core::str::from_utf8(&datagram).expect("a key");
    let put = |keyexpr, token_id| LivelinessSample {
        kind: LivelinessSampleKind::Put,
        keyexpr,
        token_id,
    };
    // SAFETY (each call): this thread is the round's one writer, and the datagram outlives it.
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_liveliness(&first, &put(lying, 1)) };
    unsafe { round.offer_liveliness(&second, &put(lying, 1)) };
    unsafe { round.offer_liveliness(&first, &put("demo/t/2", 2)) };
    unsafe { round.set_lending(None) };
    unsafe { round.seal() };
    assert!(round.deliver());
    assert_eq!(
        *heard.lock().unwrap(),
        [
            (1, "demo/t/1".to_owned(), 1),
            (2, "demo/t/1".to_owned(), 1),
            (1, "demo/t/2".to_owned(), 2)
        ]
    );
    assert_eq!(round.counts(), RoundCounts::default());
}

/// What a leg's callback a test holds is handed: the request id, the key, the payload and where
/// the payload lies.
#[cfg(feature = "query")]
type Answers = Arc<Mutex<Vec<(u32, String, Vec<u8>, usize)>>>;

/// A leg's callback that notes each reply it is handed.
#[cfg(feature = "query")]
fn answering(answers: &Answers) -> Arc<wz_capi_port::ReplyCallback> {
    use wz_session_core::reply_sink::ReplyView;
    let answers = answers.clone();
    Arc::new(wz_capi_port::ReplyCallback::shared(
        move |reply: &dyn ReplyView| {
            answers.lock().unwrap().push((
                reply.rid(),
                reply.keyexpr().to_owned(),
                reply.payload().to_vec(),
                reply.payload().as_ptr() as usize,
            ));
        },
    ))
}

/// A reply whose parts lie in a datagram a link lends, its key resolved elsewhere.
#[cfg(feature = "query")]
struct Lying<'d> {
    payload: &'d [u8],
}

#[cfg(feature = "query")]
impl wz_session_core::reply_sink::ReplyView for Lying<'_> {
    fn rid(&self) -> wz_session_core::wire_id::RequestId {
        4
    }

    fn keyexpr(&self) -> &str {
        "demo/answer"
    }

    fn kind(&self) -> wz_session_core::reply_sink::ReplyKind {
        wz_session_core::reply_sink::ReplyKind::Put
    }

    fn payload(&self) -> &[u8] {
        self.payload
    }

    fn err_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
        None
    }
}

/// A reply of a datagram a link lends is handed to its leg's callback where its payload lies, and
/// one offered with no datagram lent is written into the round; the round is idle only once both
/// are handed, which is what a leg's end waits for.
#[cfg(feature = "query")]
#[test]
fn a_reply_is_handed_where_it_lies_or_from_the_round() {
    let round = round(1024, 4);
    let answers: Answers = Arc::default();
    let callback = answering(&answers);
    let datagram = *b"answer";
    // SAFETY (each call): this thread is the round's one writer, and the datagram outlives it.
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_reply(&callback, &Lying { payload: &datagram }) };
    unsafe { round.set_lending(None) };
    let elsewhere = b"elsewhere".to_vec();
    unsafe {
        round.offer_reply(
            &callback,
            &Lying {
                payload: &elsewhere,
            },
        )
    };
    assert!(!round.is_idle(), "a reply is held");
    unsafe { round.seal() };
    assert!(round.deliver());
    assert!(round.is_idle(), "handed out");
    let answers = answers.lock().unwrap();
    assert_eq!(answers.len(), 2);
    assert_eq!(
        (
            answers[0].0,
            answers[0].1.as_str(),
            answers[0].2.as_slice(),
            answers[0].3
        ),
        (4, "demo/answer", &b"answer"[..], datagram.as_ptr() as usize),
        "read where it lies"
    );
    assert_eq!(answers[1].2, b"elsewhere");
    assert_ne!(
        answers[1].3,
        elsewhere.as_ptr() as usize,
        "written into the round, not read where the view held it"
    );
}

/// The build's area holds the sample of the build's largest rejoined message on its longest key,
/// which is what lets a session's area be sized from its own message under the build's; an area
/// one byte short of a message's sample does not hold it.
#[test]
fn the_builds_area_holds_the_builds_largest_message() {
    use crate::round::{holds_a_read, read_bytes, sample_overhead};

    assert!(holds_a_read::<
        { caps::DELIVERY_LANE_BYTES },
        { caps::PICO_UNICAST_BATCH_BYTES },
        { caps::PICO_FRAG_MAX_BYTES },
        { caps::MAX_KEYEXPR_BYTES },
        { caps::MAX_SUBSCRIPTIONS },
        { caps::MAX_LIVELINESS_SUBSCRIPTIONS },
    >());
    assert_eq!(
        read_bytes(1000, 500, 8, 2),
        1000 + 32,
        "a batch longer than a message"
    );
    assert_eq!(
        read_bytes(500, 1000, 8, 2),
        1000 + 32,
        "a message longer than a batch"
    );
    assert!(holds_a_read::<{ 1000 + 32 }, 1000, 500, 8, 2, 0>());
    assert!(!holds_a_read::<{ 1000 + 31 }, 1000, 500, 8, 2, 0>());
    assert_eq!(
        sample_overhead(8, 2),
        32,
        "a key of 8, a clock id of 16 and two subscribers' shares of 4"
    );
}

/// The speed image's area (`deploy/zephyr-mcu-speed/arm_w.conf`) is the room of one record at the
/// limits that image states: its batch of 2,048 bytes, its largest rejoined message of 4,096, its
/// keys of 64 bytes and one subscriber, 4,180 bytes; an area one byte shorter holds no read.
#[test]
fn the_speed_images_area_is_the_room_of_one_record() {
    use crate::round::{holds_a_read, read_bytes};

    assert_eq!(read_bytes(2048, 4096, 64, 1), 4180);
    assert!(holds_a_read::<4180, 2048, 4096, 64, 1, 1>());
    assert!(!holds_a_read::<4179, 2048, 4096, 64, 1, 1>());
}

/// An area stated shorter than what one record can hand it is lengthened to hold it, from the
/// session's own (lowered) message length and batch and not the build's, the larger of the two;
/// an area stated longer is kept.
#[test]
fn an_area_is_sized_from_the_sessions_message() {
    use crate::round::{holding_a_read, sample_overhead};

    let frag = caps::PICO_FRAG_MAX_BYTES / 4;
    let short = lowered(|l| {
        l.select_delivery_lane_bytes(1)?;
        l.select_pico_frag_max_bytes(Quota::at_most(frag))
    });
    let held = holding_a_read::<
        { caps::PICO_UNICAST_BATCH_BYTES },
        { caps::PICO_FRAG_MAX_BYTES },
        { caps::MAX_KEYEXPR_BYTES },
        { caps::MAX_SUBSCRIPTIONS },
        { caps::MAX_LIVELINESS_SUBSCRIPTIONS },
    >(short);
    let subscribers = if cfg!(feature = "liveliness") {
        caps::MAX_SUBSCRIPTIONS.max(caps::MAX_LIVELINESS_SUBSCRIPTIONS)
    } else {
        caps::MAX_SUBSCRIPTIONS
    };
    assert_eq!(
        held.delivery_lane_bytes(),
        frag.max(short.pico_unicast_batch_bytes())
            + sample_overhead(caps::MAX_KEYEXPR_BYTES, subscribers)
    );

    let long = SessionLimits::defaults();
    let kept = holding_a_read::<
        { caps::PICO_UNICAST_BATCH_BYTES },
        { caps::PICO_FRAG_MAX_BYTES },
        { caps::MAX_KEYEXPR_BYTES },
        { caps::MAX_SUBSCRIPTIONS },
        { caps::MAX_LIVELINESS_SUBSCRIPTIONS },
    >(long);
    assert_eq!(kept.delivery_lane_bytes(), long.delivery_lane_bytes());
}
