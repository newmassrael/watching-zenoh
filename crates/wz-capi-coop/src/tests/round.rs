// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session's round of deliveries: a record is handed to its callbacks as it was offered, read
//! where it lies in a lent datagram, a rejoined message or the session's key arena, a key that
//! lies nowhere else copied into the round's keys; a record with a part that lies nowhere the
//! round reads it is refused and counted; a sealed round refuses and counts by the record's
//! congestion control; the gate reads a link only while the round has the room of a record and no
//! record lies in the datagram the link lent.

use alloc::rc::Rc;
use alloc::sync::Arc;
use core::cell::Cell;
use std::sync::Mutex;

use wz_capi_port::{SubscriberSink, WireKey};
use wz_session_core::byte_cells::{ByteCells, ByteSource, KeptBytes};
use wz_session_core::caps;
use wz_session_core::key_arena::{KeyRef, KeySpace};
use wz_session_core::limits::SessionLimits;
use wz_session_core::placed::{Placed, PlacedRef};
use wz_session_core::reliability::Reliability;
use wz_session_core::row_callback::RowCallback;
use wz_session_core::sample::{QosLevel, Sample, SampleKind, SourceInfo};
use wz_session_core::sink::{BorrowedSample, SampleView};

use crate::engine::{SubscriberCall, SubscriberRow};
use crate::round::{ReadRoom, Round, RoundCounts, RoundGate};
#[cfg(feature = "query")]
use {
    crate::engine::LegId,
    core::sync::atomic::{AtomicUsize, Ordering},
};

/// The QoS byte of a sample sent at the data priority whose congestion control holds its sender.
const BLOCK: u8 = 0x05 | 0x08;

/// A handle of a round holding `events` records at once, whose owner outlives the test.
fn round(events: usize) -> PlacedRef<Round> {
    crate::round::leaked(events)
}

/// A subscriber row a test hands samples to, boxed so it lies where it is while a call of it runs.
struct Row {
    row: Box<SubscriberRow>,
}

impl Row {
    /// A row handing what it hears to `sink`, the timestamp shown.
    fn new(sink: SubscriberSink) -> Self {
        Self::exposing(sink, true)
    }

    /// A row handing what it hears to `sink`, the timestamp shown when `expose`.
    fn exposing(sink: SubscriberSink, expose: bool) -> Self {
        Self {
            row: Box::new(SubscriberRow::new(
                WireKey::literal().into_anchor(),
                sink,
                expose,
            )),
        }
    }

    /// A call of its callback, begun as the session's dispatch begins one.
    fn call(&self) -> SubscriberCall {
        SubscriberCall::new(self.row.begin().expect("a live row begins a call"))
    }

    /// Undeclare it: whether no call of it runs.
    fn retire(&self) -> bool {
        self.row.retire()
    }

    /// Whether it is undeclared and no call of it runs: the mark the session's walk of its tables
    /// lets it go by.
    fn drained(&self) -> bool {
        self.row.drained()
    }
}

/// The room of a record for one subscriber.
const ONE: ReadRoom = ReadRoom { callbacks: 1 };

/// A best-effort put of `len` bytes of `byte` on `demo/round`, its payload lying nowhere a round
/// reads it: what is offered to a round that refuses it before placing a part (sealed).
fn filled(len: usize, byte: u8) -> Sample {
    Sample::new_put("demo/round", vec![byte; len]).with_reliability(Reliability::BestEffort)
}

/// A best-effort put of `payload` on `keyexpr`, borrowed where it lies, as a sample read in place
/// is.
fn put<'a>(keyexpr: &'a str, payload: &'a [u8]) -> BorrowedSample<'a> {
    BorrowedSample {
        keyexpr,
        payload,
        kind: SampleKind::Put,
        reliability: Reliability::BestEffort,
    }
}

/// A best-effort put on `demo/round` whose payload is borrowed where it lies.
fn borrowed(payload: &[u8]) -> BorrowedSample<'_> {
    put("demo/round", payload)
}

/// A link that has nothing to give: what a gate over it holds back is the gate's alone.
struct Quiet;

impl wz_runtime_coop::session_drive::SessionDatagramLink for Quiet {
    fn service(&self) {}

    fn try_recv(&self) -> Option<wz_session_core::link::RxFrame> {
        None
    }
}

/// A link with nothing to give that counts how often it is asked to receive.
struct Counting(Rc<Cell<usize>>);

impl wz_runtime_coop::session_drive::SessionDatagramLink for Counting {
    fn service(&self) {}

    fn try_recv(&self) -> Option<wz_session_core::link::RxFrame> {
        self.0.set(self.0.get() + 1);
        None
    }
}

/// What [`noting`] callbacks write: the tag, the payload's first byte and where it lies.
type Noted = Arc<Mutex<Vec<(u8, u8, usize)>>>;

/// A callback the tests count the samples of: each is noted with `tag`, its payload's first byte
/// and where its payload lies.
fn noting(tag: u8, seen: &Noted) -> Row {
    let seen = seen.clone();
    Row::new(SubscriberSink::shared(move |sample: &dyn SampleView| {
        let payload = sample.payload();
        seen.lock().unwrap().push((
            tag,
            payload.first().copied().unwrap_or(0),
            payload.as_ptr() as usize,
        ));
    }))
}

/// A put whose payload, attachment, encoding schema and timestamp id lie in `datagram` (its
/// first 7, 3, 4 and 3 bytes), at the data priority, with `source` beside it.
struct Whole<'d> {
    datagram: &'d [u8],
    source: &'d SourceInfo,
}

impl SampleView for Whole<'_> {
    fn keyexpr(&self) -> &str {
        "demo/a"
    }

    fn payload(&self) -> &[u8] {
        &self.datagram[..7]
    }

    fn kind(&self) -> SampleKind {
        SampleKind::Put
    }

    fn reliability(&self) -> Reliability {
        Reliability::BestEffort
    }

    fn qos(&self) -> Option<QosLevel> {
        Some(QosLevel::from_raw(5))
    }

    fn attachment(&self) -> Option<&[u8]> {
        Some(&self.datagram[7..10])
    }

    fn source_info(&self) -> Option<&SourceInfo> {
        Some(self.source)
    }

    fn timestamp_parts(&self) -> Option<(u64, &[u8])> {
        Some((42, &self.datagram[14..17]))
    }

    fn encoding_parts(&self) -> Option<(u32, Option<&[u8]>)> {
        Some((7, Some(&self.datagram[10..14])))
    }
}

/// A sample with every part, each lying in the datagram a link lends, is handed to its subscriber
/// with every part as it was offered, its payload read where it lies; the round is empty once it
/// is handed, answering no owned hint. Turned red by a part the round drops or reads anywhere but
/// where it lies, or by a hint it answers.
#[test]
fn a_lent_sample_is_handed_with_every_part_where_it_lies() {
    type Seen = (
        String,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<(u32, Option<Vec<u8>>)>,
        usize,
    );
    let round = round(4);
    let source = SourceInfo::new(&[9, 9], 3, 4);
    let datagram = *b"payloadatttext\x01\x02\x03";
    let sample = Whole {
        datagram: &datagram,
        source: &source,
    };
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let rest: Arc<Mutex<Vec<String>>> = Arc::default();
    let callback = {
        let (seen, rest, source) = (seen.clone(), rest.clone(), source.clone());
        Row::new(SubscriberSink::shared(move |view: &dyn SampleView| {
            seen.lock().unwrap().push((
                view.keyexpr().to_owned(),
                view.payload().to_vec(),
                view.attachment().map(<[u8]>::to_vec),
                view.encoding_parts()
                    .map(|(id, schema)| (id, schema.map(<[u8]>::to_vec))),
                view.payload().as_ptr() as usize,
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
            // Nothing is built on the heap for a record of the round: it answers no owned hint.
            if view.timestamp().is_some() || view.encoding().is_some() {
                rest.push("a hint".to_owned());
            }
        }))
    };
    // SAFETY (each call): this thread is the round's one writer, as a session's step is, and the
    // datagram outlives the round's record of it.
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_sample(callback.call(), &sample, true) };
    unsafe { round.set_lending(None) };
    unsafe { round.seal() };
    assert!(round.deliver(), "the sealed round is handed out");
    assert_eq!(
        *seen.lock().unwrap(),
        [(
            "demo/a".to_owned(),
            b"payload".to_vec(),
            Some(b"att".to_vec()),
            Some((7, Some(b"text".to_vec()))),
            datagram.as_ptr() as usize
        )]
    );
    assert_eq!(
        *rest.lock().unwrap(),
        Vec::<String>::new(),
        "every part as offered"
    );
    assert!(!round.deliver(), "nothing is left");
    assert_eq!(round.counts(), RoundCounts::default());
    assert_eq!(round.tally().lent(), 1, "read where it lies");
}

/// A subscriber that does not see timestamps is handed the round's sample with no timestamp, as
/// parts or as a hint, and every other part as it was offered; one that sees them, offered the same
/// record, is handed the timestamp. Turned red by a row that shows a timestamp it was declared not
/// to see, or hides another part with it.
#[test]
fn a_row_that_sees_no_timestamp_is_handed_every_other_part() {
    type Seen = (bool, Option<Vec<u8>>, Option<(u32, Option<Vec<u8>>)>, bool);
    let round = round(4);
    let source = SourceInfo::new(&[9, 9], 3, 4);
    let datagram = *b"payloadatttext\x01\x02\x03";
    let sample = Whole {
        datagram: &datagram,
        source: &source,
    };
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let row = |expose| {
        let seen = seen.clone();
        Row::exposing(
            SubscriberSink::shared(move |view: &dyn SampleView| {
                seen.lock().unwrap().push((
                    view.timestamp_parts().is_some() || view.timestamp().is_some(),
                    view.attachment().map(<[u8]>::to_vec),
                    view.encoding_parts()
                        .map(|(id, schema)| (id, schema.map(<[u8]>::to_vec))),
                    view.source_info().is_some(),
                ));
            }),
            expose,
        )
    };
    let (shown, hidden) = (row(true), row(false));
    // SAFETY (each call): this thread is the round's one writer, as a session's step is, and the
    // datagram outlives the round's record of it.
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_sample(shown.call(), &sample, true) };
    unsafe { round.offer_sample(hidden.call(), &sample, false) };
    unsafe { round.set_lending(None) };
    unsafe { round.seal() };
    assert!(round.deliver(), "the sealed round is handed out");
    let (attachment, encoding) = (Some(b"att".to_vec()), Some((7u32, Some(b"text".to_vec()))));
    assert_eq!(
        *seen.lock().unwrap(),
        [
            (true, attachment.clone(), encoding.clone(), true),
            (false, attachment, encoding, true)
        ]
    );
}

/// A subscriber that does not see timestamps is handed a sample carrying none as it lies, with no
/// copy made of it, and one carrying a timestamp as a copy without it. Turned red by a row that
/// copies every sample it hides timestamps from, or hands on a timestamp it was declared not to see.
#[test]
fn a_row_that_sees_no_timestamp_hands_a_sample_without_one_as_it_lies() {
    use wz_session_core::sink::SampleRef;

    /// Notes where the sample handed lay and whether it carried a timestamp.
    unsafe fn note(context: *mut core::ffi::c_void, sample: &SampleRef<'_>) {
        // SAFETY: the context is the test's cell, which stands while the row does.
        let noted = unsafe { &*context.cast::<Cell<(usize, bool)>>() };
        noted.set((
            core::ptr::from_ref(sample) as usize,
            sample.timestamp.is_some(),
        ));
    }
    let noted = Cell::new((0usize, false));
    // SAFETY: `note` reads its context alone, on this thread, while `noted` stands; nothing drops
    // the context.
    let sink =
        unsafe { SubscriberSink::raw(note, core::ptr::from_ref(&noted).cast_mut().cast(), None) };
    let row = Row::exposing(sink, false);
    let zid = [7u8; 16];
    let bare = SampleRef::new("demo/round", b"p", SampleKind::Put, Reliability::BestEffort);
    let mut stamped = SampleRef::new("demo/round", b"p", SampleKind::Put, Reliability::BestEffort);
    stamped.timestamp = Some((1, &zid[..]));
    let call = row.call();
    call.hand(&bare);
    assert_eq!(
        noted.get(),
        (core::ptr::from_ref(&bare) as usize, false),
        "a sample with no timestamp is handed as it lies"
    );
    call.hand(&stamped);
    let (at, shown) = noted.get();
    assert!(
        at != core::ptr::from_ref(&stamped) as usize && !shown,
        "CONTROL: a timestamp is hidden in a copy"
    );
    assert!(!call.end(), "the row is not undeclared");
}

/// The samples of a datagram a link lends are read where they lie: one record for a sample
/// however many subscribers it reaches, the link held back from the next datagram until they are
/// handed out, and each handed to its callbacks in the order it came.
#[test]
fn the_samples_of_a_lent_datagram_are_handed_where_they_lie() {
    use wz_runtime_coop::session_drive::SessionDatagramLink;

    let round = round(4);
    // SAFETY (every call on the round and the gate here): this thread is the round's one writer,
    // as a session's step is under its lock, and the datagram outlives every use below.
    let gate = unsafe { RoundGate::new(Quiet, round, ONE) };
    let seen: Noted = Arc::default();
    let (first, second) = (noting(1, &seen), noting(2, &seen));
    let datagram = [1u8, 1, 2, 2];
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_sample(first.call(), &borrowed(&datagram[..2]), true) };
    unsafe { round.offer_sample(second.call(), &borrowed(&datagram[..2]), false) };
    unsafe { round.offer_sample(first.call(), &borrowed(&datagram[2..]), true) };
    assert_eq!(
        gate.takes_input(),
        <crate::round::CoopForm as wz_session_core::row_callback::ThreadForm>::OTHER_THREADS,
        "a round of threads takes the datagram's next record; one of one thread hands these out first"
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
            round.tally().rounds(),
            round.tally().samples(),
            round.tally().lent()
        ),
        (1, 2, 2),
        "one round of two samples, both read where they lie"
    );
}

/// A rejoined message kept in a buffer of `cells`: its first `len` bytes, each `byte`.
fn kept_in(cells: &'static ByteCells<8, 2>, byte: u8, len: usize) -> KeptBytes {
    let mut buf = cells.claim().expect("a free buffer");
    buf.as_mut_slice().fill(byte);
    KeptBytes::of(buf, len)
}

/// A rejoined message's records are read where its chain's buffer lies, beside a datagram's read
/// where it lies, each in its own place, and the round keeps the buffer while it reads it: past
/// the delivery that empties the table, until the lock holder lets go of it, which the gate does
/// before a link is read. Turned red by a round that copies the message's record, gives the buffer
/// back while the table reads it, or keeps it once the table is emptied and a link is read.
#[test]
fn a_rejoined_message_is_read_where_its_kept_buffer_lies() {
    use wz_runtime_coop::session_drive::SessionDatagramLink;

    static CHAINS: ByteCells<8, 2> = ByteCells::new();
    let round = round(4);
    let gate = unsafe { RoundGate::new(Quiet, round, ONE) };
    let seen: Noted = Arc::default();
    let first = noting(1, &seen);
    let datagram = [1u8, 1];
    let kept = kept_in(&CHAINS, 2, 2);
    let chain = kept.as_slice().as_ptr() as usize;
    // SAFETY (each call): this thread is the round's one writer, and the datagram outlives it.
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.lend_rejoined(&kept) };
    unsafe { round.offer_sample(first.call(), &borrowed(kept.as_slice()), true) };
    unsafe { round.end_rejoined(kept) };
    unsafe { round.offer_sample(first.call(), &borrowed(&datagram[..]), true) };
    unsafe { round.set_lending(None) };
    assert!(round.lends_a_datagram(), "the chain is held where it lies");
    unsafe { round.settle() };
    assert_eq!(
        CHAINS.in_use(),
        1,
        "CONTROL: the table reads the message, so its buffer is kept"
    );
    unsafe { round.seal() };
    assert!(round.deliver());
    assert_eq!(
        *seen.lock().unwrap(),
        [(1, 2, chain), (1, 1, datagram.as_ptr() as usize)],
        "each read where it lies, in the order offered"
    );
    assert_eq!(round.tally().lent(), 2);
    assert_eq!(
        CHAINS.in_use(),
        1,
        "emptied with no lock held, the buffer waits for the lock holder"
    );
    assert!(gate.try_recv().is_none(), "the quiet link gives nothing");
    assert_eq!(
        CHAINS.in_use(),
        0,
        "the gate let go of the buffer before it read the link"
    );
}

/// A rejoined message whose records the table does not read is given back as its offer ends, and
/// a second one in the same round, while the table reads the first, finds no place: its record is
/// refused and counted and its buffer given back, so the round keeps one buffer at most, the one
/// its table reads. Turned red by a round that keeps a buffer it reads nothing in, reads a second
/// one, or lets go of the first while the table still reads it.
#[test]
fn a_round_keeps_only_the_rejoined_buffer_its_table_reads() {
    static CHAINS: ByteCells<8, 2> = ByteCells::new();
    let round = round(4);
    let seen: Noted = Arc::default();
    let first = noting(1, &seen);
    let unread = kept_in(&CHAINS, 3, 2);
    // SAFETY (each call): this thread is the round's one writer.
    unsafe { round.lend_rejoined(&unread) };
    unsafe { round.end_rejoined(unread) };
    assert_eq!(
        CHAINS.in_use(),
        0,
        "nothing read in it, it went back at once"
    );
    let one = kept_in(&CHAINS, 4, 2);
    let two = kept_in(&CHAINS, 5, 2);
    let at_one = one.as_slice().as_ptr() as usize;
    unsafe { round.lend_rejoined(&one) };
    unsafe { round.offer_sample(first.call(), &borrowed(one.as_slice()), true) };
    unsafe { round.end_rejoined(one) };
    unsafe { round.lend_rejoined(&two) };
    unsafe { round.offer_sample(first.call(), &borrowed(two.as_slice()), true) };
    unsafe { round.end_rejoined(two) };
    assert_eq!(
        CHAINS.in_use(),
        1,
        "the second, unread, went back; the first is kept"
    );
    assert_eq!(
        round.counts(),
        RoundCounts {
            dropped: 1,
            held_over: 0,
            unplaced: 1,
        },
        "the second's record found no place"
    );
    unsafe { round.seal() };
    assert!(round.deliver());
    assert_eq!(
        *seen.lock().unwrap(),
        [(1, 4, at_one)],
        "the first alone, read where it lies"
    );
    assert_eq!(round.tally().lent(), 1);
    unsafe { round.settle() };
    assert_eq!(
        CHAINS.in_use(),
        0,
        "emptied, the lock holder let go of the first"
    );
}

/// A group's receive buffer given back while a record of the round reads a datagram in it is
/// kept, the round sealed and handed out meanwhile, and goes back to its table once the lock
/// holder settles the round after the delivery; one in which no record reads goes back at once.
/// Turned red by a round that lets go of the buffer a delivery reads, or keeps one it reads
/// nothing in.
#[cfg(feature = "group")]
#[test]
fn a_given_back_group_buffer_is_kept_while_a_record_reads_in_it() {
    static RX: ByteCells<16, 2> = ByteCells::new();
    let round = round(4);
    let seen: Noted = Arc::default();
    let first = noting(1, &seen);
    let mut buf = RX.claim().expect("a group's buffer");
    buf.as_mut_slice()[..2].copy_from_slice(&[7, 7]);
    let (base, _) = buf.raw();
    // SAFETY: the first two bytes of the buffer, which the claim holds until it is given back and
    // the round, which keeps it, lets go of it after the delivery read them.
    let datagram = unsafe { core::slice::from_raw_parts(base.cast_const(), 2) };
    // SAFETY (each call): this thread is the round's one writer, as a session's step is.
    unsafe { round.set_lending(Some(datagram)) };
    unsafe { round.offer_sample(first.call(), &borrowed(datagram), true) };
    unsafe { round.set_lending(None) };
    unsafe { round.seal() };
    unsafe { round.keep_rx(buf) };
    assert_eq!(RX.in_use(), 1, "a sealed record reads in it, so it is kept");
    let other = RX.claim().expect("the other buffer");
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
    unsafe { round.settle() };
    assert_eq!(RX.in_use(), 0, "settled, the buffer is its table's again");
}

/// A key arena of 256 bytes the test leaks, so it outlives every key and round of the test.
fn key_space() -> KeySpace {
    use crate::arena::{AllocatorMemory, SessionArena};

    let bytes = KeySpace::span_bytes(256).expect("a small arena");
    let arena: &'static mut SessionArena = Box::leak(Box::new(
        SessionArena::of_bytes(bytes, &AllocatorMemory).expect("the host has the memory"),
    ));
    arena
        .arena_mut()
        .lend_keys(256, SessionLimits::defaults().max_keyexpr_bytes_held())
        .expect("the arena holds the key arena")
}

/// The owner of a round as `round` makes one, that reads the keys of `keys` where their blocks
/// lie.
fn round_reading(keys: KeySpace) -> &'static mut Placed<Round> {
    let round = crate::round::leaked_placed(4);
    round.get_mut().reads_keys_in(keys);
    round
}

/// A put of no payload whose keyexpr is the whole text of `key`, as a peer's alias read where its
/// row keeps it is.
struct HeldSample<'k> {
    key: &'k KeyRef,
}

impl SampleView for HeldSample<'_> {
    fn keyexpr(&self) -> &str {
        self.key.as_str()
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

    fn keyexpr_held(&self) -> Option<&KeyRef> {
        Some(self.key)
    }
}

/// What [`keyed`] callbacks write: each sample's keyexpr and where it lies.
type Keyed = Arc<Mutex<Vec<(String, usize)>>>;

/// A callback that notes the keyexpr of each sample it is handed and where it lies.
fn keyed(seen: &Keyed) -> Row {
    let seen = seen.clone();
    Row::new(SubscriberSink::shared(move |sample: &dyn SampleView| {
        let key = sample.keyexpr();
        seen.lock()
            .unwrap()
            .push((key.to_owned(), key.as_ptr() as usize));
    }))
}

/// A key a sample names by a row of the session's key arena is read where the row's block lies,
/// after the row let go of it (the alias undeclared while the record waited): the round holds the
/// block, one count for the records that read it in turn, until the lock holder settles the
/// round after the delivery. Turned red by a round that copies the key, takes a count for each
/// record or none, or hands the count back with no lock held.
#[test]
fn a_held_key_is_read_where_its_block_lies_after_its_row_lets_go() {
    let keys = key_space();
    let round = round_reading(keys);
    let seen: Keyed = Arc::default();
    let first = keyed(&seen);
    let row = keys.key("demo/alias").expect("room");
    let at = row.as_str().as_ptr() as usize;
    // SAFETY (each call): this thread is the round's one writer, as a session's step is.
    unsafe { round.offer_sample(first.call(), &HeldSample { key: &row }, true) };
    unsafe { round.offer_sample(first.call(), &HeldSample { key: &row }, true) };
    drop(row);
    assert!(
        keys.counts().used > 0,
        "the round holds the block its row let go of"
    );
    unsafe { round.seal() };
    assert!(round.deliver());
    assert_eq!(
        *seen.lock().unwrap(),
        [("demo/alias".to_owned(), at), ("demo/alias".to_owned(), at)],
        "each record read where the block lies"
    );
    assert!(
        keys.counts().used > 0,
        "handed out with no lock held, the block waits for the lock holder"
    );
    unsafe { round.settle() };
    assert_eq!(
        keys.counts().used,
        0,
        "one count for both records, handed back once"
    );
}

/// The row a held key was read from given another key, as a face's rows are when the face goes
/// and the next one takes them: the record still reads the first key where its block lies, and the
/// new key takes another block. Turned red by a block given back while the round holds it.
#[test]
fn a_row_given_a_new_key_does_not_move_a_held_one() {
    let keys = key_space();
    let round = round_reading(keys);
    let seen: Keyed = Arc::default();
    let first = keyed(&seen);
    let mut row = keys.key("demo/a").expect("room");
    let at_a = row.as_str().as_ptr() as usize;
    // SAFETY (each call): this thread is the round's one writer.
    unsafe { round.offer_sample(first.call(), &HeldSample { key: &row }, true) };
    row = keys.key("demo/b").expect("room");
    let at_b = row.as_str().as_ptr() as usize;
    assert_ne!(at_a, at_b, "the held block is not given to the new key");
    unsafe { round.offer_sample(first.call(), &HeldSample { key: &row }, true) };
    drop(row);
    unsafe { round.seal() };
    assert!(round.deliver());
    assert_eq!(
        *seen.lock().unwrap(),
        [("demo/a".to_owned(), at_a), ("demo/b".to_owned(), at_b)]
    );
    unsafe { round.settle() };
    assert_eq!(keys.counts().used, 0, "both blocks back once settled");
}

/// The CONTROL of the two above: a round that reads no key arena copies the key into its keys, so
/// the block goes back as soon as its row lets go of it, before the delivery, which reads the copy.
#[test]
fn a_round_that_reads_no_key_arena_copies_the_key() {
    let keys = key_space();
    let round = round(4);
    let seen: Keyed = Arc::default();
    let first = keyed(&seen);
    let row = keys.key("demo/alias").expect("room");
    let at = row.as_str().as_ptr() as usize;
    // SAFETY (each call): this thread is the round's one writer.
    unsafe { round.offer_sample(first.call(), &HeldSample { key: &row }, true) };
    drop(row);
    assert_eq!(
        keys.counts().used,
        0,
        "nothing holds the block once its row lets go"
    );
    unsafe { round.seal() };
    assert!(round.deliver());
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "demo/alias", "the copy reads the key");
    assert_ne!(seen[0].1, at, "read from the round's copy");
}

/// A round let go of at its session's end ends the calls its records owe, before the arena that
/// lent its tables, and hands nothing after: a row undeclared while its call waited is the round's
/// to let go of then, and one still declared has no call running. The CONTROL is the retirement
/// while the record waits, which finds the call running.
#[test]
fn a_round_let_go_of_ends_the_calls_its_records_owe() {
    let round = round(4);
    let seen: Noted = Arc::default();
    let (first, second) = (noting(1, &seen), noting(2, &seen));
    let datagram = [1u8, 1, 2, 2];
    // SAFETY (each call): this thread is the round's one writer, no delivery runs, and the
    // datagram outlives the round's records of it.
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_sample(first.call(), &borrowed(&datagram[..2]), true) };
    unsafe { round.offer_sample(second.call(), &borrowed(&datagram[2..]), true) };
    unsafe { round.set_lending(None) };
    unsafe { round.seal() };
    assert!(!first.retire(), "CONTROL: the waiting record owes a call");
    unsafe { round.let_go() };
    assert!(
        round.take_marked(),
        "the undeclared row's last call ended with the round's tables"
    );
    assert!(first.drained(), "and its latch is the mark a walk reads");
    assert!(!round.take_marked(), "asking clears the mark");
    assert!(second.retire(), "the declared row's call ended too");
    assert!(!round.deliver(), "nothing is left to hand");
    assert!(seen.lock().unwrap().is_empty(), "and nothing was handed");
}

/// A round is handed to one delivery at a time: a delivery asked for from inside a callback of
/// the one running hands nothing, and each record is handed once, its call ended. The CONTROL is
/// the delivery after it, which finds the round emptied.
#[test]
fn a_round_is_handed_to_one_delivery_at_a_time() {
    let round = round(4);
    let inner: Arc<Mutex<Vec<bool>>> = Arc::default();
    let again = round;
    let noted = inner.clone();
    let callback = Row::new(SubscriberSink::shared(move |_: &dyn SampleView| {
        let handed = again.deliver();
        noted.lock().unwrap().push(handed);
    }));
    let datagram = [1u8, 1, 2, 2];
    // SAFETY (each call): this thread is the round's one writer, no delivery runs, and the
    // datagram outlives the round's records of it.
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_sample(callback.call(), &borrowed(&datagram[..2]), true) };
    unsafe { round.offer_sample(callback.call(), &borrowed(&datagram[2..]), true) };
    unsafe { round.set_lending(None) };
    unsafe { round.seal() };
    assert!(round.deliver(), "the sealed round is handed out");
    assert_eq!(
        *inner.lock().unwrap(),
        [false, false],
        "each record handed once, and no delivery inside the one running"
    );
    assert!(!round.deliver(), "CONTROL: the round was emptied");
    assert!(callback.retire(), "every call of the row ended");
}

/// A row undeclared while a record owes it a call is handed nothing when the round is handed out,
/// and the delivery's end of that call, its last, leaves the row for the session to let go of. The
/// CONTROL is a row still declared, handed the same record.
#[test]
fn a_row_undeclared_while_its_call_waits_is_handed_nothing_and_let_go_after() {
    let round = round(4);
    let seen: Noted = Arc::default();
    let (gone, kept) = (noting(1, &seen), noting(2, &seen));
    let datagram = [9u8; 4];
    let sample = borrowed(&datagram);
    // SAFETY (each call): this thread is the round's one writer, no delivery runs, and the
    // datagram outlives the round's record of it.
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_sample(gone.call(), &sample, true) };
    unsafe { round.offer_sample(kept.call(), &sample, false) };
    unsafe { round.set_lending(None) };
    unsafe { round.seal() };
    assert!(!gone.retire(), "a call of it waits");
    assert!(!round.take_marked(), "not before the call ends");
    assert!(!gone.drained());
    assert!(round.deliver());
    let tags: Vec<u8> = seen.lock().unwrap().iter().map(|(t, _, _)| *t).collect();
    assert_eq!(tags, [2], "CONTROL: the declared row alone is handed it");
    assert!(round.take_marked(), "the delivery ended its last call");
    assert!(gone.drained());
    assert!(!kept.drained(), "the declared row is no walk's to take");
    assert!(!round.take_marked());
}

/// A row the session took out of its tables is a drop under way until what the round handed for
/// it is dropped, which an undeclaration that waits for its row reads; each drop is counted on its
/// own. The CONTROL is the round before any was taken.
#[test]
fn a_rows_drop_is_under_way_until_its_count_is_given_back() {
    let round = round(4);
    assert!(round.released_settled(), "CONTROL: no drop under way");
    let (one, two) = (round.releasing(), round.releasing());
    assert!(!round.released_settled());
    drop(one);
    assert!(
        !round.released_settled(),
        "the other drop is still under way"
    );
    drop(two);
    assert!(round.released_settled());
}

/// A call the round refuses (sealed, or no room) is ended at once, so the row it was begun on is
/// not kept waiting for a call that never runs. The CONTROL is a call the round holds, which keeps
/// the row's latch until it is handed out.
#[test]
fn a_refused_call_is_ended_at_once() {
    let round = round(4);
    let seen: Noted = Arc::default();
    let (held, refused) = (noting(1, &seen), noting(2, &seen));
    let datagram = [1u8; 4];
    // SAFETY (each call): this thread is the round's one writer, no delivery runs, and the
    // datagram outlives the round's record of it.
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_sample(held.call(), &borrowed(&datagram), true) };
    unsafe { round.set_lending(None) };
    unsafe { round.seal() };
    unsafe { round.offer_sample(refused.call(), &filled(4, 2), true) };
    assert_eq!(round.counts().dropped, 1);
    assert!(refused.retire(), "the refused call ended");
    assert!(!round.take_marked(), "and let nothing wait");
    assert!(!held.retire(), "CONTROL: the held call still runs");
}

/// A sample offered again to a subscriber it is for already, in a fan-out of its own (a message
/// that came twice), is a record of its own, handed to that subscriber twice.
#[test]
fn a_sample_offered_again_to_its_subscriber_is_a_record_of_its_own() {
    let round = round(4);
    let seen: Noted = Arc::default();
    let first = noting(1, &seen);
    let datagram = [3u8; 4];
    let sample = borrowed(&datagram);
    // SAFETY (each call): this thread is the round's one writer, and the datagram outlives the
    // round's records of it.
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_sample(first.call(), &sample, true) };
    unsafe { round.offer_sample(first.call(), &sample, true) };
    unsafe { round.set_lending(None) };
    unsafe { round.seal() };
    assert!(round.deliver());
    let tags: Vec<(u8, u8)> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|(t, b, _)| (*t, *b))
        .collect();
    assert_eq!(tags, [(1, 3), (1, 3)]);
    assert_eq!(round.tally().samples(), 2, "two records");
}

/// A record is joined only by the later rows of its own fan-out: a sample of the same bytes in a
/// fan-out of its own is a record of its own, whichever row it reaches. The CONTROL is the second
/// row of one fan-out, which joins the first's record.
#[test]
fn a_record_is_joined_only_by_the_rows_of_its_own_fan_out() {
    let round = round(4);
    let seen: Noted = Arc::default();
    let (first, second, third) = (noting(1, &seen), noting(2, &seen), noting(3, &seen));
    let datagram = [7u8; 4];
    let sample = borrowed(&datagram);
    // SAFETY (each call): this thread is the round's one writer, and the datagram outlives the
    // round's records of it.
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_sample(first.call(), &sample, true) };
    unsafe { round.offer_sample(second.call(), &sample, false) };
    unsafe { round.offer_sample(third.call(), &sample, true) };
    unsafe { round.set_lending(None) };
    unsafe { round.seal() };
    assert!(round.deliver());
    let tags: Vec<u8> = seen.lock().unwrap().iter().map(|(t, _, _)| *t).collect();
    assert_eq!(tags, [1, 2, 3], "every row is handed the sample, in order");
    assert_eq!(
        round.tally().samples(),
        2,
        "CONTROL: the second row joined the first's record; the third fan-out wrote its own"
    );
}

/// A sealed round refuses what is offered until it is handed out, and counts it by its congestion
/// control: apart when it holds its sender (reliable, `block`), and as a drop otherwise, a
/// reliable sample with no QoS having zenoh's default, `drop`.
#[test]
fn a_sealed_round_refuses_and_counts_by_congestion_control() {
    let round = round(4);
    let seen: Noted = Arc::default();
    let first = noting(1, &seen);
    let datagram = [1u8, 1, 5, 5];
    // SAFETY (each call): this thread is the round's one writer, and the datagram outlives the
    // round's records of it.
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_sample(first.call(), &borrowed(&datagram[..2]), true) };
    unsafe { round.set_lending(None) };
    unsafe { round.seal() };
    unsafe { round.offer_sample(first.call(), &filled(4, 2), true) };
    let held = filled(4, 3)
        .with_reliability(Reliability::Reliable)
        .with_qos(QosLevel::from_raw(BLOCK));
    unsafe { round.offer_sample(first.call(), &held, true) };
    let reliable = filled(4, 4).with_reliability(Reliability::Reliable);
    unsafe { round.offer_sample(first.call(), &reliable, true) };
    assert_eq!(
        round.counts(),
        RoundCounts {
            dropped: 2,
            held_over: 1,
            unplaced: 0
        }
    );
    assert!(round.deliver());
    let bytes: Vec<u8> = seen.lock().unwrap().iter().map(|(_, b, _)| *b).collect();
    assert_eq!(bytes, [1], "only what came before the seal");
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_sample(first.call(), &borrowed(&datagram[2..]), true) };
    unsafe { round.set_lending(None) };
    unsafe { round.seal() };
    assert!(
        round.deliver(),
        "CONTROL: handed out, the round takes records again"
    );
}

/// The gate reads a link while the round has the room of a record, an entry and the callbacks it
/// owes, and not once too few callbacks are left or the round holds as many records as it may; an
/// empty round takes a record whatever its room, so a link is never stopped for good.
#[test]
fn the_gate_reads_a_link_only_while_the_round_has_a_records_room() {
    use wz_runtime_coop::session_drive::SessionDatagramLink;

    let every = ReadRoom {
        callbacks: caps::DELIVERY_LANE_CALLBACKS,
    };
    let round = round(4);
    // SAFETY (each call): this thread is the round's one writer, and the datagram outlives the
    // rounds' records of it.
    let gate = unsafe { RoundGate::new(Quiet, round, every) };
    let seen: Noted = Arc::default();
    let first = noting(1, &seen);
    let datagram = [1u8, 2];
    assert!(gate.takes_input(), "an empty round");
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_sample(first.call(), &borrowed(&datagram[..1]), true) };
    unsafe { round.set_lending(None) };
    assert!(
        !gate.takes_input(),
        "one callback owed leaves less than a record owing every one"
    );
    unsafe { round.seal() };
    assert!(round.deliver());
    assert!(gate.takes_input(), "handed out, the room is back");

    let one = self::round(1);
    let gate = unsafe { RoundGate::new(Quiet, one, ONE) };
    unsafe { one.set_lending(Some(&datagram[..])) };
    unsafe { one.offer_sample(first.call(), &borrowed(&datagram[1..]), true) };
    unsafe { one.set_lending(None) };
    assert!(!gate.takes_input(), "a round of one record holds one");
    let more = ReadRoom {
        callbacks: caps::DELIVERY_LANE_CALLBACKS + 1,
    };
    let huge = unsafe { RoundGate::new(Quiet, self::round(4), more) };
    assert!(
        huge.takes_input(),
        "an empty round takes a record owing more callbacks than it holds"
    );
}

/// While a source the gate does not hold back owes the round records (a lost face's tokens), the
/// gate reads no link, an empty round's included, so what that source owes comes first. The
/// CONTROL is the same round once nothing is owed.
#[cfg(feature = "liveliness")]
#[test]
fn the_gate_reads_no_link_while_retractions_are_owed() {
    use wz_runtime_coop::session_drive::SessionDatagramLink;
    use wz_session_core::round::Owing;

    let round = round(4);
    // SAFETY: this thread is the round's one writer.
    let gate = unsafe { RoundGate::new(Quiet, round, ONE) };
    round.owe(Owing::Retractions, true);
    assert!(!gate.takes_input(), "owed, no link is read");
    round.owe(Owing::Retractions, false);
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
    let round = round(4);
    let seen: Noted = Arc::default();
    let first = noting(1, &seen);
    let datagram = [1u8; 4];
    // SAFETY (each call): this thread is the round's one writer, and the datagram outlives the
    // round's record of it.
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_sample(first.call(), &borrowed(&datagram), true) };
    unsafe { round.set_lending(None) };
    unsafe { round.seal() };
    #[cfg(debug_assertions)]
    round.offering_gated(true);
    let held = filled(4, 2)
        .with_reliability(Reliability::Reliable)
        .with_qos(QosLevel::from_raw(BLOCK));
    unsafe { round.offer_sample(first.call(), &held, true) };
    assert_eq!(round.counts().held_over, 1);
}

/// While the round captures, an offer hands its call to the session's own put, in the order they
/// came, and holds nothing; each call made from there reaches its row, and ending them keeps no
/// row waiting. Once the capture is taken, what is offered is held again.
#[cfg(feature = "local-subscriber")]
#[test]
fn a_captured_offer_hands_out_the_call_and_holds_nothing() {
    let round = round(4);
    let seen: Noted = Arc::default();
    let (third, first) = (noting(3, &seen), noting(1, &seen));
    let sample = filled(8, 1);
    // SAFETY (each call): this thread is the round's one writer.
    unsafe { round.capture() };
    unsafe { round.offer_sample(third.call(), &sample, true) };
    unsafe { round.offer_sample(first.call(), &sample, false) };
    let mut captured = unsafe { round.captured() };
    let handed = wz_session_core::sink::SampleRef::of(&sample);
    for call in captured.iter() {
        call.hand(&handed);
    }
    let tags: Vec<u8> = seen.lock().unwrap().iter().map(|(t, _, _)| *t).collect();
    assert_eq!(tags, [3, 1], "each call, in the order offered");
    while let Some(call) = captured.pop() {
        round.end_call(call);
    }
    assert!(third.retire() && first.retire(), "every call ended");
    assert!(!round.take_marked(), "and no row waits");
    unsafe { round.seal() };
    assert!(!round.deliver(), "nothing was held");
    let held = noting(4, &seen);
    let datagram = [4u8; 8];
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_sample(held.call(), &borrowed(&datagram), true) };
    unsafe { round.set_lending(None) };
    unsafe { round.seal() };
    assert!(round.deliver(), "CONTROL: once taken, an offer is held");
}

/// The changes a liveliness callback a test holds is handed: its tag, the key and the token.
#[cfg(feature = "liveliness")]
type Heard = Arc<Mutex<Vec<(u8, String, u64)>>>;

/// A liveliness subscriber's row, boxed so it lies where it is while a call of it runs.
#[cfg(feature = "liveliness")]
struct Hearing {
    row: Box<crate::engine::LivelinessRow>,
}

#[cfg(feature = "liveliness")]
impl Hearing {
    /// A call of its callback, begun as the session's dispatch begins one.
    fn call(&self) -> crate::engine::LivelinessCall {
        crate::engine::LivelinessCall::new(self.row.begin().expect("a live row begins a call"))
    }
}

/// A liveliness subscriber's row that notes each change it is handed with `tag`.
#[cfg(feature = "liveliness")]
fn hearing(tag: u8, heard: &Heard) -> Hearing {
    use wz_session_core::declare::liveliness_sample::LivelinessSample;
    let heard = heard.clone();
    Hearing {
        row: Box::new(crate::engine::LivelinessRow::new(
            WireKey::literal().into_anchor(),
            wz_capi_port::LivelinessSink::shared(move |sample: LivelinessSample<'_>| {
                heard
                    .lock()
                    .unwrap()
                    .push((tag, sample.keyexpr.to_owned(), sample.token_id));
            }),
        )),
    }
}

/// A token is one record however many liveliness subscribers it reaches, its key read where it
/// lies in the lent datagram or copied into the round's keys when it lies elsewhere, and each is
/// handed to its callbacks in the order it came.
#[cfg(feature = "liveliness")]
#[test]
fn the_tokens_of_a_round_are_handed_in_order() {
    use wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleKind};

    let round = round(4);
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
    unsafe { round.offer_liveliness(first.call(), &put(lying, 1), None) };
    unsafe { round.offer_liveliness(second.call(), &put(lying, 1), None) };
    unsafe { round.offer_liveliness(first.call(), &put("demo/t/2", 2), None) };
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

/// A token whose key is a key of the session's key arena, as the retraction of a lost face's token
/// names it, is read where the key's block lies after the row let go of it: the round holds a count
/// until the lock holder settles it after the delivery. Turned red by a round that copies the key
/// or keeps the block past the settle.
#[cfg(feature = "liveliness")]
#[test]
fn a_token_named_by_a_held_key_is_read_where_its_block_lies() {
    use wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleKind};

    let keys = key_space();
    let round = round_reading(keys);
    let heard: Heard = Arc::default();
    let first = hearing(1, &heard);
    let row = keys.key("demo/t/held").expect("room");
    let retracted = LivelinessSample {
        kind: LivelinessSampleKind::Delete,
        keyexpr: row.as_str(),
        token_id: 3,
    };
    // SAFETY (each call): this thread is the round's one writer, as a session's step is.
    unsafe { round.offer_liveliness(first.call(), &retracted, Some(&row)) };
    drop(row);
    assert!(keys.counts().used > 0, "the round holds the token's block");
    unsafe { round.seal() };
    assert!(round.deliver());
    assert_eq!(*heard.lock().unwrap(), [(1, "demo/t/held".to_owned(), 3)]);
    assert!(keys.counts().used > 0, "it waits for the lock holder");
    unsafe { round.settle() };
    assert_eq!(keys.counts().used, 0, "settled, the block is back");
}

/// What a leg's callback a test holds is handed: the request id, the key, the payload and where
/// the payload lies.
#[cfg(feature = "query")]
type Answers = Arc<Mutex<Vec<(u32, String, Vec<u8>, usize)>>>;

/// One leg's callback, held as the session's plane holds a leg's: called through its holder, with
/// the counts the round's records take of its row and give back.
#[cfg(feature = "query")]
struct OneLeg {
    callback: wz_capi_port::ReplyCallback,
    held: AtomicUsize,
    released: AtomicUsize,
}

#[cfg(feature = "query")]
impl crate::round::LegHolders<crate::round::CoopCalls> for OneLeg {
    fn hold(&self, leg: LegId) -> bool {
        assert_eq!(leg, LegId::FIRST, "the test's one leg");
        self.held.fetch_add(1, Ordering::SeqCst);
        true
    }

    fn call(&self, _leg: LegId, reply: &dyn wz_session_core::reply_sink::ReplyView) {
        self.callback.call(reply);
    }

    fn release(&self, _leg: LegId) -> Option<wz_capi_port::ReplyCallback> {
        self.released.fetch_add(1, Ordering::SeqCst);
        None
    }
}

/// A leg whose callback notes each reply it is handed.
#[cfg(feature = "query")]
fn answering(answers: &Answers) -> Arc<OneLeg> {
    use wz_session_core::reply_sink::ReplyView;
    let answers = answers.clone();
    Arc::new(OneLeg {
        callback: wz_capi_port::ReplyCallback::shared(move |reply: &dyn ReplyView| {
            answers.lock().unwrap().push((
                reply.rid(),
                reply.keyexpr().to_owned(),
                reply.payload().to_vec(),
                reply.payload().as_ptr() as usize,
            ));
        }),
        held: AtomicUsize::new(0),
        released: AtomicUsize::new(0),
    })
}

/// The round `round` owns, told that `legs` holds the callbacks of the legs its replies are for.
#[cfg(feature = "query")]
fn holding_legs(
    round: &'static mut Placed<Round>,
    legs: &Arc<OneLeg>,
) -> &'static mut Placed<Round> {
    // The round reaches the legs for as long as it stands, which is past the test's frame: a
    // count of them is left to it for good.
    let leaked: &'static Arc<OneLeg> =
        alloc::boxed::Box::leak(alloc::boxed::Box::new(Arc::clone(legs)));
    let held: core::ptr::NonNull<dyn wz_session_core::round::LegHolders<crate::round::CoopCalls>> =
        core::ptr::NonNull::from(&**leaked);
    // SAFETY: the legs are leaked, so they stand for as long as the round reaches them.
    unsafe { round.get_mut().calls_legs_of(held) };
    round
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
/// one whose payload lies nowhere the round reads it is refused, counted as held over (a reply
/// holds its sender) and apart, and takes no count of its leg's row; the round is idle only once
/// the held one is handed, which is what a leg's end waits for. Turned red by a round that copies
/// a reply, or refuses one after taking its leg's count.
#[cfg(feature = "query")]
#[test]
fn a_reply_is_read_where_it_lies_and_one_lying_elsewhere_is_refused() {
    let answers: Answers = Arc::default();
    let legs = answering(&answers);
    let round = holding_legs(crate::round::leaked_placed(4), &legs);
    let datagram = *b"answer";
    // SAFETY (each call): this thread is the round's one writer, and the datagram outlives it.
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_reply(LegId::FIRST, &Lying { payload: &datagram }) };
    unsafe { round.set_lending(None) };
    let elsewhere = b"elsewhere".to_vec();
    unsafe {
        round.offer_reply(
            LegId::FIRST,
            &Lying {
                payload: &elsewhere,
            },
        )
    };
    assert_eq!(
        round.counts(),
        RoundCounts {
            dropped: 0,
            held_over: 1,
            unplaced: 1,
        },
        "the reply lying elsewhere found no place"
    );
    assert_eq!(
        legs.held.load(Ordering::SeqCst),
        1,
        "the refused reply took no count"
    );
    assert!(!round.is_idle(), "a reply is held");
    unsafe { round.seal() };
    assert!(round.deliver());
    assert!(round.is_idle(), "handed out");
    let answers = answers.lock().unwrap();
    assert_eq!(answers.len(), 1, "the held reply alone");
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
}

/// A reply's record holds one count of its leg's row from its offer until its call is ended, which
/// the delivery that hands it out gives back; a reply the round refuses takes no count, and a round
/// never told of the legs holds no reply. Turned red by a record that holds no count while it waits
/// for its delivery, or one whose count is never given back.
#[cfg(feature = "query")]
#[test]
fn a_replys_record_holds_its_legs_row_until_its_call_is_ended() {
    let answers: Answers = Arc::default();
    let legs = answering(&answers);
    let told = holding_legs(crate::round::leaked_placed(4), &legs);
    let datagram = *b"r";
    let counts = |legs: &OneLeg| {
        (
            legs.held.load(Ordering::SeqCst),
            legs.released.load(Ordering::SeqCst),
        )
    };
    // SAFETY (each call): this thread is the round's one writer, and the datagram outlives it.
    unsafe { told.set_lending(Some(&datagram[..])) };
    unsafe { told.offer_reply(LegId::FIRST, &Lying { payload: &datagram }) };
    assert_eq!(counts(&legs), (1, 0), "the record holds the leg's row");
    unsafe { told.seal() };
    unsafe { told.offer_reply(LegId::FIRST, &Lying { payload: &datagram }) };
    assert_eq!(counts(&legs), (1, 0), "a reply refused takes no count");
    unsafe { told.set_lending(None) };
    assert!(told.deliver());
    assert_eq!(answers.lock().unwrap().len(), 1);
    assert_eq!(
        counts(&legs),
        (1, 1),
        "its call ended, the record gave its count back"
    );

    let told_none = round(4);
    unsafe { told_none.set_lending(Some(&datagram[..])) };
    unsafe { told_none.offer_reply(LegId::FIRST, &Lying { payload: &datagram }) };
    unsafe { told_none.set_lending(None) };
    assert!(
        told_none.is_idle(),
        "a round told of no legs holds no reply"
    );
}

/// A reply whose key is a key of the session's key arena is read where its block lies, the round
/// holding a count past the row's own until it is settled after the delivery. Turned red by a
/// round that copies a reply's held key or never hands its count back.
#[cfg(feature = "query")]
#[test]
fn a_reply_named_by_a_held_key_is_read_where_its_block_lies() {
    struct HeldReply<'k> {
        key: &'k KeyRef,
    }

    impl wz_session_core::reply_sink::ReplyView for HeldReply<'_> {
        fn rid(&self) -> wz_session_core::wire_id::RequestId {
            5
        }

        fn keyexpr(&self) -> &str {
            self.key.as_str()
        }

        fn keyexpr_held(&self) -> Option<&KeyRef> {
            Some(self.key)
        }

        fn kind(&self) -> wz_session_core::reply_sink::ReplyKind {
            wz_session_core::reply_sink::ReplyKind::Put
        }

        fn payload(&self) -> &[u8] {
            &[]
        }

        fn err_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
            None
        }
    }

    let keys = key_space();
    let answers: Answers = Arc::default();
    let legs = answering(&answers);
    let round = holding_legs(round_reading(keys), &legs);
    let row = keys.key("demo/answer/held").expect("room");
    // SAFETY (each call): this thread is the round's one writer.
    unsafe { round.offer_reply(LegId::FIRST, &HeldReply { key: &row }) };
    drop(row);
    assert!(keys.counts().used > 0, "the round holds the reply's block");
    unsafe { round.seal() };
    assert!(round.deliver());
    assert_eq!(answers.lock().unwrap()[0].1, "demo/answer/held");
    unsafe { round.settle() };
    assert_eq!(keys.counts().used, 0, "settled, the block is back");
}

/// A record whose payload lies in the datagram a link lends is read there; one whose payload lies
/// nowhere the round reads it is refused, counted with the records that found no room and apart,
/// and handed to no callback. Turned red by a round that copies a part, or refuses one without
/// counting it.
#[test]
fn a_record_with_a_part_the_round_cannot_read_where_it_lies_is_refused_and_counted() {
    let round = round(4);
    let seen: Noted = Arc::default();
    let first = noting(1, &seen);
    let datagram = [1u8, 2];
    let elsewhere = b"x".to_vec();
    // SAFETY (each call): this thread is the round's one writer, and the datagram outlives it.
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_sample(first.call(), &borrowed(&datagram), true) };
    unsafe { round.set_lending(None) };
    unsafe { round.offer_sample(first.call(), &borrowed(&elsewhere), true) };
    assert_eq!(
        round.counts(),
        RoundCounts {
            dropped: 1,
            held_over: 0,
            unplaced: 1,
        }
    );
    unsafe { round.seal() };
    assert!(round.deliver());
    assert_eq!(
        *seen.lock().unwrap(),
        [(1, 1, datagram.as_ptr() as usize)],
        "the lent record alone, read where it lies"
    );
    assert_eq!(
        (round.tally().samples(), round.tally().lent()),
        (1, 1),
        "the round handed out the lent record alone"
    );
}

/// The gate asks a filling round for room in its keys: once the keys a session composed leave no
/// room for one more of the longest, no link is read until the round is handed out, so no key
/// finds no place. Turned red by a gate that asks for none of the keys.
// A round of one thread takes no second message while it holds one, whatever its keys.
#[cfg(feature = "threads")]
#[test]
fn the_gate_stops_a_link_where_the_rounds_keys_have_no_room() {
    let round = round(8);
    let seen: Noted = Arc::default();
    let first = noting(1, &seen);
    let half = caps::MAX_KEYEXPR_BYTES / 2 + 1;
    let (a, b) = ("a".repeat(half), "b".repeat(half));
    // SAFETY (each call): this thread is the round's one writer and holds no borrow of its table.
    unsafe { round.offer_sample(first.call(), &put(&a, &[]), true) };
    assert!(
        unsafe { round.has_room(ONE) },
        "CONTROL: one key leaves room for another"
    );
    unsafe { round.offer_sample(first.call(), &put(&b, &[]), true) };
    assert!(
        !unsafe { round.has_room(ONE) },
        "two keys leave no room for one more of the longest"
    );
    assert_eq!(round.counts(), RoundCounts::default(), "nothing refused");
    unsafe { round.seal() };
    assert!(round.deliver());
    unsafe { round.settle() };
    assert!(
        unsafe { round.has_room(ONE) },
        "handed out, the keys are free"
    );
    assert_eq!(seen.lock().unwrap().len(), 2);
}

/// While a record reads a rejoined message, the gate reads no link, so no second rejoined message
/// can reach the round (a datagram carries one fragment at most, at its end); the round is handed
/// out all the same, with the gate shut, and the next read the gate lets through finds the
/// message's buffer back. Turned red by a delivery that waits for a read, or a gate that reads a
/// link while the round reads the rejoined message.
#[test]
fn a_round_reading_a_rejoined_message_is_handed_out_with_its_gate_shut() {
    use wz_runtime_coop::session_drive::SessionDatagramLink;

    static CHAINS: ByteCells<8, 1> = ByteCells::new();
    let round = round(4);
    let reads = Rc::new(Cell::new(0));
    // SAFETY (each call): this thread is the round's one writer, as a session's step is.
    let gate = unsafe { RoundGate::new(Counting(reads.clone()), round, ONE) };
    let seen: Noted = Arc::default();
    let first = noting(1, &seen);
    let mut buf = CHAINS.claim().expect("the chain's buffer");
    buf.as_mut_slice().fill(9);
    let kept = KeptBytes::of(buf, 4);
    let message = kept.as_slice().as_ptr() as usize;
    unsafe { round.lend_rejoined(&kept) };
    unsafe { round.offer_sample(first.call(), &borrowed(kept.as_slice()), true) };
    unsafe { round.end_rejoined(kept) };
    assert!(gate.try_recv().is_none());
    assert!(!gate.recv_with(&mut |_| {}));
    assert_eq!(reads.get(), 0, "the gate reads no link");
    unsafe { round.seal() };
    assert!(round.deliver(), "handed out with the gate shut");
    assert_eq!(*seen.lock().unwrap(), [(1, 9, message)]);
    assert_eq!(CHAINS.in_use(), 1, "the buffer waits for the lock holder");
    assert!(gate.try_recv().is_none());
    assert_eq!(reads.get(), 1, "the gate reads the link again");
    assert_eq!(CHAINS.in_use(), 0, "and let go of the buffer first");
}
