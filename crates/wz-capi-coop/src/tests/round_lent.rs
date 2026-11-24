// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The round in a build that keeps no delivery area (`rx-lent-only`): a record is read where its
//! parts lie, one with a part that lies nowhere the round reads it is refused and counted, the gate
//! stops a link where the round's keys have no room for one more key, and a round that reads a
//! rejoined message is handed out with the gate shut and opens it once handed out.

use alloc::rc::Rc;
use alloc::sync::Arc;
use core::cell::Cell;
use core::num::NonZeroU32;
use std::sync::Mutex;

use wz_capi_port::{SubscriberSink, WireKey};
use wz_runtime_coop::session_drive::SessionDatagramLink;
use wz_session_core::byte_cells::{ByteCells, ByteSource, KeptBytes};
use wz_session_core::caps;
use wz_session_core::reliability::Reliability;
use wz_session_core::row_callback::RowCallback;
use wz_session_core::sample::SampleKind;
use wz_session_core::session_tables::SubscriberHandle;
use wz_session_core::sink::{BorrowedSample, SampleView};

use crate::engine::{SubscriberCall, SubscriberRow};
use crate::round::{ReadRoom, Round, RoundCounts, RoundGate};

/// The room of a record for one subscriber.
const ONE: ReadRoom = ReadRoom { callbacks: 1 };

/// A subscriber row, boxed so it lies where it is while a call of it runs, and its handle.
struct Row {
    row: Box<SubscriberRow>,
    handle: SubscriberHandle,
}

impl Row {
    /// A call of its callback, begun as the session's dispatch begins one.
    fn call(&self) -> SubscriberCall {
        SubscriberCall::new(
            self.row.begin().expect("a live row begins a call"),
            self.handle,
        )
    }
}

/// What [`noting`] callbacks write: each sample's keyexpr and where its payload lies.
type Noted = Arc<Mutex<Vec<(String, usize)>>>;

/// A row whose callback notes each sample it is handed.
fn noting(seen: &Noted) -> Row {
    let seen = seen.clone();
    Row {
        row: Box::new(SubscriberRow::new(
            1,
            None,
            WireKey::literal(),
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                seen.lock().unwrap().push((
                    sample.keyexpr().to_owned(),
                    sample.payload().as_ptr() as usize,
                ));
            }),
            true,
        )),
        handle: SubscriberHandle::from_bits(NonZeroU32::new(2).expect("not zero"))
            .expect("an index"),
    }
}

/// A best-effort put of `payload` on `keyexpr`, borrowed where it lies.
fn put<'a>(keyexpr: &'a str, payload: &'a [u8]) -> BorrowedSample<'a> {
    BorrowedSample {
        keyexpr,
        payload,
        kind: SampleKind::Put,
        reliability: Reliability::BestEffort,
    }
}

/// A link with nothing to give that counts how often it is asked to receive.
struct Counting(Rc<Cell<usize>>);

impl SessionDatagramLink for Counting {
    fn service(&self) {}

    fn try_recv(&self) -> Option<wz_session_core::link::RxFrame> {
        self.0.set(self.0.get() + 1);
        None
    }
}

/// A record whose payload lies in the datagram a link lends is read there; one whose payload lies
/// nowhere the round reads it is refused, counted with the records that found no room and apart,
/// and handed to no callback. Turned red by a lent-only round that copies a part, or refuses one
/// without counting it.
#[test]
fn a_record_with_a_part_the_round_cannot_read_where_it_lies_is_refused_and_counted() {
    let round = Round::leaked(4);
    let seen: Noted = Arc::default();
    let first = noting(&seen);
    let datagram = [1u8, 2];
    let elsewhere = b"x".to_vec();
    // SAFETY (each call): this thread is the round's one writer, and the datagram outlives it.
    unsafe { round.set_lending(Some(&datagram[..])) };
    unsafe { round.offer_sample(first.call(), &put("demo/a", &datagram), true) };
    unsafe { round.set_lending(None) };
    unsafe { round.offer_sample(first.call(), &put("demo/b", &elsewhere), true) };
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
        [("demo/a".to_owned(), datagram.as_ptr() as usize)],
        "the lent record alone, read where it lies"
    );
}

/// The gate asks a filling round for room in its keys: once the keys a session composed leave no
/// room for one more of the longest, no link is read until the round is handed out, so no key
/// finds no place. Turned red by a gate that still asks for an area's bytes, or none of the keys.
#[test]
fn the_gate_stops_a_link_where_the_rounds_keys_have_no_room() {
    let round = Round::leaked(8);
    let seen: Noted = Arc::default();
    let first = noting(&seen);
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
    static CHAINS: ByteCells<8, 1> = ByteCells::new();
    let round = Round::leaked(4);
    let reads = Rc::new(Cell::new(0));
    let gate = unsafe { RoundGate::new(Counting(reads.clone()), round.clone(), ONE) };
    let seen: Noted = Arc::default();
    let first = noting(&seen);
    let mut buf = CHAINS.claim().expect("the chain's buffer");
    buf.as_mut_slice().fill(9);
    let kept = KeptBytes::of(buf, 4);
    let message = kept.as_slice().as_ptr() as usize;
    // SAFETY (each call): this thread is the round's one writer, as a session's step is.
    unsafe { round.lend_rejoined(&kept) };
    unsafe { round.offer_sample(first.call(), &put("demo/r", kept.as_slice()), true) };
    unsafe { round.end_rejoined(kept) };
    assert!(gate.try_recv().is_none());
    assert!(!gate.recv_with(&mut |_| {}));
    assert_eq!(reads.get(), 0, "the gate reads no link");
    unsafe { round.seal() };
    assert!(round.deliver(), "handed out with the gate shut");
    assert_eq!(*seen.lock().unwrap(), [("demo/r".to_owned(), message)]);
    assert_eq!(CHAINS.in_use(), 1, "the buffer waits for the lock holder");
    assert!(gate.try_recv().is_none());
    assert_eq!(reads.get(), 1, "the gate reads the link again");
    assert_eq!(CHAINS.in_use(), 0, "and let go of the buffer first");
}
