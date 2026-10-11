// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What one inbound frame costs the heap on the MCU session loop, counted.
//!
//! A real session pair on the host lwIP loopback: an acceptor (the session
//! under measurement, driven one iteration at a time through the shared
//! [`SessionPump`] and the MCU application layer) and an initiator that dials
//! it. Once both are established the initiator's socket sends ONE datagram, a
//! `Frame` carrying `N` Push(Put) messages, and the acceptor's single drive
//! iteration that receives it, decodes it and delivers every Put to a
//! subscriber is run under a counting `#[global_allocator]`.
//!
//! A frame's cost is `frame + N * record`. The frame part is everything that is
//! paid once per datagram whatever it carries — the datagram copied out of the
//! socket, the frame's payload copied out of that copy, and the list the
//! records are collected into, whose length the peer chooses. The per-record
//! part is what one Put costs from its decode to its subscriber. Measuring
//! frames of 1, 2 and 8 records separates the two without naming either:
//! `frame = 2 * cost(1) - cost(2)`, `record = cost(2) - cost(1)`, and a frame
//! part of zero makes the cost exactly linear in `N`.
//!
//! - With `rx-in-place` the loop dispatches the datagram where the socket holds
//!   it, record by record (fixed-memory step S2): the frame part must be ZERO.
//!   And each Put is decoded where the datagram lies and delivered to its
//!   subscriber as a view over those bytes (step S3, ARCHITECTURE section 9.2):
//!   the per-record part must be ZERO on the fixed bounded backing
//!   (`bounded-heapless`, the MCU profile's), and exactly the TWO allocations
//!   the subscriber matcher's chunk splits make on the growable one (the AP's
//!   backing, whose scratch lists grow; `pubsub::fire_into` and
//!   `keyexpr_match::keyexpr_intersects_target`). Before S3 it was 7 and 5:
//!   the boxed owned Push, its keyexpr and payload copies, the resolved keyexpr
//!   `String` and the subscriber's payload copy, plus those two.
//! - Without it (the copying loop every shipped image runs today) the frame
//!   part must be POSITIVE. That half is the instrument's own control: a count
//!   that read zero on the loop that is known to copy would prove nothing about
//!   the loop that is meant not to.
//!
//! Either way every Put must reach the subscriber with exactly the payload the
//! shared batch decoder reads out of the same payload (the decoder the AP and
//! the copying loop dispatch from), on exactly the keyexpr it carries, in
//! order.
//!
//! A second test pins the one behaviour the two loops are meant to differ in:
//! a frame whose last record does not decode.
//!
//! Host-test level: no board runs it, and the stack depth of the in-place
//! dispatch is not measured here.

// Not on the `session-slot` profile, whose sessions are made in a slot and not
// through the `Rc` seams this file builds them with: `session_slot_allocations`
// counts that profile's, receive path included.
#![cfg(not(feature = "session-slot"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use wz_codecs::push::PushOwnedVariant;
use wz_codecs::wire_const;
use wz_link_lwip::LwipLink;
use wz_runtime_coop::session_drive::{
    SessionDriveConfig, SessionLinks, SessionPump, SessionRole, UdpPeer,
};
use wz_runtime_coop::session_runtime::new_session_actions;
use wz_runtime_coop::{ClockSource, CoopRuntime, CoopTime};
use wz_session_core::driver_loop::{DriverLoopOutcome, DriverOutcome, IterationEvent};
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::locality::Locality;
use wz_session_core::network_message::{parse_frame_payload, NetworkMessage};
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;
use wz_session_core::session_actions::SessionLinkActions;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::sink::BoxedSink;
use wz_session_core::WhatAmI;
use wz_session_lwip::{app_layer, LwipLinks, LwipSessionLink};

/// The links the test opens its sockets with: `LwipLinks::new` by default, and with
/// `static-link-storage` (Round 3277) over a leaked pool, since a test is host code
/// and may allocate where a firmware declares a `static` pool. The count below
/// reads the receive path, which the pool does not touch.
fn new_links(link: Rc<LwipLink>) -> LwipLinks {
    #[cfg(not(feature = "static-link-storage"))]
    {
        LwipLinks::new(link)
    }
    #[cfg(feature = "static-link-storage")]
    {
        LwipLinks::new(link, wz_link_lwip::test_bind::session_sockets())
    }
}

/// Counts the allocations made BY THE CURRENT THREAD, so the parallel test
/// threads of this binary cannot move each other's numbers.
struct CountingAllocator;

thread_local! {
    // `const` initialisation with a destructor-free type: reading it from
    // inside `alloc` cannot itself allocate.
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call forwards to `System` unchanged; the only addition is a
// thread-local counter bump, which neither allocates nor unwinds.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// Run `f` and return its result with the number of allocations it made on
/// this thread.
fn allocations_during<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let before = ALLOCATIONS.with(Cell::get);
    let out = f();
    let after = ALLOCATIONS.with(Cell::get);
    (out, after - before)
}

/// A clock that never moves: no deadline fires, so an iteration does only what
/// its inbound datagram asks of it.
#[derive(Clone, Default)]
struct Frozen;
impl ClockSource for Frozen {
    fn now_us(&self) -> u64 {
        0
    }
}

/// A deterministic stand-in for a board's TRNG (the acceptor mints a cookie).
struct Counting(u8);
impl wz_session_core::entropy::EntropySource for Counting {
    fn try_fill_bytes(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(), wz_session_core::entropy::EntropyUnavailable> {
        for b in buf {
            self.0 = self.0.wrapping_add(1);
            *b = self.0;
        }
        Ok(())
    }
}

fn params(zid: u8) -> SessionInitParams {
    SessionInitParams {
        version: 0x09,
        whatami: WhatAmI::Peer,
        zid: vec![zid; 4],
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: vec![],
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        cookie_signing_key: wz_session_core::signing_key::SigningKey::new(vec![7u8; 32])
            .expect("key"),
    }
}

const KEY: &str = "rx/frame";

/// The payload of the `i`th Put: eight bytes no other Put in the frame shares.
fn payload_of(i: usize) -> [u8; 8] {
    [i as u8, 0xa5, (i >> 8) as u8, 0x5a, 1, 2, 3, i as u8 ^ 0xff]
}

/// One `Frame` at `sn` whose payload is `n` Push(Put) messages on [`KEY`], and
/// that payload alone (what the batch decoder reads).
fn frame_of(sn: u64, n: usize) -> (Vec<u8>, Vec<u8>) {
    let mut payload = Vec::new();
    for i in 0..n {
        // The session's own literal Put builder, so the wire is what a peer's
        // `put` produces.
        let push = wz_session_core::push_build::build_push_literal(KEY, &payload_of(i))
            .expect("a literal Put");
        let view = push.try_as_borrowed().expect("a borrowed view");
        payload.extend_from_slice(&view.encode_to_vec());
    }
    (frame_wire(sn, &[], &payload), payload)
}

/// A reliable Frame at `sn` carrying `payload`, with `chain` as its own
/// extension chain (the Z flag set when there is one): the header, the SN as a
/// VLE (seven bits a byte, low first, the top bit saying another follows), the
/// chain, the payload.
fn frame_wire(sn: u64, chain: &[u8], payload: &[u8]) -> Vec<u8> {
    let z = if chain.is_empty() {
        0
    } else {
        wire_const::FLAG_T_Z
    };
    let mut wire = vec![wire_const::T_MID_FRAME | wire_const::FLAG_T_FRAME_R | z];
    let mut rest = sn;
    while rest >= 0x80 {
        wire.push((rest as u8 & 0x7f) | 0x80);
        rest >>= 7;
    }
    wire.push(rest as u8);
    wire.extend_from_slice(chain);
    wire.extend_from_slice(payload);
    wire
}

/// The Puts the shared batch decoder reads out of `payload`, in order: each
/// one's payload and the keyexpr the copying path resolves for it (every Put
/// here names its keyexpr literally, so that is its suffix).
fn decoded_puts(payload: &[u8]) -> Vec<(Vec<u8>, String)> {
    let messages = parse_frame_payload(payload).expect("the frame decodes");
    let mut out = Vec::new();
    for message in &messages {
        let NetworkMessage::Push(push) = message else {
            panic!("only Push messages were encoded");
        };
        let PushOwnedVariant::CodecZenohMsgPut(put) = &push.body else {
            panic!("only Puts were encoded");
        };
        let (id, suffix) = wz_session_core::wireexpr_resolve::id_and_suffix(&push.keyexpr.body);
        assert_eq!(id, 0, "a literal keyexpr");
        out.push((
            wz_session_core::put_payload::inline_bytes(put)
                .expect("an inline payload")
                .to_vec(),
            String::from(suffix.expect("a keyexpr")),
        ));
    }
    out
}

type Pump = SessionPump<Frozen, LwipSessionLink<Rc<LwipLink>>>;

/// The drive outcomes one frame turn reported, by kind: kept so a run that
/// delivers nothing says what it did instead. Counted in a `Cell`, so keeping
/// it costs the measured window nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PollTally {
    frame_payload: usize,
    /// Push records lent where the datagram lies (`IterationEvent::InPlace`).
    in_place: usize,
    /// Fragments read where the datagram lies
    /// (`IterationEvent::InPlaceFragment`).
    fragment_in_place: usize,
    /// Fragments the copying path decoded (`Poll(Fragment)`).
    fragment: usize,
    /// Chains the Router aborted or refused (`ReassemblyDropped`).
    dropped: usize,
    sn_rejected: usize,
    parse_error: usize,
    other: usize,
}

/// The transport extension chain a `FramePayload` reported, kept in fixed
/// storage: whether the frame said it had one, how many entries it handed
/// over, and their header bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FrameExts {
    has_ext: bool,
    len: usize,
    headers: [u8; 8],
}

impl FrameExts {
    fn of(has_ext: bool, extensions: &[wz_codecs::ext_entry::ExtEntryOwned]) -> Self {
        let mut headers = [0u8; 8];
        for (slot, ext) in headers.iter_mut().zip(extensions) {
            *slot = ext.header;
        }
        Self {
            has_ext,
            len: extensions.len(),
            headers,
        }
    }
}

/// What the subscriber was handed for one Put, recorded into fixed storage so
/// that recording it allocates nothing inside the measured window: the payload,
/// the keyexpr's bytes with their length, and the address the payload was
/// handed at (where the sample's bytes lie, which says whether they are a copy).
type Delivery = ([u8; 8], [u8; 16], usize, usize);

/// A delivery as comparable values: the payload and the keyexpr.
fn delivery_of((payload, key, len, _): &Delivery) -> (Vec<u8>, String) {
    (
        payload.to_vec(),
        String::from_utf8(key[..*len].to_vec()).expect("a UTF-8 keyexpr"),
    )
}

/// The two sessions, established, and what the acceptor's subscriber saw.
struct Pair {
    acceptor: Pump,
    on_event: Box<dyn FnMut(IterationEvent<'_>)>,
    /// What the acceptor's drive reported, by kind, since the last frame turn.
    polls: Rc<Cell<PollTally>>,
    /// The transport extension chain the latest `FramePayload` reported.
    frame_exts: Rc<Cell<FrameExts>>,
    /// The initiator's session: whose transmit SN each measured frame takes,
    /// so the acceptor's SN gate admits it as the initiator's next frame.
    initiator: Rc<SessionLinkActions<CoopRuntime<Frozen>, CoopTime<Frozen>>>,
    /// The initiator's socket: what the measured frames are sent from.
    initiator_sink: Rc<dyn BoxedLinkDriver>,
    /// Every Put the subscriber was handed, in order. Its capacity is reserved
    /// before anything is measured, so recording a delivery does not itself
    /// allocate.
    delivered: Arc<Mutex<Vec<Delivery>>>,
    /// The acceptor's application layer: where a test registers the queryable
    /// or the pending get it measures.
    #[cfg_attr(not(feature = "query-queryable"), allow(dead_code))]
    observer: Rc<RefCell<ApplicationLayerObserver>>,
}

impl Pair {
    fn establish(link: &Rc<LwipLink>, port: u16) -> Self {
        let runtime = CoopRuntime::new(Frozen);
        let links = new_links(link.clone());
        let config = |role| SessionDriveConfig {
            timeouts: SessionTimeouts::spec_defaults(),
            role,
            max_iters: None,
        };

        let opened = links.open_acceptor(port).expect("bind the acceptor");
        let acceptor_actions = new_session_actions(
            opened.sink,
            params(0xa1),
            CoopTime::new(&runtime),
            Counting(1),
        );
        let mut acceptor = SessionPump::new(
            runtime.clone(),
            opened.pump,
            acceptor_actions.clone(),
            CoopTime::new(&runtime),
            config(SessionRole::Acceptor),
        );

        let opened = links
            .open_initiator(UdpPeer {
                addr: [127, 0, 0, 1],
                port,
            })
            .expect("open the initiator");
        let initiator_sink = opened.sink.clone();
        let initiator_actions =
            SessionLinkActions::<CoopRuntime<Frozen>, CoopTime<Frozen>>::new_generic(
                opened.sink,
                params(0xb1),
                CoopTime::new(&runtime),
            );
        let mut initiator = SessionPump::new(
            runtime.clone(),
            opened.pump,
            initiator_actions.clone(),
            CoopTime::new(&runtime),
            config(SessionRole::Initiator),
        );

        // Room for the most Puts one message carries here: a reassembled one
        // fills a whole reassembly slot.
        let delivered: Arc<Mutex<Vec<Delivery>>> = Arc::new(Mutex::new(Vec::with_capacity(512)));
        let observer = Rc::new(RefCell::new(ApplicationLayerObserver::new()));
        let seen = delivered.clone();
        observer
            .borrow_mut()
            .subscribers
            .register_sink(
                KEY,
                Locality::Any,
                BoxedSink::new(move |sample| {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(sample.payload());
                    let key = sample.keyexpr().as_bytes();
                    let mut key_bytes = [0u8; 16];
                    key_bytes[..key.len()].copy_from_slice(key);
                    let at = sample.payload().as_ptr() as usize;
                    seen.lock()
                        .expect("not poisoned")
                        .push((bytes, key_bytes, key.len(), at));
                }),
            )
            .expect("register the subscriber");
        let mut dispatch = app_layer::dispatch_to(observer.clone(), acceptor_actions.clone());
        let polls = Rc::new(Cell::new(PollTally::default()));
        let tally = polls.clone();
        let frame_exts = Rc::new(Cell::new(FrameExts::default()));
        let exts = frame_exts.clone();
        let mut on_event: Box<dyn FnMut(IterationEvent<'_>)> = Box::new(move |event| {
            let mut t = tally.get();
            match &event {
                IterationEvent::Poll(outcome) => match outcome {
                    DriverLoopOutcome::FramePayload {
                        has_ext,
                        extensions,
                        ..
                    } => {
                        t.frame_payload += 1;
                        exts.set(FrameExts::of(*has_ext, extensions));
                    }
                    DriverLoopOutcome::RxSnRejected { .. } => t.sn_rejected += 1,
                    DriverLoopOutcome::ParseError(_) => t.parse_error += 1,
                    #[cfg(feature = "reassembly")]
                    DriverLoopOutcome::Fragment { .. } => t.fragment += 1,
                    _ => t.other += 1,
                },
                IterationEvent::InPlace(_) => t.in_place += 1,
                IterationEvent::InPlaceFragment(_) => t.fragment_in_place += 1,
                IterationEvent::ReassemblyDropped(_) => t.dropped += 1,
                _ => {}
            }
            tally.set(t);
            dispatch(event)
        });

        let mut established = false;
        for _ in 0..64 {
            runtime.run_until_idle();
            assert!(initiator.step(&mut |_| {}).is_none(), "the initiator ended");
            assert!(acceptor.step(&mut on_event).is_none(), "the acceptor ended");
            if acceptor_actions.is_established() {
                established = true;
                break;
            }
        }
        assert!(established, "the pair established over the loopback");
        // The initiator has nothing more to say; settle whatever the last turn
        // left in flight so the measured iterations start from a quiet link.
        for _ in 0..4 {
            assert!(initiator.step(&mut |_| {}).is_none());
            assert!(acceptor.step(&mut on_event).is_none());
        }

        Self {
            acceptor,
            on_event,
            polls,
            frame_exts,
            initiator: initiator_actions,
            initiator_sink,
            delivered,
            observer,
        }
    }

    /// One acceptor iteration with nothing sent: what an idle turn costs.
    fn idle_turn(&mut self) -> usize {
        let Self {
            acceptor, on_event, ..
        } = self;
        let (finished, allocations) = allocations_during(|| acceptor.step(on_event));
        assert!(finished.is_none(), "the acceptor ended on an idle turn");
        allocations
    }

    /// Send a frame of `n` Puts and run the ONE acceptor iteration that
    /// receives it. Returns the allocations that iteration made and the Puts
    /// the shared decoder reads out of the frame's payload.
    fn frame_turn(&mut self, n: usize) -> (usize, Vec<(Vec<u8>, String)>) {
        let (wire, payload) = frame_of(self.next_sn(), n);
        let expected = decoded_puts(&payload);
        let (allocations, polls, delivered) = self.turn(&wire);
        assert_eq!(
            delivered, expected,
            "every Put reached the subscriber, in order, with the payload and the \
             keyexpr the shared batch decoder reads out of the same payload (the \
             turn reported {polls:?})"
        );
        assert_eq!(
            (polls.sn_rejected, polls.parse_error, polls.other),
            (0, 0, 0),
            "the frame turn reported only data"
        );
        (allocations, expected)
    }

    /// The initiator's next reliable transmit SN.
    fn next_sn(&self) -> u64 {
        self.initiator.next_outbound_frame_sn(
            Priority::DEFAULT,
            true,
            self.initiator.negotiated_sn_mask(),
        )
    }

    /// Send `wire` from the initiator's socket and run the ONE acceptor
    /// iteration that receives it: its allocations, what it reported, and the
    /// Put payloads the subscriber was handed.
    fn turn(&mut self, wire: &[u8]) -> (usize, PollTally, Vec<(Vec<u8>, String)>) {
        self.delivered.lock().expect("not poisoned").clear();
        self.polls.set(PollTally::default());
        let sent = self
            .initiator_sink
            .send_blocking(wire, Reliability::Reliable);
        assert_eq!(
            sent,
            wz_session_core::link::LinkSendOutcome::Sent,
            "the frame left the initiator's socket"
        );
        let Self {
            acceptor, on_event, ..
        } = self;
        let (finished, allocations): (Option<DriverOutcome>, usize) =
            allocations_during(|| acceptor.step(on_event));
        assert!(finished.is_none(), "the acceptor ended on the turn");
        let delivered = self
            .delivered
            .lock()
            .expect("not poisoned")
            .iter()
            .map(delivery_of)
            .collect();
        (allocations, self.polls.get(), delivered)
    }
}

/// A frame whose LAST record does not decode: two Puts, then a Push header
/// with nothing after it.
///
/// - The copying loop decodes the frame's records into one list first, so the
///   broken record refuses the whole frame: nothing is delivered, and the turn
///   reports the parse error.
/// - The in-place loop decodes and dispatches one record at a time, so the two
///   Puts before the broken record have been delivered when the error is
///   reported. That is zenoh-pico's receive loop, and the one behaviour the
///   two paths are meant to differ in.
///
/// Either way the turn reports the parse error once, which both paths raise as
/// `framing.error` on the session in the same call.
#[test]
fn a_frame_that_breaks_after_two_records_is_reported_after_what_was_dispatched() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    let mut pair = Pair::establish(&link, 7493);

    let (mut wire, mut payload) = frame_of(pair.next_sn(), 2);
    let whole = decoded_puts(&payload);
    assert_eq!(
        whole.len(),
        2,
        "the two Puts before the break are well formed"
    );
    wire.push(wire_const::N_MID_PUSH);
    payload.push(wire_const::N_MID_PUSH);
    assert!(
        parse_frame_payload(&payload).is_err(),
        "the batch decode refuses the payload whole"
    );
    let (_, polls, delivered) = pair.turn(&wire);

    // In place, each Put is lent as it is decoded (`IterationEvent::InPlace`).
    #[cfg(feature = "rx-in-place")]
    let expected = (
        whole,
        PollTally {
            in_place: 2,
            parse_error: 1,
            ..PollTally::default()
        },
    );
    #[cfg(not(feature = "rx-in-place"))]
    let expected = (
        Vec::<(Vec<u8>, String)>::new(),
        PollTally {
            parse_error: 1,
            ..PollTally::default()
        },
    );
    assert_eq!(
        (delivered, polls),
        expected,
        "(Puts delivered, what the turn reported)"
    );
}

/// A unit the in-place path does not read in place goes down the copying path
/// and is COUNTED, by why: here a `Fragment` on a session that does not
/// reassemble, so has no slot to stage it into. The pump's counts say so; the
/// unit is not read in place. (A session that reassembles reads it in place:
/// `fragments` below.)
#[cfg(all(feature = "rx-in-place", not(feature = "reassembly")))]
#[test]
fn a_fragment_takes_the_copying_path_and_is_counted() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    let mut pair = Pair::establish(&link, 7495);

    let (frame, _) = frame_of(pair.next_sn(), 1);
    // The same SN and payload as a final reliable fragment (no M flag).
    let mut fragment = frame;
    fragment[0] = wire_const::T_MID_FRAGMENT | wire_const::FLAG_T_FRAGMENT_R;
    let before = pair.acceptor.rx_path_counts();
    let _ = pair.turn(&fragment);
    let after = pair.acceptor.rx_path_counts();
    assert_eq!(
        (
            after.in_place - before.in_place,
            after.fragment - before.fragment,
            after.copied() - before.copied(),
        ),
        (0, 1, 1),
        "(read in place, fragments copied, units copied)"
    );
}

#[test]
fn the_frame_path_of_an_inbound_frame_is_counted_per_frame_and_per_record() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    let mut pair = Pair::establish(&link, 7491);

    #[cfg(feature = "rx-in-place")]
    let paths_before = pair.acceptor.rx_path_counts();
    let idle = pair.idle_turn();
    let (one, puts) = pair.frame_turn(1);
    assert_eq!(puts.len(), 1);
    let (two, _) = pair.frame_turn(2);
    let (eight, puts) = pair.frame_turn(8);
    assert_eq!(puts.len(), 8);
    let fixed = wz_session_core::bounded::ENFORCES_CAPACITY;
    // Printed so a run reports its numbers, red or green.
    std::println!(
        "allocations: idle {idle}, frame of 1 {one}, of 2 {two}, of 8 {eight} \
         (fixed bounded backing: {fixed})"
    );

    // The turn with nothing to receive allocates nothing, so what the frame
    // turns count is the frame's.
    assert_eq!(idle, 0, "an idle iteration allocates nothing");
    let per_record = two - one;
    let frame_part = (2 * one).checked_sub(two).expect("cost(2) <= 2 * cost(1)");

    // S3: a Put whose keyexpr fits costs nothing on the fixed backing; on the
    // growable one, exactly the two chunk lists the subscriber matcher grows.
    #[cfg(feature = "rx-in-place")]
    let matcher_scratch = if fixed { 0 } else { 2 };
    #[cfg(feature = "rx-in-place")]
    assert_eq!(
        (frame_part, per_record, eight),
        (0, matcher_scratch, 8 * matcher_scratch),
        "(allocations paid once per frame, per Put, cost of a frame of 8): with the \
         datagram dispatched where the socket holds it and each Put delivered where \
         it lies, a Put costs the heap only the matcher's growable scratch"
    );
    // Every frame was read where the socket held it; none was copied.
    #[cfg(feature = "rx-in-place")]
    {
        let after = pair.acceptor.rx_path_counts();
        assert_eq!(
            (
                after.in_place - paths_before.in_place,
                after.copied() - paths_before.copied()
            ),
            (3, 0),
            "(frames read in place, units copied) over the three frame turns"
        );
    }
    #[cfg(not(feature = "rx-in-place"))]
    assert!(
        frame_part > 0 && eight > 8 * per_record,
        "the copying loop pays per frame (datagram copy, payload copy, record list): \
         frame part {frame_part}, frame of 8 {eight} against 8 records of {per_record}"
    );
}

/// The query and reply planes on the same loop: a frame of Responses to a
/// pending get, and a frame of Requests to a queryable, each against the
/// copying loop (the control) and in place.
///
/// - A Response read in place is handed to its pending get as a view over the
///   frame (ARCHITECTURE section 9.2): it costs the heap NOTHING, on either
///   backing, against the copying loop's per-frame copies and per-Response
///   owned record (the boxed Response, its keyexpr and payload copies, the
///   resolved keyexpr `String` and the reply the registry builds).
/// - A Request read in place reaches its queryable as a view too, through a
///   responder that borrows the query's keyexpr until a reply is staged (a
///   staged reply is an owned record, on both loops): it costs the heap only
///   the queryable matcher's growable scratch, and nothing on the fixed backing.
///   The copying loop pays its frame and record copies besides.
///
/// Either way each Response's payload and keyexpr reach the get, and each
/// Request's keyexpr and rid reach the queryable, exactly as the shared batch
/// decoder reads them out of the same frame.
#[cfg(feature = "query-queryable")]
mod query_and_reply {
    use super::*;
    use wz_session_core::reply_sink::ReplyView;

    /// Rids the pending get waits on and the queries carry.
    const RID: u64 = 0x31;

    /// What a get or a queryable was handed, in fixed storage: the payload (a
    /// reply's; a query carries none here), the keyexpr, and the rid.
    type Handed = ([u8; 8], [u8; 16], usize, u64);

    fn handed_of((payload, key, len, rid): &Handed) -> (Vec<u8>, String, u64) {
        (
            payload.to_vec(),
            String::from_utf8(key[..*len].to_vec()).expect("a UTF-8 keyexpr"),
            *rid,
        )
    }

    fn record(payload: &[u8], keyexpr: &str, rid: u64) -> Handed {
        let mut bytes = [0u8; 8];
        bytes[..payload.len()].copy_from_slice(payload);
        let mut key = [0u8; 16];
        key[..keyexpr.len()].copy_from_slice(keyexpr.as_bytes());
        (bytes, key, keyexpr.len(), rid)
    }

    /// A frame at `sn` carrying `records` back to back, and its payload.
    fn frame_of_records(sn: u64, records: &[Vec<u8>]) -> (Vec<u8>, Vec<u8>) {
        let payload = records.concat();
        (frame_wire(sn, &[], &payload), payload)
    }

    fn response(i: usize) -> Vec<u8> {
        wz_session_core::response_build::ResponseReplyBuilder::new(
            RID,
            0,
            Some(KEY),
            &payload_of(i),
        )
        .build()
        .expect("a reply")
        .try_as_borrowed()
        .expect("a borrowed view")
        .encode_to_vec()
    }

    fn request(rid: u64) -> Vec<u8> {
        wz_session_core::request_build::RequestQueryBuilder::new(rid, 0, Some(KEY))
            .build()
            .expect("a query")
            .try_as_borrowed()
            .expect("a borrowed view")
            .encode_to_vec()
    }

    /// What the shared batch decoder reads out of a payload of Responses: each
    /// one's payload, keyexpr and rid.
    fn decoded_replies(payload: &[u8]) -> Vec<(Vec<u8>, String, u64)> {
        parse_frame_payload(payload)
            .expect("the frame decodes")
            .iter()
            .map(|message| {
                let NetworkMessage::Response(response) = message else {
                    panic!("only Responses were encoded");
                };
                let wz_codecs::response::ResponseOwnedVariant::CodecZenohReply(reply) =
                    &response.body
                else {
                    panic!("only replies were encoded");
                };
                let wz_codecs::reply::ReplyOwnedVariant::CodecZenohMsgPut(put) = &reply.body else {
                    panic!("only Put replies were encoded");
                };
                let (_, suffix) =
                    wz_session_core::wireexpr_resolve::id_and_suffix(&response.keyexpr.body);
                (
                    wz_session_core::put_payload::inline_bytes(put)
                        .expect("an inline payload")
                        .to_vec(),
                    String::from(suffix.expect("a keyexpr")),
                    response.request_id,
                )
            })
            .collect()
    }

    #[test]
    fn a_reply_read_in_place_reaches_its_get_and_costs_the_heap_nothing() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let link = Rc::new(link);
        let mut pair = Pair::establish(&link, 7505);
        let got: Arc<Mutex<Vec<Handed>>> = Arc::new(Mutex::new(Vec::with_capacity(64)));
        let into = got.clone();
        // Through the sink form, which both backings have.
        pair.observer
            .borrow_mut()
            .replies
            .register_sink(
                RID,
                1,
                None,
                wz_session_core::reply_acceptance::ReplyAcceptance::Any,
                wz_session_core::reply_sink::ConsolidatingSink::passthrough(
                    wz_session_core::reply_sink::BoxedReplySink::new(
                        move |view: &dyn ReplyView| {
                            into.lock().expect("not poisoned").push(record(
                                view.payload(),
                                view.keyexpr(),
                                view.rid(),
                            ));
                        },
                        |_| {},
                    ),
                ),
            )
            .expect("register the get");
        let mut costs = Vec::new();
        for n in [1usize, 2, 8] {
            let records: Vec<Vec<u8>> = (0..n).map(response).collect();
            let (wire, payload) = frame_of_records(pair.next_sn(), &records);
            let expected = decoded_replies(&payload);
            got.lock().expect("not poisoned").clear();
            let (cost, polls, _) = pair.turn(&wire);
            let handed: Vec<_> = got
                .lock()
                .expect("not poisoned")
                .iter()
                .map(handed_of)
                .collect();
            assert_eq!(
                handed, expected,
                "{n} replies (the turn reported {polls:?})"
            );
            costs.push(cost);
        }
        std::println!(
            "replies: frame of 1 {}, of 2 {}, of 8 {}",
            costs[0],
            costs[1],
            costs[2]
        );
        #[cfg(feature = "rx-in-place")]
        assert_eq!(
            costs,
            [0, 0, 0],
            "a Response read in place costs the heap nothing, per frame or per reply"
        );
        #[cfg(not(feature = "rx-in-place"))]
        assert!(
            costs[2] > costs[1] && costs[1] > costs[0] && costs[0] > 0,
            "the copying loop pays per frame and per reply (the instrument's control): \
             {costs:?}"
        );
    }

    #[test]
    fn a_query_read_in_place_reaches_its_queryable_and_costs_only_the_matchers_scratch() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let link = Rc::new(link);
        let mut pair = Pair::establish(&link, 7507);
        let got: Arc<Mutex<Vec<Handed>>> = Arc::new(Mutex::new(Vec::with_capacity(64)));
        let into = got.clone();
        // Through the sink form, which both backings have.
        pair.observer
            .borrow_mut()
            .queryables
            .register_sink(
                KEY,
                Locality::Any,
                false,
                wz_session_core::query_sink::BoxedQuerySink::new(move |view, _out| {
                    into.lock().expect("not poisoned").push(record(
                        &[],
                        view.keyexpr(),
                        view.rid(),
                    ));
                }),
            )
            .expect("register the queryable");
        // A frame as wide as the widest measured one, first: the observer's
        // staging buffers for replies and Finals keep the capacity they grew
        // to, so what follows measures queries and not a first growth.
        let warm: Vec<Vec<u8>> = (0..8).map(|i| request(RID + 100 + i)).collect();
        let (wire, _) = frame_of_records(pair.next_sn(), &warm);
        let _ = pair.turn(&wire);
        let mut costs = Vec::new();
        for n in [1u64, 2, 8] {
            let records: Vec<Vec<u8>> = (0..n).map(|i| request(RID + i)).collect();
            let (wire, _) = frame_of_records(pair.next_sn(), &records);
            let expected: Vec<(Vec<u8>, String, u64)> = (0..n)
                .map(|i| (vec![0u8; 8], String::from(KEY), RID + i))
                .collect();
            got.lock().expect("not poisoned").clear();
            let (cost, polls, _) = pair.turn(&wire);
            let handed: Vec<_> = got
                .lock()
                .expect("not poisoned")
                .iter()
                .map(handed_of)
                .collect();
            assert_eq!(
                handed, expected,
                "{n} queries (the turn reported {polls:?})"
            );
            costs.push(cost);
        }
        std::println!(
            "queries: frame of 1 {}, of 2 {}, of 8 {}",
            costs[0],
            costs[1],
            costs[2]
        );
        // In place a query costs what the queryable matcher's growable scratch
        // costs (its two chunk lists, as the subscriber matcher's), and on the
        // fixed backing nothing: not its decode, not its keyexpr, and not the
        // responder the matched queryable is handed. Its Final is staged into
        // capacity already there and sent through the session's own path.
        #[cfg(feature = "rx-in-place")]
        {
            let scratch = if wz_session_core::bounded::ENFORCES_CAPACITY {
                0
            } else {
                2
            };
            assert_eq!(
                costs,
                [scratch, 2 * scratch, 8 * scratch],
                "a Request read in place costs the heap only the matcher's growable scratch"
            );
        }
        #[cfg(not(feature = "rx-in-place"))]
        assert!(
            costs[2] > costs[1] && costs[1] > costs[0] && costs[0] > 0,
            "the copying loop pays per frame and per query (the instrument's control): \
             {costs:?}"
        );
    }
}

/// A Frame carrying an extension chain of its own: two unit extensions this
/// side does not define, neither mandatory, which a participant reads past.
///
/// In place, the chain is read and judged where the frame lies and handed over
/// OWNED only with an owned record, so a frame of Puts with a chain costs the
/// heap exactly what the same frame without one costs (before, the chain was
/// owned for every frame: one allocation per frame and one per entry). On both
/// loops a record handed over owned comes in a `FramePayload` carrying the
/// chain the copying decode reads, entry for entry.
#[test]
fn a_frame_extension_chain_is_owned_only_when_an_owned_record_needs_it() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    let mut pair = Pair::establish(&link, 7503);
    // Ids 5 and 6, unit encoded, M clear; the first carries the chain flag.
    const CHAIN: [u8; 2] = [0x80 | 0x05, 0x06];

    let (_, payload) = frame_of(0, 2);
    let expected = decoded_puts(&payload);
    let plain = frame_wire(pair.next_sn(), &[], &payload);
    let (plain_cost, _, got) = pair.turn(&plain);
    assert_eq!(got, expected);
    let chained = frame_wire(pair.next_sn(), &CHAIN, &payload);
    let (chained_cost, _, got) = pair.turn(&chained);
    assert_eq!(
        got, expected,
        "the chain changes nothing the subscriber sees"
    );
    std::println!("frame of 2 Puts: {plain_cost} without a chain, {chained_cost} with one");
    #[cfg(feature = "rx-in-place")]
    assert_eq!(
        chained_cost, plain_cost,
        "in place, a frame whose every record is lent never owns its chain"
    );
    #[cfg(not(feature = "rx-in-place"))]
    assert!(
        chained_cost > plain_cost,
        "the copying loop owns the chain of every frame (the instrument's control)"
    );

    let oam = wz_codecs::oam::Oam {
        id: 7,
        ..Default::default()
    }
    .encode_to_vec();
    pair.frame_exts.set(FrameExts::default());
    let chained = frame_wire(pair.next_sn(), &CHAIN, &oam);
    let (_, polls, _) = pair.turn(&chained);
    assert_eq!(
        polls.frame_payload, 1,
        "the OAM record is handed over owned"
    );
    assert_eq!(
        pair.frame_exts.get(),
        FrameExts {
            has_ext: true,
            len: 2,
            headers: [CHAIN[0], CHAIN[1], 0, 0, 0, 0, 0, 0],
        },
        "the owned record's FramePayload carries the frame's chain"
    );
}

/// ARCHITECTURE section 9.3 on the MCU loop: a fragmented message is copied
/// ONCE, each fragment's payload from where the socket holds the datagram into
/// its chain's slot of the session's own `reassembly_pool_mcu` table, and the
/// completed message is read in that slot.
///
/// Measured per fragment turn under the counting allocator: a fragment that
/// does not complete its chain costs the heap NOTHING, and the turn that
/// completes it costs exactly what a whole frame of the same Puts costs (the
/// matcher's growable scratch on the AP backing, nothing on the fixed one).
/// Before this, each fragment was copied onto the heap, its payload copied
/// again out of that copy and staged into a growable buffer, and the completed
/// message copied into a list of owned messages before the first Put reached a
/// subscriber.
///
/// Each delivered payload lies INSIDE the table's slots (the pool's own
/// `slot_index_of_ptr` confirms the slot), which is the witness that nothing
/// copied the message out of its slot on the way. What the subscriber is handed
/// is what the shared batch decoder reads out of the same message, in order.
#[cfg(all(feature = "rx-in-place", feature = "transport-fragmentation"))]
mod fragments {
    use super::*;

    /// The fragmenter's own per-fragment head budget: one header byte and the
    /// widest SN (`frame_encode`'s `FRAG_HEADER_BUDGET`). A chunk of `c` bytes
    /// takes an `mtu` of `c` plus this.
    const HEAD_BUDGET: usize = 1 + 10;

    impl PollTally {
        fn plus(self, other: Self) -> Self {
            Self {
                frame_payload: self.frame_payload + other.frame_payload,
                in_place: self.in_place + other.in_place,
                fragment_in_place: self.fragment_in_place + other.fragment_in_place,
                fragment: self.fragment + other.fragment,
                dropped: self.dropped + other.dropped,
                sn_rejected: self.sn_rejected + other.sn_rejected,
                parse_error: self.parse_error + other.parse_error,
                other: self.other + other.other,
            }
        }
    }

    /// The fragments the session's own fragmenter writes for `body` (a frame
    /// payload) in chunks of `chunk` bytes, reliable, on the initiator's next
    /// SNs, so the acceptor's SN gate admits each as the next.
    fn chain_of(pair: &Pair, body: &[u8], chunk: usize) -> Vec<Vec<u8>> {
        let count = body.len().div_ceil(chunk);
        let base = pair.next_sn();
        for _ in 1..count {
            pair.next_sn();
        }
        let chain = wz_session_core::frame_encode::fragment_body(
            body,
            true,
            chunk + HEAD_BUDGET,
            base,
            pair.initiator.negotiated_sn_mask(),
            None,
        );
        assert_eq!(chain.len(), count, "the fragmenter cut {chunk}-byte chunks");
        chain
    }

    /// What [`send`] measured: every turn's allocations, what the turns
    /// reported summed, what the subscriber was handed on the last turn, and
    /// the addresses it was handed at.
    type Sent = (Vec<usize>, PollTally, Vec<(Vec<u8>, String)>, Vec<usize>);

    /// Send `fragments` one turn each, and what that measured ([`Sent`]).
    fn send(pair: &mut Pair, fragments: &[Vec<u8>]) -> Sent {
        let mut costs = Vec::with_capacity(fragments.len());
        let mut tally = PollTally::default();
        let mut delivered = Vec::new();
        for fragment in fragments {
            let (cost, polls, got) = pair.turn(fragment);
            costs.push(cost);
            tally = tally.plus(polls);
            delivered = got;
        }
        let at = pair
            .delivered
            .lock()
            .expect("not poisoned")
            .iter()
            .map(|d| d.3)
            .collect();
        (costs, tally, delivered, at)
    }

    /// The table's slots are all home and the Router holds no chain: the slot
    /// accounting identity at a quiescent point.
    fn all_slots_home(pair: &Pair) {
        let router = pair.acceptor.reassembly();
        let arena = router.staging();
        assert_eq!(
            (
                router.active_chains(),
                arena.free_count(),
                router.staging_available()
            ),
            (0, 4, 4),
            "(chains open, slots on the pool's freelist, slots the arena serves)"
        );
    }

    #[test]
    fn a_fragmented_message_is_staged_once_and_read_in_its_slot() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let link = Rc::new(link);
        let mut pair = Pair::establish(&link, 7497);
        let fixed = wz_session_core::bounded::ENFORCES_CAPACITY;
        let matcher_scratch = if fixed { 0 } else { 2 };
        for puts in [1usize, 2, 8] {
            let (_, body) = frame_of(0, puts);
            let expected = decoded_puts(&body);
            // Chains from two fragments (the last one byte) to one per byte.
            for chunk in [body.len() - 1, body.len() / 2, 7, 3, 2, 1] {
                let chain = chain_of(&pair, &body, chunk);
                let before = pair.acceptor.rx_path_counts();
                let (costs, tally, delivered, at) = send(&mut pair, &chain);
                let after = pair.acceptor.rx_path_counts();
                std::println!(
                    "{puts} Put(s) in {} fragment(s) of {chunk}: allocations per turn {costs:?}",
                    chain.len()
                );
                let (last, staged) = costs.split_last().expect("a chain");
                assert!(
                    staged.iter().all(|cost| *cost == 0),
                    "a fragment that does not complete its chain costs the heap nothing: \
                     {costs:?} ({puts} Puts, chunk {chunk})"
                );
                assert_eq!(
                    *last,
                    puts * matcher_scratch,
                    "the completing turn costs what a whole frame of the same Puts does \
                     ({puts} Puts, chunk {chunk})"
                );
                assert_eq!(delivered, expected, "{puts} Puts, chunk {chunk}");
                let arena = pair.acceptor.reassembly().staging();
                assert!(
                    at.iter()
                        .all(|addr| arena.slot_of(*addr as *const u8).is_some()),
                    "every payload was handed over inside a reassembly slot"
                );
                assert_eq!(
                    tally,
                    PollTally {
                        in_place: puts,
                        fragment_in_place: chain.len(),
                        ..PollTally::default()
                    },
                    "{puts} Puts, chunk {chunk}"
                );
                assert_eq!(
                    (
                        after.fragment_in_place - before.fragment_in_place,
                        after.copied() - before.copied()
                    ),
                    (chain.len() as u32, 0),
                    "(fragments read in place, units copied)"
                );
                all_slots_home(&pair);
            }
        }
    }

    /// The largest message one slot holds is reassembled; one Put more is
    /// refused at the fragment that crosses the slot, COUNTED, and its slot goes
    /// home; the next message is reassembled as if nothing had happened.
    #[test]
    fn a_message_past_its_slot_is_refused_and_counted() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let link = Rc::new(link);
        let mut pair = Pair::establish(&link, 7499);
        let put_len = frame_of(0, 1).1.len();
        let fits = 4096 / put_len;
        // The widest fragment the session socket takes whole: its receive slot
        // less the fragmenter's head budget (the slim profile's slot is 256).
        let chunk = wz_link_lwip::rx_sockets::SESSION_RX_SLOT_SIZE - HEAD_BUDGET;

        let (_, body) = frame_of(0, fits);
        let chain = chain_of(&pair, &body, chunk);
        let (_, tally, delivered, _) = send(&mut pair, &chain);
        assert_eq!(delivered.len(), fits, "the fullest slot is reassembled");
        assert_eq!(tally.dropped, 0);
        all_slots_home(&pair);

        let (_, body) = frame_of(0, fits + 1);
        assert!(body.len() > 4096, "one Put more does not fit a slot");
        let chain = chain_of(&pair, &body, chunk);
        // Up to the fragment that crosses the slot's end.
        let crossing = 4096 / chunk + 1;
        let (_, tally, delivered, _) = send(&mut pair, &chain[..crossing]);
        assert_eq!(
            (delivered.len(), tally.dropped),
            (0, 1),
            "(Puts delivered, chains dropped)"
        );
        all_slots_home(&pair);

        let (_, body) = frame_of(0, 2);
        let chain = chain_of(&pair, &body, 7);
        let (_, _, delivered, _) = send(&mut pair, &chain);
        assert_eq!(delivered, decoded_puts(&body));
        all_slots_home(&pair);
    }

    /// A duplicate fragment is refused by the channel's SN gate and CLEARS the
    /// chain it would have joined (the dbuf-clear both references make); a
    /// skipped fragment passes the gate and the Router aborts the chain,
    /// counted. Either way the slot goes home and the next message reassembles.
    #[test]
    fn a_duplicate_or_a_gap_ends_the_chain_and_gives_its_slot_back() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let link = Rc::new(link);
        let mut pair = Pair::establish(&link, 7501);
        let (_, body) = frame_of(0, 2);
        let expected = decoded_puts(&body);

        let chain = chain_of(&pair, &body, 7);
        assert!(chain.len() >= 3);
        let resent = [chain[0].clone(), chain[1].clone(), chain[1].clone()];
        let (_, tally, delivered, _) = send(&mut pair, &resent);
        assert_eq!(
            (delivered.len(), tally.sn_rejected, tally.fragment_in_place),
            (0, 1, 2),
            "(Puts delivered, SN rejections, fragments staged)"
        );
        all_slots_home(&pair);

        let chain = chain_of(&pair, &body, 7);
        let gapped = [chain[0].clone(), chain[2].clone()];
        let (_, tally, delivered, _) = send(&mut pair, &gapped);
        assert_eq!(
            (delivered.len(), tally.dropped),
            (0, 1),
            "(Puts delivered, chains dropped)"
        );
        all_slots_home(&pair);

        let chain = chain_of(&pair, &body, 7);
        let (_, _, delivered, _) = send(&mut pair, &chain);
        assert_eq!(delivered, expected);
        all_slots_home(&pair);
    }
}
