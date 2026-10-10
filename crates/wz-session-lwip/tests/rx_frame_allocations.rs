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
//! The quantity asserted is the FRAME PATH's share of that count. A frame's
//! cost is `frame + N * record`: the per-record part (the owned message the
//! decode builds and the keyexpr the subscriber match resolves) is a later
//! step's, and the frame part is everything that is paid once per datagram
//! whatever it carries — the datagram copied out of the socket, the frame's
//! payload copied out of that copy, and the list the records are collected
//! into, whose length the peer chooses. Measuring frames of 1, 2 and 8 records
//! separates the two without naming either: `frame = 2 * cost(1) - cost(2)`,
//! and a frame part of zero makes the cost exactly linear in `N`.
//!
//! - With `rx-in-place` the loop dispatches the datagram where the socket holds
//!   it, record by record: the frame part must be ZERO.
//! - Without it (the copying loop every shipped image runs today) the frame
//!   part must be POSITIVE. That half is the instrument's own control: a count
//!   that read zero on the loop that is known to copy would prove nothing about
//!   the loop that is meant not to.
//!
//! Either way every Put must reach the subscriber with exactly the bytes the
//! shared batch decoder reads out of the same payload (the decoder the AP and
//! the copying loop dispatch from), in order.
//!
//! A second test pins the one behaviour the two loops are meant to differ in:
//! a frame whose last record does not decode.
//!
//! Host-test level: no board runs it, and the stack depth of the in-place
//! dispatch is not measured here.

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
    // A reliable Frame with no extensions: the header, the SN as a VLE (seven
    // bits a byte, low first, the top bit saying another follows), the payload.
    let mut wire = vec![wire_const::T_MID_FRAME | wire_const::FLAG_T_FRAME_R];
    let mut rest = sn;
    while rest >= 0x80 {
        wire.push((rest as u8 & 0x7f) | 0x80);
        rest >>= 7;
    }
    wire.push(rest as u8);
    wire.extend_from_slice(&payload);
    (wire, payload)
}

/// The Put payloads the shared batch decoder reads out of `payload`, in order.
fn decoded_puts(payload: &[u8]) -> Vec<Vec<u8>> {
    let messages = parse_frame_payload(payload).expect("the frame decodes");
    let mut out = Vec::new();
    for message in &messages {
        let NetworkMessage::Push(push) = message else {
            panic!("only Push messages were encoded");
        };
        let PushOwnedVariant::CodecZenohMsgPut(put) = &push.body else {
            panic!("only Puts were encoded");
        };
        out.push(
            wz_session_core::put_payload::inline_bytes(put)
                .expect("an inline payload")
                .to_vec(),
        );
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
    sn_rejected: usize,
    parse_error: usize,
    other: usize,
}

/// The two sessions, established, and what the acceptor's subscriber saw.
struct Pair {
    acceptor: Pump,
    on_event: Box<dyn FnMut(IterationEvent<'_>)>,
    /// What the acceptor's drive reported, by kind, since the last frame turn.
    polls: Rc<Cell<PollTally>>,
    /// The initiator's session: whose transmit SN each measured frame takes,
    /// so the acceptor's SN gate admits it as the initiator's next frame.
    initiator: Rc<SessionLinkActions<CoopRuntime<Frozen>, CoopTime<Frozen>>>,
    /// The initiator's socket: what the measured frames are sent from.
    initiator_sink: Rc<dyn BoxedLinkDriver>,
    /// Every Put payload the subscriber was handed, in order. Its capacity is
    /// reserved before anything is measured, so recording a delivery does not
    /// itself allocate.
    delivered: Arc<Mutex<Vec<[u8; 8]>>>,
}

impl Pair {
    fn establish(link: &Rc<LwipLink>, port: u16) -> Self {
        let runtime = CoopRuntime::new(Frozen);
        let links = LwipLinks::new(link.clone());
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

        let delivered: Arc<Mutex<Vec<[u8; 8]>>> = Arc::new(Mutex::new(Vec::with_capacity(64)));
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
                    seen.lock().expect("not poisoned").push(bytes);
                }),
            )
            .expect("register the subscriber");
        let mut dispatch = app_layer::dispatch_to(observer, acceptor_actions.clone());
        let polls = Rc::new(Cell::new(PollTally::default()));
        let tally = polls.clone();
        let mut on_event: Box<dyn FnMut(IterationEvent<'_>)> = Box::new(move |event| {
            if let IterationEvent::Poll(outcome) = &event {
                let mut t = tally.get();
                match outcome {
                    DriverLoopOutcome::FramePayload { .. } => t.frame_payload += 1,
                    DriverLoopOutcome::RxSnRejected { .. } => t.sn_rejected += 1,
                    DriverLoopOutcome::ParseError(_) => t.parse_error += 1,
                    _ => t.other += 1,
                }
                tally.set(t);
            }
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
            initiator: initiator_actions,
            initiator_sink,
            delivered,
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
    fn frame_turn(&mut self, n: usize) -> (usize, Vec<Vec<u8>>) {
        let (wire, payload) = frame_of(self.next_sn(), n);
        let expected = decoded_puts(&payload);
        let (allocations, polls, delivered) = self.turn(&wire);
        assert_eq!(
            delivered, expected,
            "every Put reached the subscriber, in order, with the bytes the \
             shared batch decoder reads out of the same payload (the turn reported {polls:?})"
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
    fn turn(&mut self, wire: &[u8]) -> (usize, PollTally, Vec<Vec<u8>>) {
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
            .map(|p| p.to_vec())
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

    #[cfg(feature = "rx-in-place")]
    let expected = (
        whole,
        PollTally {
            frame_payload: 2,
            parse_error: 1,
            ..PollTally::default()
        },
    );
    #[cfg(not(feature = "rx-in-place"))]
    let expected = (
        Vec::<Vec<u8>>::new(),
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

#[test]
fn the_frame_path_of_an_inbound_frame_is_counted_per_frame_and_per_record() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    let mut pair = Pair::establish(&link, 7491);

    let idle = pair.idle_turn();
    let (one, puts) = pair.frame_turn(1);
    assert_eq!(puts.len(), 1);
    let (two, _) = pair.frame_turn(2);
    let (eight, puts) = pair.frame_turn(8);
    assert_eq!(puts.len(), 8);
    // Printed so a run reports its numbers, red or green.
    std::println!("allocations: idle {idle}, frame of 1 {one}, of 2 {two}, of 8 {eight}");

    // The turn with nothing to receive allocates nothing, so what the frame
    // turns count is the frame's.
    assert_eq!(idle, 0, "an idle iteration allocates nothing");
    let per_record = two - one;
    let frame_part = (2 * one).checked_sub(two).expect("cost(2) <= 2 * cost(1)");

    #[cfg(feature = "rx-in-place")]
    assert_eq!(
        (frame_part, eight),
        (0, 8 * per_record),
        "(allocations paid once per frame, cost of a frame of 8): with the datagram \
         dispatched where the socket holds it, a frame costs only its records"
    );
    #[cfg(not(feature = "rx-in-place"))]
    assert!(
        frame_part > 0 && eight > 8 * per_record,
        "the copying loop pays per frame (datagram copy, payload copy, record list): \
         frame part {frame_part}, frame of 8 {eight} against 8 records of {per_record}"
    );
}
