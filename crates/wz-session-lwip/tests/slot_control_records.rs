// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the CONTROL records of a frame cost the heap on the per-session slot
//! profile, counted (fixed-memory step S9d, the codec layer's owned mirrors).
//!
//! `session_slot_allocations` counts a session from its slot to its close with a
//! Put, a KeepAlive and a Close in it. Those are the records the receive path of
//! that profile has read where the frame lies since step S3. This file counts the
//! other kinds of network message a peer puts in a frame, which that file never
//! sends, each in a frame of its own so that a cost belongs to one kind:
//!
//! - a `DeclKexpr` (a keyexpr alias), a `DeclSubscriber` and the `UndeclSubscriber`
//!   that withdraws it, a `DeclFinal`;
//! - an `Interest` that asks for subscribers, and the `Interest` that cancels it;
//! - a `ResponseFinal` (the end of a reply stream nobody here is waiting for);
//! - an `Oam`, which nothing reads, and a MID this build has no decoder for.
//!
//! Before the slot profile lent them they were each decoded into an owned message:
//! a boxed `DeclareOwned` whose lists and text are heap containers, a batch `Vec`
//! to hold it and, when the frame carried an extension chain, a `Vec` of the
//! chain's own entries. Each of those windows must now cost the heap NOTHING, and
//! each record must still do what it did: the alias must resolve a later message,
//! the subscriber declaration must reach the application's observer, the interest
//! must be answered, and the one frame that carries a record this build must refuse
//! (a mandatory extension nobody implements) must end the walk with the error.
//!
//! The count is attributed to the measurement's own thread (`support/alloc_count`),
//! and only the acceptor's ONE drive iteration that reads the frame is counted:
//! the initiator's send, which builds an owned message to encode, is outside the
//! window, as the frame the test builds is.
//!
//! Host-test level: no board runs it, and the stack the lent record takes is not
//! measured here.

#![cfg(all(
    feature = "session-slot",
    feature = "declare-subscriber",
    feature = "codec-response-final"
))]
// A refused claim hands back what it was offered, a whole driver and its socket,
// which is what makes the refusal free of the heap; boxing it would allocate.
#![allow(clippy::result_large_err)]

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use wz_codecs::wire_const;
#[cfg(not(feature = "static-link-storage"))]
use wz_link_lwip::rx_sockets::bind_session_rx;
use wz_link_lwip::rx_sockets::SessionRxSocket;
#[cfg(feature = "static-link-storage")]
use wz_link_lwip::test_bind::session_rx as bind_session_rx;
use wz_link_lwip::{ipv4_addr_from_octets, LwipLink};
use wz_runtime_coop::session_drive::{SessionDriveConfig, SessionPump, SessionRole};
use wz_runtime_coop::session_runtime::{new_session_in_slot, SessionHandle};
use wz_runtime_coop::{ClockSource, CoopRuntime, CoopTime};
use wz_session_core::decl_sink::{BoxedDeclSink, BoxedUndeclSink, DeclView};
use wz_session_core::driver_loop::{DriverOutcome, IterationEvent};
use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome};
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::reliability::Reliability;
use wz_session_core::session_init_params::{cookie_bytes, zid_bytes, SessionInitParams};
use wz_session_core::session_slot::{SessionSlots, SlotDriver};
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::WhatAmI;
use wz_session_lwip::driver::{share_socket, LwipUdpDriver};
use wz_session_lwip::{app_layer, LwipSessionLink};

#[path = "support/alloc_count.rs"]
mod alloc_count;
use alloc_count::Measurement;

#[global_allocator]
static GLOBAL: alloc_count::CountingAllocator = alloc_count::CountingAllocator;

/// A clock that never moves: no deadline fires, so a session does only what the
/// other end asks of it.
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

type Rt = CoopRuntime<Frozen>;
type Pump = SessionPump<Frozen, LwipSessionLink<Rc<LwipLink>>>;
type Handle = SessionHandle<Frozen>;
type Slots = SessionSlots<Rt, CoopTime<Frozen>, LwipUdpDriver, Counting, 2>;
static SESSIONS: Slots = SessionSlots::new();

fn params(zid: u8) -> SessionInitParams {
    SessionInitParams {
        version: 0x09,
        whatami: WhatAmI::Peer,
        zid: zid_bytes(&[zid; 4]),
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: cookie_bytes(&[]),
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        cookie_signing_key: SigningKey::from_slice(&[7u8; 32]).expect("key"),
    }
}

/// What the acceptor's application layer was told, in counters (a recording that
/// stored a keyexpr would allocate inside the window it is measuring).
#[derive(Default)]
struct Told {
    declared: AtomicUsize,
    declared_id: AtomicUsize,
    undeclared: AtomicUsize,
    undeclared_id: AtomicUsize,
}

/// One end: the bundle, its pump, the application layer's callback, and what that
/// layer was told. The initiator also keeps the driver it sends raw datagrams
/// through.
struct End {
    actions: Handle,
    pump: Pump,
    on_event: Box<dyn FnMut(IterationEvent<'_>)>,
    observer: Rc<RefCell<ApplicationLayerObserver>>,
    told: Arc<Told>,
    sender: SlotDriver<LwipUdpDriver>,
}

impl End {
    /// One drive iteration; the session must not have ended.
    fn step(&mut self) {
        assert!(
            self.pump.step(&mut self.on_event).is_none(),
            "the session ended on a turn"
        );
    }
}

fn config(role: SessionRole) -> SessionDriveConfig {
    SessionDriveConfig {
        timeouts: SessionTimeouts::spec_defaults(),
        role,
        max_iters: None,
    }
}

/// One end's state, in a slot: the driver over its socket, the entropy source, the
/// bundle, and the link the loop reads. Nothing here is on the heap.
fn create(
    link: &Rc<LwipLink>,
    runtime: &Rt,
    socket: SessionRxSocket,
    peer: ([u8; 4], u16),
    zid: u8,
) -> (
    Handle,
    LwipSessionLink<Rc<LwipLink>>,
    SlotDriver<LwipUdpDriver>,
) {
    let driver = LwipUdpDriver::new(share_socket(socket), ipv4_addr_from_octets(peer.0), peer.1);
    let Ok(claim) = SESSIONS.claim(driver, Counting(zid)) else {
        panic!("a slot is free");
    };
    let sender = claim.driver_handle();
    let pump_link = LwipSessionLink::new(link.clone(), claim.driver_handle());
    let actions = new_session_in_slot(claim, params(zid), CoopTime::new(runtime));
    (actions, pump_link, sender)
}

/// The application layer of the acceptor: an observer with a declaration observer
/// that counts what the peer declared and undeclared.
fn application(
    actions: &Handle,
) -> (
    Box<dyn FnMut(IterationEvent<'_>)>,
    Rc<RefCell<ApplicationLayerObserver>>,
    Arc<Told>,
) {
    let told = Arc::new(Told::default());
    let observer = Rc::new(RefCell::new(ApplicationLayerObserver::new()));
    {
        let mut observer = observer.borrow_mut();
        let seen = told.clone();
        observer
            .remote_subscribers
            .on_subscriber_declared_sink(BoxedDeclSink::new(move |decl: &dyn DeclView| {
                seen.declared.fetch_add(1, Ordering::SeqCst);
                seen.declared_id.store(decl.id() as usize, Ordering::SeqCst);
            }))
            .expect("install the declaration observer");
        let seen = told.clone();
        observer
            .remote_subscribers
            .on_subscriber_undeclared_sink(BoxedUndeclSink::new(move |id: u64| {
                seen.undeclared.fetch_add(1, Ordering::SeqCst);
                seen.undeclared_id.store(id as usize, Ordering::SeqCst);
            }))
            .expect("install the undeclaration observer");
    }
    (
        Box::new(app_layer::dispatch_to(observer.clone(), actions.clone())),
        observer,
        told,
    )
}

/// Both ends established over the loopback, each driven by its own pump.
fn establish(link: &Rc<LwipLink>, runtime: &Rt, port: u16) -> (End, End) {
    let acceptor_socket = bind_session_rx(link, port).expect("bind the acceptor");
    let initiator_socket = bind_session_rx(link, 0).expect("bind the initiator");
    let (a_actions, a_link, a_sender) = create(link, runtime, acceptor_socket, ([0; 4], 0), 0xa1);
    let (i_actions, i_link, i_sender) = create(
        link,
        runtime,
        initiator_socket,
        ([127, 0, 0, 1], port),
        0xb1,
    );
    let (a_on_event, a_observer, a_told) = application(&a_actions);
    let (i_on_event, i_observer, i_told) = application(&i_actions);
    let mut acceptor = End {
        pump: SessionPump::new(
            runtime.clone(),
            a_link,
            a_actions.clone(),
            CoopTime::new(runtime),
            config(SessionRole::Acceptor),
        ),
        actions: a_actions,
        on_event: a_on_event,
        observer: a_observer,
        told: a_told,
        sender: a_sender,
    };
    let mut initiator = End {
        pump: SessionPump::new(
            runtime.clone(),
            i_link,
            i_actions.clone(),
            CoopTime::new(runtime),
            config(SessionRole::Initiator),
        ),
        actions: i_actions,
        on_event: i_on_event,
        observer: i_observer,
        told: i_told,
        sender: i_sender,
    };
    for _ in 0..64 {
        initiator.step();
        acceptor.step();
        if acceptor.actions.is_established() && initiator.actions.is_established() {
            break;
        }
    }
    assert!(
        acceptor.actions.is_established() && initiator.actions.is_established(),
        "the pair established over the loopback"
    );
    // A turn each way settles whatever the last handshake turn left in flight.
    for _ in 0..4 {
        initiator.step();
        acceptor.step();
    }
    (acceptor, initiator)
}

/// A reliable Frame at `sn` carrying `payload`, with `chain` as its own extension
/// chain (the Z flag set when there is one): the header, the SN as a VLE (seven
/// bits a byte, low first, the top bit saying another follows), the chain, the
/// payload.
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

/// The kinds of record this file sends, as the bytes of one network message.
mod record {
    use wz_session_core::declare_build::{
        build_declare_final, build_declare_kexpr, build_declare_subscriber,
        build_undeclare_subscriber,
    };
    use wz_session_core::interest_build::{build_interest_final, build_interest_subscribers};
    use wz_session_core::response_final_build::build_response_final;
    use wz_session_core::sample::QosLevel;

    /// The bytes of an owned `Declare`, through the borrowed view that owns the
    /// encoder.
    fn declare_bytes(declare: &wz_codecs::declare::DeclareOwned) -> Vec<u8> {
        declare
            .try_as_borrowed()
            .expect("a borrowed view")
            .encode_to_vec()
    }

    /// The bytes of an owned `Interest`.
    fn interest_bytes(interest: &wz_codecs::interest::InterestOwned) -> Vec<u8> {
        interest
            .try_as_borrowed()
            .expect("a borrowed view")
            .encode_to_vec()
    }

    /// A `DeclKexpr` binding `id` to `suffix`.
    pub fn alias(id: u64, suffix: &str) -> Vec<u8> {
        declare_bytes(&build_declare_kexpr(id, suffix).expect("a DeclKexpr"))
    }

    /// A `DeclSubscriber` of `id` on the literal `suffix`.
    pub fn subscriber(id: u64, suffix: &str) -> Vec<u8> {
        declare_bytes(&build_declare_subscriber(id, 0, Some(suffix)).expect("a DeclSubscriber"))
    }

    /// A `DeclSubscriber` of `id` on `suffix` under the alias `mapping`.
    pub fn subscriber_on_alias(id: u64, mapping: u64, suffix: &str) -> Vec<u8> {
        declare_bytes(
            &build_declare_subscriber(id, mapping, Some(suffix)).expect("a DeclSubscriber"),
        )
    }

    /// An `UndeclSubscriber` of `id`.
    pub fn undeclare_subscriber(id: u64) -> Vec<u8> {
        declare_bytes(&build_undeclare_subscriber(id))
    }

    /// A `DeclFinal`.
    pub fn declare_final() -> Vec<u8> {
        declare_bytes(&build_declare_final())
    }

    /// A subscriber `Interest` on the literal `suffix`, for the current
    /// subscribers, the future ones, or both.
    pub fn interest_subscribers(id: u64, suffix: &str, current: bool, future: bool) -> Vec<u8> {
        interest_bytes(
            &build_interest_subscribers(id, current, future, 0, Some(suffix)).expect("an Interest"),
        )
    }

    /// The `Interest` that cancels `id`.
    pub fn interest_final(id: u64) -> Vec<u8> {
        interest_bytes(&build_interest_final(id))
    }

    /// A `ResponseFinal` of request `rid`.
    pub fn response_final(rid: u64) -> Vec<u8> {
        fn bytes(done: &wz_codecs::response_final::ResponseFinalOwned) -> Vec<u8> {
            done.try_as_borrowed()
                .expect("a borrowed view")
                .encode_to_vec()
        }
        bytes(&build_response_final(rid, QosLevel::default()))
    }

    /// An Oam of id `id` with the UNIT body.
    pub fn oam(id: u64) -> Vec<u8> {
        use wz_codecs::oam::Oam;
        Oam {
            id,
            ..Oam::default()
        }
        .encode_to_vec()
    }

    /// A record whose header names a network MID this build has no decoder for.
    pub fn unknown_mid() -> Vec<u8> {
        vec![0x15, 0x01, 0x02, 0x03]
    }
}

/// The cost of one acceptor iteration that reads `wire`, and the number of
/// iterations the session survived (a refused frame ends the session).
fn read(
    measure: &Measurement,
    acceptor: &mut End,
    initiator: &End,
    what: &str,
    wire: &[u8],
) -> usize {
    let sent = initiator.sender.send_blocking(wire, Reliability::Reliable);
    assert_eq!(
        sent,
        LinkSendOutcome::Sent,
        "{what}: the frame left the socket"
    );
    let (finished, allocations): (Option<DriverOutcome>, usize) =
        measure.count(what, || acceptor.pump.step(&mut acceptor.on_event));
    assert!(finished.is_none(), "{what}: the acceptor ended on the turn");
    println!("{what}: {allocations} allocation(s)");
    allocations
}

/// The initiator's next reliable transmit SN.
fn next_sn(initiator: &End) -> u64 {
    initiator.actions.next_outbound_frame_sn(
        wz_session_core::qos::Priority::DEFAULT,
        true,
        initiator.actions.negotiated_sn_mask(),
    )
}

/// One record in one frame, at the next SN, sent from the initiator and read by
/// one acceptor iteration. Returns that iteration's allocations.
fn one_record(
    measure: &Measurement,
    acceptor: &mut End,
    initiator: &End,
    sn: &Cell<u64>,
    what: &str,
    record: &[u8],
) -> usize {
    let at = sn.get();
    sn.set(at + 1);
    read(
        measure,
        acceptor,
        initiator,
        what,
        &frame_wire(at, &[], record),
    )
}

/// What the session's reply sink still allocates to answer a CURRENT interest: it
/// builds the owned `Declare` that carries the terminating `Final`
/// (`declare_build::build_declare_final_reply`), whose envelope extension chain is a
/// heap list. That is the drain of the staged answer, not the receive of the
/// interest, and it is the one allocation a frame of control records has left.
const ANSWER_BUILD_ALLOCATIONS: usize = 1;

/// A frame of every control kind this file sends costs the heap nothing on the slot
/// profile, and each record does what it did.
#[test]
fn a_control_record_lent_in_place_costs_the_heap_nothing_and_does_its_work() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    static RUNTIME: wz_runtime_coop::RuntimeCell<Frozen, 1, 64, 1> =
        wz_runtime_coop::RuntimeCell::new();
    let runtime = RUNTIME.start(Frozen).expect("the runtime is started once");
    let (mut acceptor, initiator) = establish(&link, &runtime, 7731);

    let measure = Measurement::new();
    let sn = Cell::new(next_sn(&initiator));
    let wrong: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let check = |what: &str, allocations: usize| {
        if allocations != 0 {
            wrong
                .borrow_mut()
                .push(format!("{what}: {allocations} allocation(s)"));
        }
    };

    // An alias, then a declaration NAMING the alias: the declaration reaches the
    // observer under the keyexpr the alias stands for, which it cannot do unless
    // the alias was absorbed.
    let n = one_record(
        &measure,
        &mut acceptor,
        &initiator,
        &sn,
        "a DeclKexpr",
        &record::alias(5, "ctl/area"),
    );
    check("a DeclKexpr", n);
    assert_eq!(
        acceptor.observer.borrow().subscribers.peer().alias_count(),
        1,
        "the alias was bound"
    );

    let told = acceptor.told.clone();
    let n = one_record(
        &measure,
        &mut acceptor,
        &initiator,
        &sn,
        "a DeclSubscriber on an alias",
        &record::subscriber_on_alias(9, 5, "/x"),
    );
    check("a DeclSubscriber on an alias", n);
    assert_eq!(
        (
            told.declared.load(Ordering::SeqCst),
            told.declared_id.load(Ordering::SeqCst)
        ),
        (1, 9),
        "(declarations the application was told of, the id of the last)"
    );

    let n = one_record(
        &measure,
        &mut acceptor,
        &initiator,
        &sn,
        "a literal DeclSubscriber",
        &record::subscriber(11, "ctl/lit"),
    );
    check("a literal DeclSubscriber", n);
    assert_eq!(
        told.declared.load(Ordering::SeqCst),
        2,
        "the second declaration"
    );

    let n = one_record(
        &measure,
        &mut acceptor,
        &initiator,
        &sn,
        "an UndeclSubscriber",
        &record::undeclare_subscriber(9),
    );
    check("an UndeclSubscriber", n);
    assert_eq!(
        (
            told.undeclared.load(Ordering::SeqCst),
            told.undeclared_id.load(Ordering::SeqCst)
        ),
        (1, 9),
        "(withdrawals the application was told of, the id of the last)"
    );

    let n = one_record(
        &measure,
        &mut acceptor,
        &initiator,
        &sn,
        "a DeclFinal",
        &record::declare_final(),
    );
    check("a DeclFinal", n);

    // A FUTURE-only interest is kept and answers nothing, so its window is the
    // receive alone. The interest that also asks for the CURRENT subscribers is
    // answered with the terminating `Final` the session stages and sends in the same
    // turn; that answer is built by the session's reply sink as an owned `Declare`
    // (one allocation, `declare_envelope_extensions`), the drain of the staging and not the
    // receive, which is the interface the carry names. The receive of the same
    // record is what this file claims.
    let interests_before = acceptor
        .observer
        .borrow()
        .subscribers
        .peer()
        .interest_count();
    let n = one_record(
        &measure,
        &mut acceptor,
        &initiator,
        &sn,
        "a future subscriber Interest",
        &record::interest_subscribers(21, "ctl/**", false, true),
    );
    check("a future subscriber Interest", n);
    assert_eq!(
        acceptor
            .observer
            .borrow()
            .subscribers
            .peer()
            .interest_count(),
        interests_before + 1,
        "the interest was kept"
    );
    let n = one_record(
        &measure,
        &mut acceptor,
        &initiator,
        &sn,
        "an Interest cancelling it",
        &record::interest_final(21),
    );
    check("an Interest cancelling it", n);
    assert_eq!(
        acceptor
            .observer
            .borrow()
            .subscribers
            .peer()
            .interest_count(),
        interests_before,
        "the interest was retired"
    );
    let n = one_record(
        &measure,
        &mut acceptor,
        &initiator,
        &sn,
        "a current subscriber Interest",
        &record::interest_subscribers(22, "ctl/**", true, true),
    );
    if n > ANSWER_BUILD_ALLOCATIONS {
        wrong.borrow_mut().push(format!(
            "a current subscriber Interest: {n} allocation(s); the receive costs none and \
             the answer's owned build at most {ANSWER_BUILD_ALLOCATIONS}"
        ));
    }
    let n = one_record(
        &measure,
        &mut acceptor,
        &initiator,
        &sn,
        "an Interest cancelling that one",
        &record::interest_final(22),
    );
    check("an Interest cancelling that one", n);

    let n = one_record(
        &measure,
        &mut acceptor,
        &initiator,
        &sn,
        "a ResponseFinal",
        &record::response_final(77),
    );
    check("a ResponseFinal", n);
    let n = one_record(
        &measure,
        &mut acceptor,
        &initiator,
        &sn,
        "an Oam",
        &record::oam(3),
    );
    check("an Oam", n);
    let n = one_record(
        &measure,
        &mut acceptor,
        &initiator,
        &sn,
        "an unknown MID",
        &record::unknown_mid(),
    );
    check("an unknown MID", n);

    // Several kinds in ONE frame, in wire order: the same costs, and each does its
    // work (the declaration is told, then withdrawn).
    let before = (
        told.declared.load(Ordering::SeqCst),
        told.undeclared.load(Ordering::SeqCst),
    );
    let mut batch = Vec::new();
    batch.extend_from_slice(&record::subscriber(31, "ctl/batch"));
    batch.extend_from_slice(&record::declare_final());
    batch.extend_from_slice(&record::undeclare_subscriber(31));
    batch.extend_from_slice(&record::oam(4));
    let n = one_record(
        &measure,
        &mut acceptor,
        &initiator,
        &sn,
        "a mixed frame",
        &batch,
    );
    check("a mixed frame", n);
    assert_eq!(
        (
            told.declared.load(Ordering::SeqCst) - before.0,
            told.undeclared.load(Ordering::SeqCst) - before.1
        ),
        (1, 1),
        "(declared, withdrawn) by one frame of four records"
    );

    let wrong = wrong.into_inner();
    assert!(wrong.is_empty(), "{wrong:#?}");
}
