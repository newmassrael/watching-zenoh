// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The receive path of the per-session slot profile built WITHOUT an allocator: a datagram that
//! holds several transport messages is read where it lies, one unit after another, in the
//! iteration that received it.
//!
//! The other slot-profile files of this crate are built with the crate's default `alloc`, which
//! reaches `wz-session-core` and gives the receive a heap; it reads the rest of a datagram where
//! it lies too (`drive::dispatch_datagram`), which `slot_control_records` holds. This file is
//! built with `--no-default-features`, so no crate of the session tier
//! links `alloc`, and its application layer is the slot profile's own: the process-wide
//! [`SlotApp`] observer of closed sink types, dispatched by [`SlotDispatch`], in place of the
//! heap profile's `ApplicationLayerObserver` and its boxed closures.
//!
//! The test binary itself is host code: the harness, the counting allocator and the records the
//! test writes live on the host's heap. The claim is that the acceptor's iterations, the window
//! the allocator counts, ask it for nothing.
//!
//! lwIP is process-global: the one test holds the harness's lock for its whole body.

// Only a build with no allocator takes the walk this file is about; with `alloc` the file is empty
// (the heap form of the same datagrams is `slot_control_records`'). Not with `reassembly`, where
// `SessionPump::new` does not exist (`slot_control_records` says why).
#![cfg(all(
    feature = "session-slot",
    not(feature = "alloc"),
    not(feature = "reassembly"),
    feature = "session-unicast-open",
    feature = "session-unicast-accept",
    feature = "declare-subscriber"
))]
// A refused claim hands back what it was offered, a whole driver and its socket,
// which is what makes the refusal free of the heap; boxing it would allocate.
#![allow(clippy::result_large_err)]

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

use wz_codecs::wire_const;
use wz_link_lwip::rx_sockets::{bind_session_rx, SessionRxSocket};
use wz_link_lwip::{ipv4_addr_from_octets, LwipLink};
use wz_runtime_coop::session_drive::{SessionDriveConfig, SessionPump, SessionRole};
use wz_runtime_coop::session_runtime::{new_session_in_slot, SessionEntropy, SessionHandle};
use wz_runtime_coop::{ClockSource, CoopRuntime, CoopTime};
use wz_session_core::bounded::Storage;
use wz_session_core::decl_sink::{DeclSink, DeclView};
use wz_session_core::driver_loop::{DriverOutcome, IterationEvent};
use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome};
use wz_session_core::reliability::Reliability;
use wz_session_core::session_init_params::{cookie_bytes, zid_bytes, SessionInitParams};
use wz_session_core::session_slot::{SessionSlots, SlotDriver};
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::slot_observer::{NoSink, ObserverSinks, RegistryTables, Requesters};
use wz_session_core::WhatAmI;
use wz_session_lwip::driver::{share_socket, LwipUdpDriver};
use wz_session_lwip::LwipSessionLink;
use wz_session_mcu::app_layer::{NoReplies, SessionEvents, SlotApp, SlotDispatch};

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

/// How many subscriber declarations the application was told of, and the id of the last.
static DECLARED: AtomicUsize = AtomicUsize::new(0);
static LAST_DECLARED: AtomicUsize = AtomicUsize::new(0);

/// The application's listener on the subscribers a peer declares: a closed type with no state,
/// which counts into the statics above, so its registration and its calls allocate nothing.
struct CountDeclared;
impl DeclSink for CountDeclared {
    fn on_declared(&mut self, decl: &dyn DeclView) {
        DECLARED.fetch_add(1, Ordering::SeqCst);
        LAST_DECLARED.store(decl.id() as usize, Ordering::SeqCst);
    }
}

/// The registrations of this file's observer: the declaration listener, and none of the other
/// kinds.
struct Sinks;
impl ObserverSinks for Sinks {
    type Subscriber = NoSink;
    type SubscriberId = wz_session_core::pubsub::SubscriptionId;
    type QueryableId = wz_session_core::query::QueryableId;
    type LivelinessSubscriberId = u64;
    type Delivery = ();
    type Tables<P: Storage> =
        RegistryTables<Self::Subscriber, Self::Queryable, Self::LivelinessSubscriber, P>;
    type Queryable = NoSink;
    type LivelinessSubscriber = NoSink;
    type Declared = CountDeclared;
    type Undeclared = NoSink;
}

type Rt = CoopRuntime<Frozen, LwipUdpDriver>;
type Pump = SessionPump<Frozen, LwipSessionLink<Rc<LwipLink>>, LwipUdpDriver>;
type Handle = SessionHandle<Frozen, LwipUdpDriver>;
type Slots = SessionSlots<Rt, CoopTime<Frozen>, LwipUdpDriver, Counting, 2>;
type Dispatch = SlotDispatch<Frozen, NoReplies, NoReplies, Sinks, LwipUdpDriver>;
static SESSIONS: Slots = SessionSlots::new();
static APP: SlotApp<Sinks> = SlotApp::new();

fn params(zid: u8) -> SessionInitParams {
    SessionInitParams {
        whatami: WhatAmI::Peer,
        zid: zid_bytes(&[zid; 4]),
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: 10_000,
        keep_alive: wz_session_core::session_init_params::KeepAliveConf::PICO,
        initial_sn: 0,
        cookie: cookie_bytes(&[]),
        tx_queue: wz_session_core::session_init_params::TxQueueConf::of_snapshot(
            &wz_session_core::policy::SessionPolicy::defaults(),
            &wz_session_core::limits::SessionLimits::BUILD,
        ),
        link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
        policy: wz_session_core::policy::SessionPolicy::defaults(),
        limits: wz_session_core::limits::SessionLimits::BUILD,
        cookie_signing_key: SigningKey::from_slice(&[7u8; 32]).expect("key"),
    }
}

fn config(role: SessionRole) -> SessionDriveConfig {
    SessionDriveConfig {
        timeouts: SessionTimeouts::spec_defaults(),
        role,
        max_iters: None,
    }
}

/// The records of every Frame the acceptor's receive handed over, in the order it handed them:
/// the Frame's reliability and SN. Fixed, so recording one allocates nothing.
struct Seen {
    records: [(bool, u64); 8],
    len: usize,
}

impl Seen {
    fn new() -> Self {
        Self {
            records: [(false, 0); 8],
            len: 0,
        }
    }

    fn push(&mut self, record: (bool, u64)) {
        assert!(
            self.len < self.records.len(),
            "more records than the test sent"
        );
        self.records[self.len] = record;
        self.len += 1;
    }

    fn as_slice(&self) -> &[(bool, u64)] {
        &self.records[..self.len]
    }
}

/// One end's state, in a slot: the driver over its socket, the entropy source, the
/// bundle, and the link the loop reads.
fn create(
    link: &Rc<LwipLink>,
    runtime: &Rt,
    socket: SessionRxSocket,
    peer: Option<([u8; 4], u16)>,
    zid: u8,
) -> (
    Handle,
    SessionEntropy,
    LwipSessionLink<Rc<LwipLink>>,
    SlotDriver<LwipUdpDriver>,
) {
    let socket = share_socket(socket);
    let driver = match peer {
        Some((addr, port)) => LwipUdpDriver::new(socket, ipv4_addr_from_octets(addr), port),
        None => LwipUdpDriver::accepting(socket),
    };
    let Ok(claim) = SESSIONS.claim(driver, Counting(zid)) else {
        panic!("a slot is free");
    };
    let sender = claim.driver_handle();
    let pump_link = LwipSessionLink::new(link.clone(), claim.driver_handle());
    let (actions, entropy) = new_session_in_slot(claim, || params(zid), CoopTime::new(runtime));
    (actions, entropy, pump_link, sender)
}

/// A reliable or best-effort Frame at `sn` carrying `payload`: the header, the SN as a VLE
/// (seven bits a byte, low first, the top bit saying another follows), the payload. The
/// session's initial SN is derived from its zid, so it may take more than one byte.
fn frame_wire(reliable: bool, sn: u64, payload: &[u8]) -> Vec<u8> {
    let r = if reliable {
        wire_const::FLAG_T_FRAME_R
    } else {
        0
    };
    let mut wire = vec![wire_const::T_MID_FRAME | r];
    let mut rest = sn;
    while rest >= 0x80 {
        wire.push((rest as u8 & 0x7f) | 0x80);
        rest >>= 7;
    }
    wire.push(rest as u8);
    wire.extend_from_slice(payload);
    wire
}

/// A `Declare(DeclSubscriber)` of `id` on the literal `suffix`, as upstream's codec writes it
/// (`commons/zenoh-codec/src/network/declare.rs` @ `let mut header = declare::id::D_SUBSCRIBER;`):
/// the envelope header with no interest id and no extension, the body header with the `N` flag
/// (a suffix follows, the mapping is the receiver's), the id, the scope 0, the suffix.
fn declare_subscriber(id: u8, suffix: &str) -> Vec<u8> {
    assert!(id < 0x80 && suffix.len() < 0x80, "one-byte VLEs");
    let mut wire = vec![
        wire_const::N_MID_DECLARE,
        wire_const::D_MID_SUBSCRIBER | wire_const::FLAG_D_N,
        id,
        0x00,
        suffix.len() as u8,
    ];
    wire.extend_from_slice(suffix.as_bytes());
    wire
}

/// One datagram of two Frames, the second behind its own header, as a sender puts a message of
/// the other reliability into the open batch, and then one whose first Frame the SN gate refuses.
/// With no allocator the acceptor reads each datagram on where it lies: the walk of the first
/// Frame's records ends at the second header, the second Frame is read from there, and both are
/// handed over in the ONE iteration that received the datagram. A refused Frame is dropped with
/// its records, and the Frame behind it is still read, as upstream drains a refused Frame's reader
/// and reads the batch on. Neither iteration costs the heap anything.
#[test]
fn a_datagram_of_two_frames_is_read_where_it_lies_without_a_heap() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    static RUNTIME: wz_runtime_coop::RuntimeCell<Frozen, 1, 64, 1> =
        wz_runtime_coop::RuntimeCell::new();
    let runtime = RUNTIME
        .start::<LwipUdpDriver>(Frozen)
        .expect("the runtime is started once");

    let (observer, registered) = APP
        .install_with(|observer| {
            observer
                .remote_subscribers
                .on_subscriber_declared_sink(CountDeclared)
        })
        .ok()
        .expect("the observer is installed once");
    assert!(registered.is_ok(), "the declaration listener is registered");

    let port = 7741;
    let acceptor_socket = bind_session_rx(&link, port).expect("bind the acceptor");
    let initiator_socket = bind_session_rx(&link, 0).expect("bind the initiator");
    let (a_actions, a_entropy, a_link, _a_sender) =
        create(&link, &runtime, acceptor_socket, None, 0xa1);
    let (i_actions, i_entropy, i_link, i_sender) = create(
        &link,
        &runtime,
        initiator_socket,
        Some(([127, 0, 0, 1], port)),
        0xb1,
    );
    let mut acceptor: Pump = SessionPump::new(
        runtime.clone(),
        a_link,
        a_actions.clone(),
        a_entropy,
        CoopTime::new(&runtime),
        config(SessionRole::Acceptor),
    );
    let mut initiator: Pump = SessionPump::new(
        runtime.clone(),
        i_link,
        i_actions.clone(),
        i_entropy,
        CoopTime::new(&runtime),
        config(SessionRole::Initiator),
    );

    // The acceptor's application layer: the process-wide observer over this session's slot, and
    // beside it the record of what the receive handed over, by Frame.
    let mut dispatch: Dispatch = SlotDispatch::new(observer, a_actions.clone(), Requesters::new());
    let seen = RefCell::new(Seen::new());
    let mut on_acceptor = |event: IterationEvent<'_, '_>| {
        if let IterationEvent::InPlace(record) = event {
            seen.borrow_mut().push((record.reliable(), record.sn()));
        }
        dispatch.on_event(event);
    };
    let mut on_initiator = |_event: IterationEvent<'_, '_>| {};

    for _ in 0..64 {
        assert!(initiator.step(&mut on_initiator).is_none());
        assert!(acceptor.step(&mut on_acceptor).is_none());
        if a_actions.is_established() && i_actions.is_established() {
            break;
        }
    }
    assert!(
        a_actions.is_established() && i_actions.is_established(),
        "the pair established over the loopback"
    );
    // A turn each way settles whatever the last handshake turn left in flight.
    for _ in 0..4 {
        assert!(initiator.step(&mut on_initiator).is_none());
        assert!(acceptor.step(&mut on_acceptor).is_none());
    }

    let mask = i_actions.negotiated_sn_mask();
    let priority = wz_session_core::qos::Priority::DEFAULT;
    let reliable = i_actions.next_outbound_frame_sn(priority, true, mask);
    let best_effort = i_actions.next_outbound_frame_sn(priority, false, mask);
    // Taken from the session rather than added to: an SN wraps at the negotiated resolution.
    let best_effort_next = i_actions.next_outbound_frame_sn(priority, false, mask);
    let before = DECLARED.load(Ordering::SeqCst);
    let declared = || {
        (
            DECLARED.load(Ordering::SeqCst) - before,
            LAST_DECLARED.load(Ordering::SeqCst),
        )
    };
    let measure = Measurement::new();
    let cost = Cell::new(0usize);
    let before_records = seen.borrow().len;
    {
        let mut read = |what: &str, wire: &[u8]| {
            assert_eq!(
                i_sender.send_blocking(wire, Reliability::Reliable),
                LinkSendOutcome::Sent,
                "{what}: the datagram left the socket"
            );
            let (finished, allocations): (Option<DriverOutcome>, usize) =
                measure.count(what, || acceptor.step(&mut on_acceptor));
            assert!(finished.is_none(), "{what}: the acceptor ended on the turn");
            println!("{what}: {allocations} allocation(s)");
            cost.set(cost.get() + allocations);
        };

        let mut wire = frame_wire(true, reliable, &declare_subscriber(61, "two/a"));
        wire.extend_from_slice(&frame_wire(
            false,
            best_effort,
            &declare_subscriber(62, "two/b"),
        ));
        read("a reliable and a best-effort Frame in one datagram", &wire);
        assert_eq!(
            declared(),
            (2, 62),
            "(declarations told, the id of the last): each Frame's record in the one iteration, \
             the reliable one first"
        );

        // The reliable Frame again, at the SN already read: a duplicate the gate refuses.
        let mut wire = frame_wire(true, reliable, &declare_subscriber(63, "two/c"));
        wire.extend_from_slice(&frame_wire(
            false,
            best_effort_next,
            &declare_subscriber(64, "two/d"),
        ));
        read("a best-effort Frame behind a refused one", &wire);
        assert_eq!(
            declared(),
            (3, 64),
            "(declarations told, the id of the last): the refused Frame's record is not told, \
             the record of the Frame behind it is"
        );
    }

    let seen = seen.borrow();
    assert_eq!(
        &seen.as_slice()[before_records..],
        &[
            (true, reliable),
            (false, best_effort),
            (false, best_effort_next)
        ],
        "the records the receive handed over, by Frame, in wire order"
    );
    assert_eq!(cost.get(), 0, "the allocations of the two iterations");
}
