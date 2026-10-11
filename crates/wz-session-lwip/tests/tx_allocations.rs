// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What one OUTBOUND message costs the heap on the MCU session, counted
//! (fixed-memory step S4, ARCHITECTURE section 9.1).
//!
//! A real session pair over the host lwIP loopback, an initiator and an
//! acceptor, each over a socket whose driver LENDS the pbuf lwIP will send. The
//! messages a session sends, each run on its own under a counting
//! `#[global_allocator]`:
//!
//! - the four handshake messages, InitSyn, InitAck, OpenSyn and OpenAck, each
//!   sent by the FSM action that sends it (`SessionFsmUnicastActions`), on a
//!   session prepared the way the handshake prepares it, so what the window sees
//!   is the encode and the send and nothing of the receive that led up to it;
//! - a Close, from both of the senders that emit one;
//! - a KeepAlive;
//! - a Put, steady state, at several payload sizes.
//!
//! With `tx-lend-only` (the MCU profile's: every frame is encoded into a slot the
//! link lends) every one of them must cost the heap NOTHING. Without it (the
//! profile every shipped image and the AP run today) each must cost it
//! something, and that half is the instrument's own control: a count that read
//! zero on the path that is known to build a vector would prove nothing about
//! the path that is meant not to.
//!
//! Either way the bytes that reach the peer are the bytes the heap encoder
//! writes for the same message (`encode_init_with_role`, `encode_open_with_role`,
//! `encode_close`): the lend changes where the frame is written and nothing on
//! the wire.
//!
//! With `tx-lend-only` the refusal is witnessed too. A send for which the link
//! lends no slot (both of the driver's slots out) or that is past the link's
//! budget with no fragmentation to cut it up in is an explicit
//! `LinkRefused(NoTxSlot | Oversize)`, counted in `tx_refusals()`, with nothing
//! on the wire, nothing allocated, and no slot lost: the next send finds one.
//!
//! The count is ATTRIBUTED to the measurement's own thread, as the AP datagram
//! suites attribute theirs (`datagram_rx_pool_allocations`): a measurement owns
//! a tally, its thread works for it, and an allocation counts only when the
//! thread that makes it works for a measurement whose window is open. libtest
//! starts, reports and fails tests on threads of its own, and none of those
//! works for a measurement, so none can move a number. lwIP is process-global,
//! so every test holds the harness's lock for its whole body
//! (`lwip_test_link`'s guard, which is also this binary's SERIAL lock), runtime
//! start included. The two controls at the end pin both halves of the
//! attribution.
//!
//! Host-test level: no board runs it, and the stack depth of the lent encode is
//! not measured here.

// Not on the `session-slot` profile, whose sessions are made in a slot and not
// through the `Rc` seams this file builds them with: `session_slot_allocations`
// counts that profile's, send path included.
#![cfg(not(feature = "session-slot"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use wz_link_lwip::LwipLink;
use wz_runtime_coop::session_drive::{SessionDatagramLink, SessionLinks, UdpPeer};
use wz_runtime_coop::session_runtime::new_session_actions;
use wz_runtime_coop::{ClockSource, CoopRuntime, CoopTime};
use wz_session_core::close_reason::CloseReason;
use wz_session_core::ext_chain_role::ExtChainRole;
use wz_session_core::handshake_encode::{encode_close, encode_keep_alive};
use wz_session_core::inbound::{parse_inbound, InboundFrame};
use wz_session_core::network_message::{parse_frame_payload, NetworkMessage};
use wz_session_core::session_actions::{SessionActionsBinding, SessionLinkActions};
use wz_session_core::session_fsm_unicast::SessionFsmUnicastActions;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::WhatAmI;
use wz_session_lwip::{LwipLinks, LwipSessionLink};

/// Counts the allocations of the measurement the allocating thread works for.
struct CountingAllocator;

/// One measurement's count: whether its window is open, and what its threads
/// allocated while it was.
struct Tally {
    open: AtomicBool,
    allocations: AtomicUsize,
}

thread_local! {
    /// The measurement this thread works for, if any. `const` initialisation of
    /// a destructor-free type, so reading it from inside `alloc` cannot itself
    /// allocate.
    static OWNER: Cell<Option<&'static Tally>> = const { Cell::new(None) };
}

/// One allocation, counted against the allocating thread's measurement when
/// that measurement's window is open.
fn count_one() {
    if let Some(tally) = OWNER.with(Cell::get) {
        if tally.open.load(Ordering::SeqCst) {
            tally.allocations.fetch_add(1, Ordering::SeqCst);
        }
    }
}

// SAFETY: every call forwards to `System` unchanged; the only addition is a read
// of a thread-local without a destructor and an atomic bump, neither of which
// allocates or unwinds.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_one();
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_one();
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count_one();
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

/// A measurement owned by the test thread that made it, with a tally of its own.
struct Measurement {
    tally: &'static Tally,
}

impl Measurement {
    /// The calling thread works for the new measurement until it drops. The tally
    /// is leaked, a few bytes per test, so a thread that outlives the
    /// measurement and still reads it never reads freed memory.
    fn new() -> Self {
        let tally: &'static Tally = Box::leak(Box::new(Tally {
            open: AtomicBool::new(false),
            allocations: AtomicUsize::new(0),
        }));
        OWNER.with(|owner| owner.set(Some(tally)));
        Self { tally }
    }

    /// Run `f` and return its result with the allocations this measurement's
    /// threads made while it ran.
    fn count<R>(&self, f: impl FnOnce() -> R) -> (R, usize) {
        let before = self.tally.allocations.load(Ordering::SeqCst);
        self.tally.open.store(true, Ordering::SeqCst);
        let out = f();
        self.tally.open.store(false, Ordering::SeqCst);
        (out, self.tally.allocations.load(Ordering::SeqCst) - before)
    }
}

impl Drop for Measurement {
    fn drop(&mut self) {
        OWNER.with(|owner| owner.set(None));
    }
}

/// A clock that never moves: no deadline fires, so a send does only what it is
/// asked.
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

type Actions = SessionLinkActions<CoopRuntime<Frozen>, CoopTime<Frozen>>;
type Binding = SessionActionsBinding<CoopRuntime<Frozen>, CoopTime<Frozen>>;

/// One end of a session: its actions bundle, the socket driver those send
/// through, and the pump that reads what the other end sent.
struct Side {
    actions: Rc<Actions>,
    /// The socket driver the actions send through, which the refusal tests take
    /// every slot from.
    #[cfg(feature = "tx-lend-only")]
    sink: Rc<dyn wz_session_core::link::BoxedLinkDriver>,
    pump: LwipSessionLink<Rc<LwipLink>>,
}

impl Side {
    /// The FSM's own action methods over this end's bundle, which is how a
    /// handshake message is sent.
    fn fsm(&self) -> Binding {
        Binding::new(self.actions.clone())
    }

    /// Every datagram that has reached this end, in order. Pumps lwIP's input
    /// path first, as the drive loop does each turn.
    fn received(&self) -> Vec<Vec<u8>> {
        self.pump.service();
        let mut out = Vec::new();
        while let Some(frame) = self.pump.try_recv() {
            out.push(frame.bytes.as_slice().to_vec());
        }
        out
    }

    /// The one datagram that reached this end.
    fn one(&self) -> Vec<u8> {
        let mut all = self.received();
        assert_eq!(all.len(), 1, "exactly one datagram reached this end");
        all.pop().expect("one")
    }
}

/// The links the test opens its sockets with: `LwipLinks::new` by default, and with
/// `static-link-storage` over a leaked pool, since a test is host code and may
/// allocate where a firmware declares a `static` pool. The counts below read the
/// send path, which the pool does not touch.
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

/// An acceptor on `port` and an initiator dialling it.
fn pair(link: &Rc<LwipLink>, port: u16) -> (Side, Side) {
    let runtime = CoopRuntime::new(Frozen);
    let links = new_links(link.clone());

    let opened = links.open_acceptor(port).expect("bind the acceptor");
    let acceptor = Side {
        actions: new_session_actions(
            opened.sink.clone(),
            params(0xa1),
            CoopTime::new(&runtime),
            Counting(1),
        ),
        #[cfg(feature = "tx-lend-only")]
        sink: opened.sink,
        pump: opened.pump,
    };

    let opened = links
        .open_initiator(UdpPeer {
            addr: [127, 0, 0, 1],
            port,
        })
        .expect("open the initiator");
    let initiator = Side {
        actions: Actions::new_generic(opened.sink.clone(), params(0xb1), CoopTime::new(&runtime)),
        #[cfg(feature = "tx-lend-only")]
        sink: opened.sink,
        pump: opened.pump,
    };
    (acceptor, initiator)
}

/// What every message of a test costs the heap, kept so a test reports ALL of
/// them and not only the first that is wrong: what a message that goes through
/// the heap costs, and what one that goes through a lent slot must, which is
/// nothing. The expectation is the profile's, and each half is the other's
/// control.
#[derive(Default)]
struct Costs {
    wrong: Vec<String>,
}

impl Costs {
    fn check(&mut self, what: &str, allocations: usize) {
        println!("{what}: {allocations} allocation(s)");
        #[cfg(feature = "tx-lend-only")]
        if allocations != 0 {
            self.wrong.push(format!(
                "{what}: {allocations} allocation(s); a lend-only send is encoded into \
                 the slot the link lends and costs the heap nothing"
            ));
        }
        #[cfg(not(feature = "tx-lend-only"))]
        if allocations == 0 {
            self.wrong.push(format!(
                "{what}: 0 allocations; the heap profile builds this message in a \
                 vector, so a zero here means the instrument cannot see it, and a \
                 zero on the lend-only profile would mean nothing"
            ));
        }
    }

    fn finish(self) {
        assert!(self.wrong.is_empty(), "{:#?}", self.wrong);
    }
}

/// The four handshake messages, each sent by the FSM action that sends it.
///
/// The session each one is sent from is prepared the way the handshake prepares
/// it, through the decoder's own entry (`handle_inbound`) and nothing else: the
/// acceptor is told the initiator's InitSyn before its InitAck is sent, and the
/// initiator the InitAck before its OpenSyn. What a window then holds is the
/// encode and the send, and not the receive that led to them, which is a cost
/// the receive path owns.
#[test]
fn every_handshake_message_is_encoded_without_the_heap() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    let (acceptor, initiator) = pair(&link, 7611);
    let m = Measurement::new();
    let mut costs = Costs::default();

    // InitSyn, the initiator's.
    let ((), n) = m.count(|| initiator.fsm().send_init_syn());
    costs.check("InitSyn", n);
    let init_syn = acceptor.one();
    assert_eq!(
        init_syn,
        initiator
            .actions
            .encode_init_with_role(false, None, ExtChainRole::InitSyn)
            .expect("the heap encoder"),
        "the InitSyn on the wire is the one the heap encoder writes"
    );

    // InitAck, the acceptor's, once it has been told the InitSyn.
    acceptor
        .actions
        .handle_inbound(&init_syn)
        .expect("the acceptor reads the InitSyn");
    let ((), n) = m.count(|| acceptor.fsm().send_init_ack_with_cookie());
    costs.check("InitAck (cookie minted)", n);
    let init_ack = initiator.one();
    let cookie = match parse_inbound(&init_ack).expect("an InitAck") {
        InboundFrame::Init {
            is_ack: true, body, ..
        } => body
            .cookie
            .expect("the acceptor minted a cookie")
            .as_slice()
            .to_vec(),
        _ => panic!("the acceptor sent something other than an InitAck"),
    };
    assert_eq!(
        init_ack,
        acceptor
            .actions
            .encode_init_with_role(true, Some(&cookie), ExtChainRole::InitAck)
            .expect("the heap encoder"),
        "the InitAck on the wire is the one the heap encoder writes for the cookie it carries"
    );

    // OpenSyn, the initiator's, once it has read the InitAck (which is where it
    // learns the cookie it echoes and the peer's zid its ring origin derives from).
    initiator
        .actions
        .handle_inbound(&init_ack)
        .expect("the initiator reads the InitAck");
    let ((), n) = m.count(|| initiator.fsm().send_open_syn());
    costs.check("OpenSyn (cookie echoed)", n);
    let open_syn = acceptor.one();
    assert_eq!(
        open_syn,
        initiator
            .actions
            .encode_open_with_role(false, Some(&cookie), ExtChainRole::OpenSyn)
            .expect("the heap encoder"),
        "the OpenSyn on the wire is the one the heap encoder writes"
    );

    // OpenAck, the acceptor's. Its identity of the peer is the InitSyn's, told
    // again, as the OpenSyn's admission restores it from the cookie.
    acceptor
        .actions
        .handle_inbound(&init_syn)
        .expect("the acceptor reads the InitSyn again");
    let ((), n) = m.count(|| acceptor.fsm().send_open_ack());
    costs.check("OpenAck", n);
    let open_ack = initiator.one();
    assert_eq!(
        open_ack,
        acceptor
            .actions
            .encode_open_with_role(true, None, ExtChainRole::OpenAck)
            .expect("the heap encoder"),
        "the OpenAck on the wire is the one the heap encoder writes"
    );
    costs.finish();
}

/// A Close and a KeepAlive.
///
/// The Close is sent by both of its senders: the public one a host calls to end
/// a session, and the FSM's own `Closing` action. A KeepAlive is a one-byte
/// constant array and costs the heap nothing in either profile, which this pins
/// as a control of its own: the lend-only profile did not have to change it.
#[test]
fn a_close_and_a_keep_alive_are_sent_without_the_heap() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    let (acceptor, initiator) = pair(&link, 7612);
    let m = Measurement::new();
    let mut costs = Costs::default();

    // The acceptor learns its peer from the first datagram, so it has one to
    // answer: a KeepAlive from the initiator, which is the control.
    let ((), n) = m.count(|| initiator.actions.send_keep_alive());
    println!("KeepAlive: {n} allocation(s)");
    assert_eq!(
        n, 0,
        "a keep-alive is a constant byte and costs no allocation"
    );
    assert_eq!(acceptor.one(), encode_keep_alive().to_vec());

    let ((), n) = m.count(|| {
        acceptor
            .actions
            .send_close_with_reason(CloseReason::Generic)
    });
    costs.check("Close (host)", n);
    // The S flag is DERIVED: a session that has not reached Established closes
    // its LINK only (S clear), which is what these two sessions are.
    assert_eq!(
        initiator.one(),
        encode_close(CloseReason::Generic as u8, false).to_vec(),
        "the Close on the wire is the one the heap encoder writes"
    );

    let staged = acceptor.actions.trace_snapshot().close_reason as u8;
    let ((), n) = m.count(|| acceptor.fsm().send_close_frame_with_reason());
    costs.check("Close (FSM Closing action)", n);
    assert_eq!(
        initiator.one(),
        encode_close(staged, false).to_vec(),
        "the FSM's Close on the wire is the one the heap encoder writes"
    );
    costs.finish();
}

const KEY: &str = "tx/put";

/// The payload of the `i`th Put: bytes no other Put shares.
fn payload_of(i: usize, len: usize) -> Vec<u8> {
    (0..len).map(|b| (i * 31 + b) as u8).collect()
}

/// The (keyexpr suffix, payload) of the one Put a received datagram carries.
fn put_of(datagram: &[u8]) -> (String, Vec<u8>, u64) {
    let InboundFrame::Frame { payload, sn, .. } = parse_inbound(datagram).expect("a Frame") else {
        panic!("a Put leaves as a Frame");
    };
    let messages = parse_frame_payload(&payload).expect("the Frame decodes");
    assert_eq!(messages.len(), 1, "one Put to the Frame");
    let NetworkMessage::Push(push) = &messages[0] else {
        panic!("a Push");
    };
    let wz_codecs::push::PushOwnedVariant::CodecZenohMsgPut(put) = &push.body else {
        panic!("a Put");
    };
    let (id, suffix) = wz_session_core::wireexpr_resolve::id_and_suffix(&push.keyexpr.body);
    assert_eq!(id, 0, "a literal keyexpr");
    (
        String::from(suffix.expect("a keyexpr")),
        wz_session_core::put_payload::inline_bytes(put)
            .expect("an inline payload")
            .to_vec(),
        sn,
    )
}

/// A Put, steady state, at several sizes: the frame is encoded into the slot the
/// link lends and costs the heap nothing; every Put arrives at the peer with its
/// keyexpr, its payload, and the next sequence number.
#[test]
fn a_put_is_sent_without_the_heap_at_every_size() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    let (acceptor, initiator) = pair(&link, 7613);
    let m = Measurement::new();
    let mut costs = Costs::default();

    // The same send, once, before anything is measured: whatever a first use
    // initialises is not what a steady state costs.
    initiator
        .actions
        .send_push_literal(KEY, b"warm", true)
        .expect("the warm-up Put");
    let (_, _, first_sn) = put_of(&acceptor.one());

    for (i, len) in [1usize, 8, 64, 512].into_iter().enumerate() {
        let payload = payload_of(i, len);
        let (sent, n) = m.count(|| initiator.actions.send_push_literal(KEY, &payload, true));
        sent.expect("the Put leaves");
        costs.check(&format!("Put of {len} bytes"), n);
        let (key, got, sn) = put_of(&acceptor.one());
        assert_eq!(key, KEY, "the keyexpr");
        assert_eq!(got, payload, "the payload");
        assert_eq!(sn, first_sn + 1 + i as u64, "the next sequence number");
    }
    costs.finish();
}

/// The instrument itself, both halves of its attribution.
///
/// A window counts an allocation the measurement's own thread makes, and one it
/// makes outside the window is not counted; an allocation another thread makes
/// while the window is open is not this measurement's and is not counted.
/// Without the first half every zero above would be a window that sees nothing;
/// without the second a test running beside this one could move a number.
#[test]
fn the_count_sees_its_own_thread_and_only_its_own_thread() {
    let (_serial, _link) = wz_link_lwip::lwip_test_link();
    let m = Measurement::new();

    let (kept, n) = m.count(|| std::hint::black_box(Vec::<u8>::with_capacity(64)));
    assert!(
        n >= 1,
        "an allocation in the window on the measuring thread is counted"
    );
    drop(kept);

    let outside = std::hint::black_box(Vec::<u8>::with_capacity(64));
    let ((), n) = m.count(|| ());
    assert_eq!(n, 0, "an empty window counts nothing");
    drop(outside);

    // The other thread is started, and its handles made, BEFORE the window opens
    // (spawning allocates on the spawning thread, which would be this
    // measurement's own); inside it, this thread only flips a flag and waits for
    // the other to say it allocated.
    let go = std::sync::Arc::new(AtomicBool::new(false));
    let done = std::sync::Arc::new(AtomicBool::new(false));
    let other = {
        let (go, done) = (go.clone(), done.clone());
        std::thread::spawn(move || {
            while !go.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
            drop(std::hint::black_box(Vec::<u8>::with_capacity(64)));
            done.store(true, Ordering::SeqCst);
        })
    };
    let ((), n) = m.count(|| {
        go.store(true, Ordering::SeqCst);
        while !done.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
    });
    other.join().expect("the other thread");
    assert_eq!(
        n, 0,
        "an allocation another thread makes while the window is open is not this \
         measurement's"
    );
}

/// The refusal, which is the lend-only profile's answer to "the link lent no
/// slot": explicit, counted, with nothing on the wire, nothing allocated, and no
/// slot lost.
#[cfg(feature = "tx-lend-only")]
mod refusal {
    use super::*;

    use wz_session_core::link::LinkDropCause;
    use wz_session_core::qos::Priority;
    use wz_session_core::send_wire_error::SendWireError;
    use wz_session_core::session_actions::TxRefusalCounts;

    /// Take every slot the driver will lend, and hold them: the driver has
    /// `LENT_MAX` (two), and the table is exactly that full when the next ask is
    /// refused, which is the fill-to-N half of the exhaustion case R5 (the
    /// refusals counted below are its N+1).
    fn hold_every_slot(side: &Side) -> Vec<wz_session_core::link::TxSlotGrant> {
        let mut held = Vec::new();
        while let Some(grant) = side.sink.tx_slot_acquire(8, Priority::DEFAULT) {
            held.push(grant);
            assert!(
                held.len() <= wz_session_lwip::driver::LENT_MAX,
                "the driver lends a bounded number of slots"
            );
        }
        assert_eq!(
            held.len(),
            wz_session_lwip::driver::LENT_MAX,
            "the driver lends exactly the slots its lend table has"
        );
        held
    }

    /// With every slot out, a Put, an InitSyn and a Close are each refused, and
    /// counted; with them given back the next Put leaves.
    #[test]
    fn a_send_for_which_no_slot_is_lent_is_refused_counted_and_loses_no_slot() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let link = Rc::new(link);
        let (acceptor, initiator) = pair(&link, 7614);
        let m = Measurement::new();
        assert_eq!(initiator.actions.tx_refusals(), TxRefusalCounts::default());

        let held = hold_every_slot(&initiator);

        let (sent, n) = m.count(|| initiator.actions.send_push_literal(KEY, b"refused", true));
        assert_eq!(
            sent,
            Err(SendWireError::LinkRefused(LinkDropCause::NoTxSlot)),
            "a Put with no slot to encode into is an explicit refusal"
        );
        assert_eq!(n, 0, "and the refusal allocates nothing");

        let ((), n) = m.count(|| initiator.fsm().send_init_syn());
        assert_eq!(n, 0, "a refused InitSyn allocates nothing");

        let ((), n) = m.count(|| {
            initiator
                .actions
                .send_close_with_reason(CloseReason::Generic)
        });
        assert_eq!(n, 0, "a refused Close allocates nothing");

        assert_eq!(
            initiator.actions.tx_refusals(),
            TxRefusalCounts {
                no_slot: 3,
                oversize: 0
            },
            "the three refusals are counted, by cause"
        );
        assert!(
            acceptor.received().is_empty(),
            "a refused send puts nothing on the wire"
        );

        for grant in held {
            initiator.sink.tx_slot_abort(grant.slot);
        }
        let (sent, n) = m.count(|| initiator.actions.send_push_literal(KEY, b"leaves", true));
        sent.expect("with the slots given back the next Put leaves");
        assert_eq!(n, 0, "and costs the heap nothing");
        let (key, got, _) = put_of(&acceptor.one());
        assert_eq!((key.as_str(), got.as_slice()), (KEY, &b"leaves"[..]));
        assert_eq!(
            initiator.actions.tx_refusals().no_slot,
            3,
            "a send that found a slot is not counted as a refusal"
        );
    }

    /// A Put past the budget the session negotiated cannot be cut into a chain on
    /// a profile with no fragmentation, and is not sent whole on the heap either:
    /// it is refused as oversize, counted, and the slot it was lent is given
    /// back.
    #[cfg(not(feature = "transport-fragmentation"))]
    #[test]
    fn a_put_past_the_budget_is_refused_as_oversize_and_gives_its_slot_back() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let link = Rc::new(link);
        let (acceptor, initiator) = pair(&link, 7615);
        let m = Measurement::new();

        // The batch the pair negotiates is 1024 bytes, so a payload past it is
        // past the budget whatever else the frame carries.
        let payload = payload_of(0, 1500);
        let (sent, n) = m.count(|| initiator.actions.send_push_literal(KEY, &payload, true));
        assert_eq!(
            sent,
            Err(SendWireError::LinkRefused(LinkDropCause::Oversize)),
            "a Put past the budget, with nothing to cut it into, is refused as oversize"
        );
        assert_eq!(n, 0, "and the refusal allocates nothing");
        assert_eq!(
            initiator.actions.tx_refusals(),
            TxRefusalCounts {
                no_slot: 0,
                oversize: 1
            }
        );
        assert!(acceptor.received().is_empty(), "nothing reached the wire");

        // The slot that refusal took was given back: both are still lent.
        let held = hold_every_slot(&initiator);
        assert!(
            held.len() >= 2,
            "the refused send left every slot the driver has: {} lent",
            held.len()
        );
        for grant in held {
            initiator.sink.tx_slot_abort(grant.slot);
        }
        initiator
            .actions
            .send_push_literal(KEY, b"fits", true)
            .expect("a Put that fits leaves");
        assert_eq!(put_of(&acceptor.one()).1, b"fits".to_vec());
    }
}
