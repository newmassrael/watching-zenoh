// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session over `ws/` on the slot profile, end to end on the lwIP loopback, counted by a
//! counting allocator: the engine's slot stack wraps lwIP's TCP streams in the WebSocket framing
//! (`wz_runtime_coop::ws_link::WsStack`), a dial writes the opening request and waits for the
//! answer, and the accepting node's `WsAcceptor` answers it from a row of its handshake table.
//! What must hold:
//!
//! - a dial, the handshake it waits for, the accepted session and its close cost the heap
//!   nothing: every buffer is a cell of a table the image declared;
//! - an acceptor whose every row holds a handshake does not take the next connection: it stays
//!   queued on the port, and is taken once a row is free.
//!
//! The two nodes are in one program on one lwIP stack and one cooperative thread, as
//! `session_over_tcp` runs its pair. A dial waits for the server's answer inside its stream's polls,
//! so the dialler's polls run the accepting node's acceptor (`LwipTcpDial::with_service`), as an
//! image's polls run what else it serves; the link the acceptor yields is kept for the test to open
//! a session over.
//!
//! It runs on the node's real profile: `session-slot` for the session tables and
//! `static-link-storage` for the connections, since a connection made on the heap allocates.
//!
//! Host-test level: no board runs it.

use std::cell::RefCell;
use std::net::{IpAddr, SocketAddr};

use wz_link_lwip::tcp::{LwipTcpListener, TcpSocketPool};
use wz_link_lwip::LwipLink;
use wz_runtime_coop::ip_stack::IpDriver;
use wz_runtime_coop::session_drive::{
    Accept, Locator, PumpSlots, SessionDriveConfig, SessionRole, SlotStack,
};
use wz_runtime_coop::stream_link::{NoDial, NoStream, StreamDial, StreamSocket};
use wz_runtime_coop::udp_link::NoDatagram;
use wz_runtime_coop::ws_link::{WsAcceptor, WsSource, WsStack};
use wz_runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeCell};
use wz_session_core::byte_cells::{ByteCells, ByteSource};
use wz_session_core::close_reason::CloseReason;
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::entropy::EntropyUnavailable;
use wz_session_core::session_init_params::{cookie_bytes, SessionInitParams};
use wz_session_core::session_slot::SessionSlots;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::ws_link::{client_key, read_response, write_request, UpgradeRead};
use wz_session_core::WhatAmI;
use wz_session_lwip::stream::{LwipTcpDial, LwipTcpListen, LwipTcpStack};
use wz_session_mcu::slot_host::SessionHost;

#[path = "support/alloc_count.rs"]
mod alloc_count;
use alloc_count::Measurement;

#[global_allocator]
static GLOBAL: alloc_count::CountingAllocator = alloc_count::CountingAllocator;

/// A clock that never moves: no deadline of a session fires, so it does only what the other end
/// asks.
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
    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
        for b in buf {
            self.0 = self.0.wrapping_add(1);
            *b = self.0;
        }
        Ok(())
    }
}

/// What the stacks' `ws/` links are timed and keyed by: the port's own clock, which a dial's wait
/// for its answer reads, and a fixed pattern for a stand-in of the board's entropy.
#[derive(Clone, Copy)]
struct Source(LinkRef);
impl WsSource for Source {
    fn now_us(&self) -> u64 {
        u64::from(self.0.now_ms()) * 1_000
    }

    fn fill_entropy(&self, out: &mut [u8]) -> Result<(), EntropyUnavailable> {
        out.fill(0x5a);
        Ok(())
    }
}

/// The receive buffer of a connection: the port's window is four segments of 536 bytes.
const RX: usize = 4_096;

type LinkRef = &'static LwipLink;
/// The connections a node's dial makes at once.
const CELLS: usize = 1;
/// The connections a listener holds, queued on the port or taken.
const QUEUED: usize = 2;

type Dial = LwipTcpDial<LinkRef, RX, CELLS>;
type Stack = WsStack<NoDatagram, Dial, NoDial, Source>;
type Driver = <Stack as SlotStack>::Driver;
type Pump = <Stack as SlotStack>::Pump;
type Rt = CoopRuntime<Frozen, Driver>;
type Slots<const S: usize> = SessionSlots<Rt, CoopTime<Frozen>, Driver, Counting, S>;
type Pumps<const P: usize> = PumpSlots<Frozen, Pump, P, Driver>;
type Host<const S: usize, const P: usize> = SessionHost<Frozen, Stack, Counting, S, P>;
type Listen = LwipTcpListen<LinkRef, RX, QUEUED, QUEUED>;
/// An acceptor of one handshake at a time.
type Acceptor = WsAcceptor<Listen, NoDatagram, NoStream, Source, 1>;

/// The stack of a node over `link`, its links' buffers in `rx` and `tx`, dialling with `dial`.
fn stack(
    link: LinkRef,
    rx: &'static dyn ByteSource,
    tx: &'static dyn ByteSource,
    dial: Dial,
) -> Stack {
    LwipTcpStack::<LinkRef, RX, CELLS>::new(IpAddr::from([127, 0, 0, 1]), rx, tx, dial)
        .with_ws(Source(link))
}

fn params(zid: u8) -> SessionInitParams {
    SessionInitParams {
        whatami: WhatAmI::Peer,
        zid: wz_session_core::session_zid::SessionZid::from_array([zid; 4]),
        seq_num_res: wz_session_core::policy::SnResolution::Bits32,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: 10_000,
        keep_alive: wz_session_core::session_init_params::KeepAliveConf::PICO,
        initial_sn: 0,
        cookie: cookie_bytes([]),
        tx_queue: wz_session_core::session_init_params::TxQueueConf::of_snapshot(
            &wz_session_core::policy::SessionPolicy::defaults(),
            &wz_session_core::limits::SessionLimits::BUILD,
        ),
        link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
        policy: wz_session_core::policy::SessionPolicy::defaults(),
        limits: wz_session_core::limits::SessionLimits::BUILD,
        cookie_signing_key: SigningKey::from_slice(&[7u8; 32]).expect("key").into(),
        region: None,
    }
}

fn config(role: SessionRole) -> SessionDriveConfig {
    SessionDriveConfig {
        timeouts: SessionTimeouts::spec_defaults(),
        role,
        max_iters: None,
    }
}

/// An `on_event` that ignores what it is handed: this test is about the link.
fn ignoring() -> impl FnMut(IterationEvent<'_, '_>) + 'static {
    |_| {}
}

thread_local! {
    /// The accepting node's acceptor, which the dialler's polls run.
    static SERVER: RefCell<Option<Acceptor>> = const { RefCell::new(None) };
    /// The link it yielded, for the test to open the accepted session over.
    static ACCEPTED: RefCell<Option<Driver>> = const { RefCell::new(None) };
}

/// One turn of the accepting node's acceptor, run by every poll of the dialler's streams. A poll
/// that the acceptor's own turn makes finds it held and does nothing.
fn serve() {
    SERVER.with(|server| {
        let Ok(mut server) = server.try_borrow_mut() else {
            return;
        };
        let Some(acceptor) = server.as_mut() else {
            return;
        };
        if let Ok(Some(driver)) = acceptor.accept() {
            ACCEPTED.with(|accepted| *accepted.borrow_mut() = Some(driver));
        }
    });
}

static RUNTIME: RuntimeCell<Frozen, 8, 1_024, 4> = RuntimeCell::new();
static LISTENER: LwipTcpListener<RX, QUEUED, QUEUED> = LwipTcpListener::new();
static LISTENER_CELLS: TcpSocketPool<RX, QUEUED> = TcpSocketPool::new();
static DIAL_CELLS: TcpSocketPool<RX, CELLS> = TcpSocketPool::new();
static ACCEPT_DIAL_CELLS: TcpSocketPool<RX, CELLS> = TcpSocketPool::new();
static DIAL_SESSIONS: Slots<1> = SessionSlots::new();
static DIAL_PUMPS: Pumps<1> = PumpSlots::new();
static DIAL_RX: ByteCells<2_050, 1> = ByteCells::new();
static DIAL_TX: ByteCells<2_050, 1> = ByteCells::new();
static ACCEPT_SESSIONS: Slots<1> = SessionSlots::new();
static ACCEPT_PUMPS: Pumps<1> = PumpSlots::new();
static ACCEPT_RX: ByteCells<2_050, 1> = ByteCells::new();
static ACCEPT_TX: ByteCells<2_050, 1> = ByteCells::new();

const PORT: u16 = 47_731;

/// One node dials `ws/`, the other accepts; both sessions establish over the WebSocket link, and
/// the dialler's close ends the acceptor's. The dial, its handshake, the accepted session, the
/// exchange and the close are each counted, and none allocates. Turned red by a `ws/` dial the
/// slot stack does not carry (the dial is refused), or by a link that claims memory of the heap.
#[test]
fn a_session_opens_over_ws_between_slot_nodes_and_costs_the_heap_nothing() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link: LinkRef = Box::leak(Box::new(link));
    let runtime: Rt = RUNTIME.start(Frozen).expect("the runtime starts once");
    let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");

    LISTENER
        .listen_in(PORT, &LISTENER_CELLS)
        .expect("the node listens");
    let accept_stack = stack(
        link,
        &ACCEPT_RX,
        &ACCEPT_TX,
        LwipTcpDial::new(link, &ACCEPT_DIAL_CELLS),
    );
    let acceptor: Acceptor = accept_stack.acceptor(LwipTcpListen::new(link, &LISTENER));
    SERVER.with(|server| *server.borrow_mut() = Some(acceptor));
    ACCEPTED.with(|accepted| *accepted.borrow_mut() = None);
    let dial_stack = stack(
        link,
        &DIAL_RX,
        &DIAL_TX,
        LwipTcpDial::new(link, &DIAL_CELLS).with_service(serve),
    );
    let dialler: Host<1, 1> = SessionHost::new(
        CoopLocalSet::try_new(&runtime).expect("the heap has room"),
        &DIAL_SESSIONS,
        &DIAL_PUMPS,
        dial_stack,
    );
    let accepting: Host<1, 1> = SessionHost::new(
        CoopLocalSet::try_new(&runtime).expect("the heap has room"),
        &ACCEPT_SESSIONS,
        &ACCEPT_PUMPS,
        accept_stack,
    );

    let m = Measurement::new();
    let router = Locator::ws(SocketAddr::from(([127, 0, 0, 1], PORT)));
    let (dialled, n) = m.count("the ws dial", || {
        dialler.dial(
            |out| dialler.stack().bind_initiator_in(router, out),
            None,
            Counting(0xb0),
            || params(0xb0),
            config(SessionRole::Initiator),
            |_| ignoring(),
        )
    });
    let dialled = dialled.unwrap_or_else(|why| panic!("the dial was refused: {why:?}"));
    assert_eq!(n, 0, "the dial and its handshake cost the heap nothing");
    assert_eq!(DIAL_RX.in_use(), 1, "the link took a receive buffer");
    assert_eq!(DIAL_TX.in_use(), 1, "and a frame buffer");
    assert_eq!(
        ACCEPT_RX.in_use(),
        1,
        "the accepted link took its buffers in its row"
    );

    let driver = ACCEPTED
        .with(|accepted| accepted.borrow_mut().take())
        .expect("the acceptor answered the dial's request");
    assert!(
        matches!(driver, IpDriver::Ws(_)),
        "the accepted link is a WebSocket's"
    );
    SERVER.with(|server| {
        let server = server.borrow();
        let acceptor = server.as_ref().expect("the acceptor is kept");
        assert_eq!(acceptor.handshaking(), 0, "its row is free again");
        assert_eq!(acceptor.refused(), 0);
    });

    let (accepted, n) = m.count("the accepted session", || {
        accepting.open(
            driver,
            None,
            Counting(0xa0),
            || params(0xa0),
            config(SessionRole::Acceptor),
            |_| ignoring(),
        )
    });
    let accepted = accepted.unwrap_or_else(|why| panic!("the accept was refused: {why:?}"));
    assert_eq!(n, 0, "the accepted session costs the heap nothing");

    let ((), n) = m.count("the handshake of the sessions", || {
        for _ in 0..256 {
            local.run_until_idle();
            if dialled.actions.is_established() && accepted.actions.is_established() {
                break;
            }
        }
    });
    assert!(dialled.actions.is_established(), "the dialling end opened");
    assert!(
        accepted.actions.is_established(),
        "the accepting end opened"
    );
    assert_eq!(
        n, 0,
        "the sessions' handshake over the link costs the heap nothing"
    );

    let ((), n) = m.count("the close", || {
        dialled.actions.send_close_with_reason(CloseReason::Generic);
        for _ in 0..256 {
            local.run_until_idle();
            if accepted.task.is_finished() {
                break;
            }
        }
    });
    assert!(accepted.task.is_finished(), "the close ended the session");
    assert_eq!(n, 0, "the close costs the heap nothing");
}

static QUEUE_LISTENER: LwipTcpListener<RX, QUEUED, QUEUED> = LwipTcpListener::new();
static QUEUE_LISTENER_CELLS: TcpSocketPool<RX, QUEUED> = TcpSocketPool::new();
static CLIENT_CELLS: TcpSocketPool<RX, QUEUED> = TcpSocketPool::new();
static QUEUE_DIAL_CELLS: TcpSocketPool<RX, CELLS> = TcpSocketPool::new();
// Two links' buffers: the link the first handshake made and the row the second takes.
static QUEUE_RX: ByteCells<2_050, 2> = ByteCells::new();
static QUEUE_TX: ByteCells<2_050, 2> = ByteCells::new();

const QUEUE_PORT: u16 = 47_732;

/// An acceptor of one row with two connections waiting takes one into its row and leaves the other
/// queued on the port; once it has answered the first's request and handed over its link, it takes
/// the second. None of it allocates. Turned red by an acceptor that takes a connection it has no
/// row for, which takes the second off the port at the first turn.
#[test]
fn a_full_handshake_table_leaves_the_next_connection_queued_on_the_port() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link: LinkRef = Box::leak(Box::new(link));
    QUEUE_LISTENER
        .listen_in(QUEUE_PORT, &QUEUE_LISTENER_CELLS)
        .expect("the node listens");
    let node = stack(
        link,
        &QUEUE_RX,
        &QUEUE_TX,
        LwipTcpDial::new(link, &QUEUE_DIAL_CELLS),
    );
    let mut acceptor: Acceptor = node.acceptor(LwipTcpListen::new(link, &QUEUE_LISTENER));
    let clients = LwipTcpDial::<LinkRef, RX, QUEUED>::new(link, &CLIENT_CELLS);
    let at = SocketAddr::from(([127, 0, 0, 1], QUEUE_PORT));
    let key = client_key(b"the sample nonce");
    let mut request = [0u8; 256];
    let request_len = write_request(&mut request, at, &key).expect("room");

    let m = Measurement::new();
    let ((), n) = m.count("two connections, one row", || {
        let first = clients.dial(at).expect("the first connects");
        let second = clients.dial(at).expect("the second connects");
        let none: Result<Option<Driver>, _> = acceptor.accept();
        assert!(matches!(none, Ok(None)), "no request has arrived");
        assert_eq!(acceptor.handshaking(), 1, "the one row holds the first");
        assert_eq!(
            QUEUE_LISTENER.waiting(),
            1,
            "the second stays queued on the port"
        );

        first
            .write_all(request.get(..request_len).unwrap_or_default())
            .expect("the request is written");
        let mut answered = None;
        for _ in 0..256 {
            if let Some(link) = acceptor.accept().expect("the port is sound") {
                answered = Some(link);
                break;
            }
        }
        let answered = answered.expect("the acceptor answered the request");
        assert!(matches!(answered, IpDriver::Ws(_)));
        assert_eq!(
            QUEUE_LISTENER.waiting(),
            1,
            "answering the first took no connection off the port"
        );

        let mut reply = [0u8; 512];
        let mut got = 0usize;
        let mut upgraded = false;
        for _ in 0..256 {
            first.wait_readable(10);
            if let Ok(Some(read)) = first.try_read(reply.get_mut(got..).unwrap_or_default()) {
                got += read;
            }
            if let UpgradeRead::Upgraded { .. } = read_response(&reply[..got], &key) {
                upgraded = true;
                break;
            }
        }
        assert!(upgraded, "the first client read the upgrade");

        let next: Result<Option<Driver>, _> = acceptor.accept();
        assert!(matches!(next, Ok(None)));
        assert_eq!(acceptor.handshaking(), 1, "the free row took the second");
        assert_eq!(QUEUE_LISTENER.waiting(), 0);
        drop((answered, second));
    });
    assert_eq!(n, 0, "the acceptor's turns cost the heap nothing");
    assert_eq!(acceptor.refused(), 0);
}
