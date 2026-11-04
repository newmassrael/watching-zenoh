// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session over `tcp/`, end to end, on the slot profile (`tcp` feature): one node dials, one
//! accepts, and the handshake runs through lwIP's TCP, the engine's stream link and the session host
//! of the fixed-memory profile, then the dialler closes and the acceptor's session ends.
//!
//! The two nodes are in one program on one lwIP stack and one cooperative thread, as the UDP
//! exhaustion tests run theirs: the dialling node opens its link through its stack's dial, the
//! accepting node takes the connection off the listener its stack's acceptor holds, and each hands
//! its driver to its own host. What this holds is that the pieces fit: a `tcp/` link claims its
//! buffers from the image's tables, a session over it reaches the established state on both ends,
//! and the close frees what the link took.
//!
//! It runs on both storage profiles: by default lwIP's connections are made on the heap, and with
//! `static-link-storage` (a node's real profile, with `session-slot`) in the cells of each node's
//! own pool, declared below as an image declares them.
//!
//! Host-test level: no board runs it.

use wz_link_lwip::tcp::LwipTcpListener;
#[cfg(feature = "static-link-storage")]
use wz_link_lwip::tcp::TcpSocketPool;
use wz_link_lwip::LwipLink;
use wz_runtime_coop::session_drive::{
    Accept, IpEndpoint, Locator, PumpSlots, SessionDriveConfig, SessionRole, SlotStack,
};
use wz_runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeCell};
use wz_session_core::byte_cells::ByteCells;
use wz_session_core::close_reason::CloseReason;
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::session_init_params::{cookie_bytes, zid_bytes, SessionInitParams};
use wz_session_core::session_slot::SessionSlots;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::WhatAmI;
use wz_session_lwip::stream::{LwipTcpDial, LwipTcpListen, LwipTcpStack};
use wz_session_mcu::slot_host::SessionHost;

/// A clock that never moves: no deadline fires, so a session does only what the other end asks.
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

/// The receive buffer of a connection: the port's window is four segments of 536 bytes.
const RX: usize = 4_096;

type LinkRef = &'static LwipLink;
/// The connections a node holds at once: one, dialled or accepted.
const CELLS: usize = 1;

type Stack = LwipTcpStack<LinkRef, RX, CELLS>;
type Driver = <Stack as SlotStack>::Driver;
type Pump = <Stack as SlotStack>::Pump;
type Rt = CoopRuntime<Frozen, Driver>;
type Slots<const S: usize> = SessionSlots<Rt, CoopTime<Frozen>, Driver, Counting, S>;
type Pumps<const P: usize> = PumpSlots<Frozen, Pump, P, Driver>;
type Host<const S: usize, const P: usize> = SessionHost<Frozen, Stack, Counting, S, P>;

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
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
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

/// An `on_event` that ignores what it is handed: this test is about the link.
fn ignoring() -> impl FnMut(IterationEvent<'_, '_>) + 'static {
    |_| {}
}

static RUNTIME: RuntimeCell<Frozen, 8, 1_024, 4> = RuntimeCell::new();
static LISTENER: LwipTcpListener<RX, 1, CELLS> = LwipTcpListener::new();

/// The cells a node's connections are made in: a pool with `static-link-storage`, nothing on the
/// heap profile.
#[cfg(feature = "static-link-storage")]
type Cells = TcpSocketPool<RX, CELLS>;
#[cfg(not(feature = "static-link-storage"))]
type Cells = ();

// Each node's cells: the dialler's for the connection it dials, the acceptor's for the one its
// listener takes and for its own dial (which this test does not use).
static DIAL_CELLS: Cells = cells();
static ACCEPT_DIAL_CELLS: Cells = cells();
static ACCEPT_CELLS: Cells = cells();

const fn cells() -> Cells {
    #[cfg(feature = "static-link-storage")]
    {
        TcpSocketPool::new()
    }
    #[cfg(not(feature = "static-link-storage"))]
    {}
}

/// A node's dial over `link`, its connections made in `cells`.
fn dial(link: LinkRef, cells: &'static Cells) -> LwipTcpDial<LinkRef, RX, CELLS> {
    #[cfg(feature = "static-link-storage")]
    {
        LwipTcpDial::new(link, cells)
    }
    #[cfg(not(feature = "static-link-storage"))]
    {
        let _: &() = cells;
        LwipTcpDial::new(link)
    }
}

/// `listener` listening on `port`, the connections it takes made in `cells`.
fn listen(
    listener: &'static LwipTcpListener<RX, 1, CELLS>,
    port: u16,
    cells: &'static Cells,
) -> Result<(), wz_link_lwip::tcp::TcpError> {
    #[cfg(feature = "static-link-storage")]
    {
        listener.listen_in(port, cells)
    }
    #[cfg(not(feature = "static-link-storage"))]
    {
        let _: &() = cells;
        listener.listen(port)
    }
}

// Each node's tables: one session, one pump, and the byte tables its links take their buffers from
// (a link's receive buffer holds a batch with its length).
static DIAL_SESSIONS: Slots<1> = SessionSlots::new();
static DIAL_PUMPS: Pumps<1> = PumpSlots::new();
static DIAL_RX: ByteCells<2_050, 1> = ByteCells::new();
static DIAL_TX: ByteCells<2_050, 1> = ByteCells::new();
static ACCEPT_SESSIONS: Slots<1> = SessionSlots::new();
static ACCEPT_PUMPS: Pumps<1> = PumpSlots::new();
static ACCEPT_RX: ByteCells<2_050, 1> = ByteCells::new();
static ACCEPT_TX: ByteCells<2_050, 1> = ByteCells::new();

const PORT: u16 = 47_701;

#[test]
fn a_session_opens_over_tcp_between_a_dialling_node_and_an_accepting_one() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link: LinkRef = Box::leak(Box::new(link));
    let runtime: Rt = RUNTIME.start(Frozen).expect("the runtime starts once");
    let local = CoopLocalSet::new(&runtime);

    listen(&LISTENER, PORT, &ACCEPT_CELLS).expect("the node listens");
    let accept_stack = Stack::new(
        [127, 0, 0, 1],
        &ACCEPT_RX,
        &ACCEPT_TX,
        dial(link, &ACCEPT_DIAL_CELLS),
    );
    let mut acceptor = accept_stack.acceptor(LwipTcpListen::new(link, &LISTENER));
    let dial_stack = Stack::new([127, 0, 0, 1], &DIAL_RX, &DIAL_TX, dial(link, &DIAL_CELLS));
    let dialler: Host<1, 1> = SessionHost::new(
        CoopLocalSet::new(&runtime),
        &DIAL_SESSIONS,
        &DIAL_PUMPS,
        dial_stack,
    );
    let accepting: Host<1, 1> = SessionHost::new(
        CoopLocalSet::new(&runtime),
        &ACCEPT_SESSIONS,
        &ACCEPT_PUMPS,
        accept_stack,
    );

    // The dialling node opens a `tcp/` link and a session over it.
    let router = Locator::tcp(IpEndpoint {
        addr: [127, 0, 0, 1],
        port: PORT,
    });
    let dialled = dialler
        .dial(
            || dialler.stack().bind_initiator(router),
            None,
            Counting(0xb0),
            || params(0xb0),
            config(SessionRole::Initiator),
            |_| ignoring(),
        )
        .unwrap_or_else(|why| panic!("the dial was refused: {why:?}"));
    assert_eq!(DIAL_RX.in_use(), 1, "the link took a receive buffer");
    assert_eq!(DIAL_TX.in_use(), 1, "and a frame buffer");

    // Turn the cooperative loop until the connection arrives, then until both ends are established.
    let mut accepted = None;
    for _ in 0..256 {
        local.run_until_idle();
        if accepted.is_none() {
            if let Some(driver) = acceptor.accept().expect("the listener is sound") {
                accepted = Some(
                    accepting
                        .open(
                            driver,
                            None,
                            Counting(0xa0),
                            || params(0xa0),
                            config(SessionRole::Acceptor),
                            |_| ignoring(),
                        )
                        .unwrap_or_else(|why| panic!("the accept was refused: {why:?}")),
                );
            }
        }
        if dialled.actions.is_established()
            && accepted
                .as_ref()
                .is_some_and(|session| session.actions.is_established())
        {
            break;
        }
    }
    let accepted = accepted.expect("the connection reached the acceptor");
    assert!(dialled.actions.is_established(), "the dialling end opened");
    assert!(
        accepted.actions.is_established(),
        "the accepting end opened"
    );
    assert_eq!(
        ACCEPT_RX.in_use(),
        1,
        "the accepted link took a receive buffer"
    );

    // The dialler closes; the acceptor's session ends and its link gives its buffers back.
    dialled.actions.send_close_with_reason(CloseReason::Generic);
    for _ in 0..256 {
        local.run_until_idle();
        if accepted.task.is_finished() {
            break;
        }
    }
    assert!(accepted.task.is_finished(), "the close ended the session");
}
