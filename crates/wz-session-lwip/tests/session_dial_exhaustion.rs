// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A node that dials, filled and then asked to dial once more: the dialler's side of
//! the exhaustion cases of the N-session pool design (case R2, and the
//! session-level consequence of case R6), on the lwIP loopback, counted by a
//! counting allocator.
//!
//! A session that dials needs a socket (a cell of the `static` pool the image
//! declared), a slot of the session table, a cell of the pump table and a cell of the
//! runtime's task table (`SessionHost::dial`). This file dials `MAX_SESSIONS`
//! sessions towards a sink that counts the `InitSyn`s that arrive, then dials once
//! more, by each table that can be the full one. What must hold:
//!
//! - the dial answers a TYPED refusal naming the table (`DialRefused::Link` for the
//!   socket pool, `DialRefused::Open` for the others), never a panic and never a
//!   session half made;
//! - the refusal is COUNTED, by the table that said no and by no other;
//! - NOTHING IS SENT for a dial that is refused: the sink has seen exactly the
//!   `InitSyn`s of the dials that succeeded, because a pump does not speak until the
//!   task that runs it first runs, and a dial that cannot get a task cell never runs
//!   one;
//! - what the attempt took is GIVEN BACK (the socket, the slot, the pump cell), so a
//!   refusal never leaks a cell;
//! - nothing is allocated, in the dials that fill the node, in the refusal, in the
//!   release of a session and in the dial that takes the cell it freed;
//! - after one session is released, the same dial succeeds into the cell it freed.
//!
//! It runs on the node's real profile: `session-slot` for the session tables and
//! `static-link-storage` for the sockets, since a socket bound out of a heap box
//! allocates when a refused dial hands it back.
//!
//! Host-test level: no board runs it, and the stack the pump takes is not measured.

// A refused claim hands back what it was offered, which is what makes the refusal
// free of the heap; boxing it would allocate.
#![allow(clippy::result_large_err)]

use std::rc::Rc;

use wz_link_lwip::rx_sockets::{SessionRxPool, SessionRxSocket};
use wz_link_lwip::LwipLink;
use wz_runtime_coop::executor::SpawnRefusal;
use wz_runtime_coop::session_drive::{
    IpEndpoint, LinkOpenError, PumpSlots, SessionDriveConfig, SessionRole,
};
use wz_runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeCell};
use wz_session_core::datagram_peer::is_init_syn;
use wz_session_core::session_init_params::{cookie_bytes, zid_bytes, SessionInitParams};
use wz_session_core::session_slot::SessionSlots;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::WhatAmI;
use wz_session_lwip::driver::LwipUdpDriver;
use wz_session_lwip::session_host::{
    DialRefused, DialTarget, OpenRefused, OpenedSession, SessionHost,
};
use wz_session_lwip::{LwipLinks, LwipSessionLink};

#[path = "support/alloc_count.rs"]
mod alloc_count;
use alloc_count::Measurement;

#[global_allocator]
static GLOBAL: alloc_count::CountingAllocator = alloc_count::CountingAllocator;

/// The number of sessions a node holds, as the generated pool document states it.
const N: usize = wz_session_core::session_slot_pool_mcu::SLOT_COUNT;

/// A clock that never moves: no deadline fires, so a dial's `InitSyn` is not sent
/// again and what the sink counts is exactly what the dials sent.
#[derive(Clone, Default)]
struct Frozen;
impl ClockSource for Frozen {
    fn now_us(&self) -> u64 {
        0
    }
}

/// A deterministic stand-in for a board's TRNG.
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

type Rt = CoopRuntime<Frozen, LwipUdpDriver>;
type LinkRc = Rc<LwipLink>;
type Slots<const S: usize> = SessionSlots<Rt, CoopTime<Frozen>, LwipUdpDriver, Counting, S>;
type Pumps<const P: usize> = PumpSlots<Frozen, LwipSessionLink<LinkRc>, P, LwipUdpDriver>;
type Opened = OpenedSession<Frozen, LwipUdpDriver>;

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

fn config() -> SessionDriveConfig {
    SessionDriveConfig {
        timeouts: SessionTimeouts::spec_defaults(),
        role: SessionRole::Initiator,
        max_iters: None,
    }
}

/// Which table is the full one in a scenario, and so which refusal is expected.
#[derive(Clone, Copy, Debug)]
enum Why {
    Socket,
    SessionSlot,
    PumpCell,
    Task,
}

struct Rig<const SLOTS: usize, const PUMPS: usize, const POOL: usize, const TASKS: usize> {
    link: LinkRc,
    runtime: Rt,
    local: CoopLocalSet<Frozen>,
    host: SessionHost<Frozen, LinkRc, Counting, SLOTS, PUMPS>,
    links: LwipLinks<LinkRc>,
    sessions: &'static Slots<SLOTS>,
    pumps: &'static Pumps<PUMPS>,
    sockets: &'static SessionRxPool<POOL>,
    sink_port: u16,
    sink: SessionRxSocket,
    /// The `InitSyn`s the sink has read so far.
    init_syns: usize,
    next: u8,
}

impl<const SLOTS: usize, const PUMPS: usize, const POOL: usize, const TASKS: usize>
    Rig<SLOTS, PUMPS, POOL, TASKS>
{
    fn new(
        link: LinkRc,
        sink_port: u16,
        cell: &'static RuntimeCell<Frozen, TASKS, 256, 4>,
        sessions: &'static Slots<SLOTS>,
        pumps: &'static Pumps<PUMPS>,
        sockets: &'static SessionRxPool<POOL>,
    ) -> Self {
        let runtime = cell.start(Frozen).expect("the runtime starts once");
        let sink = wz_link_lwip::test_bind::session_rx(&link, sink_port).expect("bind the sink");
        Self {
            host: SessionHost::new(CoopLocalSet::new(&runtime), sessions, pumps, link.clone()),
            links: LwipLinks::new(link.clone(), sockets),
            local: CoopLocalSet::new(&runtime),
            runtime,
            link,
            sessions,
            pumps,
            sockets,
            sink_port,
            sink,
            init_syns: 0,
            next: 0,
        }
    }

    /// Dial the sink: a session of this node opens towards it.
    fn dial(&mut self) -> Result<Opened, DialRefused> {
        let zid = 0xb0 + self.next;
        self.next += 1;
        self.host.dial(
            &self.links,
            DialTarget::address(IpEndpoint {
                addr: [127, 0, 0, 1],
                port: self.sink_port,
            }),
            Counting(zid),
            || params(zid),
            config(),
            |_| |_: wz_session_core::driver_loop::IterationEvent<'_>| {},
        )
    }

    /// One turn: every task runs once, lwIP delivers, and the sink counts the
    /// `InitSyn`s that have arrived.
    fn turn(&mut self) {
        self.local.run_until_idle();
        self.link.poll_loopback();
        self.link.check_timeouts();
        while let Some(datagram) = self.sink.try_recv() {
            if is_init_syn(datagram.data.as_slice()) {
                self.init_syns += 1;
            }
        }
    }
}

/// Dial `fill` sessions, each of which sends its `InitSyn`; dial once more and see
/// what the table `why` that is full does; release one session and dial again.
fn dial_then_refuse<
    const SLOTS: usize,
    const PUMPS: usize,
    const POOL: usize,
    const TASKS: usize,
>(
    mut rig: Rig<SLOTS, PUMPS, POOL, TASKS>,
    fill: usize,
    why: Why,
) {
    let m = Measurement::new();
    let mut opened: Vec<Opened> = Vec::with_capacity(fill + 2);

    // FILL: each dial takes a socket, a slot, a pump cell and a task cell, and its
    // InitSyn leaves once its task runs.
    let ((), n) = m.count("fill", || {
        for k in 0..fill {
            let session = rig
                .dial()
                .unwrap_or_else(|why| panic!("dial {k} was refused: {why:?}"));
            opened.push(session);
            for _ in 0..3 {
                rig.turn();
            }
        }
    });
    assert_eq!(n, 0, "{fill} dials cost the heap nothing");
    assert_eq!(rig.init_syns, fill, "each dial sent its InitSyn, once");
    assert_eq!(rig.sockets.in_use(), fill, "a socket for each");
    assert_eq!(rig.sessions.in_use(), fill, "a slot for each");
    assert_eq!(rig.pumps.in_use(), fill, "a pump cell for each");
    assert_eq!(rig.sockets.refusals(), 0);
    assert_eq!(rig.sessions.refused(), 0);
    assert_eq!(rig.pumps.refused(), 0);
    assert_eq!(rig.runtime.task_refusals().no_task_cell, 0);

    // THE NEXT DIAL, to a node whose `why` table is full.
    let (refused, n) = m.count("the refused dial", || {
        let refused = rig.dial();
        for _ in 0..4 {
            rig.turn();
        }
        refused
    });
    let Err(refusal) = refused else {
        panic!("{why:?}: a dial past the node's capacity was accepted");
    };
    assert_eq!(n, 0, "{why:?}: a refused dial costs the heap nothing");
    let expected = match why {
        Why::Socket => DialRefused::Link(LinkOpenError::Exhausted),
        Why::SessionSlot => DialRefused::Open(OpenRefused::SessionSlot),
        Why::PumpCell => DialRefused::Open(OpenRefused::PumpCell),
        Why::Task => DialRefused::Open(OpenRefused::Task(SpawnRefusal::NoTaskCell)),
    };
    assert_eq!(
        refusal, expected,
        "{why:?}: the typed refusal names the table"
    );

    // Counted by the table that said no, and by no other.
    let (socket, slot, pump, task) = match why {
        Why::Socket => (1, 0, 0, 0),
        Why::SessionSlot => (0, 1, 0, 0),
        Why::PumpCell => (0, 0, 1, 0),
        Why::Task => (0, 0, 0, 1),
    };
    assert_eq!(
        rig.sockets.refusals(),
        socket,
        "{why:?}: the socket pool's count"
    );
    assert_eq!(
        rig.sessions.refused(),
        slot,
        "{why:?}: the session table's count"
    );
    assert_eq!(rig.pumps.refused(), pump, "{why:?}: the pump table's count");
    assert_eq!(
        rig.runtime.task_refusals().no_task_cell,
        task,
        "{why:?}: the runtime's task count"
    );

    // Nothing was sent for it, and nothing it took is kept.
    assert_eq!(
        rig.init_syns, fill,
        "{why:?}: a refused dial sent no InitSyn"
    );
    assert_eq!(rig.sockets.in_use(), fill, "{why:?}: sockets");
    assert_eq!(rig.sessions.in_use(), fill, "{why:?}: session slots");
    assert_eq!(rig.pumps.in_use(), fill, "{why:?}: pump cells");

    // RELEASE AND REDIAL: one session is let go, which frees its socket, slot, pump
    // cell and task cell, and the dial that was refused now succeeds into them.
    let ((), n) = m.count("release and redial", || {
        let first = opened.swap_remove(0);
        first.task.abort();
        drop(first);
        rig.turn();
        rig.turn();
        let again = rig
            .dial()
            .unwrap_or_else(|why| panic!("{why:?}: the redial was refused after a release"));
        opened.push(again);
        for _ in 0..3 {
            rig.turn();
        }
    });
    assert_eq!(n, 0, "a release and a redial cost the heap nothing");
    assert_eq!(rig.init_syns, fill + 1, "the redial sent its InitSyn");
    assert_eq!(rig.sockets.in_use(), fill);
    assert_eq!(rig.sessions.in_use(), fill);
    assert_eq!(rig.pumps.in_use(), fill);
}

/// The socket pool is the full one: storage for `MAX_SESSIONS` sockets, so the dial
/// answers `Link(Exhausted)` before any session table is touched.
#[test]
fn a_dial_with_no_socket_left_is_refused_typed_and_counted_and_sends_nothing() {
    static RUNTIME: RuntimeCell<Frozen, { N + 2 }, 256, 4> = RuntimeCell::new();
    static SESSIONS: Slots<{ N + 1 }> = SessionSlots::new();
    static PUMPS: Pumps<{ N + 1 }> = PumpSlots::new();
    static SOCKETS: SessionRxPool<N> = SessionRxPool::new();
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let rig = Rig::new(Rc::new(link), 7811, &RUNTIME, &SESSIONS, &PUMPS, &SOCKETS);
    dial_then_refuse(rig, N, Why::Socket);
}

/// The session table is the full one, with a socket to spare: the refused dial's
/// socket goes back to its pool.
#[test]
fn a_dial_with_no_session_slot_left_is_refused_typed_and_counted_and_gives_its_socket_back() {
    static RUNTIME: RuntimeCell<Frozen, { N + 2 }, 256, 4> = RuntimeCell::new();
    static SESSIONS: Slots<N> = SessionSlots::new();
    static PUMPS: Pumps<{ N + 1 }> = PumpSlots::new();
    static SOCKETS: SessionRxPool<{ N + 1 }> = SessionRxPool::new();
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let rig = Rig::new(Rc::new(link), 7812, &RUNTIME, &SESSIONS, &PUMPS, &SOCKETS);
    dial_then_refuse(rig, N, Why::SessionSlot);
}

/// The pump table is the full one: the slot and the socket the refused session had
/// already claimed are given back.
#[test]
fn a_dial_with_no_pump_cell_left_is_refused_typed_and_counted_and_gives_everything_back() {
    static RUNTIME: RuntimeCell<Frozen, { N + 2 }, 256, 4> = RuntimeCell::new();
    static SESSIONS: Slots<{ N + 1 }> = SessionSlots::new();
    static PUMPS: Pumps<N> = PumpSlots::new();
    static SOCKETS: SessionRxPool<{ N + 1 }> = SessionRxPool::new();
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let rig = Rig::new(Rc::new(link), 7813, &RUNTIME, &SESSIONS, &PUMPS, &SOCKETS);
    dial_then_refuse(rig, N, Why::PumpCell);
}

/// The runtime's task table is the full one, which is the case that would put an
/// `InitSyn` on the wire for a session that cannot run if the pump spoke when it
/// was built: the pump is in its cell and the session in its slot by the time the
/// task is refused, and the sink must still have seen no `InitSyn` for it. All three
/// are given back.
#[test]
fn a_dial_with_no_task_cell_left_is_refused_before_its_initsyn_leaves() {
    static RUNTIME: RuntimeCell<Frozen, N, 256, 4> = RuntimeCell::new();
    static SESSIONS: Slots<{ N + 1 }> = SessionSlots::new();
    static PUMPS: Pumps<{ N + 1 }> = PumpSlots::new();
    static SOCKETS: SessionRxPool<{ N + 1 }> = SessionRxPool::new();
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let rig = Rig::new(Rc::new(link), 7814, &RUNTIME, &SESSIONS, &PUMPS, &SOCKETS);
    dial_then_refuse(rig, N, Why::Task);
}
