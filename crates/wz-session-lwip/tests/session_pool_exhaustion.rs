// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session pool of a node, filled and then asked for one more: the acceptor's
//! side of the exhaustion cases of the N-session pool design (case R1, and the
//! session-level consequence of case R6), over real handshakes on the lwIP
//! loopback, counted by a counting allocator.
//!
//! A node of the `session-slot` profile holds at most `MAX_SESSIONS` sessions, the
//! number the generated pool document (`session_slot_pool_mcu`) states, and every
//! session is a slot of a table, a cell of a pump table and a cell of the runtime's
//! task table, claimed before the session can run. This file fills a node with that
//! many sessions, each peer dialling in with a real `InitSyn`, and then sends the
//! next `InitSyn`. What must hold, by whichever table is the one that is full:
//!
//! - the listener ANSWERS NOTHING: no `InitAck`, and no `Close`, which would need
//!   the very slot that was not there. The peer's session stays where its first
//!   message left it (its `OpenSyn` is never sent);
//! - the refusal is COUNTED, by the listener (`refused`, with its reason) and by the
//!   table that said no (`SessionSlots::refused`, `PumpSlots::refused`, the
//!   runtime's task refusals), and by no other;
//! - what the attempt took is GIVEN BACK: a lane, a session slot, a pump cell, a
//!   task cell are as free as before it, so a refusal never leaks a table cell;
//! - nothing is allocated, in the handshakes that fill the node, in the refusal, in
//!   the Close of one session and in the next peer's admission into the cell that
//!   closed freed;
//! - each session reads only the datagrams its own peer sent, though they share one
//!   socket and one queue: a Put sent by peer `k` reaches session `k` alone.
//!
//! There is one test per table that can be the full one. The headline test makes the
//! lanes the limit (every table is exactly the generated `MAX_SESSIONS`), and the
//! three after it make the session table, the pump table and the task table the
//! limit with the others to spare, which is how a node with a table sized differently
//! from the others is full.
//!
//! The application layer is not on the path: an image's `on_event` builds one on
//! the heap today (step S9), so the sessions here are run with an `on_event` that
//! counts what it is handed and nothing else.
//!
//! Host-test level: no board runs it, and the stack the pump takes is not measured.

// A refused claim hands back what it was offered, which is what makes the refusal
// free of the heap; boxing it would allocate.
#![allow(clippy::result_large_err)]

use std::sync::atomic::{AtomicUsize, Ordering};

use wz_link_lwip::rx_sockets::SESSION_RX_SLOTS;
use wz_link_lwip::{ipv4_addr_from_octets, ipv4_addr_loopback, LwipLink};
use wz_runtime_coop::session_drive::{PumpSlots, SessionDriveConfig, SessionRole};
use wz_runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeCell};
use wz_session_core::close_reason::CloseReason;
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::session_init_params::{cookie_bytes, zid_bytes, SessionInitParams};
use wz_session_core::session_slot::SessionSlots;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::WhatAmI;
use wz_session_lwip::driver::{share_socket, LwipUdpDriver};
use wz_session_lwip::listener::{AcceptPass, SessionListener};
use wz_session_lwip::session_host::{OpenRefused, OpenedSession, SessionHost};
use wz_session_lwip::LwipSessionLink;

#[path = "support/alloc_count.rs"]
mod alloc_count;
use alloc_count::Measurement;

#[global_allocator]
static GLOBAL: alloc_count::CountingAllocator = alloc_count::CountingAllocator;

/// The number of sessions a node holds, as the generated pool document states it.
const N: usize = wz_session_core::session_slot_pool_mcu::SLOT_COUNT;

/// A clock that never moves: no deadline fires, so a session does only what the
/// other end asks of it, and an `InitSyn` nobody answers is not sent again.
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
type LinkRef = &'static LwipLink;
type Slots<const S: usize> = SessionSlots<Rt, CoopTime<Frozen>, LwipUdpDriver, Counting, S>;
type Pumps<const P: usize> = PumpSlots<Frozen, LwipSessionLink<LinkRef>, P>;
type Host<const S: usize, const P: usize> = SessionHost<Frozen, LinkRef, Counting, S, P>;
type Opened = OpenedSession<Frozen>;

fn params(zid: u8) -> SessionInitParams {
    SessionInitParams {
        whatami: WhatAmI::Peer,
        zid: zid_bytes(&[zid; 4]),
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: 10_000,
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

const KEY: &str = "pool/put";

/// What each session's `on_event` has been handed: Puts read in place, by session.
/// Each scenario has a block of `BLOCK` indices of its own (the tests of a file share
/// the statics): accepted session `k` is index `k` of the block, and the session
/// that dialled as peer `k` is `DIALLED + k`.
const DIALLED: usize = 32;
const BLOCK: usize = 64;
static PUTS: [AtomicUsize; 8 * BLOCK] = [const { AtomicUsize::new(0) }; 8 * BLOCK];

fn puts(session: usize) -> usize {
    PUTS[session].load(Ordering::SeqCst)
}

/// An `on_event` that counts the Puts it is handed, into [`PUTS`], and nothing else.
fn counting(session: usize) -> impl FnMut(IterationEvent<'_>) + 'static {
    move |event| {
        if matches!(event, IterationEvent::InPlace(_)) {
            PUTS[session].fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// Which table is the full one in a scenario, and so which refusal is expected.
#[derive(Clone, Copy, Debug)]
enum Why {
    Lane,
    SessionSlot,
    PumpCell,
    Task,
}

/// The tables of the node under test (the acceptor) and of the peers that dial it.
struct Rig<
    const LANES: usize,
    const SLOTS: usize,
    const PUMPS: usize,
    const DIALERS: usize,
    const TASKS: usize,
> {
    link: LinkRef,
    port: u16,
    local: CoopLocalSet<Frozen>,
    runtime: Rt,
    listener: &'static SessionListener<LANES>,
    sessions: &'static Slots<SLOTS>,
    pumps: &'static Pumps<PUMPS>,
    acceptor: Host<SLOTS, PUMPS>,
    dialler: Host<DIALERS, DIALERS>,
    /// Sockets for the peers that will dial, bound before any window, since a
    /// socket's own state is step S7's and not what is measured here.
    sockets: Vec<wz_link_lwip::rx_sockets::SessionRxSocket>,
    accepted: Vec<Opened>,
    next_acceptor: u8,
    next_dialler: u8,
    /// This scenario's block of [`PUTS`].
    base: usize,
}

impl<
        const LANES: usize,
        const SLOTS: usize,
        const PUMPS: usize,
        const DIALERS: usize,
        const TASKS: usize,
    > Rig<LANES, SLOTS, PUMPS, DIALERS, TASKS>
{
    #[allow(clippy::too_many_arguments)]
    fn new(
        link: LinkRef,
        port: u16,
        cell: &'static RuntimeCell<Frozen, TASKS, 256, 4>,
        listener: &'static SessionListener<LANES>,
        sessions: &'static Slots<SLOTS>,
        pumps: &'static Pumps<PUMPS>,
        dial_sessions: &'static Slots<DIALERS>,
        dial_pumps: &'static Pumps<DIALERS>,
    ) -> Self {
        let runtime = cell.start(Frozen).expect("the runtime starts once");
        let local = CoopLocalSet::new(&runtime);
        let listening = wz_link_lwip::test_bind::session_rx(link, port).expect("bind the listener");
        assert!(listener.listen(listening).is_ok(), "listens once");
        // One for each dial the scenario makes: the node's `fill`, the one more, and
        // the redial after one of them closes.
        let sockets = (0..=DIALERS)
            .map(|_| wz_link_lwip::test_bind::session_rx(link, 0).expect("bind a dialler"))
            .collect();
        Self {
            link,
            port,
            acceptor: SessionHost::new(CoopLocalSet::new(&runtime), sessions, pumps, link),
            dialler: SessionHost::new(CoopLocalSet::new(&runtime), dial_sessions, dial_pumps, link),
            local,
            runtime,
            listener,
            sessions,
            pumps,
            sockets,
            accepted: Vec::with_capacity(SLOTS + 2),
            next_acceptor: 0,
            next_dialler: 0,
            // The four scenarios are on ports 7801 to 7804, one block each.
            base: usize::from(port - 7801) * BLOCK,
        }
    }

    /// One turn of the node: the listener decides what has arrived, then every task
    /// runs once. An `InitSyn` it admits becomes a session that reads and answers
    /// it in this same turn.
    fn turn(&mut self) -> AcceptPass {
        let host = &self.acceptor;
        let accepted = &mut self.accepted;
        let next = &mut self.next_acceptor;
        let base = self.base;
        let pass = self.listener.accept_pass(self.link, &mut |admission| {
            let k = usize::from(*next);
            *next += 1;
            host.admit(
                admission,
                Counting(0xa0 + k as u8),
                params(0xa0 + k as u8),
                config(SessionRole::Acceptor),
                |_| counting(base + k),
            )
            .map(|opened| accepted.push(opened))
        });
        self.local.run_until_idle();
        pass
    }

    /// A peer dials the node: a session of the dialling side opens over one of the
    /// sockets bound beforehand, and its `InitSyn` leaves when its task first runs.
    fn dial(&mut self) -> (usize, Result<Opened, OpenRefused>) {
        let k = usize::from(self.next_dialler);
        self.next_dialler += 1;
        let socket = self.sockets.pop().expect("a socket for every dialler");
        let driver = LwipUdpDriver::new(
            share_socket(socket),
            ipv4_addr_from_octets([127, 0, 0, 1]),
            self.port,
        );
        let opened = self.dialler.open(
            driver,
            None,
            Counting(0xb0 + k as u8),
            params(0xb0 + k as u8),
            config(SessionRole::Initiator),
            |_| counting(self.base + DIALLED + k),
        );
        (k, opened)
    }

    /// Turn until `done`, a bounded number of times.
    fn turns_until(&mut self, what: &str, mut done: impl FnMut(&Self) -> bool) {
        for _ in 0..64 {
            if done(self) {
                return;
            }
            self.turn();
        }
        panic!("{what}: not reached in 64 turns");
    }

    fn established(&self, session: &Opened) -> bool {
        session.actions.is_established()
    }
}

/// Fill a node with `fill` sessions through real handshakes, send one `InitSyn`
/// more, and check what the table `why` that is full does with it; then close one
/// session and admit the next peer into the cell it frees.
#[allow(clippy::too_many_arguments)]
fn fill_then_refuse<
    const LANES: usize,
    const SLOTS: usize,
    const PUMPS: usize,
    const DIALERS: usize,
    const TASKS: usize,
>(
    mut rig: Rig<LANES, SLOTS, PUMPS, DIALERS, TASKS>,
    fill: usize,
    why: Why,
) {
    let m = Measurement::new();
    let mut dialled: Vec<Opened> = Vec::with_capacity(DIALERS + 1);

    // FILL: `fill` peers dial in, one at a time, each through a full handshake. The
    // listener admits each into a lane, a session slot, a pump cell and a task cell.
    let ((), n) = m.count("fill", || {
        for k in 0..fill {
            let (_, opened) = rig.dial();
            dialled.push(opened.unwrap_or_else(|why| panic!("dial {k} was refused: {why:?}")));
            rig.turns_until("a handshake", |rig| {
                rig.accepted.len() == k + 1
                    && rig.established(&dialled[k])
                    && rig.established(&rig.accepted[k])
            });
        }
    });
    assert_eq!(
        n, 0,
        "{fill} handshakes through the listener cost the heap nothing"
    );
    assert_eq!(rig.listener.counts().admitted as usize, fill);
    assert_eq!(rig.listener.counts().refused(), 0);
    assert_eq!(rig.listener.in_use(), fill, "a lane for each session");
    assert_eq!(rig.sessions.in_use(), fill, "a slot for each");
    assert_eq!(rig.pumps.in_use(), fill, "a pump cell for each");
    assert_eq!(rig.sessions.refused(), 0);
    assert_eq!(rig.pumps.refused(), 0);
    for session in &rig.accepted {
        assert_eq!(
            session.actions.trace_snapshot().send_init_ack_with_cookie,
            1,
            "each session answered its own InitSyn, once"
        );
    }

    // ROUTING: one table, one socket, one queue, and each session reads only its
    // own peer's datagrams: a Put from peer `k` reaches accepted session `k` alone,
    // and a Put the other way reaches peer `k` alone.
    let ((), n) = m.count("a put each way", || {
        for (k, peer) in dialled.iter().enumerate().take(fill) {
            peer.actions
                .send_push_literal(KEY, &[k as u8; 8], true)
                .expect("the dialling peer's Put leaves");
            rig.turn();
            rig.accepted[k]
                .actions
                .send_push_literal(KEY, &[k as u8; 8], true)
                .expect("the accepted session's Put leaves");
            rig.turn();
        }
    });
    assert_eq!(
        n, 0,
        "a Put each way over the shared socket costs the heap nothing"
    );
    for k in 0..fill {
        assert_eq!(
            puts(rig.base + k),
            1,
            "accepted session {k} read its own peer's Put, once"
        );
        assert_eq!(
            puts(rig.base + DIALLED + k),
            1,
            "peer {k} read its own session's Put, once"
        );
    }

    // THE NEXT INITSYN: from one more peer, to a node whose `why` table is full.
    let mut extra = None;
    let ((), n) = m.count("the refused InitSyn", || {
        let (_, opened) = rig.dial();
        extra = Some(opened.unwrap_or_else(|why| panic!("the extra dial was refused: {why:?}")));
        for _ in 0..8 {
            rig.turn();
        }
    });
    let extra_session = extra.expect("dialled");
    assert_eq!(n, 0, "refusing an InitSyn costs the heap nothing");

    // Nothing was answered: the peer sent its InitSyn and never got an InitAck, so it
    // never sent an OpenSyn and is not established.
    let trace = extra_session.actions.trace_snapshot();
    assert_eq!(trace.send_init_syn, 1, "the peer did send its InitSyn");
    assert_eq!(trace.send_open_syn, 0, "and was answered with nothing");
    assert!(!rig.established(&extra_session));
    assert!(
        !extra_session.task.is_finished(),
        "no Close came back either: the refused peer is still waiting for its InitAck"
    );
    assert_eq!(rig.accepted.len(), fill, "no session was built for it");

    // Counted, by the listener and by the table that said no, and by no other.
    let counts = rig.listener.counts();
    assert_eq!(counts.admitted as usize, fill);
    assert_eq!(counts.refused(), 1, "{why:?}: one refusal, counted once");
    assert_eq!(counts.strays, 0);
    assert_eq!(rig.listener.refused(), 1);
    let task_refusals = rig.runtime.task_refusals().no_task_cell;
    let (lane, slot, pump, task) = match why {
        Why::Lane => (1, 0, 0, 0),
        Why::SessionSlot => (0, 1, 0, 0),
        Why::PumpCell => (0, 0, 1, 0),
        Why::Task => (0, 0, 0, 1),
    };
    assert_eq!(counts.refused_no_lane, lane, "{why:?}: lanes");
    assert_eq!(
        counts.refused_no_session_slot, slot,
        "{why:?}: session slots"
    );
    assert_eq!(counts.refused_no_pump_cell, pump, "{why:?}: pump cells");
    assert_eq!(counts.refused_no_task_cell, task, "{why:?}: task cells");
    assert_eq!(
        rig.sessions.refused(),
        slot,
        "{why:?}: the session table's count"
    );
    assert_eq!(rig.pumps.refused(), pump, "{why:?}: the pump table's count");
    assert_eq!(task_refusals, task, "{why:?}: the runtime's task count");
    assert_eq!(
        rig.listener.rx_drops(),
        0,
        "the socket's queue never overflowed"
    );

    // Nothing the attempt took is kept: every table is as full as the sessions that
    // exist and no fuller.
    assert_eq!(rig.listener.in_use(), fill, "{why:?}: lanes");
    assert_eq!(rig.sessions.in_use(), fill, "{why:?}: session slots");
    assert_eq!(rig.pumps.in_use(), fill, "{why:?}: pump cells");

    // RELEASE AND REUSE: one session closes, which frees its lane, slot, pump cell
    // and task cell, and the next peer's InitSyn is admitted into them. The peer that
    // was refused is let go first (its InitSyn will not be sent again).
    extra_session.task.abort();
    drop(extra_session);
    let ((), n) = m.count("close and reuse", || {
        dialled[0]
            .actions
            .send_close_with_reason(CloseReason::Generic);
        rig.turns_until("the close", |rig| rig.accepted[0].task.is_finished());
        // The session's lane, pump cell and (once its handles go) slot are freed by
        // the END of its task, not by whoever still holds a handle to it: a peer
        // whose session has ended cannot hold the shared queue by lingering.
        assert_eq!(
            rig.listener.in_use(),
            fill - 1,
            "the lane went with the task"
        );
        assert_eq!(rig.pumps.in_use(), fill - 1, "the pump cell went with it");
        // The closed session is let go on both sides.
        drop(rig.accepted.swap_remove(0));
        let closed = dialled.swap_remove(0);
        closed.task.abort();
        drop(closed);
        rig.turn();
        rig.turn();

        // The next peer dials, and is admitted.
        let (_, opened) = rig.dial();
        dialled.push(opened.unwrap_or_else(|why| panic!("the redial was refused: {why:?}")));
        rig.turns_until("the redial's handshake", |rig| {
            rig.accepted.len() == fill && rig.accepted.iter().all(|s| rig.established(s))
        });
    });
    assert_eq!(n, 0, "a close and the next admission cost the heap nothing");
    let counts = rig.listener.counts();
    assert_eq!(
        counts.admitted as usize,
        fill + 1,
        "the freed cell took the next peer"
    );
    assert_eq!(counts.refused(), 1, "and that was not a refusal");
    assert_eq!(rig.listener.in_use(), fill);
    assert_eq!(rig.sessions.in_use(), fill);
    assert_eq!(rig.pumps.in_use(), fill);
}

/// The headline case. The listener, the session table and the pump table are each
/// exactly `MAX_SESSIONS` (the generated number), so the lanes are what is full when
/// the `MAX_SESSIONS + 1`th peer sends its `InitSyn`.
#[test]
fn n_sessions_fill_the_node_and_the_next_initsyn_is_answered_with_nothing() {
    static RUNTIME: RuntimeCell<Frozen, 16, 256, 4> = RuntimeCell::new();
    static LISTENER: SessionListener<N> = SessionListener::new();
    static SESSIONS: Slots<N> = SessionSlots::new();
    static PUMPS: Pumps<N> = PumpSlots::new();
    static DIAL_SESSIONS: Slots<{ N + 1 }> = SessionSlots::new();
    static DIAL_PUMPS: Pumps<{ N + 1 }> = PumpSlots::new();
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link: LinkRef = Box::leak(Box::new(link));
    let rig = Rig::new(
        link,
        7801,
        &RUNTIME,
        &LISTENER,
        &SESSIONS,
        &PUMPS,
        &DIAL_SESSIONS,
        &DIAL_PUMPS,
    );
    fill_then_refuse(rig, N, Why::Lane);
}

/// The listener has a lane to spare and the session table is the full one: the
/// table says no, counts it, and the lane that was reserved for the peer is given
/// back.
#[test]
fn a_full_session_table_refuses_the_next_initsyn_and_gives_its_lane_back() {
    static RUNTIME: RuntimeCell<Frozen, 16, 256, 4> = RuntimeCell::new();
    static LISTENER: SessionListener<{ N + 1 }> = SessionListener::new();
    static SESSIONS: Slots<N> = SessionSlots::new();
    static PUMPS: Pumps<{ N + 1 }> = PumpSlots::new();
    static DIAL_SESSIONS: Slots<{ N + 1 }> = SessionSlots::new();
    static DIAL_PUMPS: Pumps<{ N + 1 }> = PumpSlots::new();
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link: LinkRef = Box::leak(Box::new(link));
    let rig = Rig::new(
        link,
        7802,
        &RUNTIME,
        &LISTENER,
        &SESSIONS,
        &PUMPS,
        &DIAL_SESSIONS,
        &DIAL_PUMPS,
    );
    fill_then_refuse(rig, N, Why::SessionSlot);
}

/// The session table has a slot to spare and the pump table is the full one: the
/// slot the refused session had already claimed is given back with it.
#[test]
fn a_full_pump_table_refuses_the_next_initsyn_and_gives_its_session_slot_back() {
    static RUNTIME: RuntimeCell<Frozen, 16, 256, 4> = RuntimeCell::new();
    static LISTENER: SessionListener<{ N + 1 }> = SessionListener::new();
    static SESSIONS: Slots<{ N + 1 }> = SessionSlots::new();
    static PUMPS: Pumps<N> = PumpSlots::new();
    static DIAL_SESSIONS: Slots<{ N + 1 }> = SessionSlots::new();
    static DIAL_PUMPS: Pumps<{ N + 1 }> = PumpSlots::new();
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link: LinkRef = Box::leak(Box::new(link));
    let rig = Rig::new(
        link,
        7803,
        &RUNTIME,
        &LISTENER,
        &SESSIONS,
        &PUMPS,
        &DIAL_SESSIONS,
        &DIAL_PUMPS,
    );
    fill_then_refuse(rig, N, Why::PumpCell);
}

/// Every other table has a cell to spare and the runtime's task table is the full
/// one: the session that cannot be hosted as a task is never run, and the pump cell,
/// session slot and lane it had claimed are given back. The runtime holds the `N + 1`
/// tasks of the peers that dial in and the `N` of the sessions that answer them, so
/// `2N + 1` cells are exactly full when the `N + 1`th session is asked for.
#[test]
fn a_full_task_table_refuses_the_next_initsyn_and_gives_everything_back() {
    static RUNTIME: RuntimeCell<Frozen, { 2 * N + 1 }, 256, 4> = RuntimeCell::new();
    static LISTENER: SessionListener<{ N + 1 }> = SessionListener::new();
    static SESSIONS: Slots<{ N + 1 }> = SessionSlots::new();
    static PUMPS: Pumps<{ N + 1 }> = PumpSlots::new();
    static DIAL_SESSIONS: Slots<{ N + 1 }> = SessionSlots::new();
    static DIAL_PUMPS: Pumps<{ N + 1 }> = PumpSlots::new();
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link: LinkRef = Box::leak(Box::new(link));
    let rig = Rig::new(
        link,
        7804,
        &RUNTIME,
        &LISTENER,
        &SESSIONS,
        &PUMPS,
        &DIAL_SESSIONS,
        &DIAL_PUMPS,
    );
    fill_then_refuse(rig, N, Why::Task);
}

/// The cheapest thing to throw at a listener is a flood of datagrams that are not an
/// `InitSyn`, from a peer it has no session for, and it must cost the node no table
/// cell: the listening socket's queue (the shared queue every session reads) takes
/// what it holds and DROPS and COUNTS the rest, the listener drops each stray it
/// reads and counts it, and no lane, session slot, pump cell or task cell is taken
/// for any of it, and none of it allocates. The next real `InitSyn` is admitted as
/// if nothing had happened.
#[test]
fn a_flood_of_strays_fills_the_queue_and_is_dropped_and_counted_and_takes_no_cell() {
    static RUNTIME: RuntimeCell<Frozen, 16, 256, 4> = RuntimeCell::new();
    static LISTENER: SessionListener<N> = SessionListener::new();
    static SESSIONS: Slots<N> = SessionSlots::new();
    static PUMPS: Pumps<N> = PumpSlots::new();
    static DIAL_SESSIONS: Slots<{ N + 1 }> = SessionSlots::new();
    static DIAL_PUMPS: Pumps<{ N + 1 }> = PumpSlots::new();
    const PORT: u16 = 7805;
    // The queue holds one datagram fewer than its slot count (a ring of `Q` entries).
    const QUEUED: usize = SESSION_RX_SLOTS - 1;
    const SENT: usize = SESSION_RX_SLOTS + 10;
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link: LinkRef = Box::leak(Box::new(link));
    let mut rig = Rig::new(
        link,
        PORT,
        &RUNTIME,
        &LISTENER,
        &SESSIONS,
        &PUMPS,
        &DIAL_SESSIONS,
        &DIAL_PUMPS,
    );
    let flooder = wz_link_lwip::test_bind::session_rx(link, 0).expect("bind the flooder");
    let m = Measurement::new();

    // A Frame header and an InitAck header, alternately: neither opens a session.
    let (pass, n) = m.count("a flood of strays", || {
        for i in 0..SENT {
            let stray = if i % 2 == 0 {
                [0x05u8, 0, 0, 0]
            } else {
                [0x21u8, 0, 0, 0]
            };
            flooder
                .send_to(ipv4_addr_loopback(), PORT, &stray)
                .expect("the stray leaves");
            link.poll_loopback();
        }
        rig.turn()
    });
    assert_eq!(n, 0, "a flood of strays costs the heap nothing");
    assert_eq!(
        pass.strays as usize, QUEUED,
        "the listener read, dropped and counted every stray the queue held"
    );
    assert_eq!(
        pass.admitted + pass.refused,
        0,
        "and admitted or refused none"
    );
    assert_eq!(rig.listener.counts().strays as usize, QUEUED);
    assert_eq!(
        rig.listener.rx_drops() as usize,
        SENT - QUEUED,
        "the socket dropped and counted what its queue could not hold"
    );
    assert_eq!(rig.listener.in_use(), 0, "no lane");
    assert_eq!(rig.sessions.in_use(), 0, "no session slot");
    assert_eq!(rig.pumps.in_use(), 0, "no pump cell");
    assert_eq!(rig.accepted.len(), 0);
    assert_eq!(rig.runtime.task_refusals().no_task_cell, 0);

    // The listener is as it was: a real InitSyn is admitted and shaken hands with.
    let (_, opened) = rig.dial();
    let dialled = opened.unwrap_or_else(|why| panic!("the dial was refused: {why:?}"));
    rig.turns_until("a handshake after the flood", |rig| {
        rig.accepted.len() == 1 && rig.established(&dialled) && rig.established(&rig.accepted[0])
    });
    assert_eq!(rig.listener.counts().admitted, 1);
    assert_eq!(rig.listener.refused(), 0);
}
