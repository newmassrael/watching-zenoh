// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The acceptor e2e on the fixed-memory profile (fixed-memory step S9c): the same
//! handshake and the same reactive peer as the heap form, with every table the run
//! needs in statics the image declares and this crate linking no `alloc`.
//!
//! The heap form takes an `AcceptorTopology`-like pair of ends, builds the session
//! with `new_session_actions` into an `Rc` and drives a `SessionPump` it owns on its
//! stack. This one claims what the session needs from [`AcceptorStatics`]: a socket of
//! a static pool for the listener, a slot of the session table, a cell of the pump
//! table, a cell of the task table, and runs the pump as a task of a static runtime.
//! The acceptor is the profile's: a [`SessionListener`] over one socket reads the
//! peer's `InitSyn` and admits the session only after the three claims are made
//! (`SessionHost::admit`), so an e2e whose peer asked for a session the node cannot
//! hold gets no answer, which is the contract the pool profile has.
//!
//! The reactive peer, the counters and the verdict are `crate::Run`, the heap form's
//! own, so the two forms cannot disagree about what a handshake that reached
//! `Established` is.
//!
//! What a run still asks the heap for is the session tier's: the codec owned mirrors
//! and `wz-session-core`'s encoders. None of it is this crate's, which the crate
//! enforces by not linking `alloc`.

use core::cell::RefCell;

use wz::link_lwip::rx_sockets::{SessionRxPool, SESSION_RX_SLOT_SIZE};
use wz::link_lwip::{ipv4_addr_loopback, LwipLink, LwipUdpSocket, UdpSocketPool};
use wz::runtime_coop::session_drive::{PumpSlots, SessionDriveConfig, SessionRole};
use wz::runtime_coop::{CoopLocalSet, CoopRuntime, CoopTime, RuntimeCell};
use wz::session_lwip::driver::LwipUdpDriver;
use wz::session_lwip::listener::SessionListener;
use wz::session_lwip::session_host::{OpenRefused, OpenedSession, SessionHost};
use wz::session_lwip::{LwipLinks, LwipSessionLink};
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::entropy::EntropySource;
use wz_session_core::session_slot::SessionSlots;
use wz_session_core::session_timeouts::SessionTimeouts;

use crate::{
    acceptor_params, wires, AcceptorE2eReport, AcceptorStage, ClockSource, DataMode, Run,
    MAX_ITERS, PEER_PORT, SESSION_PORT,
};

/// Rx queue depth of the reactive peer socket: it receives only the acceptor's
/// session-control replies, one per drive iteration, so at most two are ever
/// outstanding.
const PEER_RX_SLOTS: usize = 4;

/// Tasks the runtime holds: the session's pump, with room beside it.
const TASKS: usize = 2;
/// Bytes of one task cell. The task future is the pump's handle and the application
/// layer's state (a reference to the run and the caller's fragment hook), well under
/// this; the number is the e2e's own, sized with margin, and a task that did not fit
/// is a counted refusal (`task_refusals().too_large`), which the run reports as an
/// e2e that never established.
const TASK_BYTES: usize = 512;
/// Timers the runtime holds: the handshake and the lease deadlines of one session.
const TIMERS: usize = 4;

// The runtime's tables are held under the task and timer ceilings the deploy file
// states for the machine (`session_pool.process`): an e2e that outgrows one is a build
// failure that names the line. (The slot table here is one slot, and the session type
// is generic over the clock and the entropy source, so the typed-slot ceiling is
// asserted by the images that name both.)
const _: () = {
    assert!(
        TASKS <= wz_session_core::caps::MAX_TASKS,
        "TASKS exceeds the deploy file's max_tasks"
    );
    assert!(
        TIMERS <= wz_session_core::caps::MAX_TIMERS,
        "TIMERS exceeds the deploy file's max_timers"
    );
};
/// How many turns the run takes at most before it gives up: a bound for a regression,
/// as the heap form's iteration cap is, since a run that never admitted its session
/// has no pump whose own budget would end it.
const MAX_TURNS: usize = MAX_ITERS * 4;

/// What the acceptor e2e declares, as an image declares it, in a `static`:
///
/// ```ignore
/// static E2E: AcceptorStatics<BoardClock, BoardEntropy> = AcceptorStatics::new();
/// let report = run_acceptor_e2e_fixed(&E2E, clock, entropy, DataMode::WholeFrame, || {}, |_| {});
/// ```
///
/// A set of statics runs ONE e2e: the runtime is started once, and the sockets of its
/// pools are bound by the run and given back when it returns, so a second run on the
/// same statics is refused by the runtime's cell. A host test that runs several makes
/// a set of statics for each.
///
/// Like every table of the profile it is `Sync` by the profile's rule (one cooperative
/// task on one core drives it), not by anything a compiler can check.
pub struct AcceptorStatics<C: ClockSource + 'static, E: EntropySource + Send + 'static> {
    runtime: RuntimeCell<C, TASKS, TASK_BYTES, TIMERS>,
    sessions: SessionSlots<CoopRuntime<C>, CoopTime<C>, LwipUdpDriver, E, 1>,
    pumps: PumpSlots<C, LwipSessionLink<&'static LwipLink>, 1>,
    listener: SessionListener<1>,
    /// The listener's socket.
    sockets: SessionRxPool<1>,
    /// The reactive peer's socket.
    peer_sockets: UdpSocketPool<SESSION_RX_SLOT_SIZE, PEER_RX_SLOTS, 1>,
    /// The run the session's `on_event` and the peer's reactions write into.
    run: RefCell<Run>,
}

// SAFETY: the profile's rule, stated on the type: the e2e is driven by one cooperative
// task on one core, which is the only thing that reaches `run`; every other member is
// a table that is `Sync` by the same rule.
unsafe impl<C: ClockSource + 'static, E: EntropySource + Send + 'static> Sync
    for AcceptorStatics<C, E>
{
}

impl<C: ClockSource + 'static, E: EntropySource + Send + 'static> AcceptorStatics<C, E> {
    /// The statics of one e2e, for a `static`.
    pub const fn new() -> Self {
        Self {
            runtime: RuntimeCell::new(),
            sessions: SessionSlots::new(),
            pumps: PumpSlots::new(),
            listener: SessionListener::new(),
            sockets: SessionRxPool::new(),
            peer_sockets: UdpSocketPool::new(),
            run: RefCell::new(Run::new(DataMode::WholeFrame)),
        }
    }
}

impl<C: ClockSource + 'static, E: EntropySource + Send + 'static> Default
    for AcceptorStatics<C, E>
{
    fn default() -> Self {
        Self::new()
    }
}

/// Send one datagram from the peer to the acceptor's session port, best effort as
/// every datagram of the e2e is (a lost one is a handshake that stalls and says so).
fn peer_send(peer: &LwipUdpSocket<SESSION_RX_SLOT_SIZE, PEER_RX_SLOTS>, bytes: &[u8]) {
    let _ = peer.send_to(ipv4_addr_loopback(), SESSION_PORT, bytes);
}

/// Drive the acceptor session e2e over `statics` to a verdict.
///
/// The parameters are `run_acceptor_e2e_with_progress`'s (the heap form), with the statics in
/// place of the topology: `clock_source` is the monotonic time the runtime and the
/// lease comparator read, `entropy` the source the cookie nonce and the signing key are
/// drawn from, `data_mode` what the peer sends once the session is `Established`,
/// `on_fragment` the hook of the dispatched fragment (only under `reassembly`), and
/// `on_stage` the stage announcements. `on_fragment` is `'static` because the session's
/// application layer keeps it in its task.
///
/// An e2e whose socket could not be bound, whose runtime was already started, or whose
/// peer's `InitSyn` the node refused, returns the report of a run that never
/// established, the outcome the image already reads as a failure.
pub fn run_acceptor_e2e_fixed<C, E, H, S>(
    statics: &'static AcceptorStatics<C, E>,
    clock_source: C,
    entropy: E,
    data_mode: DataMode,
    on_fragment: H,
    mut on_stage: S,
) -> AcceptorE2eReport
where
    C: ClockSource + 'static,
    E: EntropySource + Send + 'static,
    H: FnMut() + 'static,
    S: FnMut(AcceptorStage),
{
    *statics.run.borrow_mut() = Run::new(data_mode);
    let never_established =
        |statics: &AcceptorStatics<C, E>| statics.run.borrow().report(false, 0, 0);

    // ── The stack, the runtime and the host the session is opened by.
    let link = LwipLink::init_static();
    let Some(runtime) = statics.runtime.start(clock_source) else {
        return never_established(statics);
    };
    let local = CoopLocalSet::new(&runtime);
    let host: SessionHost<C, &'static LwipLink, E, 1, 1> = SessionHost::new(
        CoopLocalSet::new(&runtime),
        &statics.sessions,
        &statics.pumps,
        link,
    );

    // ── The acceptor: one socket, listened on. The session is built when the peer's
    //    InitSyn asks for it.
    let links = LwipLinks::new(link, &statics.sockets);
    let Ok(socket) = links.bind_socket(SESSION_PORT) else {
        return never_established(statics);
    };
    if statics.listener.listen(socket).is_err() {
        return never_established(statics);
    }

    // ── The reactive crafted peer: a second endpoint on the same loopback.
    let Ok(mut peer) = LwipUdpSocket::<SESSION_RX_SLOT_SIZE, PEER_RX_SLOTS>::bind_in(
        link,
        PEER_PORT,
        &statics.peer_sockets,
    ) else {
        return never_established(statics);
    };

    // R311y819 -- through the MCU construction seam, which draws the cookie nonce from
    // the supplied `EntropySource`; the signing key is drawn from the same source first.
    let mut entropy = entropy;
    let mut params = Some(acceptor_params(&mut entropy));
    let mut entropy = Some(entropy);
    let mut on_fragment = Some(on_fragment);
    let mut session: Option<OpenedSession<C>> = None;

    // Open the handshake: the initiator's first move. The reactive peer drives OpenSyn
    // and the application data off the acceptor's real replies.
    peer_send(&peer, wires::initsyn().as_slice());
    on_stage(AcceptorStage::AwaitInitAck);

    for _ in 0..MAX_TURNS {
        local.run_until_idle();
        statics
            .listener
            .accept_pass(link, &mut |admission| -> Result<(), OpenRefused> {
                // One session is admitted: the entropy source, the parameters and the
                // hook go into it, and a second InitSyn finds them gone and is refused
                // as the session table having no slot for it.
                let (Some(entropy), Some(params), Some(mut hook)) =
                    (entropy.take(), params.take(), on_fragment.take())
                else {
                    return Err(OpenRefused::SessionSlot);
                };
                let run = &statics.run;
                let opened = host.admit(
                    admission,
                    entropy,
                    params,
                    SessionDriveConfig {
                        timeouts: SessionTimeouts::spec_defaults(),
                        role: SessionRole::Acceptor,
                        max_iters: Some(MAX_ITERS),
                    },
                    |_handle| {
                        move |event: IterationEvent<'_>| {
                            run.borrow_mut().event(event, &mut hook);
                        }
                    },
                )?;
                session = Some(opened);
                Ok(())
            });

        // The reactive peer: take whatever the acceptor has sent it and advance the
        // peer SM. The datagram is read where the socket holds it and the run's
        // reaction does not outlive the borrow.
        while let Some(datagram) = peer.try_recv() {
            statics.run.borrow_mut().react(
                datagram.data.as_slice(),
                &mut |bytes| peer_send(&peer, bytes),
                &mut on_stage,
            );
        }

        if session
            .as_ref()
            .is_some_and(|opened| opened.task.is_finished())
        {
            break;
        }
    }

    let (established, init_ack, open_ack) = match &session {
        Some(opened) => {
            let trace = opened.actions.trace_snapshot();
            (
                opened.actions.is_established(),
                trace.send_init_ack_with_cookie,
                trace.send_open_ack,
            )
        }
        None => (false, 0, 0),
    };
    statics.run.borrow().report(established, init_ack, open_ack)
}
