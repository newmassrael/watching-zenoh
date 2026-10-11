// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The multicast e2e on the fixed-memory profile (fixed-memory step S9c): the same
//! scenario and the same report as the heap form, with the group socket, the pump and
//! the runtime in statics the image declares and this crate linking no `alloc`.
//!
//! The heap form builds a dispatcher, a runtime and a driver on its stack and hands
//! them to `run_multicast_session`, which loops until the session ends. This one puts
//! the session in a cell of [`MulticastSlots`] (the table's one cell is the group's),
//! draws the group socket from a static pool, takes its runtime from a
//! [`RuntimeCell`], and steps the pump by hand with the same step the loop is made of.
//! The pump is ONE for both drives: the bounded round trip runs it without a stop
//! request and the departure runs the same pump with one, where the heap form builds
//! a second loop over the same dispatcher. The departing Close, the Running to
//! Stopped transition and the cleared table are the pump's, so the two forms prove the
//! same transitions.
//!
//! What the run still asks the heap for is the session tier's: the encoders of
//! `wz-session-core` and the owned wire mirrors of a queued `Put`. None of it is this
//! crate's, which the crate enforces by not linking `alloc`.

use wz::link_lwip::rx_sockets::{
    bind_session_multicast_rx_in, SessionMulticastRxPool, SESSION_MULTICAST_GROUP_DEFAULT,
};
use wz::runtime_coop::RuntimeCell;
use wz::session_lwip::multicast_drive::{LwipMulticastDriver, MulticastSession, MulticastSlots};
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::multicast_dispatch::{MulticastConfig, MulticastDispatcher};
use wz_session_core::multicast_tx::{multicast_put_literal, MulticastTxItem};

use crate::{
    own_params, payload, peer_join, tx_fragments, ClockSource, LwipLink, MulticastE2eReport,
    MulticastOutcome, MulticastStage, Observed, KEYEXPR, MAX_ITERS, MAX_PEERS, PORT,
};

/// Tasks the runtime holds. The pump is stepped by hand, so no task is spawned; the
/// table is the smallest the runtime's cell has.
const TASKS: usize = 1;
/// Bytes of one task cell (unused, see [`TASKS`]).
const TASK_BYTES: usize = 64;
/// Timers the runtime holds: nothing sleeps on this run.
const TIMERS: usize = 1;

/// What the multicast e2e declares, as an image declares it, in a `static`:
///
/// ```ignore
/// static E2E: MulticastE2eStatics<BoardClock> = MulticastE2eStatics::new();
/// let report = run_multicast_e2e_fixed(&E2E, LwipLink::init_static(), BoardClock, |_| {});
/// ```
///
/// A set of statics runs ONE e2e: the runtime is started once and the group socket's
/// cell is given back when the run returns, so a second run on the same statics is
/// refused by the runtime's cell. A host test that runs several makes a set of statics
/// for each.
///
/// Like every table of the profile it is `Sync` by the profile's rule (one cooperative
/// loop on one core drives it), not by anything a compiler can check.
pub struct MulticastE2eStatics<C: ClockSource + 'static> {
    runtime: RuntimeCell<C, TASKS, TASK_BYTES, TIMERS>,
    /// The multicast group's session: one cell.
    groups: MulticastSlots<C, MAX_PEERS, 1>,
    /// The group socket's storage: one 32 x 1536 byte cell.
    sockets: SessionMulticastRxPool<1>,
}

// SAFETY: the profile's rule, stated on the type: the e2e is one loop on one core, the
// only thing that reaches the tables, which are `Sync` by the same rule.
unsafe impl<C: ClockSource + 'static> Sync for MulticastE2eStatics<C> {}

impl<C: ClockSource + 'static> MulticastE2eStatics<C> {
    /// The statics of one e2e, for a `static`.
    pub const fn new() -> Self {
        Self {
            runtime: RuntimeCell::new(),
            groups: MulticastSlots::new(),
            sockets: SessionMulticastRxPool::new(),
        }
    }
}

impl<C: ClockSource + 'static> Default for MulticastE2eStatics<C> {
    fn default() -> Self {
        Self::new()
    }
}

/// Drive the multicast transport e2e over `statics` to a verdict.
///
/// The parameters are [`crate::run_multicast_e2e_with_progress`]'s with the statics in
/// place of the heap: `link` is the lwIP link (`LwipLink::init_static()`, with the
/// multicast egress routed over the loop netif by the caller where the build has one),
/// `clock_source` the monotonic time the runtime reads, `on_stage` the stage
/// announcements.
///
/// A run whose runtime was already started, whose group socket could not be bound or
/// whose join failed returns the report of a run that never joined, which the image
/// already reads as a failure (or, on a plain link, as the skip).
pub fn run_multicast_e2e_fixed<C, S>(
    statics: &'static MulticastE2eStatics<C>,
    link: &'static LwipLink,
    clock_source: C,
    mut on_stage: S,
) -> MulticastE2eReport
where
    C: ClockSource + 'static,
    S: FnMut(MulticastStage),
{
    let group = SESSION_MULTICAST_GROUP_DEFAULT;
    on_stage(MulticastStage::JoinGroup);

    // The runtime first: a second run on these statics is refused here, before it
    // binds or sends anything.
    let Some(runtime) = statics.runtime.start(clock_source) else {
        return MulticastE2eReport::no_join();
    };

    // Bind the group socket in its static cell and join. With no IGMP-capable netif
    // the join fails, the cell goes back to its pool and the report says so.
    let Ok(socket) = bind_session_multicast_rx_in(link, group, PORT, &statics.sockets) else {
        return MulticastE2eReport::no_join();
    };

    // Pre-admit the peer at our loopback source, before the driver wraps the socket
    // (see `peer_join`).
    let _ = socket.send_to(group, PORT, &peer_join());

    let own = own_params();
    let payload = payload();
    let tx_fragmented = tx_fragments(&payload, &own);
    let session = MulticastSession {
        dispatcher: MulticastDispatcher::<MAX_PEERS>::new(MulticastConfig::new(5_000)),
        driver: LwipMulticastDriver::new(socket, group, PORT),
        params: own,
        tick_ms: 5,
        max_iters: Some(MAX_ITERS),
    };
    let Ok(mut pump) = statics.groups.claim(runtime, link, session) else {
        return MulticastE2eReport::no_join();
    };

    // One queued Put on the reliable channel; the pull-seam yields it once.
    let mut pending: Option<MulticastTxItem> = multicast_put_literal(KEYEXPR, &payload).ok();

    // The bounded round trip: the peer JOIN, the Put's fragments, their reassembly.
    let mut seen = Observed::default();
    on_stage(MulticastStage::RoundTrip);
    let outcome: MulticastOutcome = {
        let mut on_event = |event: IterationEvent<'_>| seen.observe(event);
        let mut next_tx = || pending.take();
        loop {
            if let Some(outcome) = pump.step(&mut on_event, &mut next_tx, None) {
                break outcome;
            }
        }
    };
    let active_peers = pump.dispatcher().active_peers();

    // The departure: the SAME pump asked to stop. The stop is polled before the
    // iteration budget, so it is answered on the step it is first asked on.
    on_stage(MulticastStage::Departure);
    let mut on_event = |_event: IterationEvent<'_>| {};
    let mut next_tx = || None;
    let mut stop = || true;
    let departure = loop {
        if let Some(outcome) = pump.step(&mut on_event, &mut next_tx, Some(&mut stop)) {
            break outcome;
        }
    };
    let departed = departure == MulticastOutcome::Stopped && pump.dispatcher().active_peers() == 0;

    // The IGMP leave AFTER the zenoh-level departure: the Close has to ride the
    // membership it is announcing on.
    let _ = link.leave_multicast_group(group);

    MulticastE2eReport::joined(outcome, tx_fragmented, active_peers, &seen, departed)
}
