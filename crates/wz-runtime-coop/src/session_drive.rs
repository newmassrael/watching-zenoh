// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The cooperative unicast session drive loop, over any datagram link.
//!
//! The MCU analog of `wz_runtime_tokio::session_glue::drive_session_until_terminal`,
//! minus the `tokio::select!`: a cooperative single-task polling loop. Every
//! decision PRIMITIVE is the shared `wz_session_core` SSOT — this module is
//! only the loop STRUCTURE that sequences them:
//!
//! - inbound: [`SessionDatagramLink::try_recv`] ->
//!   [`wz_session_core::link::LinkEvent::Rx`] -> [`dispatch_link_event`] (the
//!   shared dispatch core) -> `report_outcome_reassembling` (reassembly-gated)
//!   or the bare `on_event(Poll)` otherwise.
//! - deadlines: [`HandshakeDeadlineTracker`] yields the handshake deadline;
//!   in Established the keepalive-resetting lease deadline applies and
//!   [`check_lease_deadline`] (the shared comparator) runs when it elapses.
//!   The sync loop fires a deadline when `now_ms >= deadline_ms` — the
//!   busy-poll equivalent of the AP `select!` sleep branch winning the race.
//! - outbound is transparent: the FSM action methods call
//!   `link_driver().send_blocking` on the link's own `BoxedLinkDriver`.
//!
//! R2915 — the loop used to live in `wz-session-lwip`, typed on lwIP's link
//! and UDP driver, so no MCU profile could run a session over any other
//! network stack. zenoh-pico's Zephyr port runs its session over Zephyr's
//! own BSD sockets, which a wz Zephyr profile could not do without writing a
//! second copy of this loop. The loop now names only what it needs from a
//! link — [`SessionDatagramLink`] — and each network stack implements that
//! seam (`wz_session_lwip::LwipSessionLink` over lwIP).

use alloc::rc::Rc;

use wz_runtime_core::TimeSource;
use wz_session_core::drive::SessionEngine;
#[cfg(feature = "transport-keepalive")]
use wz_session_core::drive::{check_keepalive_deadline, keepalive_wake_deadline};
use wz_session_core::drive::{
    check_lease_deadline, dispatch_link_event, dispatch_pending, lease_wake_deadline,
    new_session_engine,
};
use wz_session_core::driver_loop::{DriverOutcome, IterationEvent};
use wz_session_core::link::{LinkEvent, RxFrame};
use wz_session_core::session_actions::SessionLinkActions;
use wz_session_core::session_fsm_unicast::SessionFsmUnicastEvent;
use wz_session_core::session_timeouts::{HandshakeDeadlineTracker, SessionTimeouts};

#[cfg(feature = "reassembly")]
use crate::reassembly_rx::{mcu_reassembly, CoopReassembly};
#[cfg(feature = "reassembly")]
use wz_session_core::drive::report_outcome_reassembling;
// R311mh — sweep_reporting moved drive -> reassembly_dispatch (pure reassembly
// helper, not a unicast-drive one).
#[cfg(feature = "reassembly")]
use wz_session_core::reassembly_dispatch::sweep_reporting;

use crate::{yield_now, ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime};

/// What the drive loop needs from a network stack: advance its input path,
/// and hand over the next inbound datagram.
///
/// The OUTBOUND half is not here. It is the link's
/// [`wz_session_core::link::BoxedLinkDriver`], which lives inside the
/// session's action bundle and is reached by the FSM action methods, not by
/// the loop. One object usually implements both.
pub trait SessionDatagramLink {
    /// Advance the stack's input path by one pass. A stack the loop must
    /// pump (lwIP `NO_SYS`, polled from this thread) does its work here; one
    /// whose input runs on its own thread or ISR does nothing.
    fn service(&self);

    /// The next inbound datagram as a frame, or `None` when nothing is
    /// queued. Taking a datagram also RETARGETS the link's replies to that
    /// datagram's source — the acceptor learns its peer from the InitSyn,
    /// and every reply after it goes back to whoever just spoke.
    fn try_recv(&self) -> Option<RxFrame>;
}

/// The handshake role to activate the FSM with before the loop starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// Listen for an inbound peer (the InitSyn arrives first). Activates
    /// the FSM via the `inbound.start` event.
    Acceptor,
    /// Dial a configured peer (emit the InitSyn first). Activates the FSM
    /// via the `outbound.start` event.
    Initiator,
}

impl SessionRole {
    /// The events that activate the FSM in this role, in order.
    ///
    /// R2831 — the initiator takes TWO, as the AP's `initiator_open` does:
    /// `OutboundStart` enters LinkOpening and `LinkOpened` moves to
    /// SentInitSyn, whose entry sends the InitSyn. The UDP link is open by
    /// the time a pump exists (the driver's socket is already bound), so
    /// both are raised at once. Raising only the first left an MCU initiator
    /// in LinkOpening forever, silent on the wire; nothing drove one until
    /// the dialer did.
    fn activation(self) -> &'static [SessionFsmUnicastEvent] {
        match self {
            SessionRole::Acceptor => &[SessionFsmUnicastEvent::InboundStart],
            SessionRole::Initiator => &[
                SessionFsmUnicastEvent::OutboundStart,
                SessionFsmUnicastEvent::LinkOpened,
            ],
        }
    }
}

/// R311lw — the static parameterization of one [`run_session`] drive: the
/// handshake-deadline budget, the FSM activation role, and the test-only
/// iteration cap, separated from the loop's live collaborators (the
/// runtime / link / actions / clock handles + the `on_event` observer) via
/// the Introduce-Parameter-Object refactor. The unicast MCU sibling of
/// `wz_session_core::multicast_params::MulticastDriveConfig` (R311ls/R311lt):
/// it brings [`run_session`] within clippy's argument-count bound. All three
/// fields are `Copy`, so this owns them by value and carries no lifetime.
pub struct SessionDriveConfig {
    /// The handshake deadline budget ([`SessionTimeouts::spec_defaults`]);
    /// seeds the [`HandshakeDeadlineTracker`] the loop polls each tick.
    pub timeouts: SessionTimeouts,
    /// The role to activate the FSM with before the loop starts
    /// ([`SessionRole::Acceptor`] listens for an inbound peer;
    /// [`SessionRole::Initiator`] dials the configured peer).
    pub role: SessionRole,
    /// `Some(n)` caps the loop for test determinism; `None` drives unbounded
    /// for production.
    pub max_iters: Option<usize>,
}

/// Drive one logical session over `link` to a terminal FSM state (or the
/// `config.max_iters` cap). Builds the FSM engine from `actions` via the
/// shared [`new_session_engine`], activates `config.role`, then polls until
/// `engine.is_in_final_state()`.
///
/// Parameters:
/// - `runtime` — the [`CoopRuntime`] whose `run_until_idle` is pumped each
///   tick (spawned keepalive workers + deadline-keyed timers).
/// - `link` — the [`SessionDatagramLink`]: serviced each tick, and the source
///   of inbound frames. Its outbound twin sits inside `actions`.
/// - `actions` — the session action bundle; its `clock` MUST share an epoch
///   with `clock` (R263) so the lease comparator's `now_ms` and the recorded
///   keepalive / established stamps agree. Build one [`CoopTime`], clone it
///   into `new_generic`, pass the original here.
/// - `config` — the static run parameterization ([`SessionDriveConfig`]).
/// - `on_event` — the per-iteration observer (`Poll` with the decoded
///   `FramePayload` batch the application dispatches, or `Lease`).
pub fn run_session<C, L, F>(
    runtime: &CoopRuntime<C>,
    link: L,
    actions: &Rc<SessionLinkActions<CoopRuntime<C>, CoopTime<C>>>,
    clock: &CoopTime<C>,
    config: SessionDriveConfig,
    mut on_event: F,
) -> DriverOutcome
where
    C: ClockSource,
    L: SessionDatagramLink,
    F: FnMut(IterationEvent<'_>),
{
    let mut pump = SessionPump::new(
        runtime.clone(),
        link,
        actions.clone(),
        clock.clone(),
        config,
    );
    loop {
        // The synchronous driver owns the executor pass: nothing else is
        // driving this runtime, so spawned workers and deadline-keyed
        // timers only advance because this loop says so. `step` deliberately
        // does not do it — see its doc.
        pump.runtime().run_until_idle();
        if let Some(outcome) = pump.step(&mut on_event) {
            return outcome;
        }
    }
}

/// One MCU session, ready to be advanced one iteration at a time.
///
/// R2364 — extracted from [`run_session`], whose body this used to be
/// inline. The extraction exists so that the sequencing of an iteration —
/// link input, parked-unit drain, inbound dispatch, handshake / lease
/// deadline, keepalive deadline — is written ONCE and both drivers share
/// it: the synchronous [`run_session`] loop, and [`session_task`], the
/// `!Send` future that runs the session as a task ON the cooperative
/// executor via [`CoopLocalSet::spawn_local`].
///
/// Generic over the link `L` it OWNS: the synchronous loop may hand it a
/// borrow-backed link, while a spawned task must be `'static` and therefore
/// hands it one that owns its shares.
pub struct SessionPump<C: ClockSource, L: SessionDatagramLink> {
    runtime: CoopRuntime<C>,
    link: L,
    actions: Rc<SessionLinkActions<CoopRuntime<C>, CoopTime<C>>>,
    clock: CoopTime<C>,
    engine: SessionEngine<CoopRuntime<C>, CoopTime<C>>,
    deadline_tracker: HandshakeDeadlineTracker,
    #[cfg(feature = "reassembly")]
    reasm: CoopReassembly,
    iter: usize,
    max_iters: Option<usize>,
}

impl<C: ClockSource, L: SessionDatagramLink> SessionPump<C, L> {
    /// Build the engine, activate the configured role, and arm the
    /// handshake deadline tracker — everything [`run_session`] does before
    /// entering its loop.
    ///
    /// Takes its collaborators BY VALUE. Every one of them is a cheap
    /// shared handle (`CoopRuntime` is `Arc`-backed; the action bundle is
    /// `Rc`; `CoopTime` is a clock handle), so owning them costs a refcount
    /// and buys the `'static` that [`CoopLocalSet::spawn_local`] requires.
    pub fn new(
        runtime: CoopRuntime<C>,
        link: L,
        actions: Rc<SessionLinkActions<CoopRuntime<C>, CoopTime<C>>>,
        clock: CoopTime<C>,
        config: SessionDriveConfig,
    ) -> Self {
        let SessionDriveConfig {
            timeouts,
            role,
            max_iters,
        } = config;

        let mut engine = new_session_engine(&actions);
        // `new_session_engine` returns an un-initialized engine (the AP
        // convention — the caller runs the SCXML initial transition into the
        // `Init` state). Without this the `role.activation()` below lands on
        // an engine that never entered `Init`, so `inbound.start` /
        // `outbound.start` does not transition into `AwaitingInitSyn` /
        // `LinkOpening` and the whole handshake stalls.
        engine.initialize();
        for event in role.activation() {
            engine.process_event(*event);
        }

        Self {
            runtime,
            link,
            actions,
            clock,
            engine,
            deadline_tracker: HandshakeDeadlineTracker::new(timeouts),
            #[cfg(feature = "reassembly")]
            reasm: mcu_reassembly(),
            iter: 0,
            max_iters,
        }
    }

    /// Borrow the runtime this session was built against. The synchronous
    /// driver uses it to take the executor pass that [`Self::step`] does
    /// not.
    pub fn runtime(&self) -> &CoopRuntime<C> {
        &self.runtime
    }

    /// Advance the session by one iteration. `Some(outcome)` means the
    /// session is finished (terminal FSM state, or the test iteration cap);
    /// `None` means call again.
    ///
    /// Deliberately does NOT pump the runtime. Who drives the executor is
    /// the DRIVER's question and the two drivers answer it differently:
    /// [`run_session`] owns its loop and so takes the pass itself, while
    /// [`session_task`] runs INSIDE the executor — pumping from there would
    /// have the session drive the pool that is currently polling it, which
    /// is precisely the inversion [`CoopLocalSet`] exists to remove.
    pub fn step<F>(&mut self, on_event: &mut F) -> Option<DriverOutcome>
    where
        F: FnMut(IterationEvent<'_>),
    {
        if self.engine.is_in_final_state() {
            return Some(DriverOutcome::Terminated);
        }
        if let Some(limit) = self.max_iters {
            if self.iter >= limit {
                return Some(DriverOutcome::IterationLimit);
            }
            self.iter += 1;
        }

        self.link.service();

        let now_ms = self.clock.now_monotonic_ms();
        // Sweep expired reassembly chains and surface the eviction count as
        // an `IterationEvent::ReassemblyTimeout` (the shared SSOT — the AP
        // loop calls the same primitive). A stalled chain whose continuation
        // never arrives is reclaimed here once `now_ms` crosses its deadline.
        #[cfg(feature = "reassembly")]
        sweep_reporting(&mut self.reasm, now_ms, &mut *on_event);

        // R311y632 (§17) — the parked remainder of the LAST unit first. A unit
        // is a batch, and `try_recv` below would otherwise hold the second
        // message until the peer sends again.
        if let Some(outcome) = dispatch_pending(&self.actions, &mut self.engine) {
            #[cfg(feature = "reassembly")]
            report_outcome_reassembling(
                &outcome,
                &mut self.reasm,
                &self.actions,
                now_ms,
                &mut *on_event,
            );
            #[cfg(not(feature = "reassembly"))]
            on_event(IterationEvent::Poll(&outcome));
            return None;
        }

        // Inbound datagram? Dispatch it and loop promptly for the next. The
        // link has already retargeted its replies to the datagram's source.
        // Unicast MCU session shell — one peer per link, so no source
        // attribution is needed.
        if let Some(frame) = self.link.try_recv() {
            let outcome =
                dispatch_link_event(LinkEvent::Rx(frame), &self.actions, &mut self.engine);
            #[cfg(feature = "reassembly")]
            report_outcome_reassembling(
                &outcome,
                &mut self.reasm,
                &self.actions,
                now_ms,
                &mut *on_event,
            );
            #[cfg(not(feature = "reassembly"))]
            on_event(IterationEvent::Poll(&outcome));
            return None;
        }

        // No inbound: the handshake / lease deadline. The tracker yields the
        // active handshake deadline; in Established it disarms and the
        // lease-expiry deadline applies — armed via the shared
        // `lease_wake_deadline` helper (R311kx: baseline
        // max(established_at, any-RX `last_inbound_at` — R311la pico
        // `_received` parity) + the adopted min(local, peer) window, the
        // same arithmetic the comparator re-derives). Fire when
        // `now_ms >= deadline_ms` — the busy-poll equivalent of the AP
        // select! sleep branch.
        let deadline: Option<(u64, Option<SessionFsmUnicastEvent>)> = match self
            .deadline_tracker
            .poll(self.engine.get_current_state(), now_ms)
        {
            Some((dl_ms, ev)) => Some((dl_ms, Some(ev))),
            None => lease_wake_deadline(&self.actions).map(|dl| (dl, None)),
        };
        if let Some((deadline_ms, kind)) = deadline {
            if now_ms >= deadline_ms {
                match kind {
                    None => {
                        let lease_outcome =
                            check_lease_deadline(&self.actions, &mut self.engine, now_ms);
                        on_event(IterationEvent::Lease(lease_outcome));
                    }
                    Some(event) => {
                        self.engine.process_event(event);
                    }
                }
            }
        }

        // R311kx — keepalive TX deadline, the busy-poll twin of the AP
        // loop's min-deadline select arm: compare against the TX wake
        // deadline each tick and run the (self-guarded) check only when it
        // crossed, so the steady state stays event-free — the observer
        // sees `Emitted` verdicts, not a per-tick `WithinInterval` flood.
        #[cfg(feature = "transport-keepalive")]
        if let Some(ka_deadline_ms) = keepalive_wake_deadline(&self.actions) {
            if now_ms >= ka_deadline_ms {
                let ka_outcome = check_keepalive_deadline(&self.actions, now_ms);
                on_event(IterationEvent::KeepAlive(ka_outcome));
            }
        }

        None
    }
}

/// The MCU session AS A TASK — the `!Send` future that
/// [`CoopLocalSet::spawn_local`] hosts.
///
/// R2364. This is the MCU answer to what `TokioRuntime::spawn` gives the AP
/// profile: the MCU action bundle is `Rc`-backed and `!Send` on purpose (that
/// `Rc` is what reaches ARMv6-M, where `alloc::sync::Arc` does not exist), so
/// the session runs IN the local set rather than as a caller-owned loop.
///
/// Awaits [`yield_now`] between iterations rather than spinning, so every
/// other task in the pool — and the local set's own runtime pass — gets a
/// turn each time round. The returned value is the same [`DriverOutcome`]
/// [`run_session`] returns; reach it through the [`CoopLocalJoinHandle`] the
/// spawn hands back.
pub async fn session_task<C, L, F>(
    runtime: CoopRuntime<C>,
    link: L,
    actions: Rc<SessionLinkActions<CoopRuntime<C>, CoopTime<C>>>,
    clock: CoopTime<C>,
    config: SessionDriveConfig,
    mut on_event: F,
) -> DriverOutcome
where
    C: ClockSource,
    L: SessionDatagramLink,
    F: FnMut(IterationEvent<'_>),
{
    let mut pump = SessionPump::new(runtime, link, actions, clock, config);
    loop {
        if let Some(outcome) = pump.step(&mut on_event) {
            return outcome;
        }
        yield_now().await;
    }
}

/// Spawn one MCU session onto `local` and return its join handle.
///
/// The convenience form of [`session_task`] + [`CoopLocalSet::spawn_local`],
/// and the call site a deploy `main()` writes. The runtime the session is
/// built against is the local set's own, so a caller cannot accidentally
/// pump one runtime while the session rides another.
///
/// `link` and `on_event` must be `'static` here where [`run_session`] takes
/// any: a detached task cannot borrow the caller's stack. An observer that
/// needs to publish out of the task should capture an `Rc<RefCell<..>>` —
/// `!Send` is fine, which is the whole point of the local set.
pub fn spawn_session<C, L, F>(
    local: &CoopLocalSet<C>,
    link: L,
    actions: Rc<SessionLinkActions<CoopRuntime<C>, CoopTime<C>>>,
    clock: CoopTime<C>,
    config: SessionDriveConfig,
    on_event: F,
) -> CoopLocalJoinHandle<DriverOutcome>
where
    C: ClockSource + 'static,
    L: SessionDatagramLink + 'static,
    F: FnMut(IterationEvent<'_>) + 'static,
{
    local.spawn_local(session_task(
        local.runtime().clone(),
        link,
        actions,
        clock,
        config,
        on_event,
    ))
}
