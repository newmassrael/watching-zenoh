// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `run_session` — the synchronous MCU session drive loop.
//!
//! The MCU analog of `wz_runtime_tokio::session_glue::drive_session_until_terminal`,
//! minus the `tokio::select!`: a cooperative single-task polling loop. Every
//! decision PRIMITIVE is the shared `wz_session_core` SSOT — this function is
//! only the loop STRUCTURE that sequences them on the lwIP profile:
//!
//! - inbound: [`LwipUdpDriver::try_recv`] -> [`wz_session_core::link::LinkEvent::Rx`]
//!   -> [`dispatch_link_event`] (the shared dispatch core) ->
//!   `report_outcome_reassembling` (reassembly-gated) or the bare
//!   `on_event(Poll)` otherwise.
//! - deadlines: [`HandshakeDeadlineTracker`] yields the handshake deadline;
//!   in Established the keepalive-resetting lease deadline applies and
//!   [`check_lease_deadline`] (the shared comparator) runs when it elapses.
//!   The sync loop fires a deadline when `now_ms >= deadline_ms` — the
//!   busy-poll equivalent of the AP `select!` sleep branch winning the race.
//! - outbound is transparent: the FSM action methods call
//!   `link_driver().send_blocking` -> [`LwipUdpDriver`]'s `socket.send_to`.

use alloc::rc::Rc;
use core::ops::Deref;

use wz_link_lwip::LwipLink;
use wz_runtime_coop::{
    yield_now, ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime,
};
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
use wz_runtime_coop::reassembly_rx::{mcu_reassembly, CoopReassembly};
#[cfg(feature = "reassembly")]
use wz_session_core::drive::report_outcome_reassembling;
// R311mh — sweep_reporting moved drive -> reassembly_dispatch (pure reassembly
// helper, not a unicast-drive one).
#[cfg(feature = "reassembly")]
use wz_session_core::reassembly_dispatch::sweep_reporting;

use crate::driver::LwipUdpDriver;

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
    fn start_event(self) -> SessionFsmUnicastEvent {
        match self {
            SessionRole::Acceptor => SessionFsmUnicastEvent::InboundStart,
            SessionRole::Initiator => SessionFsmUnicastEvent::OutboundStart,
        }
    }
}

/// R311lw — the static parameterization of one [`run_session`] drive: the
/// handshake-deadline budget, the FSM activation role, and the test-only
/// iteration cap, separated from the loop's live collaborators (the
/// runtime / link / driver / actions / clock handles + the `on_event`
/// observer) via the Introduce-Parameter-Object refactor. The unicast MCU
/// sibling of
/// [`wz_session_core::multicast_params::MulticastDriveConfig`]
/// (R311ls/R311lt): it brings `run_session` within clippy's argument-count
/// bound, retiring the `#[allow(clippy::too_many_arguments)]` the prior
/// 9-arg signature carried. All three fields are `Copy`, so — unlike
/// `MulticastDriveConfig`, which must borrow its non-`Copy` `params` (the
/// `Vec`-bearing `MulticastParams`) — this owns them by value and carries
/// no lifetime.
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

/// Drive one logical session over the lwIP link to a terminal FSM state (or
/// the `config.max_iters` cap). Builds the FSM engine from `actions` via the
/// shared [`new_session_engine`], activates `config.role`, then polls until
/// `engine.is_in_final_state()`.
///
/// Parameters:
/// - `runtime` — the [`CoopRuntime`] whose `run_until_idle` is pumped each
///   tick (spawned keepalive workers + deadline-keyed timers).
/// - `link` — the [`LwipLink`]; `poll_loopback` + `check_timeouts` drive the
///   lwIP input path each tick. This is the loopback / QEMU shape — a real
///   multi-NIC deploy drives netif input from the RX ISR instead (carry tail).
/// - `driver` — the concrete [`LwipUdpDriver`] (for `try_recv` + `set_peer`);
///   the same object lives inside `actions` as `Rc<dyn BoxedLinkDriver>` for
///   the outbound send seam.
/// - `actions` — the session action bundle; its `clock` MUST share an epoch
///   with `clock` (R263) so the lease comparator's `now_ms` and the recorded
///   keepalive / established stamps agree. Build one [`CoopTime`], clone it
///   into `new_generic`, pass the original here.
/// - `config` — the static run parameterization ([`SessionDriveConfig`]:
///   handshake-deadline budget, FSM activation role, test iteration cap),
///   the unicast sibling of the multicast loops' `MulticastDriveConfig`.
/// - `on_event` — the per-iteration observer (`Poll` with the decoded
///   `FramePayload` batch the application dispatches, or `Lease`).
pub fn run_session<C, F>(
    runtime: &CoopRuntime<C>,
    link: &LwipLink,
    driver: &Rc<LwipUdpDriver>,
    actions: &Rc<SessionLinkActions<CoopRuntime<C>, CoopTime<C>>>,
    clock: &CoopTime<C>,
    config: SessionDriveConfig,
    mut on_event: F,
) -> DriverOutcome
where
    C: ClockSource,
    F: FnMut(IterationEvent<'_>),
{
    let mut pump = SessionPump::new(
        runtime.clone(),
        link,
        driver.clone(),
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
/// lwIP input, parked-unit drain, inbound dispatch, handshake / lease
/// deadline, keepalive deadline — is written ONCE and both drivers share
/// it: the synchronous [`run_session`] loop, and [`session_task`], the
/// `!Send` future that runs the session as a task ON the cooperative
/// executor via [`CoopLocalSet::spawn_local`]. Two loops over one
/// sequence would be two things to keep in step, which is exactly the
/// duplication this crate's module doc refuses between the AP and MCU
/// profiles.
///
/// Generic over the link handle `L` rather than borrowing `&LwipLink`,
/// because the two drivers hold the link differently and neither should be
/// forced into the other's shape: the synchronous loop borrows one off the
/// caller's stack (`&LwipLink`), while a spawned task must be `'static` and
/// therefore owns a share (`Rc<LwipLink>`). A `Deref<Target = LwipLink>`
/// bound admits both at no runtime cost.
pub struct SessionPump<C: ClockSource, L: Deref<Target = LwipLink>> {
    runtime: CoopRuntime<C>,
    link: L,
    driver: Rc<LwipUdpDriver>,
    actions: Rc<SessionLinkActions<CoopRuntime<C>, CoopTime<C>>>,
    clock: CoopTime<C>,
    engine: SessionEngine<CoopRuntime<C>, CoopTime<C>>,
    deadline_tracker: HandshakeDeadlineTracker,
    #[cfg(feature = "reassembly")]
    reasm: CoopReassembly,
    iter: usize,
    max_iters: Option<usize>,
}

impl<C: ClockSource, L: Deref<Target = LwipLink>> SessionPump<C, L> {
    /// Build the engine, activate the configured role, and arm the
    /// handshake deadline tracker — everything [`run_session`] used to do
    /// before entering its loop.
    ///
    /// Takes its collaborators BY VALUE. Every one of them is a cheap
    /// shared handle (`CoopRuntime` is `Arc`-backed; the driver and the
    /// action bundle are `Rc`; `CoopTime` is a clock handle), so owning
    /// them costs a refcount and buys the `'static` that
    /// [`CoopLocalSet::spawn_local`] requires.
    pub fn new(
        runtime: CoopRuntime<C>,
        link: L,
        driver: Rc<LwipUdpDriver>,
        actions: Rc<SessionLinkActions<CoopRuntime<C>, CoopTime<C>>>,
        clock: CoopTime<C>,
        config: SessionDriveConfig,
    ) -> Self {
        // The static parameter-object SSOT (R311lw); destructure into the
        // names the body uses, mirroring the multicast loops'
        // `MulticastDriveConfig` handling.
        let SessionDriveConfig {
            timeouts,
            role,
            max_iters,
        } = config;

        let mut engine = new_session_engine(&actions);
        // `new_session_engine` returns an un-initialized engine (the AP
        // convention — the caller runs the SCXML initial transition into the
        // `Init` state). Without this the `role.start_event()` below lands on
        // an engine that never entered `Init`, so `inbound.start` /
        // `outbound.start` does not transition into `AwaitingInitSyn` /
        // `LinkOpening` and the whole handshake stalls. The Stage 4b smoke
        // never surfaced this (an acceptor with no inbound peer terminates on
        // `max_iters` regardless of FSM state); the Stage 5 real-handshake
        // e2e is what exercises it.
        engine.initialize();
        engine.process_event(role.start_event());

        Self {
            runtime,
            link,
            driver,
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

        // Drive the lwIP input path (loopback / QEMU shape). Real-NIC
        // deploys drive netif input from the RX ISR instead of
        // poll_loopback (carry tail).
        self.link.poll_loopback();
        self.link.check_timeouts();

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

        // Inbound datagram? Dispatch it and loop promptly for the next.
        if let Some(dg) = self.driver.try_recv() {
            // Reply to whoever just spoke (the acceptor reply path).
            self.driver.set_peer(dg.src_addr, dg.src_port);
            // Unicast MCU session shell — one peer per link, so no source
            // attribution is needed (the multicast MCU drive is a later round).
            let event = LinkEvent::Rx(RxFrame::new(dg.data.as_slice().to_vec()));
            let outcome = dispatch_link_event(event, &self.actions, &mut self.engine);
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
        // same arithmetic the comparator re-derives; the prior arming
        // read the inbound stamp alone with the local window, so a
        // silent peer was never lease-checked). Fire when
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
/// profile, and closing that gap is the point: before it, the session could
/// not be spawned at all, because [`wz_runtime_core::Runtime::spawn`]
/// requires `F: Send` while the MCU action bundle is `Rc`-backed and `!Send`
/// on purpose (that `Rc` is what reaches ARMv6-M, where `alloc::sync::Arc`
/// does not exist). The session therefore ran as a caller-owned loop that
/// *called* the executor instead of running *in* it. It now runs in it.
///
/// Awaits [`yield_now`] between iterations rather than spinning, so every
/// other task in the pool — and the local set's own runtime pass — gets a
/// turn each time round. The returned value is the same [`DriverOutcome`]
/// [`run_session`] returns; reach it through the
/// [`CoopLocalJoinHandle`] the spawn hands back.
///
/// Takes `Rc<LwipLink>` where [`run_session`] takes `&LwipLink`: a spawned
/// task outlives the call that created it, so it must own its share of the
/// link.
pub async fn session_task<C, F>(
    runtime: CoopRuntime<C>,
    link: Rc<LwipLink>,
    driver: Rc<LwipUdpDriver>,
    actions: Rc<SessionLinkActions<CoopRuntime<C>, CoopTime<C>>>,
    clock: CoopTime<C>,
    config: SessionDriveConfig,
    mut on_event: F,
) -> DriverOutcome
where
    C: ClockSource,
    F: FnMut(IterationEvent<'_>),
{
    let mut pump = SessionPump::new(runtime, link, driver, actions, clock, config);
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
/// `on_event` must be `'static` here where [`run_session`] takes any
/// closure: a detached task cannot borrow the caller's stack. An observer
/// that needs to publish out of the task should capture an `Rc<RefCell<..>>`
/// — `!Send` is fine, which is the whole point of the local set.
pub fn spawn_session<C, F>(
    local: &CoopLocalSet<C>,
    link: Rc<LwipLink>,
    driver: Rc<LwipUdpDriver>,
    actions: Rc<SessionLinkActions<CoopRuntime<C>, CoopTime<C>>>,
    clock: CoopTime<C>,
    config: SessionDriveConfig,
    on_event: F,
) -> CoopLocalJoinHandle<DriverOutcome>
where
    C: ClockSource + 'static,
    F: FnMut(IterationEvent<'_>) + 'static,
{
    local.spawn_local(session_task(
        local.runtime().clone(),
        link,
        driver,
        actions,
        clock,
        config,
        on_event,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use alloc::vec;
    use core::cell::RefCell;

    use wz_link_lwip::ipv4_addr_loopback;
    use wz_link_lwip::rx_sockets::bind_session_rx;
    use wz_session_core::link::BoxedLinkDriver;
    use wz_session_core::reliability::Reliability;
    use wz_session_core::session_actions::SessionLinkActions;
    use wz_session_core::session_init_params::SessionInitParams;
    use wz_session_core::signing_key::SigningKey;
    use wz_session_core::WhatAmI;

    use crate::driver::{LwipUdpDriver, SharedSessionSocket};

    /// Frozen host clock — `now_us` is constant, so no handshake / lease
    /// deadline ever elapses (`now_ms >= deadline_ms` stays false). Keeps
    /// the loop-machinery check deterministic (terminates on max_iters, not
    /// on a timing race).
    #[derive(Clone, Default)]
    struct FrozenClock;
    impl ClockSource for FrozenClock {
        fn now_us(&self) -> u64 {
            0
        }
    }

    fn test_params() -> SessionInitParams {
        SessionInitParams {
            version: 0x05,
            whatami: WhatAmI::Peer,
            zid: vec![0x01, 0x02, 0x03, 0x04],
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 1024,
            lease_ms: 10_000,
            initial_sn: 0,
            cookie: vec![0u8; 16],
            cookie_signing_key: SigningKey::new(vec![7u8; 32]).expect(">=32-byte key"),
        }
    }

    /// Stage 4b integration smoke. lwIP under NO_SYS=1 is a process-global
    /// single-init resource (a second `lwip_init` aborts "netif already
    /// added") while cargo runs a binary's tests on parallel threads. R311lu
    /// resolved the R71-deferred harness: this test and the multicast_drive
    /// loop test now share wz-link-lwip's `lwip_test_link` init-once +
    /// serialized handle (exposed via its `test-support` dev-feature), so two
    /// lwIP-touching tests coexist in one binary. Hold `_serial` for the test
    /// body; drive the input path through the returned link.
    #[test]
    fn mcu_session_shell_drives_over_lwip() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();

        // (1) Outbound seam: LwipUdpDriver::send_blocking -> LwipUdpSocket::
        // send_to -> lwIP loopback -> LwipUdpDriver::try_recv. The adapter
        // drives a real datagram round trip over the shared socket.
        {
            let port: u16 = 7450;
            let socket: SharedSessionSocket = Rc::new(RefCell::new(
                bind_session_rx(&link, port).expect("bind session rx"),
            ));
            let driver = LwipUdpDriver::new(socket, ipv4_addr_loopback(), port);

            let payload: &[u8] = b"stage4b wz-session-lwip driver send";
            driver.send_blocking(payload, Reliability::Reliable);
            link.poll_loopback();
            link.check_timeouts();

            let dg = driver.try_recv().expect("loopback datagram delivered");
            std::assert_eq!(&dg.data[..], payload);
            std::assert_eq!(dg.src_port, port);
        }

        // (2) The full loop machinery composes over the live CoopRuntime +
        // the real SessionLinkActions + the LwipUdpDriver: an acceptor with
        // no inbound peer and a frozen clock ticks the sync loop and returns
        // IterationLimit (no deadline fires, no final state reached). The
        // real session machinery runs on the MCU profile through a live
        // socket; the real-wire acceptor handshake e2e is Stage 5.
        {
            let port: u16 = 7451;
            let socket: SharedSessionSocket = Rc::new(RefCell::new(
                bind_session_rx(&link, port).expect("bind session rx"),
            ));
            let driver = Rc::new(LwipUdpDriver::new(socket, ipv4_addr_loopback(), port));

            let runtime = CoopRuntime::new(FrozenClock);
            let clock = CoopTime::new(&runtime);
            let driver_sink: Rc<dyn BoxedLinkDriver> = driver.clone();
            // R311ja — `R = CoopRuntime<FrozenClock>` annotated: `new_generic`
            // returns the non-injective `R::ActionsHandle<T>` (lwIP `Rc`), so
            // the `Rc<dyn _>` driver arg cannot back-infer `R`.
            let actions =
                SessionLinkActions::<CoopRuntime<FrozenClock>, CoopTime<FrozenClock>>::new_generic(
                    driver_sink,
                    test_params(),
                    clock.clone(),
                );

            let outcome = run_session(
                &runtime,
                &link,
                &driver,
                &actions,
                &clock,
                SessionDriveConfig {
                    timeouts: SessionTimeouts::spec_defaults(),
                    role: SessionRole::Acceptor,
                    max_iters: Some(32),
                },
                |_event| {},
            );
            std::assert_eq!(outcome, DriverOutcome::IterationLimit);
        }
    }

    /// R2364 — the MCU session runs AS A TASK on the cooperative executor.
    ///
    /// This is the fact `runtime-coop`'s residual said did not exist: the
    /// session bundle is `Rc`-backed and therefore `!Send`, so
    /// `Runtime::spawn` (which requires `F: Send`) could never take it, and
    /// there was no spawn call site anywhere in the MCU session stack — the
    /// session ran as a caller-owned loop that CALLED `run_until_idle`
    /// instead of running inside it.
    ///
    /// What is asserted, in the order that makes each one load-bearing:
    ///
    /// 1. The session occupies a live slot in the executor's local pool.
    ///    A caller-driven pump can never make that count non-zero — it is
    ///    the direct witness of "hosted BY the executor".
    /// 2. It advances ONE iteration per executor pass, and only when the
    ///    executor is pumped. With `max_iters = 1` the first pass runs the
    ///    single permitted iteration and yields; the task is still
    ///    unfinished. The second pass hits the cap and completes it. A task
    ///    that ran a private loop to completion, or one that was never
    ///    scheduled at all, both fail this.
    /// 3. Its outcome is the same value the synchronous driver produces
    ///    from the same config — the two drivers share one sequence
    ///    (`SessionPump::step`), so they must agree.
    /// 4. The slot is vacated on completion.
    /// 5. A `Send` task spawned through the ordinary `Runtime::spawn` also
    ///    advances under the local set's pump, i.e. one pump call really
    ///    does drive both pools (the module contract `CoopLocalSet`
    ///    documents).
    #[test]
    fn mcu_session_runs_as_a_task_on_the_cooperative_executor() {
        use core::cell::Cell;
        use wz_runtime_coop::CoopLocalSet;
        use wz_runtime_core::Runtime;

        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let link = Rc::new(link);

        let make_session = |port: u16| {
            let socket: SharedSessionSocket = Rc::new(RefCell::new(
                bind_session_rx(&link, port).expect("bind session rx"),
            ));
            let driver = Rc::new(LwipUdpDriver::new(socket, ipv4_addr_loopback(), port));
            let runtime = CoopRuntime::new(FrozenClock);
            let clock = CoopTime::new(&runtime);
            let driver_sink: Rc<dyn BoxedLinkDriver> = driver.clone();
            let actions =
                SessionLinkActions::<CoopRuntime<FrozenClock>, CoopTime<FrozenClock>>::new_generic(
                    driver_sink,
                    test_params(),
                    clock.clone(),
                );
            (runtime, clock, driver, actions)
        };

        // The reference value: the synchronous driver, one permitted
        // iteration. Assertion 3 compares against this rather than against a
        // literal, so the two drivers are pinned to each other.
        let sync_outcome = {
            let (runtime, clock, driver, actions) = make_session(7452);
            run_session(
                &runtime,
                &link,
                &driver,
                &actions,
                &clock,
                SessionDriveConfig {
                    timeouts: SessionTimeouts::spec_defaults(),
                    role: SessionRole::Acceptor,
                    max_iters: Some(1),
                },
                |_event| {},
            )
        };

        let (runtime, clock, driver, actions) = make_session(7453);
        let local = CoopLocalSet::new(&runtime);

        // Assertion 5's probe: an ordinary `Send` task on the shared pool,
        // spawned through the unchanged `Runtime` contract.
        let send_task_ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let send_task_flag = send_task_ran.clone();
        let _send_handle = runtime.spawn(async move {
            send_task_flag.store(true, std::sync::atomic::Ordering::Release);
        });

        // The `!Send` observer: an `Rc<Cell<_>>` capture would not compile
        // under `Runtime::spawn`. It compiles here, which is the bound this
        // whole module exists to drop.
        let iterations = Rc::new(Cell::new(0usize));
        let iterations_in_task = iterations.clone();

        let handle = spawn_session(
            &local,
            link.clone(),
            driver.clone(),
            actions,
            clock,
            SessionDriveConfig {
                timeouts: SessionTimeouts::spec_defaults(),
                role: SessionRole::Acceptor,
                max_iters: Some(1),
            },
            move |_event| {
                iterations_in_task.set(iterations_in_task.get() + 1);
            },
        );

        // (1) Hosted by the executor, and (2) not yet advanced — spawning
        // queues the task, it does not run it.
        std::assert_eq!(local.live_local_task_count(), 1);
        std::assert!(!handle.is_finished());

        // (2) One pass, one iteration. The task consumed its single
        // permitted iteration and yielded back rather than running on.
        local.run_until_idle();
        std::assert_eq!(local.live_local_task_count(), 1);
        std::assert!(
            !handle.is_finished(),
            "one executor pass must advance the session exactly one \
             iteration, not run it to completion"
        );

        // (5) One pump drove the shared pool too.
        std::assert!(
            send_task_ran.load(std::sync::atomic::Ordering::Acquire),
            "CoopLocalSet::run_until_idle must drive the runtime's Send \
             pool as well as its own local tasks"
        );

        // The second pass reaches the iteration cap and the task completes.
        local.run_until_idle();
        std::assert!(handle.is_finished());

        // (3) + (4).
        let task_outcome = local
            .block_on_local(handle)
            .expect("session task completed without being aborted");
        std::assert_eq!(task_outcome, sync_outcome);
        std::assert_eq!(task_outcome, DriverOutcome::IterationLimit);
        std::assert_eq!(local.live_local_task_count(), 0);

        // The observer never fired (frozen clock, no inbound traffic), which
        // is why assertion 2 counts executor passes rather than events.
        std::assert_eq!(iterations.get(), 0);
    }
}
