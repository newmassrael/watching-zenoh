// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//!   [`report_outcome_reassembling`] (reassembly-gated) or the bare
//!   `on_event(Poll)` otherwise.
//! - deadlines: [`HandshakeDeadlineTracker`] yields the handshake deadline;
//!   in Established the keepalive-resetting lease deadline applies and
//!   [`check_lease_deadline`] (the shared comparator) runs when it elapses.
//!   The sync loop fires a deadline when `now_ms >= deadline_ms` — the
//!   busy-poll equivalent of the AP `select!` sleep branch winning the race.
//! - outbound is transparent: the FSM action methods call
//!   `link_driver().send_blocking` -> [`LwipUdpDriver`]'s `socket.send_to`.

use wz_link_lwip::LwipLink;
use wz_runtime_core::TimeSource;
use wz_runtime_lwip::{ClockSource, LwipRuntime, LwipTime};
#[cfg(feature = "transport-keepalive")]
use wz_session_core::drive::{check_keepalive_deadline, keepalive_wake_deadline};
use wz_session_core::drive::{
    check_lease_deadline, dispatch_link_event, lease_wake_deadline, new_session_engine,
};
use wz_session_core::driver_loop::{DriverOutcome, IterationEvent};
use wz_session_core::link::{LinkEvent, RxFrame};
use wz_session_core::session_actions::SessionLinkActions;
use wz_session_core::session_fsm_unicast::SessionFsmUnicastEvent;
use wz_session_core::session_timeouts::{HandshakeDeadlineTracker, SessionTimeouts};

#[cfg(feature = "reassembly")]
use wz_runtime_lwip::reassembly_rx::mcu_reassembly;
#[cfg(feature = "reassembly")]
use wz_session_core::drive::{report_outcome_reassembling, sweep_reporting};

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
/// - `runtime` — the [`LwipRuntime`] whose `run_until_idle` is pumped each
///   tick (spawned keepalive workers + deadline-keyed timers).
/// - `link` — the [`LwipLink`]; `poll_loopback` + `check_timeouts` drive the
///   lwIP input path each tick. This is the loopback / QEMU shape — a real
///   multi-NIC deploy drives netif input from the RX ISR instead (carry tail).
/// - `driver` — the concrete [`LwipUdpDriver`] (for `try_recv` + `set_peer`);
///   the same object lives inside `actions` as `Rc<dyn BoxedLinkDriver>` for
///   the outbound send seam.
/// - `actions` — the session action bundle; its `clock` MUST share an epoch
///   with `clock` (R263) so the lease comparator's `now_ms` and the recorded
///   keepalive / established stamps agree. Build one [`LwipTime`], clone it
///   into `new_generic`, pass the original here.
/// - `config` — the static run parameterization ([`SessionDriveConfig`]:
///   handshake-deadline budget, FSM activation role, test iteration cap),
///   the unicast sibling of the multicast loops' `MulticastDriveConfig`.
/// - `on_event` — the per-iteration observer (`Poll` with the decoded
///   `FramePayload` batch the application dispatches, or `Lease`).
pub fn run_session<C, F>(
    runtime: &LwipRuntime<C>,
    link: &LwipLink,
    driver: &alloc::rc::Rc<LwipUdpDriver>,
    actions: &alloc::rc::Rc<SessionLinkActions<LwipRuntime<C>, LwipTime<C>>>,
    clock: &LwipTime<C>,
    config: SessionDriveConfig,
    mut on_event: F,
) -> DriverOutcome
where
    C: ClockSource,
    F: FnMut(IterationEvent<'_>),
{
    // The static parameter-object SSOT (R311lw); destructure into the local
    // names the body uses, mirroring the multicast loops' `MulticastDriveConfig`
    // handling.
    let SessionDriveConfig {
        timeouts,
        role,
        max_iters,
    } = config;

    let mut engine = new_session_engine(actions);
    // `new_session_engine` returns an un-initialized engine (the AP
    // convention — the caller runs the SCXML initial transition into the
    // `Init` state). Without this the `role.start_event()` below lands on an
    // engine that never entered `Init`, so `inbound.start` / `outbound.start`
    // does not transition into `AwaitingInitSyn` / `LinkOpening` and the
    // whole handshake stalls. The Stage 4b smoke never surfaced this (an
    // acceptor with no inbound peer terminates on `max_iters` regardless of
    // FSM state); the Stage 5 real-handshake e2e is what exercises it.
    engine.initialize();
    engine.process_event(role.start_event());

    let mut deadline_tracker = HandshakeDeadlineTracker::new(timeouts);
    #[cfg(feature = "reassembly")]
    let mut reasm = mcu_reassembly();
    let mut iter: usize = 0;

    loop {
        if engine.is_in_final_state() {
            return DriverOutcome::Terminated;
        }
        if let Some(limit) = max_iters {
            if iter >= limit {
                return DriverOutcome::IterationLimit;
            }
            iter += 1;
        }

        // Drive the lwIP input path (loopback / QEMU shape) + the runtime
        // task pool + deadline-keyed timers. Real-NIC deploys drive netif
        // input from the RX ISR instead of poll_loopback (carry tail).
        link.poll_loopback();
        link.check_timeouts();
        runtime.run_until_idle();

        let now_ms = clock.now_monotonic_ms();
        // Sweep expired reassembly chains and surface the eviction count as
        // an `IterationEvent::ReassemblyTimeout` (the shared SSOT — the AP
        // loop calls the same primitive). A stalled chain whose continuation
        // never arrives is reclaimed here once `now_ms` crosses its deadline.
        #[cfg(feature = "reassembly")]
        sweep_reporting(&mut reasm, now_ms, &mut on_event);

        // Inbound datagram? Dispatch it and loop promptly for the next.
        if let Some(dg) = driver.try_recv() {
            // Reply to whoever just spoke (the acceptor reply path).
            driver.set_peer(dg.src_addr, dg.src_port);
            // Unicast MCU session shell — one peer per link, so no source
            // attribution is needed (the multicast MCU drive is a later round).
            let event = LinkEvent::Rx(RxFrame::new(dg.data.as_slice().to_vec()));
            let outcome = dispatch_link_event(event, actions, &mut engine);
            #[cfg(feature = "reassembly")]
            report_outcome_reassembling(&outcome, &mut reasm, actions, now_ms, &mut on_event);
            #[cfg(not(feature = "reassembly"))]
            on_event(IterationEvent::Poll(&outcome));
            continue;
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
        let deadline: Option<(u64, Option<SessionFsmUnicastEvent>)> =
            match deadline_tracker.poll(engine.get_current_state(), now_ms) {
                Some((dl_ms, ev)) => Some((dl_ms, Some(ev))),
                None => lease_wake_deadline(actions).map(|dl| (dl, None)),
            };
        if let Some((deadline_ms, kind)) = deadline {
            if now_ms >= deadline_ms {
                match kind {
                    None => {
                        let lease_outcome = check_lease_deadline(actions, &mut engine, now_ms);
                        on_event(IterationEvent::Lease(lease_outcome));
                    }
                    Some(event) => {
                        engine.process_event(event);
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
        if let Some(ka_deadline_ms) = keepalive_wake_deadline(actions) {
            if now_ms >= ka_deadline_ms {
                let ka_outcome = check_keepalive_deadline(actions, now_ms);
                on_event(IterationEvent::KeepAlive(ka_outcome));
            }
        }
    }
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
            whatami: 0x02,
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

        // (2) The full loop machinery composes over the live LwipRuntime +
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

            let runtime = LwipRuntime::new(FrozenClock);
            let clock = LwipTime::new(&runtime);
            let driver_sink: Rc<dyn BoxedLinkDriver> = driver.clone();
            // R311ja — `R = LwipRuntime<FrozenClock>` annotated: `new_generic`
            // returns the non-injective `R::ActionsHandle<T>` (lwIP `Rc`), so
            // the `Rc<dyn _>` driver arg cannot back-infer `R`.
            let actions =
                SessionLinkActions::<LwipRuntime<FrozenClock>, LwipTime<FrozenClock>>::new_generic(
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
}
