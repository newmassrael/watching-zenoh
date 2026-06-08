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

use alloc::sync::Arc;

use wz_link_lwip::LwipLink;
use wz_runtime_core::{Runtime, TimeSource};
use wz_runtime_lwip::{ClockSource, LwipRuntime, LwipTime};
use wz_session_core::drive::{check_lease_deadline, dispatch_link_event, new_session_engine};
use wz_session_core::driver_loop::{DriverOutcome, IterationEvent};
use wz_session_core::link::{LinkEvent, RxFrame};
use wz_session_core::session_actions::SessionLinkActions;
use wz_session_core::session_fsm_unicast::SessionFsmUnicastEvent;
use wz_session_core::session_timeouts::{HandshakeDeadlineTracker, SessionTimeouts};

#[cfg(feature = "reassembly")]
use wz_runtime_lwip::reassembly_rx::mcu_reassembly;
#[cfg(feature = "reassembly")]
use wz_session_core::drive::report_outcome_reassembling;

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

/// Drive one logical session over the lwIP link to a terminal FSM state (or
/// the `max_iters` cap). Builds the FSM engine from `actions` via the shared
/// [`new_session_engine`], activates `role`, then polls until
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
/// - `timeouts` — handshake deadline budget ([`SessionTimeouts::spec_defaults`]).
/// - `max_iters` — `Some(n)` caps the loop for test determinism; `None` for
///   unbounded production drive.
/// - `on_event` — the per-iteration observer (`Poll` with the decoded
///   `FramePayload` batch the application dispatches, or `Lease`).
#[allow(clippy::too_many_arguments)]
pub fn run_session<C, F>(
    runtime: &LwipRuntime<C>,
    link: &LwipLink,
    driver: &alloc::rc::Rc<LwipUdpDriver>,
    actions: &Arc<SessionLinkActions<LwipRuntime<C>, LwipTime<C>>>,
    clock: &LwipTime<C>,
    timeouts: &SessionTimeouts,
    role: SessionRole,
    max_iters: Option<usize>,
    mut on_event: F,
) -> DriverOutcome
where
    C: ClockSource,
    F: FnMut(IterationEvent<'_>),
{
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

    let lease_ms = if actions.params.lease_in_seconds {
        actions.params.lease.saturating_mul(1000)
    } else {
        actions.params.lease
    };
    let mut deadline_tracker = HandshakeDeadlineTracker::new(*timeouts);
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
        #[cfg(feature = "reassembly")]
        reasm.sweep(now_ms);

        // Inbound datagram? Dispatch it and loop promptly for the next.
        if let Some(dg) = driver.try_recv() {
            // Reply to whoever just spoke (the acceptor reply path).
            driver.set_peer(dg.src_addr, dg.src_port);
            let event = LinkEvent::Rx(RxFrame {
                bytes: dg.data.as_slice().to_vec(),
            });
            let outcome = dispatch_link_event(event, actions, &mut engine);
            #[cfg(feature = "reassembly")]
            report_outcome_reassembling(&outcome, &mut reasm, actions, now_ms, &mut on_event);
            #[cfg(not(feature = "reassembly"))]
            on_event(IterationEvent::Poll(&outcome));
            continue;
        }

        // No inbound: the handshake / lease deadline. The tracker yields the
        // active handshake deadline; in Established it disarms and the
        // keepalive-resetting lease deadline applies (R84 baseline read via
        // the shared mutex seam). Fire when `now_ms >= deadline_ms` — the
        // busy-poll equivalent of the AP select! sleep branch.
        let deadline: Option<(u64, Option<SessionFsmUnicastEvent>)> =
            match deadline_tracker.poll(engine.get_current_state(), now_ms) {
                Some((dl_ms, ev)) => Some((dl_ms, Some(ev))),
                None => {
                    let stamp = <LwipRuntime<C> as Runtime>::with_mutex_mut(
                        &actions.last_inbound_keepalive_at,
                        |g| *g,
                    );
                    stamp.map(|s| (s.saturating_add(lease_ms), None))
                }
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use alloc::vec;
    use core::cell::RefCell;

    use wz_link_lwip::rx_sockets::bind_session_rx;
    use wz_link_lwip::{ipv4_addr_loopback, LwipLink};
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
            lease: 10,
            lease_in_seconds: true,
            initial_sn: 0,
            cookie: vec![0u8; 16],
            cookie_signing_key: SigningKey::new(vec![7u8; 32]).expect(">=32-byte key"),
        }
    }

    /// Stage 4b integration smoke. lwIP under NO_SYS=1 is a process-global
    /// single-init resource and `LwipLink::init` adds the loopback netif
    /// (not re-entrant: a second init aborts "netif already added"). The
    /// idiomatic downstream shape is therefore one init per process — this
    /// single test inits once and exercises both seams in sequence. (A
    /// second lwIP-touching test would need an init-once harness shared via
    /// a `wz-link-lwip-test-support` sibling crate — wz-link-lwip's own
    /// `lwip_test_link` is `pub(crate)`, not reachable here; deferred until
    /// a second test actually needs it, R71 / YAGNI.)
    #[test]
    fn mcu_session_shell_drives_over_lwip() {
        let link = LwipLink::init();

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
            let actions =
                SessionLinkActions::new_generic(driver_sink, test_params(), clock.clone());

            let timeouts = SessionTimeouts::spec_defaults();
            let outcome = run_session(
                &runtime,
                &link,
                &driver,
                &actions,
                &clock,
                &timeouts,
                SessionRole::Acceptor,
                Some(32),
                |_event| {},
            );
            std::assert_eq!(outcome, DriverOutcome::IterationLimit);
        }
    }
}
