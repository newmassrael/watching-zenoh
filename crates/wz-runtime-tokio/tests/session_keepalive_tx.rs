// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311kw / R311kx — keepalive TX track tests.
//!
//! R311kw: every production TX path funnels through the
//! `SessionLinkActions::send_wire` seam, which stamps the
//! `last_outbound_at` slot — the deadline-model equivalent of
//! zenoh-pico's `_z_transport_common_t._transmitted` flag (set on
//! every send in common/tx.c:98/153, consumed by the keepalive tasks
//! in unicast/lease.c:183/196 to suppress a KeepAlive when the line
//! already spoke). The stamp tests pin that behaviour for the direct
//! primitive path AND the FSM action path.
//!
//! R311kx: the keepalive TX emitter rides the stamp —
//! `check_keepalive_deadline` emits a bare MID 0x04 KeepAlive when the
//! line has been idle for `adopted_lease / LEASE_EXPIRE_FACTOR`
//! (zenoh-pico `_zp_unicast_keep_alive_task_fn`, unicast/lease.c:172).
//! The checker tests pin the Inactive / WithinInterval / Emitted
//! verdicts and the adopted-min cadence; the loop test pins the
//! `drive_session_until_terminal` wiring (deadline arming + emit +
//! the lease-expiry interplay) over wall-clock-short leases, the R76b
//! loop-testing convention.

use std::sync::Arc;

use sce_rust_runtime::Engine;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{
    new_session_actions, new_session_engine, BoxedLinkDriver, SessionActionsBinding,
    SessionLinkActions,
};
use wz_runtime_tokio_test_support::{fixture_session_init_params, NoopOutboundDriver};

fn fresh_setup() -> (
    Arc<SessionLinkActions>,
    Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>,
) {
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(NoopOutboundDriver::default());
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    (actions, engine)
}

/// The slot starts empty: no wire emit has happened at construction,
/// so the keepalive emitter's baseline falls back to `established_at`
/// (and pre-Established it has no baseline at all).
#[test]
fn last_outbound_at_starts_empty() {
    let (actions, _engine) = fresh_setup();
    assert!(
        actions.last_outbound_at.lock().unwrap().is_none(),
        "no TX has happened at construction"
    );
}

/// The direct wire primitive (`send_close_with_reason`, the same
/// `send_wire` seam every Frame / Fragment / batch-flush emit routes
/// through) stamps the slot.
#[cfg(feature = "codec-close")]
#[test]
fn close_emit_stamps_last_outbound_at() {
    use wz_runtime_tokio::session_glue::CloseReason;
    let (actions, _engine) = fresh_setup();
    actions.send_close_with_reason(CloseReason::Generic);
    assert!(
        actions.last_outbound_at.lock().unwrap().is_some(),
        "CLOSE emit must stamp the outbound slot (pico sets _transmitted on every t_msg send)"
    );
}

/// The FSM action path (SentInitSyn.onentry -> `send_init_syn`)
/// stamps the slot too — handshake t_msg emits count as line
/// activity exactly as pico's common/tx.c seam records them.
#[cfg(all(feature = "codec-init-body", feature = "session-unicast-open"))]
#[test]
fn handshake_emit_stamps_last_outbound_at() {
    let (actions, mut engine) = fresh_setup();
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);
    assert_eq!(engine.get_current_state(), S::SentInitSyn);
    assert!(
        actions.last_outbound_at.lock().unwrap().is_some(),
        "InitSyn emit must stamp the outbound slot"
    );
}

// ── R311kx — keepalive TX emitter ──

#[cfg(feature = "transport-keepalive")]
mod keepalive_emitter {
    use super::*;
    use wz_runtime_core::TimeSource;
    use wz_runtime_tokio::session_glue::{check_keepalive_deadline, KeepAliveCheckOutcome};
    use wz_runtime_tokio_test_support::LifecycleRecordingDriver;

    /// Recording variant of `fresh_setup`: the driver snapshot exposes
    /// every emitted wire frame so the tests can assert the bare MID
    /// 0x04 shape.
    fn recording_setup() -> (
        Arc<LifecycleRecordingDriver>,
        Arc<SessionLinkActions>,
        Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>,
    ) {
        let recorder = Arc::new(LifecycleRecordingDriver::default());
        let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = recorder.clone();
        let actions =
            new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
        let mut engine = new_session_engine(&actions);
        engine.initialize();
        (recorder, actions, engine)
    }

    /// Drive the engine into Established through the initiator event
    /// chain (the lease-deadline test convention); `record_established_at`
    /// fires on entry, stamping the baseline + opening the send gate.
    fn drive_to_established(engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>) {
        engine.process_event(E::OutboundStart);
        engine.process_event(E::LinkOpened);
        engine.process_event(E::InitAckReceived);
        engine.process_event(E::OpenAckReceived);
        assert_eq!(engine.get_current_state(), S::Established);
    }

    /// Pre-Established the emitter is dormant — pico spawns the
    /// keep-alive task only after `_z_open` completes.
    #[test]
    fn checker_inactive_pre_established() {
        let (_rec, actions, _engine) = recording_setup();
        let now = actions.clock.now_monotonic_ms();
        assert_eq!(
            check_keepalive_deadline(&actions, now),
            KeepAliveCheckOutcome::Inactive
        );
    }

    /// The idle window (`adopted_lease / 3`) elapsing emits exactly one
    /// bare-header KeepAlive; the emit re-stamps `last_outbound_at`, so
    /// a re-check inside the fresh window reports `WithinInterval`.
    ///
    /// `now_ms` is parameterised (the R77 comparator-test convention), so
    /// idle time is simulated by passing a FUTURE check instant — the
    /// `TokioTime` epoch starts near 0, which saturates stamp
    /// back-dating to no-ops.
    #[test]
    fn idle_window_emits_one_keepalive_then_suppresses() {
        let (rec, actions, mut engine) = recording_setup();
        drive_to_established(&mut engine);
        let sends_before = rec.snapshot().sends.len();

        // 4_000 ms past the (real, near-epoch) baseline stamps: beyond
        // the 10_000/3 interval.
        let idle_check = actions.clock.now_monotonic_ms() + 4_000;
        assert_eq!(
            check_keepalive_deadline(&actions, idle_check),
            KeepAliveCheckOutcome::Emitted
        );
        let snap = rec.snapshot();
        assert_eq!(snap.sends.len(), sends_before + 1, "exactly one emit");
        assert_eq!(
            snap.sends.last().unwrap().0,
            vec![0x04],
            "KeepAlive = bare MID 0x04 header, zero-byte body (pico parity)"
        );
        assert_eq!(actions.trace_snapshot().send_keep_alive, 1);
        // The emit re-stamped the slot at the REAL clock instant: a check
        // right after it (inside the fresh window) suppresses.
        assert_eq!(
            check_keepalive_deadline(&actions, actions.clock.now_monotonic_ms()),
            KeepAliveCheckOutcome::WithinInterval
        );
    }

    /// The cadence divides the ADOPTED window (R311kv min(local, peer)):
    /// a peer-advertised 3_000 ms lease makes the interval 1_000 ms, so
    /// a 2_000 ms idle line emits where the local-only 10_000/3 window
    /// would still suppress.
    #[test]
    fn cadence_uses_adopted_peer_lease_min() {
        let (_rec, actions, mut engine) = recording_setup();
        drive_to_established(&mut engine);
        // 2_000 ms past the near-epoch baseline stamps (future-`now_ms`
        // convention, see `idle_window_emits_one_keepalive_then_suppresses`).
        let idle_check = actions.clock.now_monotonic_ms() + 2_000;

        assert_eq!(
            check_keepalive_deadline(&actions, idle_check),
            KeepAliveCheckOutcome::WithinInterval,
            "local-only window: 2_000 < 10_000/3"
        );
        *actions.peer_open_lease_ms.lock().unwrap() = Some(3_000);
        assert_eq!(
            check_keepalive_deadline(&actions, idle_check),
            KeepAliveCheckOutcome::Emitted,
            "adopted window: 2_000 >= 3_000/3"
        );
    }

    /// Wire self-parity: the emitted frame parses back as a KeepAlive on
    /// the inbound side and resets the receiver's lease stamp — the
    /// full liveness round trip the emitter exists for.
    #[cfg(feature = "codec-keep-alive")]
    #[test]
    fn emitted_keepalive_parses_inbound_and_stamps_lease() {
        let (rec, actions, mut engine) = recording_setup();
        drive_to_established(&mut engine);
        let idle_check = actions.clock.now_monotonic_ms() + 4_000;
        assert_eq!(
            check_keepalive_deadline(&actions, idle_check),
            KeepAliveCheckOutcome::Emitted
        );
        let wire = rec.snapshot().sends.last().unwrap().0.clone();

        let (receiver_actions, _engine2) = fresh_setup();
        assert!(receiver_actions
            .last_inbound_keepalive_at
            .lock()
            .unwrap()
            .is_none());
        receiver_actions
            .handle_inbound(&wire)
            .expect("emitted KeepAlive must parse");
        assert!(
            receiver_actions
                .last_inbound_keepalive_at
                .lock()
                .unwrap()
                .is_some(),
            "inbound KeepAlive resets the receiver's lease window"
        );
    }

    /// Loop wiring over wall-clock-short leases (the R76b convention): an
    /// Established session whose link never speaks (PendingDriver) must
    /// keep emitting KeepAlives at lease/3 cadence from the loop's own
    /// deadline arming, and the lease deadline must still fire (the
    /// R311kw-carried wake-arming fix: the pre-kx loop armed from
    /// `last_inbound_keepalive_at` alone, so with no peer KeepAlive this
    /// test would block on the link poll forever).
    #[tokio::test]
    async fn drive_loop_emits_keepalives_and_expires_silent_peer() {
        use std::sync::Mutex;
        use wz_runtime_tokio::session_glue::{
            drive_session_until_terminal, IterationEvent, LeaseCheckOutcome, SessionTimeouts,
        };
        use wz_runtime_tokio::LinkDriver;
        use wz_session_core::link::LinkEvent;
        use wz_session_core::reliability::Reliability;
        use wz_session_core::session_init_params::SessionInitParams;

        /// Link that never produces an event: the acceptor-side poll
        /// pends forever, so every loop wake comes from the deadline arm.
        struct PendingDriver;
        impl LinkDriver for PendingDriver {
            async fn open(&mut self) -> std::io::Result<()> {
                Ok(())
            }
            async fn send(
                &mut self,
                _frame: &wz_runtime_tokio::TxFrame<'_>,
                _reliability: Reliability,
            ) -> std::io::Result<()> {
                Ok(())
            }
            async fn close(&mut self) -> std::io::Result<()> {
                Ok(())
            }
            async fn poll_event(&mut self) -> LinkEvent {
                std::future::pending().await
            }
        }

        let params = SessionInitParams {
            // 300 ms lease -> 100 ms keepalive interval: 2+ emits before
            // the silent peer expires the session.
            lease_ms: 300,
            ..fixture_session_init_params()
        };
        let recorder = Arc::new(LifecycleRecordingDriver::default());
        let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = recorder.clone();
        let clock = TokioTime::new();
        let actions = new_session_actions(outbound, params, clock);
        let mut engine = new_session_engine(&actions);
        engine.initialize();
        drive_to_established(&mut engine);

        let mut driver = PendingDriver;
        let keepalive_emits = Arc::new(Mutex::new(0u32));
        let lease_expired = Arc::new(Mutex::new(0u32));
        let ka_for_cb = keepalive_emits.clone();
        let lease_for_cb = lease_expired.clone();
        let outcome = drive_session_until_terminal(
            &mut driver,
            &actions,
            &mut engine,
            // Iteration cap bounds the test if the FSM lingers in
            // Closing after the lease expiry.
            Some(16),
            &clock,
            &SessionTimeouts::spec_defaults(),
            |event| match event {
                IterationEvent::KeepAlive(KeepAliveCheckOutcome::Emitted) => {
                    *ka_for_cb.lock().unwrap() += 1;
                }
                IterationEvent::Lease(LeaseCheckOutcome::Expired) => {
                    *lease_for_cb.lock().unwrap() += 1;
                }
                _ => {}
            },
        )
        .await;
        let _ = outcome; // Terminated or IterationLimit — both bounded.

        assert!(
            *keepalive_emits.lock().unwrap() >= 2,
            "a silent link must produce >= 2 cadence emits inside one lease window, got {}",
            *keepalive_emits.lock().unwrap()
        );
        assert_eq!(
            *lease_expired.lock().unwrap(),
            1,
            "the silent peer still expires the session (TX liveness does not mask RX silence)"
        );
        let keepalive_frames = recorder
            .snapshot()
            .sends
            .iter()
            .filter(|(bytes, _)| bytes == &vec![0x04])
            .count();
        assert!(
            keepalive_frames >= 2,
            "the emits reached the wire as bare 0x04 frames, got {keepalive_frames}"
        );
    }
}
