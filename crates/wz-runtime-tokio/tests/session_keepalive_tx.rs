// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
        actions.link.last_outbound_at.lock().unwrap().is_none(),
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
        actions.link.last_outbound_at.lock().unwrap().is_some(),
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
        actions.link.last_outbound_at.lock().unwrap().is_some(),
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

    /// The keepalive worker is the machine's duty for `Established` alone:
    /// its exit stops it, so a session in `Closing` sends no KeepAlive after
    /// its Close frame however long the line stays idle, and neither drive
    /// loop nor the pacer has a wake to arm for one. The transport is still
    /// available in `Closing` (only `Closed` releases the link), so the
    /// stopped worker is the only thing that keeps the emit off the wire.
    #[test]
    fn keepalive_stops_when_the_session_leaves_established() {
        use wz_runtime_tokio::session_glue::keepalive_wake_deadline;
        let (rec, actions, mut engine) = recording_setup();
        drive_to_established(&mut engine);
        assert!(
            *actions.link.keepalive_armed.lock().unwrap(),
            "Established entry starts the keepalive worker"
        );
        assert!(keepalive_wake_deadline(&actions).is_some());

        engine.process_event(E::SessionClose);
        assert_eq!(engine.get_current_state(), S::Closing);
        assert!(
            !*actions.link.keepalive_armed.lock().unwrap(),
            "the exit from Established stops the keepalive worker"
        );
        assert!(
            *actions.link.transport_available.lock().unwrap(),
            "Closing still holds the link, so the transport gate does not stop the emit"
        );
        assert_eq!(
            keepalive_wake_deadline(&actions),
            None,
            "a stopped worker arms no wake"
        );

        // 4_000 ms is past the 10_000/3 interval that emits in Established.
        let idle_check = actions.clock.now_monotonic_ms() + 4_000;
        assert_eq!(
            check_keepalive_deadline(&actions, idle_check),
            KeepAliveCheckOutcome::Inactive
        );
        let keepalives = rec
            .snapshot()
            .sends
            .iter()
            .filter(|(bytes, _)| bytes == &vec![0x04])
            .count();
        assert_eq!(keepalives, 0, "no KeepAlive reached the wire in Closing");
        assert_eq!(actions.trace_snapshot().send_keep_alive, 0);
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

    /// A driver with a queue between the hand-over of a frame and its write: it
    /// reports when its writer last finished a write, which the test sets.
    struct QueuedDriver {
        ms_since_write: std::sync::Mutex<Option<u64>>,
    }

    impl BoxedLinkDriver for QueuedDriver {
        fn send_blocking(
            &self,
            _bytes: &[u8],
            _reliability: wz_runtime_tokio::Reliability,
        ) -> wz_runtime_tokio::session_glue::LinkSendOutcome {
            wz_runtime_tokio::session_glue::LinkSendOutcome::Sent
        }
        fn reports_wire_writes(&self) -> bool {
            true
        }
        fn ms_since_wire_write(&self) -> Option<u64> {
            *self.ms_since_write.lock().unwrap()
        }
        fn open_blocking(&self) {}
        fn close_blocking(&self) {}
    }

    fn queued_setup(
        ms_since_write: Option<u64>,
    ) -> (
        Arc<QueuedDriver>,
        Arc<SessionLinkActions>,
        Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>,
    ) {
        let driver = Arc::new(QueuedDriver {
            ms_since_write: std::sync::Mutex::new(ms_since_write),
        });
        let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = driver.clone();
        let actions =
            new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
        let mut engine = new_session_engine(&actions);
        engine.initialize();
        (driver, actions, engine)
    }

    /// A frame handed to a link that has a queue is not line activity: only the
    /// writer's own report of a finished write moves the keepalive baseline. A
    /// non-control emit (CLOSE, at background priority) must leave the stamp
    /// empty on such a link, where the same emit stamps it on an inline link
    /// (`close_emit_stamps_last_outbound_at`).
    #[cfg(feature = "codec-close")]
    #[test]
    fn a_handover_to_a_queued_link_does_not_stamp_the_line() {
        use wz_runtime_tokio::session_glue::CloseReason;
        let (_driver, actions, _engine) = queued_setup(None);
        actions.send_close_with_reason(CloseReason::Generic);
        assert!(
            actions.link.last_outbound_at.lock().unwrap().is_none(),
            "a frame still in the writer's queue has not spoken on the line"
        );
    }

    /// The wake deadline follows the driver's write report: a write that finished
    /// just now pushes the next keepalive a full interval out, and a link that
    /// reports an old write (its writer stuck behind data) leaves it at the
    /// establishment baseline, so the emitter fires.
    #[test]
    fn the_wake_deadline_follows_the_drivers_write_report() {
        use wz_runtime_tokio::session_glue::keepalive_wake_deadline;
        let (driver, actions, mut engine) = queued_setup(None);
        drive_to_established(&mut engine);
        let established = keepalive_wake_deadline(&actions).expect("armed once established");

        // The writer finished a write 0 ms ago: the deadline moves past the
        // establishment baseline, to at least now + interval.
        *driver.ms_since_write.lock().unwrap() = Some(0);
        std::thread::sleep(std::time::Duration::from_millis(20));
        let after_write = keepalive_wake_deadline(&actions).expect("still armed");
        assert!(
            after_write > established,
            "a fresh write must defer the keepalive: {after_write} vs {established}"
        );

        // A write the writer finished long ago (older than the session): the
        // establishment baseline wins and the deadline falls back to it.
        *driver.ms_since_write.lock().unwrap() = Some(3_600_000);
        assert_eq!(
            keepalive_wake_deadline(&actions),
            Some(established),
            "an old write report must not defer the keepalive"
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
            .link
            .last_inbound_at
            .lock()
            .unwrap()
            .is_none());
        receiver_actions
            .handle_inbound(&wire)
            .expect("emitted KeepAlive must parse");
        assert!(
            receiver_actions
                .link
                .last_inbound_at
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
    /// `last_inbound_at` alone, so with no peer KeepAlive this
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

    /// A link that is readable at every call and never suspends on its own: a session with an
    /// endless backlog. It counts the events it hands out and, at `notify_at`, wakes a task
    /// that was waiting, which stands for any other task of the thread (another session's
    /// timer, say) becoming ready in the middle of the backlog.
    #[cfg(feature = "codec-keep-alive")]
    struct FloodDriver {
        handed_out: Arc<std::sync::atomic::AtomicUsize>,
        total: usize,
        notify_at: usize,
        wake: Arc<tokio::sync::Notify>,
    }

    #[cfg(feature = "codec-keep-alive")]
    impl wz_runtime_tokio::LinkDriver for FloodDriver {
        async fn open(&mut self) -> std::io::Result<()> {
            Ok(())
        }
        async fn send(
            &mut self,
            _frame: &wz_runtime_tokio::TxFrame<'_>,
            _reliability: wz_session_core::reliability::Reliability,
        ) -> std::io::Result<()> {
            Ok(())
        }
        async fn close(&mut self) -> std::io::Result<()> {
            Ok(())
        }
        async fn poll_event(&mut self) -> wz_session_core::link::LinkEvent {
            use wz_session_core::link::{LinkEvent, LostCause, RxFrame};
            let n = self
                .handed_out
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            if n == self.notify_at {
                self.wake.notify_one();
            }
            if n > self.total {
                return LinkEvent::Lost {
                    cause: LostCause::PeerClosed,
                };
            }
            // A KeepAlive from the peer: one event of one unit, valid in Established.
            LinkEvent::Rx(RxFrame::new(vec![0x04]))
        }
    }

    /// What the thread's other task sees: how many events of the flood had been handed out when
    /// it first ran, after it was woken at `notify_at`.
    #[cfg(feature = "codec-keep-alive")]
    async fn handed_out_when_the_other_task_ran<F, Fut>(
        driver_runs: F,
        total: usize,
        notify_at: usize,
    ) -> usize
    where
        F: FnOnce(FloodDriver) -> Fut,
        Fut: core::future::Future<Output = ()>,
    {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let handed_out = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(AtomicUsize::new(0));
        let wake = Arc::new(tokio::sync::Notify::new());
        let other = {
            let (handed_out, seen, wake) = (handed_out.clone(), seen.clone(), wake.clone());
            tokio::spawn(async move {
                wake.notified().await;
                seen.store(handed_out.load(Ordering::SeqCst), Ordering::SeqCst);
            })
        };
        let driver = FloodDriver {
            handed_out,
            total,
            notify_at,
            wake,
        };
        driver_runs(driver).await;
        other.await.expect("the other task ends");
        seen.load(Ordering::SeqCst)
    }

    /// The property Layer E7s depends on, without a clock or a loaded machine: while a session
    /// has a backlog, a task that becomes ready on its thread runs within one turn of that
    /// session, which is `TURN_UNIT_BUDGET` (8) units, and not when the backlog is gone. One
    /// thread, one endless flood of one-unit events, a second task woken at the thousandth.
    #[cfg(feature = "codec-keep-alive")]
    #[tokio::test]
    async fn a_task_that_wakes_during_a_backlog_runs_within_one_turn() {
        use wz_runtime_tokio::session_glue::{drive_session_until_terminal, SessionTimeouts};
        const TOTAL: usize = 20_000;
        const NOTIFY_AT: usize = 1_000;
        const TURN_UNITS: usize = 8;

        let (_rec, actions, mut engine) = recording_setup();
        drive_to_established(&mut engine);
        let clock = TokioTime::new();
        let seen = handed_out_when_the_other_task_ran(
            |mut driver| async move {
                let _ = drive_session_until_terminal(
                    &mut driver,
                    &actions,
                    &mut engine,
                    Some(2 * TOTAL),
                    &clock,
                    &SessionTimeouts::spec_defaults(),
                    |_| {},
                )
                .await;
            },
            TOTAL,
            NOTIFY_AT,
        )
        .await;
        assert!(
            seen >= NOTIFY_AT,
            "the other task ran before it was woken: {seen}"
        );
        assert!(
            seen - NOTIFY_AT <= TURN_UNITS,
            "the other task was woken at event {NOTIFY_AT} and ran at event {seen}: the backlog \
             kept the thread for {} events, more than one turn of {TURN_UNITS}",
            seen - NOTIFY_AT
        );
    }

    /// The control of the test above: the same flood and the same second task, driven by a bare
    /// loop that takes the next event and does nothing else. The link never suspends, so the
    /// second task runs only when the flood is over. This is what proves that what lets it run in
    /// the test above is the session loop's yield and not the link's behaviour.
    #[cfg(feature = "codec-keep-alive")]
    #[tokio::test]
    async fn without_the_loops_yield_the_same_flood_keeps_the_thread() {
        use wz_runtime_tokio::LinkDriver;
        const TOTAL: usize = 20_000;
        const NOTIFY_AT: usize = 1_000;
        let seen = handed_out_when_the_other_task_ran(
            |mut driver| async move {
                loop {
                    if matches!(
                        driver.poll_event().await,
                        wz_session_core::link::LinkEvent::Lost { .. }
                    ) {
                        break;
                    }
                }
            },
            TOTAL,
            NOTIFY_AT,
        )
        .await;
        assert!(
            seen > TOTAL,
            "the second task ran at event {seen}, inside the flood of {TOTAL}: the link yields \
             by itself, so the test above would prove nothing"
        );
    }
}
