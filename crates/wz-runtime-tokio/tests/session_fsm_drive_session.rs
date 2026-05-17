// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R76b — production driver-loop integration tests.
//!
//! Exercises `drive_session_until_terminal`, the long-running async
//! loop that composes `poll_and_dispatch_one` (one LinkEvent per
//! tick) with a `tokio::select!` race against a lease-deadline
//! sleep so a silent peer reaches `lease.expired -> Closing`
//! without the driver poll blocking indefinitely.
//!
//! R77's `check_lease_deadline` unit tests cover the leaf
//! comparator. R76b's tests cover the loop wiring:
//!   - `Terminated` outcome when the engine reaches a terminal
//!     state (final-state check at iteration top).
//!   - `IterationLimit` outcome when `max_iters` exhausts before
//!     terminal.
//!   - Event-driven termination via a staged `LinkEvent::Lost`.
//!   - Lease-branch firing via a short-lease + hanging driver
//!     (wall-clock dependency; the leaf logic is already covered
//!     deterministically by R77).

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use sce_rust_runtime::Engine;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal, BoxedLinkDriver, DriverLoopOutcome, DriverOutcome,
    IterationEvent, LeaseCheckOutcome, SessionLinkActions,
};
use wz_runtime_tokio::{LinkDriver, LinkEvent, LostCause, Reliability, RxFrame, TxFrame};
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, install_session_actions_for_test,
};

/// Inert outbound driver — `SessionLinkActions::new` requires one
/// for the Lua-closure capture path; `drive_session_until_terminal`
/// drives the inbound driver independently.
#[derive(Default)]
struct NoopOutboundDriver {
    _state: Mutex<()>,
}

impl BoxedLinkDriver for NoopOutboundDriver {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) {}
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

/// Staged-event `LinkDriver` (same shape as the R76 driver_loop
/// scaffolding; duplicated rather than extracted to keep the
/// test-support boundary minimal until the broader test scaffolding
/// gets its own retrospective).
struct QueueDriver {
    events: VecDeque<LinkEvent>,
}

impl QueueDriver {
    fn with(events: Vec<LinkEvent>) -> Self {
        Self {
            events: events.into(),
        }
    }
}

impl LinkDriver for QueueDriver {
    async fn open(&mut self) -> io::Result<()> {
        Ok(())
    }
    async fn send(
        &mut self,
        _frame: &TxFrame<'_>,
        _reliability: Reliability,
    ) -> io::Result<()> {
        Ok(())
    }
    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
    async fn poll_event(&mut self) -> LinkEvent {
        self.events.pop_front().unwrap_or(LinkEvent::Lost {
            cause: LostCause::PeerClosed,
        })
    }
}

/// Never-returning `LinkDriver` — `poll_event` resolves to
/// `std::future::pending`, so the only way out of the driver loop
/// when this driver is in use is the lease-deadline branch (or the
/// iteration-limit branch). Models a peer that has gone silent
/// (TCP RX queue empty, no `Lost` signalled by the OS).
struct HangingDriver;

impl LinkDriver for HangingDriver {
    async fn open(&mut self) -> io::Result<()> {
        Ok(())
    }
    async fn send(
        &mut self,
        _frame: &TxFrame<'_>,
        _reliability: Reliability,
    ) -> io::Result<()> {
        Ok(())
    }
    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
    async fn poll_event(&mut self) -> LinkEvent {
        std::future::pending::<LinkEvent>().await
    }
}

fn fresh_setup() -> (Arc<SessionLinkActions>, Engine<SessionFsmUnicastPolicy>) {
    fresh_setup_with_lease_ms(10_000)
}

fn fresh_setup_with_lease_ms(
    lease_ms: u64,
) -> (Arc<SessionLinkActions>, Engine<SessionFsmUnicastPolicy>) {
    let outbound: Arc<dyn BoxedLinkDriver> = Arc::new(NoopOutboundDriver::default());
    let mut params = fixture_session_init_params();
    params.lease = lease_ms;
    params.lease_in_seconds = false;
    let actions = SessionLinkActions::new(outbound, params);
    let lua = install_session_actions_for_test(actions.clone());
    let mut engine = Engine::new(SessionFsmUnicastPolicy::new(lua));
    engine.initialize();
    (actions, engine)
}

fn drive_to_established(engine: &mut Engine<SessionFsmUnicastPolicy>) {
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);
    engine.process_event(E::InitAckReceived);
    engine.process_event(E::OpenAckReceived);
    assert_eq!(engine.get_current_state(), S::Established);
}

// ── Scenario 1: engine already terminal → Terminated, no iteration
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r76b_returns_terminated_when_engine_already_final() {
    let (actions, mut engine) = fresh_setup();
    // LinkOpening -> link.lost -> Closed (direct edge, no Closing).
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkLost);
    assert!(
        engine.is_in_final_state(),
        "engine must be in final state before drive_session entry"
    );

    let mut driver = QueueDriver::with(vec![]);
    let outcome =
        drive_session_until_terminal(&mut driver, &actions, &mut engine, Some(5), |_| {})
            .await;
    assert!(
        matches!(outcome, DriverOutcome::Terminated),
        "already-final engine must return Terminated; got {outcome:?}"
    );
}

// ── Scenario 2: hanging driver + non-terminal engine + max_iters=1
//                → IterationLimit (no inbound stamp, no lease branch,
//                  poll branch hangs forever, but the next iteration
//                  top trips the limit before we even reach poll)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r76b_iteration_limit_when_loop_cannot_terminate() {
    let (actions, mut engine) = fresh_setup();
    drive_to_established(&mut engine);
    assert!(
        !engine.is_in_final_state(),
        "Established is non-terminal — drive_session must run"
    );
    // Hanging driver + no inbound keepalive stamp + lease branch
    // would never fire (None branch in drive_session). With
    // max_iters=0, the loop body never runs and we exit on the
    // limit check at iteration top.
    let mut driver = HangingDriver;
    let outcome =
        drive_session_until_terminal(&mut driver, &actions, &mut engine, Some(0), |_| {})
            .await;
    assert_eq!(
        outcome,
        DriverOutcome::IterationLimit,
        "max_iters=0 with non-terminal engine must surface IterationLimit"
    );
}

// ── Scenario 3: staged Lost event drives engine to terminal
//                via poll_and_dispatch_one branch
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r76b_link_lost_event_drives_loop_to_terminated() {
    let (actions, mut engine) = fresh_setup();
    engine.process_event(E::OutboundStart);
    assert_eq!(engine.get_current_state(), S::LinkOpening);

    // Stage a Lost event; LinkOpening -> link.lost -> Closed (direct
    // edge), which is a final state.
    let mut driver = QueueDriver::with(vec![LinkEvent::Lost {
        cause: LostCause::PeerClosed,
    }]);
    let outcome =
        drive_session_until_terminal(&mut driver, &actions, &mut engine, Some(5), |_| {})
            .await;
    assert!(
        matches!(outcome, DriverOutcome::Terminated),
        "staged Lost must drive loop to Terminated; got {outcome:?}"
    );
    assert!(
        engine.is_in_final_state(),
        "engine must be in final state after Terminated return"
    );
}

// ── Scenario 4: hanging driver + Established + recent stamp +
//                short lease → lease branch fires within the
//                wall-clock budget; FSM reaches Closing or beyond
//
// Wall-clock dependency: lease=20ms + iter limit=8 gives the loop
// up to ~160ms of wall budget to advance past Closing. R77's
// `check_lease_deadline` unit tests cover the deterministic leaf
// logic; this test verifies only the loop's select! wiring fires
// the sleep branch when a peer goes silent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r76b_lease_branch_fires_with_silent_peer() {
    let (actions, mut engine) = fresh_setup_with_lease_ms(20);
    drive_to_established(&mut engine);
    *actions.last_inbound_keepalive_at.lock().unwrap() = Some(Instant::now());

    let mut driver = HangingDriver;
    let outcome =
        drive_session_until_terminal(&mut driver, &actions, &mut engine, Some(8), |_| {})
            .await;

    // The outcome is Terminated (FSM reached Closed via Closing) or
    // IterationLimit (if the test host is slow enough that 8 iters
    // didn't fully terminate). Either way, the lease branch must
    // have fired at least once — assert the FSM has advanced past
    // Established.
    let state = engine.get_current_state();
    assert!(
        !matches!(state, S::Established | S::Init),
        "lease branch must have fired and advanced FSM past Established; \
         outcome={outcome:?} state={state:?}"
    );
}

// ── R83 Scenario A: observer captures the per-iteration outcome
//                    stream — proves R74 FramePayload reaches the
//                    application-layer consumer via R83 wiring
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r83_observer_captures_framepayload_and_linklost_in_order() {
    let (actions, mut engine) = fresh_setup();
    engine.process_event(E::OutboundStart);
    assert_eq!(engine.get_current_state(), S::LinkOpening);

    // Stage two events: Frame (no-FSM-transition, surfaces as
    // DriverLoopOutcome::FramePayload) then Lost (LinkOpening ->
    // link.lost -> Closed terminal edge). Observer should see both
    // Poll events in order; the loop then returns Terminated on the
    // next iteration top.
    let mut driver = QueueDriver::with(vec![
        // T_MID_FRAME (0x05) without R flag, sn=0, empty payload.
        LinkEvent::Rx(RxFrame {
            bytes: vec![0x05, 0x00],
        }),
        LinkEvent::Lost {
            cause: LostCause::PeerClosed,
        },
    ]);

    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_for_observer = captured.clone();
    let outcome = drive_session_until_terminal(
        &mut driver,
        &actions,
        &mut engine,
        Some(5),
        |ev| {
            captured_for_observer
                .lock()
                .unwrap()
                .push(format!("{ev:?}"));
        },
    )
    .await;

    assert!(
        matches!(outcome, DriverOutcome::Terminated),
        "staged Frame + Lost must drive loop to Terminated; got {outcome:?}"
    );

    let log = captured.lock().unwrap();
    assert_eq!(
        log.len(),
        2,
        "observer must fire exactly twice (Frame + Lost); got {log:?}"
    );
    assert!(
        log[0].starts_with("Poll(FramePayload"),
        "first iteration: observer sees FramePayload from R74 wiring; \
         got {:?}",
        log[0]
    );
    assert!(
        log[1].starts_with("Poll(LinkLost"),
        "second iteration: observer sees LinkLost; got {:?}",
        log[1]
    );
}

// ── R83 Scenario B: observer FnMut captures FramePayload.messages
//                    structurally (not via Debug string) — proves the
//                    application-layer consumer can read the decoded
//                    NetworkMessage batch through the &DriverLoopOutcome
//                    reference
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r83_observer_reads_framepayload_messages_through_reference() {
    let (actions, mut engine) = fresh_setup();
    engine.process_event(E::OutboundStart);

    // Frame with a single Unknown-MID record (0x1D = N_MID_PUSH) so
    // FramePayload.messages.len() == 1 deterministically.
    let mut driver = QueueDriver::with(vec![
        LinkEvent::Rx(RxFrame {
            bytes: vec![0x05, 0x00, 0x1D, 0xAA],
        }),
        LinkEvent::Lost {
            cause: LostCause::PeerClosed,
        },
    ]);

    let payload_record_counts: Arc<Mutex<Vec<usize>>> =
        Arc::new(Mutex::new(Vec::new()));
    let counts_for_observer = payload_record_counts.clone();
    let _ = drive_session_until_terminal(
        &mut driver,
        &actions,
        &mut engine,
        Some(5),
        |ev| {
            if let IterationEvent::Poll(DriverLoopOutcome::FramePayload {
                messages,
                ..
            }) = ev
            {
                counts_for_observer.lock().unwrap().push(messages.len());
            }
        },
    )
    .await;

    let counts = payload_record_counts.lock().unwrap();
    assert_eq!(
        counts.as_slice(),
        &[1usize],
        "observer must read exactly one FramePayload with 1 message; \
         got {counts:?}"
    );
}

// ── R83 Scenario C: observer fires on the Lease branch too — short
//                    lease + hanging driver + recent stamp ensures
//                    the sleep arm wins
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r83_observer_fires_on_lease_branch() {
    let (actions, mut engine) = fresh_setup_with_lease_ms(20);
    drive_to_established(&mut engine);
    *actions.last_inbound_keepalive_at.lock().unwrap() = Some(Instant::now());

    let mut driver = HangingDriver;
    let lease_outcomes: Arc<Mutex<Vec<LeaseCheckOutcome>>> =
        Arc::new(Mutex::new(Vec::new()));
    let outcomes_for_observer = lease_outcomes.clone();
    let _ = drive_session_until_terminal(
        &mut driver,
        &actions,
        &mut engine,
        Some(8),
        |ev| {
            if let IterationEvent::Lease(o) = ev {
                outcomes_for_observer.lock().unwrap().push(o);
            }
        },
    )
    .await;

    let captured = lease_outcomes.lock().unwrap();
    assert!(
        captured.contains(&LeaseCheckOutcome::Expired),
        "lease branch must fire at least once with Expired verdict \
         (short lease + silent peer); captured={captured:?}"
    );
}
