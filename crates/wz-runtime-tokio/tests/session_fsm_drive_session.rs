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
// R294 — lease deadline arithmetic migrated to u64 ms via TokioTime

use sce_rust_runtime::Engine;
use wz_runtime_core::TimeSource;
use wz_runtime_tokio::runtime_impl::TokioTime;
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
    async fn send(&mut self, _frame: &TxFrame<'_>, _reliability: Reliability) -> io::Result<()> {
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
    async fn send(&mut self, _frame: &TxFrame<'_>, _reliability: Reliability) -> io::Result<()> {
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
    let actions = SessionLinkActions::new(outbound, params, TokioTime::new());
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
    let clock = TokioTime::new();
    let outcome =
        drive_session_until_terminal(&mut driver, &actions, &mut engine, Some(5), &clock, |_| {})
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
    let clock = TokioTime::new();
    let outcome =
        drive_session_until_terminal(&mut driver, &actions, &mut engine, Some(0), &clock, |_| {})
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
    let clock = TokioTime::new();
    let outcome =
        drive_session_until_terminal(&mut driver, &actions, &mut engine, Some(5), &clock, |_| {})
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
    *actions.last_inbound_keepalive_at.lock().unwrap() = Some(actions.clock.now_monotonic_ms());

    let mut driver = HangingDriver;
    let clock = TokioTime::new();
    let outcome =
        drive_session_until_terminal(&mut driver, &actions, &mut engine, Some(8), &clock, |_| {})
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

// ── R85 Scenario: max_iters=None (unlimited) terminates cleanly on
//                  a finite event sequence — closes R81 carry #3
//                  ("max_iters=None production case untested directly").
//
// QueueDriver returns Lost { PeerClosed } when its queue is
// exhausted, so even without an explicit Lost stage the loop
// terminates. The test stages the Lost event explicitly so the
// driver's queue-exhaustion fallback isn't load-bearing for the
// assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r85_unlimited_iters_terminates_on_finite_event_sequence() {
    let (actions, mut engine) = fresh_setup();
    engine.process_event(E::OutboundStart);
    assert_eq!(engine.get_current_state(), S::LinkOpening);

    // Finite sequence: KeepAlive (populates lease stamp without
    // transition) then Lost (LinkOpening -> link.lost -> Closed, a
    // terminal state). max_iters=None must NOT pin the loop — the
    // is_in_final_state() check at iteration top must trip after
    // the Lost arm completes.
    let mut driver = QueueDriver::with(vec![
        LinkEvent::Rx(wz_runtime_tokio::RxFrame {
            bytes: vec![0x04], // T_MID_KEEP_ALIVE
        }),
        LinkEvent::Lost {
            cause: LostCause::PeerClosed,
        },
    ]);

    let clock = TokioTime::new();
    let outcome = drive_session_until_terminal(
        &mut driver,
        &actions,
        &mut engine,
        None, // unlimited
        &clock,
        |_| {},
    )
    .await;

    assert!(
        matches!(outcome, DriverOutcome::Terminated),
        "max_iters=None must surface Terminated when FSM reaches \
         final state; got {outcome:?}"
    );
    assert!(
        engine.is_in_final_state(),
        "engine must be in a terminal state after Terminated return"
    );
    // KeepAlive arm must have populated the lease stamp before the
    // Lost arm fired — this proves both events were processed by the
    // unlimited loop, not just the last one.
    assert!(
        actions.last_inbound_keepalive_at.lock().unwrap().is_some(),
        "KeepAlive iteration ran before the Lost iteration"
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
    let clock = TokioTime::new();
    let outcome =
        drive_session_until_terminal(&mut driver, &actions, &mut engine, Some(5), &clock, |ev| {
            captured_for_observer
                .lock()
                .unwrap()
                .push(format!("{ev:?}"));
        })
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

    // Frame with a single Unknown-MID record (0x1E = N_MID_DECLARE
    // — the last network MID still uncodec'd post-R97; was 0x1B=
    // RESPONSE pre-R97 and 0x1D=PUSH pre-R90) so
    // FramePayload.messages.len() == 1 deterministically.
    let mut driver = QueueDriver::with(vec![
        LinkEvent::Rx(RxFrame {
            bytes: vec![0x05, 0x00, 0x1E, 0xAA],
        }),
        LinkEvent::Lost {
            cause: LostCause::PeerClosed,
        },
    ]);

    let payload_record_counts: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
    let counts_for_observer = payload_record_counts.clone();
    let clock = TokioTime::new();
    let _ =
        drive_session_until_terminal(&mut driver, &actions, &mut engine, Some(5), &clock, |ev| {
            if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = ev {
                counts_for_observer.lock().unwrap().push(messages.len());
            }
        })
        .await;

    let counts = payload_record_counts.lock().unwrap();
    assert_eq!(
        counts.as_slice(),
        &[1usize],
        "observer must read exactly one FramePayload with 1 message; \
         got {counts:?}"
    );
}

// ── R99: pub/sub registry integration — Push wire arrives over the
//        link, drive_session_until_terminal observer adapter routes
//        the FramePayload.messages batch through
//        SubscriberRegistry::dispatch_iteration_event, the registered
//        callback fires with the inline keyexpr suffix that matches
//        its filter. End-to-end coverage of the AP MVP path:
//          link bytes → parse_inbound → Frame → parse_frame_payload
//          → NetworkMessage::Push → SubscriberRegistry → callback.
#[cfg(feature = "codec-push")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r99_subscriber_registry_routes_framepayload_push_to_callback() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wz_codecs::push::Push;
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_local::WireexprLocal;
    use wz_runtime_tokio::pubsub::SubscriberRegistry;

    let (actions, mut engine) = fresh_setup();
    engine.process_event(E::OutboundStart);

    // Build a Push with an inline keyexpr suffix "demo/topic". The
    // N flag (bit 5 = 0x20) signals the wireexpr's `parent.N`-gated
    // suffix is present; the inner body variant defaults to MsgPut
    // per R88 variant-default-uniformity so the encoded wire shape
    // is header(1) + wireexpr.id VLE(1) + suffix_len VLE(1) +
    // suffix("demo/topic", 10 bytes) + msg_put header(1) +
    // msg_put.payload_len VLE(1) = 15 bytes.
    // R125c2: wireexpr is now a tagged-union dispatched on parent.M;
    // build the Local arm so the derived header.M bit ends up set
    // (matches zenoh-pico's `_z_wireexpr_is_local(&_key) → M=1`
    // construction at network.c:42 for the zero-init mapping=LOCAL
    // sender state).
    let keyexpr_literal = "demo/topic";
    let push = Push {
        header: 0x1D | 0x20,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len: Some(keyexpr_literal.len() as u64),
                suffix: Some(keyexpr_literal),
            }),
        },
        ..Push::default()
    };
    let push_bytes = push.encode_to_vec();
    // Frame envelope: T_MID_FRAME | R = 0x25, sn=1 VLE (0x01), tail = push_bytes.
    let mut frame_wire = vec![0x25, 0x01];
    frame_wire.extend_from_slice(&push_bytes);

    let mut driver = QueueDriver::with(vec![
        LinkEvent::Rx(RxFrame { bytes: frame_wire }),
        LinkEvent::Lost {
            cause: LostCause::PeerClosed,
        },
    ]);

    // SubscriberRegistry shared with the observer closure. Arc<Mutex>
    // mirrors a production callsite where the registry is held by
    // both the drive_session task and an application-side handle
    // that wants to register / unregister concurrently.
    let registry = Arc::new(Mutex::new(SubscriberRegistry::new()));
    let hit_count = Arc::new(AtomicUsize::new(0));
    let hit_count_for_callback = hit_count.clone();
    registry
        .lock()
        .unwrap()
        .register(keyexpr_literal, move |_push| {
            hit_count_for_callback.fetch_add(1, Ordering::SeqCst);
        });

    let registry_for_observer = registry.clone();
    let clock = TokioTime::new();
    let _ =
        drive_session_until_terminal(&mut driver, &actions, &mut engine, Some(5), &clock, |ev| {
            registry_for_observer
                .lock()
                .unwrap()
                .dispatch_iteration_event(ev);
        })
        .await;

    assert_eq!(
        hit_count.load(Ordering::SeqCst),
        1,
        "subscriber callback fires exactly once for the matching keyexpr"
    );
}

// ── R83 Scenario C: observer fires on the Lease branch too — short
//                    lease + hanging driver + recent stamp ensures
//                    the sleep arm wins
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r83_observer_fires_on_lease_branch() {
    let (actions, mut engine) = fresh_setup_with_lease_ms(20);
    drive_to_established(&mut engine);
    *actions.last_inbound_keepalive_at.lock().unwrap() = Some(actions.clock.now_monotonic_ms());

    let mut driver = HangingDriver;
    let lease_outcomes: Arc<Mutex<Vec<LeaseCheckOutcome>>> = Arc::new(Mutex::new(Vec::new()));
    let outcomes_for_observer = lease_outcomes.clone();
    let clock = TokioTime::new();
    let _ =
        drive_session_until_terminal(&mut driver, &actions, &mut engine, Some(8), &clock, |ev| {
            if let IterationEvent::Lease(o) = ev {
                outcomes_for_observer.lock().unwrap().push(o);
            }
        })
        .await;

    let captured = lease_outcomes.lock().unwrap();
    assert!(
        captured.contains(&LeaseCheckOutcome::Expired),
        "lease branch must fire at least once with Expired verdict \
         (short lease + silent peer); captured={captured:?}"
    );
}
