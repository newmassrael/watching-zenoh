// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2703 §5.26 — the JOIN: the PRODUCTION drive loop is what waits.
//!
//! Two facts were already pinned separately, and together they say nothing.
//! `session::tests::a_buffered_subscription_waits_rather_than_dropping_the_newest_sample`
//! shows `Session::drain_buffered` waits for a slow consumer; `wz-rest`'s
//! `rest_sse_wire_e2e` shows a loop wired with that drain delivers. Neither
//! shows the LOOP's await providing the backpressure — and a claim true at both
//! ends and false in the join is a class this tree has paid for eight times now.
//!
//! So this drives `drive_session_until_terminal_with_extra_deadline` over a
//! scripted burst of real encoded frames, with a buffered subscription whose
//! queue is far smaller than the burst and a consumer that lags, and asserts
//! that NOTHING is lost. The loop is the only thing that can wait here: the
//! subscriber callback runs inline on it and must not block.
//!
//! ⚠ The assertion is NO LOSS rather than "the loop stalled", deliberately.
//! Stalling is the mechanism and loss is the consequence, and a timing
//! assertion on a stall would be the kind of test that passes for scheduling
//! reasons. Loss is deterministic: a queue of `CAPACITY` against a burst of
//! `BURST` is over capacity by construction, so drop-newest cannot deliver all
//! of them however the scheduler runs.
#![cfg(all(
    feature = "transport-unicast",
    feature = "declare-subscriber",
    feature = "pubsub-put",
    feature = "codec-push"
))]

use std::sync::{Arc, Mutex};

use sce_rust_runtime::Engine;
use wz_runtime_core::TimeSource;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, SubscribeOptions, TokioSession};
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal, drive_session_until_terminal_with_extra_deadline,
    new_session_actions, new_session_engine, BoxedLinkDriver, DriverLoopOutcome, ExtraDeadline,
    IterationEvent, KeepAliveCheckOutcome, LoopStages, SessionActionsBinding, SessionLinkActions,
    SessionTimeouts,
};
use wz_runtime_tokio::{LinkEvent, RxFrame};
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, LifecycleRecordingDriver, NoopOutboundDriver, QueueDriver,
};

/// Smaller than the burst on purpose — see the module docs.
const CAPACITY: usize = 2;
/// One frame per sample, all delivered before the consumer reads any.
const BURST: usize = 6;
const KEYEXPR: &str = "demo/data";

fn established(engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>) {
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);
    engine.process_event(E::InitAckReceived);
    engine.process_event(E::OpenAckReceived);
    assert_eq!(engine.get_current_state(), S::Established);
}

/// `BURST` real frames, each carrying a Put with a distinct one-byte payload,
/// captured from this tree's OWN encoder by publishing them.
///
/// Not hand-rolled: a codec change should red this fixture rather than leave it
/// describing a message nobody sends. The publishing session takes a different
/// zid because the sender is a peer — with the fixture default on both sides the
/// receiver reads the replay as its own echo and drops it, which is a way for
/// this test to pass while proving nothing.
fn burst_of_frames() -> Vec<Vec<u8>> {
    let recorder = Arc::new(LifecycleRecordingDriver::default());
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = recorder.clone();
    let mut params = fixture_session_init_params();
    params.zid = vec![0x02; 4];
    let actions = new_session_actions(outbound, params, TokioTime::new());
    *actions
        .link
        .established_at
        .lock()
        .expect("established_at poisoned in fixture") = Some(actions.clock.now_monotonic_ms());
    let session = TokioSession::new(
        actions,
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(TokioTime::new()),
    );
    for i in 0..BURST {
        session
            .publish(
                KEYEXPR,
                &[i as u8],
                PublishOptions::put().with_locality(wz_runtime_tokio::locality::Locality::Remote),
            )
            .expect("the capture publish reaches the wire");
    }
    let snap = recorder.snapshot();
    assert_eq!(
        snap.sends.len(),
        BURST,
        "the capture must be one frame per sample, or the replay below is ambiguous"
    );
    snap.sends.into_iter().map(|(bytes, _)| bytes).collect()
}

/// The claim: every sample of an over-capacity burst reaches a lagging consumer,
/// because the drive loop waited for it.
///
/// ⚠ SINGLE-THREADED on purpose, and that is what makes this a discriminator
/// rather than a race. Dropping the newest sample has no await in it, so on one
/// thread the drain that finds a full queue runs to completion before the reader
/// can be polled at all: the loss is forced, not raced for. Waiting DOES have an
/// await, so the same drain yields, the reader runs, and delivery continues.
/// The two implementations are separated by the runtime's own scheduling
/// guarantee instead of by who happens to win.
#[tokio::test]
async fn the_drive_loop_waits_for_a_lagging_buffered_consumer() {
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(NoopOutboundDriver::default());
    let actions: Arc<SessionLinkActions> =
        new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    established(&mut engine);

    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(actions.clone(), observer, Arc::new(TokioTime::new()));
    let (_subscriber, mut rx, _drain_stage) = session
        .declare_subscriber_buffered(
            "demo/**",
            SubscribeOptions::default(),
            CAPACITY,
            |sample: &dyn wz_session_core::sink::SampleView| sample.payload().to_vec(),
        )
        .expect("buffered subscriber declares");

    // ⛔ THE CONSUMER MUST NOT READ BEFORE THE QUEUE IS FULL, and this is the
    // whole anti-vacuity condition. MEASURED: the first draft let the reader
    // start at once, and because the loop drains after EVERY frame the queue
    // never held more than one sample — so the control (drop instead of wait)
    // PASSED, delivering all six. A witness whose buffer never fills cannot tell
    // backpressure from dropping, whatever it asserts.
    //
    // The release is the drain-ENTRY count, not a sleep: `CAPACITY` drains fill
    // the queue, so drain number `CAPACITY + 1` is the one whose behaviour the
    // two implementations disagree about. Releasing the reader there cannot
    // deadlock — that drain is exactly the one the reader is about to unblock.
    let drains = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let drains_seen = drains.clone();
    let reader = tokio::spawn(async move {
        // Bounded: a loop that never reaches the full-buffer drain must fail the
        // assertion below rather than hang the suite.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while drains_seen.load(std::sync::atomic::Ordering::SeqCst) <= CAPACITY {
                tokio::task::yield_now().await;
            }
        })
        .await;
        let mut got: Vec<Vec<u8>> = Vec::new();
        while got.len() < BURST {
            // Every `recv` is BOUNDED: the sender lives as long as the
            // subscription, so a lost sample never closes the channel and an
            // unbounded wait would HANG instead of failing. (Measured: the
            // sibling unit test's first draft hung its own control this way.)
            match tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await {
                Ok(Some(item)) => got.push(item),
                Ok(None) | Err(_) => break,
            }
            tokio::task::yield_now().await;
        }
        got
    });

    let events: Vec<LinkEvent> = burst_of_frames()
        .into_iter()
        .map(|wire| LinkEvent::Rx(RxFrame::new(wire)))
        .collect();
    let mut driver = QueueDriver::with(events);
    let clock = TokioTime::new();
    let session_dispatch = session.clone();
    let session_drain = session.clone();
    let _ = drive_session_until_terminal_with_extra_deadline(
        &mut driver,
        &actions,
        &mut engine,
        Some(BURST),
        &clock,
        &SessionTimeouts::spec_defaults(),
        move |event| session_dispatch.dispatch_iteration_event(event),
        ExtraDeadline {
            next_ms: || None,
            revised: None,
        },
        LoopStages {
            ingress: |_: &mut DriverLoopOutcome| {},
            // THE SEAM UNDER TEST — everything else here is production code.
            // The count is the caller's own bookkeeping, taken BEFORE the drain
            // is polled: on a single-threaded runtime nothing can run between
            // the two, so the reader cannot have consumed anything by the time
            // the full-buffer drain makes its choice.
            after_dispatch: move || {
                let session = session_drain.clone();
                drains.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move { session.drain_buffered().await }
            },
        },
    )
    .await;

    let got = reader.await.expect("reader task panicked");
    assert_eq!(
        got,
        (0..BURST).map(|i| vec![i as u8]).collect::<Vec<_>>(),
        "every sample of a {BURST}-sample burst must reach a lagging consumer \
         through a queue of {CAPACITY} -- the loop waited for it. Fewer means \
         the loop dropped what it could not hand over."
    );
}

/// The other half of the claim, and the one that says the backpressure above is
/// an improvement rather than a trade: a consumer that never reads must cost
/// this session its THROUGHPUT, not its LIFE.
///
/// Keepalive TX is emitted by this same drive loop — there is no timer task and
/// the loop's future is `!Send`, so there cannot be one — which means awaiting
/// the drain straight through would silence keepalive for as long as the
/// consumer is behind, and the peer would drop a session that is perfectly
/// healthy. Upstream never faces this: its blocking handler parks one link's rx
/// task while keepalive runs on another. So wz has to keep the duty running by
/// hand, and this is the witness that it does.
///
/// ⚠ VIRTUAL TIME (`start_paused`), and that is not a convenience. `TokioTime`
/// reads `tokio::time::Instant`, so both the loop's wake arithmetic and its
/// sleeps follow the paused clock: the lease periods below cost no wall-clock
/// and, more to the point, the test cannot pass or fail on how fast the machine
/// running it happens to be.
#[tokio::test(start_paused = true)]
async fn a_parked_drain_does_not_starve_this_sessions_keepalive() {
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(NoopOutboundDriver::default());
    let actions: Arc<SessionLinkActions> =
        new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    established(&mut engine);

    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(actions.clone(), observer, Arc::new(TokioTime::new()));
    // Capacity ONE and a receiver that is never read: the second sample fills
    // the queue and the loop parks on it for the rest of the test. `_rx` is
    // HELD rather than dropped — dropping it closes the channel, the drain
    // returns on the send error, and the loop never parks at all, which is the
    // vacuous shape this test would otherwise quietly take.
    let (_subscriber, _rx, _drain_stage) = session
        .declare_subscriber_buffered(
            "demo/**",
            SubscribeOptions::default(),
            1,
            |sample: &dyn wz_session_core::sink::SampleView| sample.payload().to_vec(),
        )
        .expect("buffered subscriber declares");

    let emitted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = emitted.clone();
    let events: Vec<LinkEvent> = burst_of_frames()
        .into_iter()
        .map(|wire| LinkEvent::Rx(RxFrame::new(wire)))
        .collect();
    let mut driver = QueueDriver::with(events);
    let clock = TokioTime::new();
    let session_dispatch = session.clone();
    let session_drain = session.clone();
    // Bounded in VIRTUAL time. A loop parked with no timer armed leaves the
    // runtime idle, so tokio advances straight to this deadline and the
    // assertion below reports zero — a starved keepalive FAILS here, it does
    // not hang here.
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        drive_session_until_terminal_with_extra_deadline(
            &mut driver,
            &actions,
            &mut engine,
            None,
            &clock,
            &SessionTimeouts::spec_defaults(),
            move |event| {
                if matches!(
                    event,
                    IterationEvent::KeepAlive(KeepAliveCheckOutcome::Emitted)
                ) {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                session_dispatch.dispatch_iteration_event(event)
            },
            ExtraDeadline {
                next_ms: || None,
                revised: None,
            },
            LoopStages {
                ingress: |_: &mut DriverLoopOutcome| {},
                after_dispatch: move || {
                    let session = session_drain.clone();
                    async move { session.drain_buffered().await }
                },
            },
        ),
    )
    .await;

    let count = emitted.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        count >= 2,
        "a loop parked on a consumer that never reads must keep emitting \
         keepalive -- got {count}. Zero means the park starved the session it \
         was applying backpressure for, trading a lost sample for a lost \
         session."
    );
}

/// R2708 (open-debt item 785) — THE HOST WIRES NOTHING AND THE BURST STILL
/// ARRIVES.
///
/// # What this is the witness for
///
/// `the_drive_loop_waits_for_a_lagging_buffered_consumer` proves the WAIT
/// happens, through `drive_session_until_terminal_with_extra_deadline` and a
/// hand-written `LoopStages::after_dispatch`. That is the shape 19 of 308 drive
/// call sites take. The other 289 use `drive_session_until_terminal`, which had
/// no stage to give — so a buffered subscription declared by a host that drives
/// the ordinary way staged its samples and stopped, and the only thing that
/// said so was a `log::error!` after the fact. R2705 paid a hosted red for
/// exactly that, and R2707 could only make forgetting LOUD.
///
/// This test drives the ordinary way and wires NOTHING. The session's drains
/// now hang off the kernel the loop already holds, so the loop reaches them
/// without being asked.
///
/// # Why it is a discriminator and not a race
///
/// The same mechanism as its sibling: single-threaded, with the reader held
/// back until the queue must be full. `CAPACITY` samples fill it; the sample
/// after that can only arrive if the loop WAITED for room. The hold-back is a
/// sleep rather than a drain-entry count because this host has no stage to
/// count in — which is the whole point of the test.
#[tokio::test]
async fn a_host_that_wires_no_stage_still_delivers_under_backpressure() {
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(NoopOutboundDriver::default());
    let actions: Arc<SessionLinkActions> =
        new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    established(&mut engine);

    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(actions.clone(), observer, Arc::new(TokioTime::new()));
    // ⚠ The third value is DROPPED here, deliberately: this test's whole claim
    // is that a host which does nothing with it is still correct.
    let (_subscriber, mut rx, _) = session
        .declare_subscriber_buffered(
            "demo/**",
            SubscribeOptions::default(),
            CAPACITY,
            |sample: &dyn wz_session_core::sink::SampleView| sample.payload().to_vec(),
        )
        .expect("buffered subscriber declares");

    let reader = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut got: Vec<Vec<u8>> = Vec::new();
        while got.len() < BURST {
            match tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await {
                Ok(Some(item)) => got.push(item),
                Ok(None) | Err(_) => break,
            }
            tokio::task::yield_now().await;
        }
        got
    });

    let events: Vec<LinkEvent> = burst_of_frames()
        .into_iter()
        .map(|wire| LinkEvent::Rx(RxFrame::new(wire)))
        .collect();
    let mut driver = QueueDriver::with(events);
    let clock = TokioTime::new();
    let session_dispatch = session.clone();
    // THE ORDINARY ENTRY, with no stages argument at all.
    let _ = drive_session_until_terminal(
        &mut driver,
        &actions,
        &mut engine,
        Some(BURST),
        &clock,
        &SessionTimeouts::spec_defaults(),
        move |event| session_dispatch.dispatch_iteration_event(event),
    )
    .await;

    let got = reader.await.expect("reader task panicked");
    assert_eq!(
        got,
        (0..BURST).map(|i| vec![i as u8]).collect::<Vec<_>>(),
        "every sample of a {BURST}-sample burst must reach a lagging consumer \
         even though this host wired no drain stage: the session's own work is \
         the loop's to do"
    );
}
