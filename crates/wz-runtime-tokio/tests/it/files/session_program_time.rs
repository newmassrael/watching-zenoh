// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A `TokioTime` made over a time base the program supplies (`program-time`): its readings, its
//! waits and its timeouts follow the program's time and not the wall clock, and so does the lease
//! of a session the drive loop times with it.
//!
//! Each wait is held for several times its length of the wall clock while the program's time
//! stands still, and must not end; then the program's time passes it and the program says so,
//! and it must. A wait that ran on the wall clock would end in the first half, and one that the
//! program's word did not wake would not end in the second.

#![cfg(feature = "program-time")]

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sce_rust_runtime::Engine;
use wz_runtime_core::{TimeSource, TimeoutElapsed};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal, new_session_actions, new_session_engine, BoxedLinkDriver,
    DriverOutcome, IterationEvent, LeaseCheckOutcome, SessionActionsBinding, SessionLinkActions,
};
use wz_runtime_tokio::time_base::{ProgramTime, TimeBaseHold};
use wz_runtime_tokio::{LinkDriver, LinkEvent, Reliability, TxFrame};
use wz_runtime_tokio_test_support::{fixture_session_init_params, NoopOutboundDriver};
use wz_session_core::session_timeouts::SessionTimeouts;

/// A millisecond of the program's time, in its nanoseconds.
const MS: u64 = 1_000_000;

/// The program's time, which each test sets.
struct SetTime(Arc<AtomicU64>);

impl ProgramTime for SetTime {
    fn now_ns(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A time base whose time the test sets, standing at five seconds of the program's epoch: a clock
/// made over it counts from its reading then, not from the epoch.
fn program_time() -> (Arc<AtomicU64>, TimeBaseHold) {
    let now = Arc::new(AtomicU64::new(5_000 * MS));
    let hold = TimeBaseHold::new(Box::new(SetTime(now.clone())));
    (now, hold)
}

/// A link that never delivers anything: a peer gone silent, so the loop ends only by its
/// deadlines.
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

fn session_on(
    clock: TokioTime,
    lease_ms: u64,
) -> (
    Arc<SessionLinkActions>,
    Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>,
) {
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(NoopOutboundDriver::default());
    let mut params = fixture_session_init_params();
    params.lease_ms = lease_ms;
    let actions = new_session_actions(outbound, params, clock);
    let mut engine = new_session_engine(&actions);
    engine.initialize().unwrap_or_else(|never| match never {});
    (actions, engine)
}

fn drive_to_established(engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>) {
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);
    engine.process_event(E::InitAckReceived);
    engine.process_event(E::OpenAckReceived);
    assert_eq!(engine.get_current_state(), S::Established);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clock_on_a_program_time_base_reads_that_time_from_when_it_was_made() {
    let (now, hold) = program_time();
    let clock = TokioTime::on_time_base(hold.time());
    let wall = TokioTime::new();
    assert_eq!(clock.now_monotonic_ms(), 0);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(clock.now_monotonic_ms(), 0, "the wall clock moved it");
    assert!(
        wall.now_monotonic_ms() >= 50,
        "CONTROL: a clock with no time base reads the wall clock"
    );
    now.fetch_add(1_234 * MS, Ordering::SeqCst);
    assert_eq!(clock.now_monotonic_ms(), 1_234);
    assert_eq!(clock.now_monotonic_us(), 1_234_000);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wait_ends_when_the_programs_time_passes_it_and_the_program_says_so() {
    let (now, hold) = program_time();
    let clock = TokioTime::on_time_base(hold.time());
    // A task of its own, so that only a wake can poll the wait again.
    let waiting = tokio::spawn(async move { clock.sleep(50).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !waiting.is_finished(),
        "four times its length of the wall clock ended a wait of the program's time"
    );
    now.fetch_add(50 * MS, Ordering::SeqCst);
    hold.advanced();
    tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .expect("the wait ends once the program's time passes it and the program says so")
        .expect("the waiting task");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_timeout_on_a_program_time_base_runs_on_that_time() {
    let (now, hold) = program_time();
    let clock = TokioTime::on_time_base(hold.time());
    assert_eq!(
        clock.timeout(10, async { 7 }).await,
        Ok(7),
        "a future ready in time is answered"
    );
    let timed = tokio::spawn(async move { clock.timeout(30, std::future::pending::<()>()).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !timed.is_finished(),
        "the wall clock ended a timeout of the program's time"
    );
    now.fetch_add(30 * MS, Ordering::SeqCst);
    hold.advanced();
    let outcome = tokio::time::timeout(Duration::from_secs(5), timed)
        .await
        .expect("the timeout ends once the program's time passes it")
        .expect("the timing task");
    assert_eq!(outcome, Err(TimeoutElapsed));
}

/// A silent peer and a lease of 20 ms: over a second of the wall clock with the program's time
/// standing still the drive loop checks no lease; once the program's time passes the lease the
/// lease is found expired, and once it passes the close's bound too the session ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lease_on_a_program_time_base_expires_only_when_that_time_passes_it() {
    let (now, hold) = program_time();
    let clock = TokioTime::on_time_base(hold.time());
    let (actions, mut engine) = session_on(clock, 20);
    drive_to_established(&mut engine);
    *actions.link.last_inbound_at.lock().unwrap() = Some(actions.clock.now_monotonic_ms());

    let outcomes: Arc<Mutex<Vec<LeaseCheckOutcome>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = outcomes.clone();
    let expired = || {
        outcomes
            .lock()
            .unwrap()
            .contains(&LeaseCheckOutcome::Expired)
    };
    let mut driver = HangingDriver;
    let timeouts = SessionTimeouts::spec_defaults();
    let drive = drive_session_until_terminal(
        &mut driver,
        &actions,
        &mut engine,
        None,
        &clock,
        &timeouts,
        move |event| {
            if let IterationEvent::Lease(outcome) = event {
                seen.lock().unwrap().push(outcome);
            }
        },
    );
    tokio::pin!(drive);

    assert!(
        tokio::time::timeout(Duration::from_secs(1), &mut drive)
            .await
            .is_err(),
        "the session ended while the program's time stood still"
    );
    assert!(
        !expired(),
        "fifty leases of the wall clock expired a lease of the program's time"
    );

    now.fetch_add(1_000 * MS, Ordering::SeqCst);
    hold.advanced();
    let until = Instant::now() + Duration::from_secs(5);
    while !expired() {
        assert!(
            Instant::now() < until,
            "the lease was not found expired once the program's time passed it"
        );
        let _ = tokio::time::timeout(Duration::from_millis(20), &mut drive).await;
    }

    now.fetch_add(1_000 * MS, Ordering::SeqCst);
    hold.advanced();
    let outcome = tokio::time::timeout(Duration::from_secs(5), &mut drive)
        .await
        .expect("the session ends once the program's time passes the close's bound");
    assert!(
        matches!(outcome, DriverOutcome::Terminated),
        "the expired session ends as terminated; got {outcome:?}"
    );
}
