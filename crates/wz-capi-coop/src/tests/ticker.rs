// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The periodic jobs a program starts on the session (`SessionEngine::start_ticker`): one runs
//! from the call that steps the session once its time has come and not before, a period after
//! its last run ended, never alongside itself, outside the session's lock, and ends when it says
//! so or is stopped.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_port::{SessionDrive, SessionEngine, Tick, WireKey};
use wz_session_core::publish_options::PublishOptions;

use super::{open, until, CatchAll, Router};

/// A job that counts its runs and goes on.
fn counting(runs: &Arc<AtomicUsize>) -> Tick {
    let runs = runs.clone();
    Arc::new(move || {
        runs.fetch_add(1, Ordering::SeqCst);
        true
    })
}

/// The clock reads whole milliseconds, so a time measured on this thread's can be one short of
/// the period the engine counted on its own.
const READING: Duration = Duration::from_millis(1);

/// A job does not run before its time and does not run unless the session is stepped: the
/// control is the wait with no step, which leaves the count where it was, and the run after it
/// comes from the first step and not a period after the start.
#[test]
fn a_job_runs_from_the_step_after_its_time_and_not_before() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let runs = Arc::new(AtomicUsize::new(0));
    let period = Duration::from_millis(60);

    let started = Instant::now();
    let id = engine
        .start_ticker(60, counting(&runs))
        .expect("the engine runs periodic jobs");
    std::thread::sleep(period + Duration::from_millis(20));
    assert_eq!(
        runs.load(Ordering::SeqCst),
        0,
        "no step was made, so nothing ran, though its time had come"
    );

    until(&engine, "the first run", || {
        runs.load(Ordering::SeqCst) == 1
    });
    assert!(
        started.elapsed() + READING >= period,
        "it ran no sooner than one period after it was started"
    );
    engine.stop_ticker(id);
}

/// A run is due a period after the PREVIOUS run ended, so a job is not run again to catch up,
/// and the gaps between runs are no shorter than the period.
#[test]
fn a_job_is_due_a_period_after_its_last_run_ended() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let at = Arc::new(Mutex::new(Vec::<Instant>::new()));
    let log = at.clone();
    let id = engine
        .start_ticker(
            25,
            Arc::new(move || {
                log.lock().unwrap().push(Instant::now());
                true
            }),
        )
        .expect("the engine runs periodic jobs");

    until(&engine, "four runs", || at.lock().unwrap().len() >= 4);
    engine.stop_ticker(id);

    let at = at.lock().unwrap();
    for pair in at.windows(2) {
        assert!(
            pair[1] - pair[0] + READING >= Duration::from_millis(25),
            "two runs {:?} apart, under the 25 ms period",
            pair[1] - pair[0]
        );
    }
}

/// A job that answers `false` is over: no later step runs it. The control is the job that
/// answers `true` beside it, which keeps running while the first one is silent.
#[test]
fn a_job_that_answers_false_is_ended() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let once = Arc::new(AtomicUsize::new(0));
    let goes_on = Arc::new(AtomicUsize::new(0));
    let ones = once.clone();
    engine
        .start_ticker(
            10,
            Arc::new(move || {
                ones.fetch_add(1, Ordering::SeqCst);
                false
            }),
        )
        .expect("the engine runs periodic jobs");
    let control = engine
        .start_ticker(10, counting(&goes_on))
        .expect("the engine runs periodic jobs");

    until(&engine, "the control to run five times", || {
        goes_on.load(Ordering::SeqCst) >= 5
    });
    assert_eq!(once.load(Ordering::SeqCst), 1, "it ran once and no more");
    engine.stop_ticker(control);
}

/// A stopped job does not run again, and stopping one that is already stopped, or never was
/// started, changes nothing.
#[test]
fn a_stopped_job_does_not_run_again() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let runs = Arc::new(AtomicUsize::new(0));
    let id = engine
        .start_ticker(10, counting(&runs))
        .expect("the engine runs periodic jobs");
    until(&engine, "the first run", || {
        runs.load(Ordering::SeqCst) >= 1
    });

    engine.stop_ticker(id);
    engine.stop_ticker(id);
    engine.stop_ticker(u64::MAX);
    let after = runs.load(Ordering::SeqCst);
    let until_then = Instant::now() + Duration::from_millis(80);
    while Instant::now() < until_then {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert_eq!(
        runs.load(Ordering::SeqCst),
        after,
        "eight periods of steps ran nothing"
    );
}

/// A job runs outside the session's lock: what it does, a publish here, takes that lock and
/// goes out on the link.
#[test]
fn a_job_may_publish_on_the_session_it_runs_on() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    let on = Arc::downgrade(&engine);
    let id = engine
        .start_ticker(
            10,
            Arc::new(move || {
                let Some(engine) = on.upgrade() else {
                    return false;
                };
                engine
                    .publish_on_wire_all(
                        "demo/tick",
                        &WireKey::literal(),
                        b"t",
                        &PublishOptions::put(),
                    )
                    .is_ok()
            }),
        )
        .expect("the engine runs periodic jobs");

    until(&engine, "the router to hear a tick", || {
        router.seen(|seen| seen.samples.iter().any(|(key, _)| key == "demo/tick"))
    });
    engine.stop_ticker(id);
}

/// A job slower than its period runs once for each step that finds it due, and does not hold the
/// caller to run again until it has caught up: one step, one run.
#[test]
fn a_job_slower_than_its_period_runs_once_a_step() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let runs = Arc::new(AtomicUsize::new(0));
    let count = runs.clone();
    let id = engine
        .start_ticker(
            2,
            Arc::new(move || {
                count.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(10));
                true
            }),
        )
        .expect("the engine runs periodic jobs");

    until(&engine, "the first run", || {
        runs.load(Ordering::SeqCst) >= 1
    });
    std::thread::sleep(Duration::from_millis(20));
    let before = runs.load(Ordering::SeqCst);
    SessionDrive::read(&*engine, false).expect("the session is open");
    assert_eq!(
        runs.load(Ordering::SeqCst),
        before + 1,
        "a step found the job due once, and ran it once"
    );
    engine.stop_ticker(id);
}

/// A closed session starts no job.
#[test]
fn a_closed_session_starts_no_job() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    SessionDrive::close(&*engine);
    assert!(
        engine.start_ticker(10, Arc::new(|| true)).is_none(),
        "there is no session to step a job from"
    );
}
