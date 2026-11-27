// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The periodic jobs a program starts on the session (`SessionEngine::start_ticker`): one runs
//! from the call that steps the session once its time has come and not before, a period after
//! its last run ended, never alongside itself, outside the session's lock, and ends when it says
//! so or is stopped.
//!
//! Each test runs in the simulated world (`tests::sim`): the session's clock moves only when the
//! test moves it, so a job comes due at the reading the script brings the clock to, and the step
//! that runs it is a step the script makes.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use wz_capi_port::{SessionDrive, SessionEngine, Tick, Tickers, WireKey};
use wz_session_core::publish_options::PublishOptions;

use super::sim::{Sim, SimEngine};
use super::CatchAll;
use crate::EngineHold;

/// The seed every test here runs on: the session's and the stand-in's entropy.
const SEED: u64 = 0x5eed_71c4;

/// The steps that bring a session just opened to rest: past the first, which moves the links
/// once, every one of them finds the links settled.
const QUIET_STEPS: usize = 4;

/// The most steps a test makes on a clock it moves a millisecond a step: a bound against a job
/// that never comes due, which no run a test waits for comes near.
const MOST_STEPS: u64 = 1_000;

/// A job that counts its runs and goes on.
fn counting(runs: &Arc<AtomicUsize>) -> Tick {
    let runs = runs.clone();
    Arc::new(move || {
        runs.fetch_add(1, Ordering::SeqCst);
        true
    })
}

/// Step `engine` and turn the world until the links are settled and nothing waits at the
/// session's end, the clock standing still: what a test counts after it is the test's own doing.
fn rest(sim: &Sim, engine: &SimEngine) {
    for _ in 0..QUIET_STEPS {
        SessionDrive::step_once(engine, 0).expect("a session without its read task steps");
        sim.turn();
    }
    sim.steps_until(engine, 0, "the session to rest", || {
        sim.waiting_for_the_session() == 0
    });
}

/// A job does not run before its time and does not run unless the session is stepped: a read a
/// millisecond before its time runs nothing, the clock moved past its time with no step runs
/// nothing (the CONTROL), and the first read after that runs it once.
#[test]
fn a_job_runs_from_the_step_after_its_time_and_not_before() {
    const PERIOD_MS: u64 = 60;
    let sim = Sim::new(SEED);
    let _router = sim.stand_in(CatchAll::None);
    let engine = sim.open(sim.config());
    let runs = Arc::new(AtomicUsize::new(0));
    let id = engine
        .start_ticker(PERIOD_MS, counting(&runs))
        .expect("the engine runs periodic jobs");

    sim.advance_ms(PERIOD_MS - 1);
    SessionDrive::read(&*engine, false).expect("the session is open");
    assert_eq!(
        runs.load(Ordering::SeqCst),
        0,
        "a read a millisecond before its time runs nothing"
    );

    sim.advance_ms(PERIOD_MS);
    assert_eq!(
        runs.load(Ordering::SeqCst),
        0,
        "CONTROL: no step was made, so nothing ran, though its time had come"
    );
    SessionDrive::read(&*engine, false).expect("the session is open");
    assert_eq!(
        runs.load(Ordering::SeqCst),
        1,
        "the first read after its time runs it, once"
    );
    engine.stop_ticker(id);
}

/// A read with no job due takes the session's lock for its wait and its step alone: the step
/// looks for a due job under its own take, by its own reading of the clock, where the jobs took a
/// take of their own. The CONTROL is a read that runs a due job: two takes more, one to take the
/// job and one to put it back and look for the next.
#[test]
fn a_read_with_no_job_due_takes_the_session_for_its_wait_and_its_step_alone() {
    let sim = Sim::new(SEED);
    let _router = sim.stand_in(CatchAll::None);
    let engine = sim.open(sim.config());
    rest(&sim, &engine);
    let takes = || engine.takes.core.load(Ordering::SeqCst);
    let before = takes();
    SessionDrive::read(&*engine, false).expect("the session is open");
    assert_eq!(takes() - before, 2, "the wait and the step");

    let runs = Arc::new(AtomicUsize::new(0));
    let id = engine
        .start_ticker(20, counting(&runs))
        .expect("the engine runs periodic jobs");
    sim.advance_ms(40);
    let before = takes();
    SessionDrive::read(&*engine, false).expect("the session is open");
    assert_eq!(runs.load(Ordering::SeqCst), 1, "the job was due and ran");
    assert_eq!(
        takes() - before,
        4,
        "CONTROL: the run takes the job in one take, puts it back and looks for the next in one more"
    );
    engine.stop_ticker(id);
}

/// A run is due a period after the PREVIOUS run ended, so a job is not run again to catch up,
/// and the gaps between runs are no shorter than the period. Each run records the reading of the
/// clock it ran at, kept beside the clock by the test that moves it.
#[test]
fn a_job_is_due_a_period_after_its_last_run_ended() {
    const PERIOD_MS: u64 = 25;
    let sim = Sim::new(SEED);
    let _router = sim.stand_in(CatchAll::None);
    let engine = sim.open(sim.config());
    let now_ms = Arc::new(AtomicU64::new(0));
    let at = Arc::new(Mutex::new(Vec::<u64>::new()));
    let (log, clock) = (at.clone(), now_ms.clone());
    let id = engine
        .start_ticker(
            PERIOD_MS,
            Arc::new(move || {
                log.lock().unwrap().push(clock.load(Ordering::SeqCst));
                true
            }),
        )
        .expect("the engine runs periodic jobs");

    while at.lock().unwrap().len() < 4 {
        assert!(
            now_ms.load(Ordering::SeqCst) < MOST_STEPS,
            "four runs did not come within {MOST_STEPS} ms of the session's clock"
        );
        SessionDrive::read(&*engine, false).expect("the session is open");
        sim.advance_ms(1);
        now_ms.fetch_add(1, Ordering::SeqCst);
    }
    engine.stop_ticker(id);

    let at = at.lock().unwrap();
    assert!(at[0] >= PERIOD_MS, "the first run came at {} ms", at[0]);
    for pair in at.windows(2) {
        assert!(
            pair[1] - pair[0] >= PERIOD_MS,
            "two runs {} ms apart, under the {PERIOD_MS} ms period",
            pair[1] - pair[0]
        );
    }
}

/// A job that answers `false` is over: no later step runs it. The control is the job that
/// answers `true` beside it, which keeps running while the first one is silent.
#[test]
fn a_job_that_answers_false_is_ended() {
    let sim = Sim::new(SEED);
    let _router = sim.stand_in(CatchAll::None);
    let engine = sim.open(sim.config());
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

    sim.steps_with_time(&engine, 1, "the control to run five times", || {
        goes_on.load(Ordering::SeqCst) >= 5
    });
    assert_eq!(once.load(Ordering::SeqCst), 1, "it ran once and no more");
    engine.stop_ticker(control);
}

/// A stopped job does not run again, and stopping one that is already stopped, or never was
/// started, changes nothing. The CONTROL is a job started beside it, which the same steps run.
#[test]
fn a_stopped_job_does_not_run_again() {
    let sim = Sim::new(SEED);
    let _router = sim.stand_in(CatchAll::None);
    let engine = sim.open(sim.config());
    let runs = Arc::new(AtomicUsize::new(0));
    let beside = Arc::new(AtomicUsize::new(0));
    let id = engine
        .start_ticker(10, counting(&runs))
        .expect("the engine runs periodic jobs");
    let control = engine
        .start_ticker(10, counting(&beside))
        .expect("the engine runs periodic jobs");
    sim.steps_with_time(&engine, 1, "the first run", || {
        runs.load(Ordering::SeqCst) >= 1
    });

    engine.stop_ticker(id);
    engine.stop_ticker(id);
    engine.stop_ticker(u64::MAX);
    let after = runs.load(Ordering::SeqCst);
    let beside_after = beside.load(Ordering::SeqCst);
    for _ in 0..80 {
        SessionDrive::read(&*engine, false).expect("the session is open");
        sim.advance_ms(1);
    }
    assert_eq!(
        runs.load(Ordering::SeqCst),
        after,
        "eight periods of steps ran nothing"
    );
    assert!(
        beside.load(Ordering::SeqCst) > beside_after,
        "CONTROL: the same steps ran the job beside it"
    );
    engine.stop_ticker(control);
}

/// A job runs outside the session's lock: what it does, a publish here, takes that lock and
/// goes out on the link.
#[test]
fn a_job_may_publish_on_the_session_it_runs_on() {
    let sim = Sim::new(SEED);
    let router = sim.stand_in(CatchAll::Held);
    let engine = sim.open(sim.config());
    let on = EngineHold::downgrade(&engine);
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

    sim.steps_with_time(&engine, 1, "the stand-in to hear a tick", || {
        router.seen(|seen| seen.samples.iter().any(|(key, _)| key == "demo/tick"))
    });
    engine.stop_ticker(id);
}

/// A job slower than its period runs once for each step that finds it due, and does not hold the
/// caller to run again until it has caught up: one step, one run. Each run takes ten of the
/// session's milliseconds, five periods.
#[test]
fn a_job_slower_than_its_period_runs_once_a_step() {
    let sim = Arc::new(Sim::new(SEED));
    let _router = sim.stand_in(CatchAll::None);
    let engine = sim.open(sim.config());
    let runs = Arc::new(AtomicUsize::new(0));
    let (count, world) = (runs.clone(), sim.clone());
    let id = engine
        .start_ticker(
            2,
            Arc::new(move || {
                count.fetch_add(1, Ordering::SeqCst);
                world.advance_ms(10);
                true
            }),
        )
        .expect("the engine runs periodic jobs");

    sim.steps_with_time(&engine, 1, "the first run", || {
        runs.load(Ordering::SeqCst) >= 1
    });
    sim.advance_ms(20);
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
    let sim = Sim::new(SEED);
    let _router = sim.stand_in(CatchAll::None);
    let engine = sim.open(sim.config());
    SessionDrive::close(&*engine);
    assert_eq!(
        engine.start_ticker(10, Arc::new(|| true)),
        Err(wz_capi_port::Refusal::Closed),
        "there is no session to step a job from"
    );
}
