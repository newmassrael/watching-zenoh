// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session the program steps itself (`SessionDrive::step_once`): opened without its read task,
//! it reads, keeps its lease, dials a lost link again and runs its callbacks only inside the
//! program's steps, each step waiting for input no longer than the bound it is given. A step is
//! refused while the read task runs, and two steps made at once each step the session, every
//! sample handed out once.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_port::{PeerLists, SessionDrive, SessionEngine, StepRefused, SubscriberSink, WireKey};
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::sink::SampleView;

use super::{config, open, open_with, CatchAll, Command, Engine, Router, ROUTER_ZID};
use crate::CoopConfig;

/// Step `engine` with the bound `most_ms` until `done`, for at most five seconds: each step of a
/// session without its read task steps it.
fn steps_until(engine: &Engine, most_ms: u32, what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        SessionDrive::step_once(engine, most_ms).expect("a session without its read task steps");
    }
}

/// A subscriber on `demo/**` that counts what it is handed.
fn counted(engine: &Engine) -> Arc<AtomicUsize> {
    let received = Arc::new(AtomicUsize::new(0));
    let count = received.clone();
    engine
        .declare_subscriber_on_wire(
            "demo/**",
            WireKey::literal(),
            Locality::Any,
            None,
            SubscriberSink::shared(move |_: &dyn SampleView| {
                count.fetch_add(1, Ordering::SeqCst);
            }),
        )
        .expect("the session declares the subscriber");
    received
}

/// A session with no read task declares, receives and publishes through the program's steps
/// alone, each bounded at nothing (only what is ready is read). The CONTROL is the push before
/// any step: nothing is handed to the subscriber between two steps.
#[test]
fn a_session_without_its_read_task_round_trips_by_its_steps_alone() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    assert!(
        !SessionDrive::read_task_is_running(&*engine),
        "the open starts no read task"
    );
    let declares_before = router.seen(|s| s.declares);
    let received = counted(&engine);
    steps_until(&engine, 0, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });

    router.send(Command::Push("demo/a", b"hello"));
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        received.load(Ordering::SeqCst),
        0,
        "CONTROL: nothing is handed out while the program makes no step"
    );
    steps_until(&engine, 0, "the push", || {
        received.load(Ordering::SeqCst) == 1
    });

    engine
        .publish_on_wire_all(
            "demo/b",
            &WireKey::literal(),
            b"world",
            &PublishOptions::put().with_locality(Locality::Remote),
        )
        .expect("a put the link carries");
    steps_until(&engine, 0, "the router to receive the put", || {
        router.seen(|s| {
            s.samples
                .iter()
                .any(|(k, v)| k == "demo/b" && v == b"world")
        })
    });
}

/// A peer that hangs (no Close, no error from its socket) is expired by the lease the program's
/// steps keep, the session dials again, declares what it holds over the new link, and receives
/// as before, every turn of it made inside a step.
#[test]
fn a_lease_that_runs_out_between_steps_is_dialled_again_by_the_steps() {
    let router = Router::start(CatchAll::None);
    let port = router.port;
    let engine = open_with(CoopConfig {
        lease_ms: 600,
        redial_ms: Some(50),
        open_timeout_ms: 300,
        ..config(&router)
    });
    let received = counted(&engine);
    steps_until(&engine, 10, "the router to see the subscriber", || {
        router.seen(|s| s.declares >= 1)
    });

    router.send(Command::Freeze);
    steps_until(&engine, 10, "the lease to run out", || {
        engine.peer_identities().is_empty()
    });
    assert!(
        !SessionDrive::is_closed(&*engine),
        "the session outlives the link its lease ended"
    );
    drop(router);

    let router = Router::start_on(port, CatchAll::None);
    steps_until(&engine, 10, "the session to declare again", || {
        router.seen(|s| s.declares >= 1)
    });
    assert_eq!(engine.peer_identities(), vec![(vec![ROUTER_ZID; 4], 0)]);
    router.send(Command::Push("demo/a", b"again"));
    steps_until(&engine, 10, "the push over the new link", || {
        received.load(Ordering::SeqCst) == 1
    });
}

/// A step bounded at nothing returns without waiting for input. The CONTROL is the read with no
/// bound of its own, which waits on the quiet link for the config's 100 ms.
// The wait that a quiet read makes on its link is the one a build with a read task beside the
// program's calls makes.
#[cfg(feature = "threads")]
#[test]
fn a_step_bounded_at_nothing_waits_for_no_input() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let span = Duration::from_millis(600);
    let end = Instant::now() + span;
    let mut steps = 0u32;
    while Instant::now() < end {
        SessionDrive::step_once(&*engine, 0).expect("the session steps");
        steps += 1;
    }
    assert!(
        steps >= 60,
        "a step bounded at nothing does not wait for input: {steps} in {span:?}"
    );
    let end = Instant::now() + span;
    let mut reads = 0u32;
    while Instant::now() < end {
        SessionDrive::read(&*engine, false).expect("the session reads");
        reads += 1;
    }
    assert!(
        reads <= 8,
        "CONTROL: a read of no bound of its own waits up to 100 ms: {reads} in {span:?}"
    );
}

/// A step is refused while the read task runs, and steps again once it is stopped; a step of a
/// closed session is refused as closed. The CONTROL is the step before the task starts.
#[cfg(feature = "threads")]
#[test]
fn a_step_is_refused_while_the_read_task_runs() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    assert_eq!(
        SessionDrive::step_once(&*engine, 0),
        Ok(()),
        "CONTROL: a session without its read task steps"
    );
    SessionDrive::start_read_task(&*engine).expect("a read task");
    assert_eq!(
        SessionDrive::step_once(&*engine, 0),
        Err(StepRefused::ReadTaskRuns)
    );
    SessionDrive::stop_read_task(&*engine).expect("the task stops");
    assert_eq!(SessionDrive::step_once(&*engine, 0), Ok(()));
    SessionDrive::close(&*engine);
    assert_eq!(
        SessionDrive::step_once(&*engine, 0),
        Err(StepRefused::Closed)
    );
}

/// A step of a closed session is refused as closed, in a build of one thread too.
#[test]
fn a_step_of_a_closed_session_is_refused_as_closed() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    SessionDrive::close(&*engine);
    assert_eq!(
        SessionDrive::step_once(&*engine, 0),
        Err(StepRefused::Closed)
    );
    assert_eq!(
        SessionDrive::step_once(&*engine, 50),
        Err(StepRefused::Closed)
    );
}

/// Two threads step one session at once while a batch of samples arrives: neither step is
/// refused or fails, and each sample of the batch is handed to the subscriber once.
#[cfg(feature = "threads")]
#[test]
fn two_steps_at_once_hand_each_sample_out_once() {
    use std::sync::Mutex;

    const SAMPLES: u8 = 20;
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let handed = Arc::new(Mutex::new(Vec::new()));
    let into = handed.clone();
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire(
            "demo/**",
            WireKey::literal(),
            Locality::Any,
            None,
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                into.lock().unwrap().extend_from_slice(sample.payload());
            }),
        )
        .expect("the session declares the subscriber");
    steps_until(&engine, 0, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });

    let all = |handed: &Mutex<Vec<u8>>| handed.lock().unwrap().len() >= usize::from(SAMPLES);
    let other = engine.clone();
    let seen = handed.clone();
    let beside = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !all(&seen) && Instant::now() < deadline {
            SessionDrive::step_once(&*other, 5).expect("the other thread's step steps");
        }
    });
    router.send(Command::PushBatch("demo/a", SAMPLES));
    steps_until(&engine, 5, "every sample of the batch", || all(&handed));
    beside.join().expect("the other thread's steps return");
    // What a step still reads after the batch is nothing more of it.
    SessionDrive::step_once(&*engine, 0).expect("the session steps");
    let mut handed = handed.lock().unwrap().clone();
    handed.sort_unstable();
    assert_eq!(
        handed,
        (0..SAMPLES).collect::<Vec<u8>>(),
        "each sample once, whichever step read it"
    );
}
