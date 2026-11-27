// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session the program steps itself (`SessionDrive::step_once`): opened without its read task,
//! it reads, keeps its lease, dials a lost link again and runs its callbacks only inside the
//! program's steps, each step waiting for input no longer than the bound it is given. A step is
//! refused while the read task runs.
//!
//! Each test runs in the simulated world (`tests::sim`): the router stand-in runs only when the
//! session waits or the test turns the world, and the clock moves only when the test moves it, so
//! what a step finds is the script's and not the host's timing. Two steps made at once on two
//! threads are the host's (`tests::step_host`).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use wz_capi_port::{PeerLists, SessionDrive, SessionEngine, StepRefused, SubscriberSink, WireKey};
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::sink::SampleView;

use super::sim::{Sim, SimEngine};
use super::{CatchAll, ROUTER_ZID};
use crate::CoopConfig;

/// The seed every test here runs on: the session's and the stand-in's entropy.
const SEED: u64 = 0x5eed_5732;

/// The steps a test makes that find nothing to read: past the first, which moves the links once,
/// every one of them finds the links settled.
const QUIET_STEPS: usize = 4;

/// A subscriber on `demo/**` that counts what it is handed.
fn counted(engine: &SimEngine) -> Arc<AtomicUsize> {
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
/// alone, each bounded at nothing (only what is ready is read), and none of those steps waits.
/// The CONTROL is the push waiting at the session's end before any step: nothing is handed to the
/// subscriber between two steps. Turned red by a read the open starts, by a delivery made outside
/// a step, and by a step bounded at nothing that waits.
#[test]
fn a_session_without_its_read_task_round_trips_by_its_steps_alone() {
    let sim = Sim::new(SEED);
    let router = sim.stand_in(CatchAll::Held);
    let engine = sim.open(sim.config());
    assert!(
        !SessionDrive::read_task_is_running(&*engine),
        "the open starts no read task"
    );
    let _open = sim.take_waits();
    let declares_before = router.seen(|s| s.declares);
    let received = counted(&engine);
    sim.steps_until(&engine, 0, "the stand-in to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });

    router.push("demo/a", b"hello");
    sim.turn();
    assert!(
        sim.waiting_for_the_session() > 0,
        "the push waits at the session's end"
    );
    assert_eq!(
        received.load(Ordering::SeqCst),
        0,
        "CONTROL: nothing is handed out while the program makes no step"
    );
    sim.steps_until(&engine, 0, "the push", || {
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
    sim.steps_until(&engine, 0, "the stand-in to receive the put", || {
        router.seen(|s| {
            s.samples
                .iter()
                .any(|(k, v)| k == "demo/b" && v == b"world")
        })
    });
    let waits = sim.take_waits();
    assert!(
        waits.iter().all(|&ms| ms == 0),
        "a step bounded at nothing waits for no input: {waits:?}"
    );
}

/// A step bounded at nothing reads what reached the session's link after earlier steps bounded
/// at nothing found the link empty and the links settled. The CONTROL is the push waiting at the
/// session's end before the steps. Turned red by a step that passes over a link its last read
/// found empty with no wait to say the link has input again: in the round's form with `listen`
/// or `group`, a read bounded at nothing that makes no wait (`Core::idle_wait`), whose gate
/// reads a link again only once a wait finds input on it or the links move.
#[test]
fn a_step_bounded_at_nothing_reads_what_came_after_a_step_found_nothing() {
    let sim = Sim::new(SEED);
    let router = sim.stand_in(CatchAll::None);
    let engine = sim.open(sim.config());
    let received = counted(&engine);
    sim.steps_until(&engine, 0, "the stand-in to see the subscriber", || {
        router.seen(|s| s.declares >= 1)
    });
    for _ in 0..QUIET_STEPS {
        SessionDrive::step_once(&*engine, 0).expect("a session without its read task steps");
    }

    router.push("demo/a", b"late");
    sim.turn();
    assert!(
        sim.waiting_for_the_session() > 0,
        "CONTROL: the push waits at the session's end"
    );
    for _ in 0..QUIET_STEPS {
        SessionDrive::step_once(&*engine, 0).expect("a session without its read task steps");
    }
    assert_eq!(
        received.load(Ordering::SeqCst),
        1,
        "a step bounded at nothing reads what its link holds"
    );
}

/// A peer that hangs (no Close, nothing more on its link) is expired by the lease the program's
/// steps keep on the session's clock, the session dials again, declares what it holds over the
/// new link, and receives as before, every turn of it made inside a step. The CONTROL is the
/// session still open once its link is gone. Turned red by a lease kept by anything but the
/// steps, and by a session that ends with its link instead of dialling again.
#[test]
fn a_lease_that_runs_out_between_steps_is_dialled_again_by_the_steps() {
    let sim = Sim::new(SEED);
    let router = sim.stand_in(CatchAll::None);
    let engine = sim.open(CoopConfig {
        lease_ms: 600,
        redial_ms: Some(50),
        open_timeout_ms: 300,
        ..sim.config()
    });
    let received = counted(&engine);
    sim.steps_until(&engine, 10, "the stand-in to see the subscriber", || {
        router.seen(|s| s.declares >= 1)
    });

    router.freeze();
    sim.steps_with_time(&engine, 10, "the lease to run out", || {
        engine.peer_identities().is_empty()
    });
    assert!(
        !SessionDrive::is_closed(&*engine),
        "CONTROL: the session outlives the link its lease ended"
    );
    drop(router);

    let router = sim.stand_in(CatchAll::None);
    sim.steps_with_time(&engine, 10, "the session to declare again", || {
        router.seen(|s| s.declares >= 1)
    });
    assert_eq!(engine.peer_identities(), vec![(vec![ROUTER_ZID; 4], 0)]);
    router.push("demo/a", b"again");
    sim.steps_until(&engine, 10, "the push over the new link", || {
        received.load(Ordering::SeqCst) == 1
    });
}

/// A step bounded at nothing asks its links for no wait. The CONTROL is the read with no bound of
/// its own, which waits on the quiet link for the config's 100 ms. Turned red by a step that
/// waits past its bound, and by a read that does not wait for the config's bound.
// The wait that a quiet read makes on its link is the one a build with a read task beside the
// program's calls makes.
#[cfg(feature = "threads")]
#[test]
fn a_step_bounded_at_nothing_waits_for_no_input() {
    let sim = Sim::new(SEED);
    let _router = sim.stand_in(CatchAll::None);
    let engine = sim.open(sim.config());
    for _ in 0..QUIET_STEPS {
        SessionDrive::step_once(&*engine, 0).expect("the session steps");
        sim.turn();
    }
    let _settling = sim.take_waits();

    SessionDrive::step_once(&*engine, 0).expect("the session steps");
    let stepped = sim.take_waits();
    assert!(
        stepped.iter().all(|&ms| ms == 0),
        "a step bounded at nothing does not wait for input: {stepped:?}"
    );
    SessionDrive::read(&*engine, false).expect("the session reads");
    let read = sim.take_waits();
    assert_eq!(
        read.iter().max(),
        Some(&100),
        "CONTROL: a read of no bound of its own waits up to 100 ms: {read:?}"
    );
}

/// A step is refused while the read task runs, and steps again once it is stopped; a step of a
/// closed session is refused as closed. The CONTROL is the step before the task starts.
#[cfg(feature = "threads")]
#[test]
fn a_step_is_refused_while_the_read_task_runs() {
    let sim = Sim::new(SEED);
    let _router = sim.stand_in(CatchAll::None);
    let engine = sim.open(sim.config());
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
    let sim = Sim::new(SEED);
    let _router = sim.stand_in(CatchAll::None);
    let engine = sim.open(sim.config());
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
