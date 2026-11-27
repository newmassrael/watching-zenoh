// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Two threads of the host step one session at once (`SessionDrive::step_once`): what the test
//! holds is a property of every interleaving the host's scheduler may choose, so it runs on the
//! host's threads and sockets, against the router stand-in on a thread of its own. A wait here
//! waits for its event; the wall clock bounds it only so that a session that never brings the
//! event about fails rather than hangs (`docs/deterministic-tests.md`, the system layer).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_port::{SessionDrive, SessionEngine, SubscriberSink, WireKey};
use wz_session_core::locality::Locality;
use wz_session_core::sink::SampleView;

use super::{open, CatchAll, Command, Engine, Router};

/// How long a wait for an event may take before the test fails rather than hangs.
const STALL: Duration = Duration::from_secs(5);

/// Step `engine` with the bound `most_ms` until `done`: each step of a session without its
/// read task steps it.
fn steps_until(engine: &Engine, most_ms: u32, what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + STALL;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        SessionDrive::step_once(engine, most_ms).expect("a session without its read task steps");
    }
}

/// Two threads step one session at once while a batch of samples arrives: neither step is
/// refused or fails, and each sample of the batch is handed to the subscriber once.
#[test]
fn two_steps_at_once_hand_each_sample_out_once() {
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
        let deadline = Instant::now() + STALL;
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
