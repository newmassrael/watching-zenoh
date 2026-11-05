// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The instrument of `docs/router-table-snapshots.md` (phase 0): what the faces' threads and the
//! writers of the tables cost each other while both run.
//!
//! A MEASUREMENT. It prints the figures and asserts only the population behind them: every Put a
//! publisher sent was routed once and reached every subscriber, and every write the writer made
//! returned. A run whose population failed measured something other than the sharing of the
//! tables, and fails instead of printing a number.

use super::*;
use crate::runtime_impl::TokioRuntime;
use crate::test_fixtures::{recording_actions, RecordingLinkDriver};
use std::sync::atomic::{AtomicBool, Ordering};
use wz_runtime_core::runtime::Runtime;

/// The publishers' threads, each a face forwarding Puts without pause.
const PUBLISHERS: u64 = 8;

/// The faces subscribed to what the publishers put: every Put is sent to each.
const FAN_OUT: u64 = 4;

/// How long the publishers and the writer run together.
const WINDOW: Duration = Duration::from_secs(3);

/// Every this many declarations, the writer also brings a face up and takes it down.
const TRANSITION_EVERY: u64 = 32;

fn zid(b: u8) -> Zid {
    Zid::from_slice(&[b, b, b, b])
}

/// A client face whose remote is `peer`, and what its link was given.
fn client(peer: Zid) -> (Arc<SessionLinkActions>, Arc<RecordingLinkDriver>) {
    let (actions, sink) = recording_actions();
    TokioRuntime::with_mutex_mut(&actions.remote_peer_zid, |s| {
        *s = Some(peer.as_slice().to_vec())
    });
    TokioRuntime::with_mutex_mut(&actions.peer_whatami, |s| *s = Some(0b10));
    (actions, sink)
}

/// `message` brought by `face`, as the face's drive hands a frame to the router.
fn bring(fwd: &RouterForwarder, face: FaceId, message: NetworkMessage) {
    let outcome = DriverLoopOutcome::FramePayload {
        priority: Priority::DEFAULT,
        reliable: true,
        sn: 0,
        messages: vec![message],
        has_ext: false,
        extensions: Vec::new(),
    };
    fwd.forward(face, IterationEvent::Poll(&outcome));
}

fn declare_sub(keyexpr: &str) -> NetworkMessage {
    NetworkMessage::Declare(Box::new(
        build_declare_subscriber(0, 0, Some(keyexpr)).expect("build declare"),
    ))
}

fn undeclare_sub(keyexpr: &str) -> NetworkMessage {
    NetworkMessage::Declare(Box::new(
        build_undeclare_subscriber_with_keyexpr(keyexpr).expect("build undeclare"),
    ))
}

/// How long each write took, from the call to its return: the wait for the tables and the work.
#[derive(Default)]
struct Waits(Vec<Duration>);

impl Waits {
    fn time(&mut self, write: impl FnOnce()) {
        let began = Instant::now();
        write();
        self.0.push(began.elapsed());
    }

    /// The count, the median, the 99th percentile and the longest, in microseconds.
    fn line(&mut self) -> String {
        self.0.sort_unstable();
        let at = |q: usize| {
            let index = (self.0.len() * q / 100).min(self.0.len().saturating_sub(1));
            self.0.get(index).map_or(0, Duration::as_micros)
        };
        format!(
            "n={} p50={}us p99={}us max={}us",
            self.0.len(),
            at(50),
            at(99),
            self.0.last().map_or(0, Duration::as_micros)
        )
    }
}

/// The faces' threads route Puts to `FAN_OUT` subscribers without pause while one writer
/// declares and undeclares subscriptions of keys nobody puts to, and every `TRANSITION_EVERY`
/// declarations brings a face up and takes it down. Prints the Puts routed per second and the
/// writer's waits, by kind of write.
#[test]
#[ignore = "a measurement of how the router's tables are shared (docs/router-table-snapshots.md, \
            phase 0); run with --release --ignored --nocapture on a build host"]
fn the_faces_and_the_writers_of_the_tables_measured_together() {
    let fwd = Arc::new(RouterForwarder::new(zid(0x01)));
    let mut subscribers = Vec::new();
    for s in 0..FAN_OUT {
        let (actions, sink) = client(zid(0xC0 + s as u8));
        fwd.register(FaceId(s), &actions);
        bring(&fwd, FaceId(s), declare_sub("demo/data"));
        subscribers.push(sink);
    }
    let mut publishers = Vec::new();
    for p in 0..PUBLISHERS {
        let id = FaceId(100 + p);
        let (actions, _sink) = client(zid(0xA0 + p as u8));
        fwd.register(id, &actions);
        publishers.push(id);
    }
    let writer_face = FaceId(200);
    let (writer_actions, _writer_sink) = client(zid(0xE0));
    fwd.register(writer_face, &writer_actions);
    for sink in &subscribers {
        sink.reset();
    }

    let routing = Arc::new(AtomicBool::new(true));
    let (done, finished) = std::sync::mpsc::channel();
    let mut threads = Vec::new();
    for id in publishers {
        let (fwd, routing, done) = (Arc::clone(&fwd), Arc::clone(&routing), done.clone());
        threads.push(std::thread::spawn(move || {
            let mut sent = 0usize;
            while routing.load(Ordering::Acquire) {
                let put = wz_session_core::push_build::build_push_literal("demo/data", b"x")
                    .expect("build push");
                bring(&fwd, id, NetworkMessage::Push(Box::new(put)));
                sent += 1;
            }
            done.send(sent).expect("the test is waiting");
        }));
    }
    drop(done);

    let began = Instant::now();
    let (mut declarations, mut transitions) = (Waits::default(), Waits::default());
    let mut round = 0u64;
    while began.elapsed() < WINDOW {
        let key = format!("demo/churn/{}", round % 64);
        declarations.time(|| bring(&fwd, writer_face, declare_sub(&key)));
        declarations.time(|| bring(&fwd, writer_face, undeclare_sub(&key)));
        if round % TRANSITION_EVERY == 0 {
            let id = FaceId(1_000 + round);
            let (actions, _sink) = client(zid(0xF0));
            transitions.time(|| fwd.register(id, &actions));
            transitions.time(|| fwd.deregister(id));
        }
        round += 1;
    }
    routing.store(false, Ordering::Release);
    let window = began.elapsed();

    let mut total = 0usize;
    for _ in 0..PUBLISHERS {
        total += finished
            .recv_timeout(Duration::from_secs(60))
            .expect("every publisher finishes: one that does not is waiting for the tables");
    }
    for thread in threads {
        thread.join().expect("a publisher of the router finishes");
    }
    assert_eq!(fwd.data_seen(), total, "every Put was routed once");
    for (s, sink) in subscribers.iter().enumerate() {
        assert_eq!(
            sink.frame_count(),
            total,
            "subscriber {s} was given every Put"
        );
    }
    // The structure is the build's value of the `routing-table-sharing` policy, so that one
    // instrument measures both values, each in a build that states it.
    println!(
        "table-sharing: structure={} publishers={PUBLISHERS} fan_out={FAN_OUT} \
         window={:.2}s puts_routed_per_s={:.0}",
        fwd.table_sharing().id(),
        window.as_secs_f64(),
        total as f64 / window.as_secs_f64()
    );
    println!("table-sharing: declarations {}", declarations.line());
    println!("table-sharing: face transitions {}", transitions.line());
}
