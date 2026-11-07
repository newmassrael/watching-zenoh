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
/// declarations brings a face up and takes it down. Prints the Puts routed per second, with the
/// writer and in a window before it with none, and the writer's waits, by kind of write.
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

    // The faces alone first: what a read costs under each value with no write to retire a route,
    // which the window with the writer cannot separate from what the writes cost the readers.
    let alone = routed_while(&fwd, &publishers, &subscribers, || {
        std::thread::sleep(Duration::from_millis(1))
    });

    let (mut declarations, mut transitions) = (Waits::default(), Waits::default());
    let mut round = 0u64;
    let together = routed_while(&fwd, &publishers, &subscribers, || {
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
    });

    // The structure is the build's value of the `routing-table-sharing` policy, so that one
    // instrument measures both values, each in a build that states it.
    println!(
        "table-sharing: structure={} publishers={PUBLISHERS} fan_out={FAN_OUT} \
         window={WINDOW:?} puts_routed_per_s={together:.0} with no writer {alone:.0}",
        fwd.table_sharing().id(),
    );
    println!("table-sharing: declarations {}", declarations.line());
    println!("table-sharing: face transitions {}", transitions.line());
}

/// The Puts a second the `publishers` route to the `subscribers` for [`WINDOW`], each from a
/// thread of its own without pause, while this thread calls `meanwhile` again and again. Asserts
/// the population: every Put routed once and given to every subscriber.
fn routed_while(
    fwd: &Arc<RouterForwarder>,
    publishers: &[FaceId],
    subscribers: &[Arc<RecordingLinkDriver>],
    mut meanwhile: impl FnMut(),
) -> f64 {
    for sink in subscribers {
        sink.reset();
    }
    let seen_before = fwd.data_seen();
    let routing = Arc::new(AtomicBool::new(true));
    let (done, finished) = std::sync::mpsc::channel();
    let mut threads = Vec::new();
    for &id in publishers {
        let (fwd, routing, done) = (Arc::clone(fwd), Arc::clone(&routing), done.clone());
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
    while began.elapsed() < WINDOW {
        meanwhile();
    }
    routing.store(false, Ordering::Release);
    let window = began.elapsed();

    let mut total = 0usize;
    for _ in publishers {
        total += finished
            .recv_timeout(Duration::from_secs(60))
            .expect("every publisher finishes: one that does not is waiting for the tables");
    }
    for thread in threads {
        thread.join().expect("a publisher of the router finishes");
    }
    assert_eq!(
        fwd.data_seen() - seen_before,
        total,
        "every Put was routed once"
    );
    for (s, sink) in subscribers.iter().enumerate() {
        assert_eq!(
            sink.frame_count(),
            total,
            "subscriber {s} was given every Put"
        );
    }
    total as f64 / window.as_secs_f64()
}

/// How many client faces the admission instrument brings up, as many as the starved router of
/// the data-plane scaling tests admits.
const ADMITTED: u64 = 2048;

/// The admission instrument reports its writes in bands of this many faces.
const BAND: u64 = 256;

/// What a copy of `value` costs and what letting the copy go costs, the least of a few tries.
fn copy_cost<T: Clone>(value: &T) -> (Duration, Duration) {
    let (mut copy, mut drop_) = (Duration::MAX, Duration::MAX);
    for _ in 0..5 {
        let began = Instant::now();
        let copied = std::hint::black_box(value.clone());
        copy = copy.min(began.elapsed());
        let began = Instant::now();
        drop(copied);
        drop_ = drop_.min(began.elapsed());
    }
    (copy, drop_)
}

fn cost_line(name: &str, (copy, drop_): (Duration, Duration)) {
    println!(
        "table-sharing: copy of {name} {}us, its release {}us",
        copy.as_micros(),
        drop_.as_micros()
    );
}

/// The kinds of write a face of the admission makes, in the order it makes them. A build without
/// the token tables makes no token write and prints no token line.
const ADMISSION_WRITES: [&str; 6] = [
    "register",
    "subscribe",
    "interest",
    "queryable",
    "queryable_interest",
    "token",
];

/// The faces of a starved router's admission, one after another with nothing else running: each
/// comes up, declares a subscriber of a key of its own and asks for the subscribers of the next
/// face's key, as each session of `wz_router_hat_data_plane_scaling` does, then declares a
/// queryable of its key, asks for the queryables of the next face's key and declares a liveliness
/// token of its key, the client store of each plane growing with the faces. Prints each kind of
/// write's time against how many faces were already up, then what a copy of the whole tables and
/// of each component a write reaches costs with every face up: the profile phase 6 of
/// `docs/router-table-snapshots.md` reads to choose which tables become persistent.
#[test]
#[ignore = "a measurement of what a write of the router's tables copies (docs/router-table-snapshots.md, \
            phase 6); run with --release --ignored --nocapture on a build host"]
fn the_writes_of_an_admission_measured_against_the_faces_already_up() {
    let fwd = RouterForwarder::new(zid(0x01));
    let mut held = Vec::new();
    let mut bands: Vec<[Waits; ADMISSION_WRITES.len()]> = Vec::new();
    for i in 0..ADMITTED {
        if i % BAND == 0 {
            bands.push(Default::default());
        }
        let waits = bands.last_mut().expect("a band is open");
        let peer = Zid::from_slice(&(0x0010_0000 + i as u32).to_be_bytes());
        let (actions, sink) = client(peer);
        let face = FaceId(i);
        waits[0].time(|| fwd.register(face, &actions));
        let own = format!("mesh/dev_{i}");
        waits[1].time(|| bring(&fwd, face, declare_sub(&own)));
        let next = format!("mesh/dev_{}", (i + 1) % ADMITTED);
        let interest = wz_session_core::interest_build::build_interest_subscribers(
            1,
            true,
            true,
            0,
            Some(&next),
        )
        .expect("build interest");
        waits[2].time(|| bring(&fwd, face, NetworkMessage::Interest(interest)));
        let queryable = build_declare_queryable_with_info(&own, QueryableInfo::local(true))
            .expect("build queryable");
        waits[3].time(|| bring(&fwd, face, NetworkMessage::Declare(Box::new(queryable))));
        let interest = wz_session_core::interest_build::build_interest_queryables(
            2,
            true,
            true,
            0,
            Some(&next),
        )
        .expect("build interest");
        waits[4].time(|| bring(&fwd, face, NetworkMessage::Interest(interest)));
        #[cfg(feature = "routing-token-tables")]
        {
            let token = build_declare_token(1, 0, Some(&own)).expect("build token");
            waits[5].time(|| bring(&fwd, face, NetworkMessage::Declare(Box::new(token))));
        }
        held.push((actions, sink));
    }
    assert_eq!(
        fwd.client_queryables_seen(),
        ADMITTED as usize,
        "every face's queryable is held"
    );

    let (_, receiver) = &held[1];
    receiver.reset();
    let put =
        wz_session_core::push_build::build_push_literal("mesh/dev_1", b"x").expect("build push");
    bring(&fwd, FaceId(0), NetworkMessage::Push(Box::new(put)));
    assert_eq!(
        receiver.frame_count(),
        1,
        "a Put of the last face's key reached the face that subscribed it"
    );

    let structure = fwd.table_sharing().id();
    for (band, waits) in bands.iter_mut().enumerate() {
        let from = band as u64 * BAND;
        for (kind, waits) in ADMISSION_WRITES.iter().zip(waits.iter_mut()) {
            if waits.0.is_empty() {
                continue;
            }
            println!(
                "table-sharing: structure={structure} faces_up={from}..{} {kind} {}",
                from + BAND,
                waits.line()
            );
        }
    }

    let tables = fwd.tables.read();
    cost_line("the tables (every map's spine)", copy_cost(&*tables));
    cost_line("faces (the map)", copy_cost(&tables.faces));
    cost_line("future_subs", copy_cost(&*tables.future_subs));
    cost_line("future_qabls", copy_cost(&*tables.future_qabls));
    #[cfg(feature = "routing-token-tables")]
    cost_line("future_tokens", copy_cost(&*tables.future_tokens));
    cost_line("mesh_ids", copy_cost(&*tables.mesh_ids));
    for hat in tables.hats.values() {
        match hat {
            Hat::Broker(hat) => {
                cost_line("a broker hat's subs", copy_cost(&*hat.subs));
                cost_line("a broker hat's qabls", copy_cost(&*hat.qabls));
                #[cfg(feature = "routing-token-tables")]
                cost_line("a broker hat's tokens", copy_cost(&*hat.tokens));
            }
            Hat::Mesh(hat) => {
                cost_line("a mesh hat's net", copy_cost(&*hat.net));
                cost_line("a mesh hat's subs", copy_cost(&*hat.subs));
            }
        }
    }
}

/// The phase 0 publishers and subscribers routing Puts with no writer, while idle client faces
/// are brought up between the windows, [`BAND`] at a time to [`ADMITTED`]. Every Put reads the
/// face map for the face it came from (`classify_inbound`) and the faces it goes to, so the Puts
/// routed per second against the faces up is what a lookup in the map costs a message as the map
/// grows: the read that the face map's form is chosen against (`docs/router-table-snapshots.md`,
/// section 6.6).
#[test]
#[ignore = "a measurement of what a message's reads of the face map cost as the faces grow \
            (docs/router-table-snapshots.md, section 6.6); run with --release --ignored \
            --nocapture on a build host"]
fn the_puts_routed_measured_against_the_faces_up() {
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
    let structure = fwd.table_sharing().id();
    let mut held = Vec::new();
    for band in 0..=ADMITTED / BAND {
        let up = band * BAND;
        let routed = routed_while(&fwd, &publishers, &subscribers, || {
            std::thread::sleep(Duration::from_millis(1))
        });
        println!(
            "table-sharing: structure={structure} idle_faces={up} publishers={PUBLISHERS} \
             fan_out={FAN_OUT} puts_routed_per_s={routed:.0}"
        );
        if up == ADMITTED {
            break;
        }
        for i in up..up + BAND {
            let peer = Zid::from_slice(&(0x0010_0000 + i as u32).to_be_bytes());
            let (actions, sink) = client(peer);
            fwd.register(FaceId(10_000 + i), &actions);
            held.push((actions, sink));
        }
    }
    // The control: each band is also a later window, after millions more Puts were routed and
    // their frames recorded and let go. With every idle face gone, a rate back near the first
    // window's is the faces' doing; a rate that stays where the last band left it is the
    // sequence of windows', and the bands say nothing of the face map.
    for i in 0..ADMITTED {
        fwd.deregister(FaceId(10_000 + i));
    }
    drop(held);
    let routed = routed_while(&fwd, &publishers, &subscribers, || {
        std::thread::sleep(Duration::from_millis(1))
    });
    println!(
        "table-sharing: structure={structure} idle_faces=0 after_all_left publishers={PUBLISHERS} \
         fan_out={FAN_OUT} puts_routed_per_s={routed:.0}"
    );
}
