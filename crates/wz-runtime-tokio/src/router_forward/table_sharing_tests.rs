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
use crate::runtime_impl::{TokioRuntime, TokioTime};
use crate::session_glue::{new_session_actions, BoxedLinkDriver, LinkSendOutcome};
use crate::Reliability;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

/// A link that counts the frames it is handed and keeps none of them.
///
/// The instruments ask a face's link one question, how many frames it was given. A recorder that
/// keeps each frame's bytes answers it too, but it also allocates and keeps every frame, some 18
/// million of them in one window at a million and a half Puts a second to four subscribers, each
/// behind its subscriber's one lock. Over that recorder the Puts routed fell from window to window
/// and stayed fallen once every idle face had left; over this link they do not fall
/// (`docs/router-table-snapshots.md`, section 6.6). What the router does with a frame ends where
/// the link is handed it, so the link here does nothing else.
#[derive(Default)]
struct CountingLinkDriver {
    frames: AtomicUsize,
}

impl CountingLinkDriver {
    /// The frames handed over since the last [`reset`](Self::reset).
    fn frame_count(&self) -> usize {
        self.frames.load(Ordering::Acquire)
    }

    fn reset(&self) {
        self.frames.store(0, Ordering::Release);
    }
}

impl BoxedLinkDriver for CountingLinkDriver {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        self.frames.fetch_add(1, Ordering::AcqRel);
        LinkSendOutcome::Sent
    }
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

/// A client face whose remote is `peer`, and the count of what its link was given.
fn client(peer: Zid) -> (Arc<SessionLinkActions>, Arc<CountingLinkDriver>) {
    let sink = Arc::new(CountingLinkDriver::default());
    let actions = new_session_actions(
        sink.clone(),
        wz_runtime_tokio_test_support::fixture_session_init_params(),
        TokioTime::new(),
    );
    TokioRuntime::with_mutex_mut(&actions.remote_peer_zid, |s| {
        *s = Some(peer.as_slice().to_vec())
    });
    TokioRuntime::with_mutex_mut(&actions.peer_whatami, |s| *s = Some(0b10));
    (actions, sink)
}

/// `message` brought by `face`, as the face's drive hands a frame to the router.
fn bring(fwd: &RouterForwarder, face: FaceId, message: NetworkMessage) {
    bring_frame(fwd, face, vec![message]);
}

/// `messages` brought by `face` in one frame, in their order.
fn bring_frame(fwd: &RouterForwarder, face: FaceId, messages: Vec<NetworkMessage>) {
    let outcome = DriverLoopOutcome::FramePayload {
        priority: Priority::DEFAULT,
        reliable: true,
        sn: 0,
        messages,
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
    let off_version_before = fwd.tables.read().routes_asked_off_version();
    let alone = routed_while(&fwd, &publishers, &subscribers, || {
        std::thread::sleep(Duration::from_millis(1))
    });
    let off_version_alone = fwd.tables.read().routes_asked_off_version();

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
    let off_version_together = fwd.tables.read().routes_asked_off_version();
    println!(
        "table-sharing: routes asked at a draft's inputs (asked, computed) with no writer {:?}, \
         with the writer {:?}",
        since(off_version_alone, off_version_before),
        since(off_version_together, off_version_alone),
    );
}

/// What a pair of counts `(asked, computed)` rose by from `was` to `now`.
fn since(now: (usize, usize), was: (usize, usize)) -> (usize, usize) {
    (now.0 - was.0, now.1 - was.1)
}

/// The Puts a second the `publishers` route to the `subscribers` for [`WINDOW`], each from a
/// thread of its own without pause, while this thread calls `meanwhile` again and again. Asserts
/// the population: every Put routed once and given to every subscriber.
fn routed_while(
    fwd: &Arc<RouterForwarder>,
    publishers: &[FaceId],
    subscribers: &[Arc<CountingLinkDriver>],
    meanwhile: impl FnMut(),
) -> f64 {
    routed_and_spent_while(fwd, publishers, subscribers, meanwhile).puts_per_s
}

/// What a window of [`routed_and_spent_while`] measured.
struct Routed {
    /// The Puts routed a second.
    puts_per_s: f64,
    /// The time the publishers' threads ran on a core, over the Puts they routed: what a Put
    /// cost the readers, whatever share of the host they were given. On a host other work also
    /// runs on, the Puts a second move with that work and this does not.
    cpu_ns_per_put: f64,
}

/// The time the calling thread has run on a core, in nanoseconds: the first field of its
/// `schedstat` (`Documentation/scheduler/sched-stats.rst`).
fn thread_cpu_ns() -> u64 {
    let stat = std::fs::read_to_string("/proc/thread-self/schedstat")
        .expect("the thread's schedstat (a Linux host)");
    stat.split_whitespace()
        .next()
        .and_then(|ns| ns.parse().ok())
        .expect("schedstat starts with the time run in nanoseconds")
}

/// [`routed_while`], with the time the publishers' threads ran on a core.
fn routed_and_spent_while(
    fwd: &Arc<RouterForwarder>,
    publishers: &[FaceId],
    subscribers: &[Arc<CountingLinkDriver>],
    mut meanwhile: impl FnMut(),
) -> Routed {
    for sink in subscribers {
        sink.reset();
    }
    let seen_before = fwd.data_seen();
    let routing = Arc::new(AtomicBool::new(true));
    let (done, finished) = std::sync::mpsc::channel();
    let mut threads = Vec::new();
    for &id in publishers {
        let (fwd, routing, done) = (Arc::clone(fwd), Arc::clone(&routing), done.clone());
        // Named, so that a profile of the run can be read for the readers alone
        // (`perf report --comm wz-publisher`).
        let publisher = std::thread::Builder::new().name("wz-publisher".into());
        threads.push(
            publisher
                .spawn(move || {
                    let mut sent = 0usize;
                    let ran_before = thread_cpu_ns();
                    while routing.load(Ordering::Acquire) {
                        let put =
                            wz_session_core::push_build::build_push_literal("demo/data", b"x")
                                .expect("build push");
                        bring(&fwd, id, NetworkMessage::Push(Box::new(put)));
                        sent += 1;
                    }
                    let ran = thread_cpu_ns() - ran_before;
                    done.send((sent, ran)).expect("the test is waiting");
                })
                .expect("a publisher's thread starts"),
        );
    }
    drop(done);

    let began = Instant::now();
    while began.elapsed() < WINDOW {
        meanwhile();
    }
    routing.store(false, Ordering::Release);
    let window = began.elapsed();

    let (mut total, mut ran) = (0usize, 0u64);
    for _ in publishers {
        let (sent, spent) = finished
            .recv_timeout(Duration::from_secs(60))
            .expect("every publisher finishes: one that does not is waiting for the tables");
        total += sent;
        ran += spent;
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
    Routed {
        puts_per_s: total as f64 / window.as_secs_f64(),
        cpu_ns_per_put: ran as f64 / total.max(1) as f64,
    }
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

/// What a writer's version costs the readers, apart from what its declaration does to the routes.
///
/// The phase 0 publishers and subscribers route Puts through windows of five kinds, in turn:
///
/// - `none`: no writer;
/// - `declaring`: a writer that declares and undeclares subscriptions of keys nobody puts to, as
///   in phase 0 but with no face coming up or going (a transition waits for a grace period);
/// - `declaring_elsewhere`: the same writer declaring into a second router that nobody routes
///   through, so that the readers share the host with the writer's work and not its tables;
/// - `unchanged_paced`: a writer that publishes versions which change nothing, at the rate the
///   declaring writer published in the window before, spinning between them so that it holds a
///   core as the declaring writer does;
/// - `unchanged`: the same writer without the pacing.
///
/// A version that changes nothing moves no input of a route, so what the readers lose under it is
/// what loading, holding and letting go of versions costs them, with the writer's own thread on
/// the host. What the declaring writer costs them beyond that, at the same rate of versions, is
/// what its declarations do: the path copies the versions are made of, and the routes and the
/// route caches they reach. The routes the readers computed in each window are counted beside it:
/// keys nobody puts to retire no route the Puts are served from, so the count is expected to stay
/// at zero, and a window where it does not measured something else. So are the routes asked at a
/// draft's inputs, and computed then: how often the writer routes through its own draft, with the
/// draft route memos off and on (section 6.9).
#[test]
#[ignore = "a measurement of what a busy writer's versions cost the readers \
            (docs/router-table-snapshots.md, section 6.7); run with --release --ignored \
            --nocapture on a build host"]
fn the_readers_under_a_busy_writer_measured_by_what_the_writes_change() {
    // `WZ_DRAFT_ROUTE_MEMOS` names the values of the draft route memos to measure
    // (docs/router-table-snapshots.md, section 6.9), `off` by default: `off,on` builds a scene of
    // each and runs each window kind in one, then in the other, so that the two values of one
    // kind are measured next to each other in time.
    let scenes: Vec<BusyScene> = std::env::var("WZ_DRAFT_ROUTE_MEMOS")
        .unwrap_or_else(|_| "off".into())
        .split(',')
        .map(|value| match value {
            "off" => BusyScene::new(false),
            "on" => BusyScene::new(true),
            other => panic!("WZ_DRAFT_ROUTE_MEMOS names {other:?}, which is neither off nor on"),
        })
        .collect();

    // `WZ_WRITER_WINDOWS` names the kinds to run, in order (all five by default), and
    // `WZ_WRITER_ROUNDS` how many times (3): a profile is taken of one kind at a time. The paced
    // writer keeps the declaring writer's last rate, or `WZ_WRITER_RATE` (20,000 a second) when
    // no declaring window ran before it.
    let kinds = std::env::var("WZ_WRITER_WINDOWS")
        .unwrap_or_else(|_| "none,declaring,declaring_elsewhere,unchanged_paced,unchanged".into());
    let rounds: usize = std::env::var("WZ_WRITER_ROUNDS")
        .ok()
        .and_then(|r| r.parse().ok())
        .unwrap_or(3);
    let first_rate: f64 = std::env::var("WZ_WRITER_RATE")
        .ok()
        .and_then(|r| r.parse().ok())
        .unwrap_or(20_000.0);
    let mut rates = vec![first_rate; scenes.len()];
    let mut round = 0u64;
    for _ in 0..rounds {
        for kind in kinds.split(',') {
            for (scene, rate) in scenes.iter().zip(rates.iter_mut()) {
                match kind {
                    "none" => {
                        scene.window(kind, &mut || std::thread::sleep(Duration::from_millis(1)));
                    }
                    "declaring" => {
                        *rate = scene.window(kind, &mut || {
                            let key = format!("demo/churn/{}", round % 64);
                            round += 1;
                            bring(&scene.fwd, WRITER_FACE, declare_sub(&key));
                            bring(&scene.fwd, WRITER_FACE, undeclare_sub(&key));
                        });
                    }
                    "declaring_elsewhere" => {
                        scene.window(kind, &mut || {
                            let key = format!("demo/churn/{}", round % 64);
                            round += 1;
                            bring(&scene.elsewhere, WRITER_FACE, declare_sub(&key));
                            bring(&scene.elsewhere, WRITER_FACE, undeclare_sub(&key));
                        });
                    }
                    "unchanged_paced" => {
                        let interval = Duration::from_secs_f64(1.0 / rate.max(1.0));
                        let mut next = Instant::now();
                        scene.window(kind, &mut || {
                            if Instant::now() >= next {
                                next += interval;
                                scene.fwd.tables.write().publish();
                            }
                        });
                    }
                    "unchanged" => {
                        scene.window(kind, &mut || scene.fwd.tables.write().publish());
                    }
                    other => panic!("WZ_WRITER_WINDOWS names {other:?}, which is not a window"),
                }
            }
        }
    }
}

/// The face the busy writer declares on, in both routers of a [`BusyScene`].
const WRITER_FACE: FaceId = FaceId(200);

/// The routers of the busy-writer instrument for one value of the draft route memos: the routed
/// one, with the phase 0 publishers and subscribers and the writer's face, and one nobody routes
/// through, with the writer's face alone. The `declaring_elsewhere` writer does the declaring
/// writer's work in the second, so that the readers share the host with that work and not the
/// tables it writes.
struct BusyScene {
    fwd: Arc<RouterForwarder>,
    elsewhere: RouterForwarder,
    publishers: Vec<FaceId>,
    subscribers: Vec<Arc<CountingLinkDriver>>,
    draft_route_memos: bool,
    /// The faces' sessions, held for as long as the routers are.
    _faces: Vec<Arc<SessionLinkActions>>,
}

impl BusyScene {
    fn new(draft_route_memos: bool) -> Self {
        let fwd =
            Arc::new(RouterForwarder::new(zid(0x01)).with_draft_route_memos(draft_route_memos));
        let mut faces = Vec::new();
        let mut subscribers = Vec::new();
        for s in 0..FAN_OUT {
            let (actions, sink) = client(zid(0xC0 + s as u8));
            fwd.register(FaceId(s), &actions);
            bring(&fwd, FaceId(s), declare_sub("demo/data"));
            subscribers.push(sink);
            faces.push(actions);
        }
        let mut publishers = Vec::new();
        for p in 0..PUBLISHERS {
            let id = FaceId(100 + p);
            let (actions, _sink) = client(zid(0xA0 + p as u8));
            fwd.register(id, &actions);
            publishers.push(id);
            faces.push(actions);
        }
        let (writer, _writer_sink) = client(zid(0xE0));
        fwd.register(WRITER_FACE, &writer);
        let elsewhere = RouterForwarder::new(zid(0x02)).with_draft_route_memos(draft_route_memos);
        let (elsewhere_writer, _elsewhere_sink) = client(zid(0xE0));
        elsewhere.register(WRITER_FACE, &elsewhere_writer);
        faces.push(writer);
        faces.push(elsewhere_writer);
        Self {
            fwd,
            elsewhere,
            publishers,
            subscribers,
            draft_route_memos,
            _faces: faces,
        }
    }

    /// One window of `kind`: the Puts routed a second, the writes published a second (as the cell
    /// counts them: one message can be one write or several), the client routes computed in it,
    /// and the routes asked at a draft's inputs and computed then (section 6.9). Answers the writes
    /// published a second.
    fn window(&self, kind: &str, meanwhile: &mut dyn FnMut()) -> f64 {
        let off_version = || self.fwd.tables.read().routes_asked_off_version();
        let computes_before = self.fwd.client_route_computes();
        let off_version_before = off_version();
        let writes_before = self.fwd.tables.writes_published();
        let elsewhere_before = self.elsewhere.tables.writes_published();
        let began = Instant::now();
        let routed = routed_and_spent_while(
            &self.fwd,
            &self.publishers,
            &self.subscribers,
            &mut *meanwhile,
        );
        let seconds = began.elapsed().as_secs_f64();
        let writes_per_s = (self.fwd.tables.writes_published() - writes_before) as f64 / seconds;
        let elsewhere_per_s =
            (self.elsewhere.tables.writes_published() - elsewhere_before) as f64 / seconds;
        let computes = self.fwd.client_route_computes() - computes_before;
        let (asked, computed) = since(off_version(), off_version_before);
        println!(
            "readers-under-writer: structure={} draft_route_memos={} window={kind} \
             puts_routed_per_s={:.0} reader_cpu_ns_per_put={:.0} \
             writes_per_s={writes_per_s:.0} elsewhere_writes_per_s={elsewhere_per_s:.0} \
             client_route_computes={computes} routes_asked_off_version={asked} \
             routes_computed_off_version={computed}",
            self.fwd.table_sharing().id(),
            if self.draft_route_memos { "on" } else { "off" },
            routed.puts_per_s,
            routed.cpu_ns_per_put
        );
        writes_per_s
    }
}

/// The keys a client leg's memo keeps, in the steps the route memo instrument measures at, each
/// declared by one of [`ADMITTED`] client faces. `WZ_MEMO_KEYS` names other steps.
const MEMO_KEYS: [u64; 4] = [256, 2_048, 16_384, 65_536];

/// How many times the route memo instrument times each write that reaches no route or one.
const MEMO_WRITES: u64 = 64;

/// How many times the route memo instrument empties its memos with a key that meets every route.
const MEMO_WIDE_ROUNDS: u64 = 3;

/// The declaration id of the route memo instrument's writes, apart from the ids its keys are
/// declared under (1 and up).
const MEMO_WRITE_ID: u64 = u64::MAX;

/// Durations in nanoseconds: the count, the median, the 99th percentile and the longest.
fn nanos_line(samples: &mut [Duration]) -> String {
    samples.sort_unstable();
    let at = |q: usize| {
        let index = (samples.len() * q / 100).min(samples.len().saturating_sub(1));
        samples.get(index).map_or(0, Duration::as_nanos)
    };
    format!(
        "n={} p50={}ns p99={}ns max={}ns",
        samples.len(),
        at(50),
        at(99),
        samples.last().map_or(0, Duration::as_nanos)
    )
}

/// Route every key of `names` through `memo` as a reader of `store`'s version does, every key
/// taken as declared, and answer the time a route took.
fn route_every_key(memo: &ClientRoutes, store: &ClientSubStore, names: &[String]) -> Duration {
    let declared = |_: &str| true;
    let began = Instant::now();
    for name in names {
        std::hint::black_box(client_route(
            store,
            Cached {
                routes: memo,
                names_a_resource: &declared,
            },
            name,
            true,
            Some,
        ));
    }
    began.elapsed() / names.len().max(1) as u32
}

/// Bring `memo` to `store`'s version as the writer does before it publishes, and answer the time
/// it took. The memo it replaces is let go after the clock stops, as a retired version is let go
/// after the publish.
fn bring_timed(memo: &mut Arc<ClientRoutes>, store: &ClientSubStore) -> Duration {
    let retired = Arc::clone(memo);
    let began = Instant::now();
    bring_client_routes(memo, store);
    let took = began.elapsed();
    drop(retired);
    took
}

/// What the writer pays to leave out of a client leg's memo the routes a change reaches, found by
/// the memo's index and by a scan of every route kept, and what keeping the index costs a reader
/// that misses (`docs/router-table-snapshots.md`, section 6.9).
///
/// [`ADMITTED`] client faces declare the keys of each step of [`MEMO_KEYS`], `mesh/dev_<k>`, and
/// four memos of the client leg route every one of them: `scan`, built with no index and taking
/// each route a change reaches out one by one, as the memos were before section 6.9; `index`,
/// indexed and taking each reached route out one by one, as section 6.9 built them;
/// `index_wholesale`, which starts the new memo from the routes that stay when a change reaches
/// more than half of them, its index walked to the end; and `index_bounded`, the memo as the router
/// builds it now, whose walk for a changed key stops past half of the routes and asks the key of
/// every route instead. Every write moves the store once
/// and brings each memo to it, timed alone: a key no route meets (declared, then withdrawn), a key
/// one route meets (a second face declaring it, then withdrawing it), and `mesh/**`, which meets
/// every route. A miss is timed by routing every key into an emptied memo, and a hit by routing
/// them again. The forms take turns, each turn starting at the next, in one process. Asserts its
/// population: the memos keep the same number of routes after every write, the number the write
/// leaves.
#[test]
#[ignore = "a measurement of the routes a change reaches found by an index and by a scan \
            (docs/router-table-snapshots.md, section 6.9); run with --release --ignored \
            --nocapture on a build host"]
fn the_routes_a_change_reaches_measured_found_by_the_index_and_by_a_scan() {
    const FORMS: [&str; 4] = ["scan", "index", "index_wholesale", "index_bounded"];
    const WRITES: [&str; 3] = [
        "reaches_no_route",
        "reaches_one_route",
        "reaches_every_route",
    ];
    let order = |turn: u64| -> [usize; 4] {
        let first = (turn % 4) as usize;
        std::array::from_fn(|n| (first + n) % 4)
    };
    let steps: Vec<u64> = std::env::var("WZ_MEMO_KEYS").map_or_else(
        |_| MEMO_KEYS.to_vec(),
        |steps| {
            steps
                .split(',')
                .map(|keys| keys.parse().expect("WZ_MEMO_KEYS names numbers of keys"))
                .collect()
        },
    );
    for keys in steps {
        let names: Vec<String> = (0..keys).map(|k| format!("mesh/dev_{k}")).collect();
        let mut store = ClientSubStore::new();
        for (k, name) in (0..keys).zip(&names) {
            store.insert(FaceId(k % ADMITTED), 1 + k / ADMITTED, name, ());
        }
        let mut memos = [
            Arc::new(ClientRoutes::new().retiring_by_route()),
            Arc::new(ClientRoutes::indexed().retiring_by_route()),
            Arc::new(ClientRoutes::indexed().retiring_wholesale_unbounded()),
            Arc::new(ClientRoutes::indexed()),
        ];
        for memo in &mut memos {
            bring_client_routes(memo, &store);
        }
        let kept = |memos: &[Arc<ClientRoutes>; 4], want: usize, after: &str| {
            for (memo, form) in memos.iter().zip(FORMS) {
                assert_eq!(
                    memo.len(),
                    want,
                    "keys={keys} form={form}: kept after {after}"
                );
            }
        };
        let mut misses: [Vec<Duration>; 4] = Default::default();
        let mut hits: [Vec<Duration>; 4] = Default::default();
        let mut writes: [[Vec<Duration>; 4]; 3] = Default::default();
        let wide = "mesh/**";
        for turn in 0..MEMO_WIDE_ROUNDS {
            for (step, change) in [true, false].into_iter().enumerate() {
                for f in order(turn) {
                    misses[f].push(route_every_key(&memos[f], &store, &names));
                    hits[f].push(route_every_key(&memos[f], &store, &names));
                }
                kept(&memos, keys as usize, "routing every key");
                if change {
                    store.insert(FaceId(0), MEMO_WRITE_ID, wide, ());
                } else {
                    store.remove_id(FaceId(0), MEMO_WRITE_ID);
                }
                for f in order(turn + step as u64) {
                    writes[2][f].push(bring_timed(&mut memos[f], &store));
                }
                kept(&memos, 0, "a change of a key every route meets");
            }
        }
        for f in order(0) {
            misses[f].push(route_every_key(&memos[f], &store, &names));
        }
        for turn in 0..MEMO_WRITES {
            let face = FaceId(turn % ADMITTED);
            store.insert(face, MEMO_WRITE_ID, &format!("mesh/fresh_{turn}"), ());
            for f in order(turn) {
                writes[0][f].push(bring_timed(&mut memos[f], &store));
            }
            store.remove_id(face, MEMO_WRITE_ID);
            for f in order(turn + 1) {
                writes[0][f].push(bring_timed(&mut memos[f], &store));
            }
            kept(&memos, keys as usize, "a change of a key no route meets");

            let reached = (turn * 7_919 % keys) as usize;
            let other = FaceId((reached as u64 + 1) % ADMITTED);
            let one = std::slice::from_ref(&names[reached]);
            store.insert(other, MEMO_WRITE_ID, &names[reached], ());
            for f in order(turn) {
                writes[1][f].push(bring_timed(&mut memos[f], &store));
            }
            kept(
                &memos,
                keys as usize - 1,
                "a change of a key one route meets",
            );
            for memo in &memos {
                route_every_key(memo, &store, one);
            }
            store.remove_id(other, MEMO_WRITE_ID);
            for f in order(turn + 1) {
                writes[1][f].push(bring_timed(&mut memos[f], &store));
            }
            kept(&memos, keys as usize - 1, "its withdrawal");
            for memo in &memos {
                route_every_key(memo, &store, one);
            }
        }
        for (f, form) in FORMS.into_iter().enumerate() {
            println!(
                "route-memo: keys={keys} faces={ADMITTED} form={form} miss_per_route {} \
                 hit_per_route {}",
                nanos_line(&mut misses[f]),
                nanos_line(&mut hits[f])
            );
            for (w, write) in WRITES.into_iter().enumerate() {
                println!(
                    "route-memo: keys={keys} faces={ADMITTED} form={form} write={write} bring {}",
                    nanos_line(&mut writes[w][f])
                );
            }
        }
    }
}

/// The fan-outs the face lookup instrument measures a delivery at.
const DELIVERY_FAN_OUTS: [u64; 4] = [1, 4, 64, 512];

/// How many faces each window of the face lookup instrument visits, whatever the fan-out.
const LOOKUPS_A_WINDOW: u64 = 4_000_000;

/// How many windows of each form the face lookup instrument takes, the forms taking turns.
const LOOKUP_WINDOWS: u64 = 6;

/// What a delivery's lookups of its faces by id cost against the faces the router holds
/// (`docs/router-table-snapshots.md`, section 6.9): `by_id` is a route that names its faces by id,
/// whose every delivery finds each one in the version's face table and reads its tier, as the
/// targeted fan-out did before its routes held their faces. `held_face` is the route as the client
/// leg keeps it now ([`HeldFace`]), whose delivery reads each face's tier and its closed mark where
/// the route holds them, as `fan_out_to_held_faces` and `egress_held` do.
///
/// Client faces come up [`BAND`] at a time to [`ADMITTED`], and at each band a route of each fan-out
/// in [`DELIVERY_FAN_OUTS`] is spread over the faces up. The two forms take turns over
/// [`LOOKUP_WINDOWS`] windows each, in one process; a window delivers [`LOOKUPS_A_WINDOW`] face
/// visits. Prints the median and the spread of the nanoseconds a delivery took in each form.
/// Asserts its population: every face of the route is found, in its tier, on every delivery.
#[test]
#[ignore = "a measurement of what a delivery's lookups of its faces by id cost against the faces \
            held (docs/router-table-snapshots.md, section 6.9); run with --release --ignored \
            --nocapture on a build host"]
fn the_face_lookups_of_a_delivery_measured_against_the_faces_held() {
    const FORMS: [&str; 2] = ["by_id", "held_face"];
    let fwd = RouterForwarder::new(zid(0x01));
    let structure = fwd.table_sharing().id();
    let mut held = Vec::new();
    for band in 1..=ADMITTED / BAND {
        for i in (band - 1) * BAND..band * BAND {
            let peer = Zid::from_slice(&(0x0010_0000 + i as u32).to_be_bytes());
            let (actions, sink) = client(peer);
            fwd.register(FaceId(i), &actions);
            held.push((actions, sink));
        }
        let up = band * BAND;
        let tables = fwd.tables.read();
        for fan_out in DELIVERY_FAN_OUTS
            .into_iter()
            .filter(|fan_out| *fan_out <= up)
        {
            let ids: Vec<FaceId> = (0..fan_out).map(|n| FaceId(n * up / fan_out)).collect();
            let faces: Vec<HeldFace> = ids
                .iter()
                .map(|id| HeldFace::of(*id, &tables.faces[id]))
                .collect();
            let tier = faces[0].tier;
            let deliveries = LOOKUPS_A_WINDOW / fan_out;
            let mut took: [Vec<Duration>; 2] = Default::default();
            for window in 0..LOOKUP_WINDOWS {
                let forms = if window % 2 == 0 { [0, 1] } else { [1, 0] };
                for form in forms {
                    let mut found = 0u64;
                    let began = Instant::now();
                    for _ in 0..deliveries {
                        if form == 0 {
                            for id in std::hint::black_box(&ids) {
                                found += u64::from(
                                    tables.faces.get(id).is_some_and(|state| state.tier == tier),
                                );
                            }
                        } else {
                            for face in std::hint::black_box(&faces) {
                                found += u64::from(face.tier == tier && !face.is_closed());
                            }
                        }
                    }
                    took[form].push(began.elapsed() / deliveries as u32);
                    assert_eq!(
                        found,
                        deliveries * fan_out,
                        "every face of the route is found in its tier on every delivery"
                    );
                }
            }
            for (form, name) in FORMS.into_iter().enumerate() {
                println!(
                    "face-lookups: structure={structure} faces_up={up} fan_out={fan_out} \
                     form={name} per_delivery {}",
                    nanos_line(&mut took[form])
                );
            }
        }
    }
}

/// The totals the declaration throughput instrument runs, one after the other on one router.
const CHURN_TOTALS: [u64; 3] = [1_000, 10_000, 100_000];

/// How many declarations each frame of the throughput instrument carries, one router each: one, as
/// a client that sends each control message in a frame of its own brings them, and many, as one
/// whose control messages share the frame open while they are staged does.
const CHURN_PER_FRAME: [usize; 2] = [1, 64];

/// One client face declares a queryable and withdraws it, again and again, each time with an id
/// it has not used, as a session does that declares and undeclares beside its own traffic, in
/// frames of each size of [`CHURN_PER_FRAME`]. Prints what one declaration costs the face's thread
/// for each total, run one after the other on the same router, so a later total is measured
/// behind every declaration that came before it.
///
/// A MEASUREMENT, with one bound: the last total's cost a declaration stays within four times the
/// first's, which a cost that grows with the declarations already taken (a log, a memo or a map
/// that keeps one entry per id) breaks by far, and a host's noise does not. The population is
/// asserted too: every queryable declared was withdrawn.
#[test]
#[ignore = "a measurement of the declarations one face can bring the router a second; run with \
            --release --ignored --nocapture on a build host"]
fn the_declarations_of_one_face_measured_against_their_count() {
    for per_frame in CHURN_PER_FRAME {
        let fwd = RouterForwarder::new(zid(0x01));
        let face = FaceId(1);
        let (actions, _sink) = client(zid(0xC1));
        fwd.register(face, &actions);
        let mut last_id = 0u64;
        let mut costs = Vec::new();
        for total in CHURN_TOTALS {
            let began = Instant::now();
            let mut frame = Vec::with_capacity(per_frame);
            for _ in 0..total / 2 {
                last_id += 1;
                let declare = build_declare_queryable_with_id_info(
                    last_id,
                    "demo/beside/admin",
                    QueryableInfo::local(false),
                )
                .expect("build queryable");
                for message in [declare, build_undeclare_queryable(last_id)] {
                    frame.push(NetworkMessage::Declare(Box::new(message)));
                    if frame.len() == per_frame {
                        bring_frame(&fwd, face, std::mem::take(&mut frame));
                    }
                }
            }
            if !frame.is_empty() {
                bring_frame(&fwd, face, frame);
            }
            let cost = began.elapsed() / u32::try_from(total).expect("a total fits");
            println!(
                "declaration-churn: structure={} per_frame={per_frame} declarations={total} \
                 per_declaration={}ns per_second={:.0}",
                fwd.table_sharing().id(),
                cost.as_nanos(),
                1e9 / cost.as_nanos().max(1) as f64,
            );
            assert_eq!(
                fwd.client_queryables_seen(),
                0,
                "every queryable declared was withdrawn"
            );
            costs.push(cost);
        }
        let (first, last) = (costs[0], costs[costs.len() - 1]);
        assert!(
            last <= first * 4,
            "a declaration in frames of {per_frame} costs {last:?} after {} of them and \
             {first:?} after {}: the cost grows with the declarations already taken",
            CHURN_TOTALS.iter().sum::<u64>(),
            CHURN_TOTALS[0],
        );
    }
}

/// The face that subscribes in the tests of a frame's writes.
const SUBSCRIBER: FaceId = FaceId(1);

/// The face that puts in the tests of a frame's writes.
const PUBLISHER: FaceId = FaceId(2);

/// A router with two client faces, [`SUBSCRIBER`] and [`PUBLISHER`]; the subscriber's link, and
/// both faces' sessions, which the test holds for as long as the router.
fn subscriber_and_publisher() -> (
    RouterForwarder,
    Arc<CountingLinkDriver>,
    [Arc<SessionLinkActions>; 2],
) {
    let fwd = RouterForwarder::new(zid(0x01));
    let (subscriber, sink) = client(zid(0xC1));
    let (publisher, _) = client(zid(0xC2));
    fwd.register(SUBSCRIBER, &subscriber);
    fwd.register(PUBLISHER, &publisher);
    (fwd, sink, [subscriber, publisher])
}

/// Declarations, withdrawals by id and a redeclaration, in an order whose result depends on it:
/// `demo/b` (id 2) and `demo/a` (id 4, declared again after id 1 withdrew it) stand at the end,
/// and `demo/c` came and went.
fn declarations_in_order() -> Vec<NetworkMessage> {
    let declare = |id: u64, keyexpr: &str| {
        NetworkMessage::Declare(Box::new(
            build_declare_subscriber(id, 0, Some(keyexpr)).expect("build declare"),
        ))
    };
    let undeclare = |id: u64| NetworkMessage::Declare(Box::new(build_undeclare_subscriber(id)));
    vec![
        declare(1, "demo/a"),
        declare(2, "demo/b"),
        undeclare(1),
        declare(3, "demo/c"),
        undeclare(3),
        declare(4, "demo/a"),
    ]
}

/// For each of `keys`, the frames a Put of it from [`PUBLISHER`] gives the subscriber's link.
fn delivered(fwd: &RouterForwarder, sink: &CountingLinkDriver, keys: &[&str]) -> Vec<usize> {
    keys.iter()
        .map(|key| {
            sink.reset();
            let put =
                wz_session_core::push_build::build_push_literal(key, b"x").expect("build push");
            bring(fwd, PUBLISHER, NetworkMessage::Push(Box::new(put)));
            sink.frame_count()
        })
        .collect()
}

/// The declarations of one frame leave the tables as the same declarations brought one frame
/// each do, withdrawals and a redeclaration among them, and are published once and not once each.
#[test]
fn a_frame_of_declarations_leaves_the_tables_as_one_frame_each_does_and_is_published_once() {
    const KEYS: [&str; 3] = ["demo/a", "demo/b", "demo/c"];

    let (one_each, one_each_sink, _one_each_faces) = subscriber_and_publisher();
    let before = one_each.tables.writes_published();
    for message in declarations_in_order() {
        bring(&one_each, SUBSCRIBER, message);
    }
    let one_each_writes = one_each.tables.writes_published() - before;

    let (one_frame, one_frame_sink, _one_frame_faces) = subscriber_and_publisher();
    let before = one_frame.tables.writes_published();
    bring_frame(&one_frame, SUBSCRIBER, declarations_in_order());
    let one_frame_writes = one_frame.tables.writes_published() - before;

    assert_eq!(
        one_each_writes, 6,
        "a frame of one declaration is one write"
    );
    assert_eq!(
        one_frame_writes, 1,
        "the declarations of one frame share one write, published once"
    );
    assert_eq!(
        one_each.client_subs_seen(),
        2,
        "demo/b and demo/a declared again stand"
    );
    assert_eq!(
        one_frame.client_subs_seen(),
        one_each.client_subs_seen(),
        "one frame holds what one frame each holds"
    );
    assert_eq!(
        delivered(&one_each, &one_each_sink, &KEYS),
        [1, 1, 0],
        "one frame each: demo/a and demo/b reach the subscriber, demo/c does not"
    );
    assert_eq!(
        delivered(&one_frame, &one_frame_sink, &KEYS),
        [1, 1, 0],
        "one frame: the same, so the frame's order was kept"
    );
}

/// A frame of more declarations than one write holds takes the tables once for each
/// [`TABLE_WRITES_PER_GUARD`] of them, and every declaration is taken.
#[test]
fn a_frame_of_more_declarations_than_a_write_holds_is_published_once_per_bound() {
    let (fwd, _sink, _faces) = subscriber_and_publisher();
    let count = 2 * TABLE_WRITES_PER_GUARD + 1;
    let frame = (1..=count as u64)
        .map(|id| {
            NetworkMessage::Declare(Box::new(
                build_declare_subscriber(id, 0, Some(format!("demo/bound/{id}").as_str()))
                    .expect("build declare"),
            ))
        })
        .collect();
    let before = fwd.tables.writes_published();
    bring_frame(&fwd, SUBSCRIBER, frame);
    assert_eq!(
        fwd.tables.writes_published() - before,
        3,
        "two full writes and one for the declaration past them"
    );
    assert_eq!(
        fwd.client_subs_seen(),
        count,
        "every declaration of the frame was taken"
    );
}

/// A Put between declarations of one frame is routed by the declaration before it, which was
/// published first, and ends the write: the declaration after it takes the tables again.
#[test]
fn a_put_between_declarations_of_one_frame_is_routed_by_the_one_before_it() {
    let (fwd, sink, _faces) = subscriber_and_publisher();
    bring(&fwd, SUBSCRIBER, declare_sub("demo/a"));
    sink.reset();
    let alias = |id: wz_session_core::wire_id::ExprId, keyexpr: &str| {
        NetworkMessage::Declare(Box::new(
            wz_session_core::declare_build::build_declare_kexpr(id, keyexpr).expect("kexpr"),
        ))
    };
    let put =
        wz_session_core::push_build::build_push_aliased(5, None, b"x").expect("build aliased push");
    let before = fwd.tables.writes_published();
    bring_frame(
        &fwd,
        PUBLISHER,
        vec![
            alias(5, "demo/a"),
            NetworkMessage::Push(Box::new(put)),
            alias(6, "demo/b"),
        ],
    );
    assert_eq!(
        sink.frame_count(),
        1,
        "the Put named the alias the frame declared before it, and reached the subscriber"
    );
    assert_eq!(
        fwd.tables.writes_published() - before,
        2,
        "the Put ended the first write, and the declaration after it took a second"
    );
}
