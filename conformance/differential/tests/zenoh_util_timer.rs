// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-util`, the timer (the last slice of the crate): upstream's crate (`up_util`) and wz's
//! (`wz_util`) given the same events to run, results equal as text.
//!
//! The timer runs on the clock, so what is compared is what does not depend on the instant: the
//! ORDER the events ran in, what ran and what did not, and the `Debug` text of each object in each
//! state. Every wait asks a condition (an event ran) instead of sleeping a time where the time
//! would be a race, and the time a thing must NOT happen in is long against the intervals.
//!
//! * THE ORDER: events added in no order, and events added to a timer that is waiting for a later
//!   one, run by the time they are due;
//! * ONCE, PERIODIC, DEFUSED: an event that runs once, one defused before and after it ran, one that
//!   repeats and is defused; the fuse and the handle (`Debug` of the handle says whether the event
//!   is alive) and the `Debug` of the event;
//! * STOP AND START: events due while the timer is stopped run when it starts again, an event added
//!   while it is stopped is lost, stopping and starting twice change nothing, in the synchronous and
//!   the asynchronous forms and with the task spawned blocking;
//! * THE ORDERING OF EVENTS: equality is the time, and the order is the reverse of it (a min-heap);
//! * OUTSIDE A RUNTIME: a timer made where there is no runtime panics, with the same words.
//!
//! Upstream runs an event through `Arc::get_mut(..).unwrap()`, which is sure of being the only owner
//! of the future only if nobody cloned the event, and `TimedEvent` is `Clone`. A clone that is alive
//! when the event is due makes the unwrap panic in the task of the timer, which ends it, and every
//! event that was still waiting, and every one added later, is lost without a word. It is a class,
//! built by hand, counted and held on both sides: wz drops the event whose future is shared with a
//! message and the timer goes on.

use std::{
    panic::{catch_unwind, set_hook, take_hook, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, MutexGuard, Once,
    },
};

static LOCK: Mutex<()> = Mutex::new(());

/// The tests run on the clock and on threads of their own, so they take turns.
fn serial() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

static QUIET: AtomicBool = AtomicBool::new(false);

fn quiet_hook() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = take_hook();
        set_hook(Box::new(move |info| {
            if !QUIET.load(Ordering::SeqCst) {
                previous(info)
            }
        }));
    });
}

/// Runs `f` with the panic report off (the panic of a thread of the timer is a result here, and the
/// report would be noise): the text of the panic, or `None`.
fn panic_text<T>(f: impl FnOnce() -> T) -> Option<String> {
    quiet_hook();
    QUIET.store(true, Ordering::SeqCst);
    let out = catch_unwind(AssertUnwindSafe(f));
    QUIET.store(false, Ordering::SeqCst);
    match out {
        Ok(_) => None,
        Err(payload) => Some(
            payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "?".to_string()),
        ),
    }
}

macro_rules! timer_cases {
    ($m:ident, $u:ident) => {
        mod $m {
            use std::{
                sync::{
                    atomic::{AtomicUsize, Ordering},
                    Arc, Mutex,
                },
                time::{Duration, Instant},
            };

            use async_trait::async_trait;
            use tokio::runtime::{Builder, Runtime};
            use $u::{Timed, TimedEvent, Timer};

            use super::{panic_text, QUIET};

            /// An event that counts its runs.
            pub struct Count(pub Arc<AtomicUsize>);

            #[async_trait]
            impl Timed for Count {
                async fn run(&mut self) {
                    self.0.fetch_add(1, Ordering::SeqCst);
                }
            }

            /// An event that says its name when it runs.
            pub struct Say(pub Arc<Mutex<Vec<&'static str>>>, pub &'static str);

            #[async_trait]
            impl Timed for Say {
                async fn run(&mut self) {
                    self.0.lock().unwrap().push(self.1);
                }
            }

            fn runtime() -> Runtime {
                Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .unwrap()
            }

            fn ms(n: u64) -> Duration {
                Duration::from_millis(n)
            }

            /// Asks the condition every few milliseconds until it holds or the time is out.
            async fn until(timeout_ms: u64, mut cond: impl FnMut() -> bool) -> bool {
                let end = Instant::now() + ms(timeout_ms);
                while Instant::now() < end {
                    if cond() {
                        return true;
                    }
                    tokio::time::sleep(ms(5)).await;
                }
                cond()
            }

            fn counter() -> Arc<AtomicUsize> {
                Arc::new(AtomicUsize::new(0))
            }

            fn n(c: &Arc<AtomicUsize>) -> usize {
                c.load(Ordering::SeqCst)
            }

            /// The part of the `Debug` of an event that is not the instant.
            fn debug_of(ev: &TimedEvent) -> String {
                let s = format!("{ev:?}");
                match s.split_once(", period") {
                    Some((_, rest)) => format!("TimedEvent {{ period{rest}"),
                    None => s,
                }
            }

            /// Events added in no order, then events added to a timer that waits for a later one.
            pub fn order() -> Vec<String> {
                runtime().block_on(async {
                    let timer = Timer::new(false);
                    let log = Arc::new(Mutex::new(Vec::new()));
                    let base = Instant::now();
                    for (name, at) in [("c", 120), ("a", 30), ("d", 150), ("b", 60)] {
                        timer
                            .add_async(TimedEvent::once(base + ms(at), Say(log.clone(), name)))
                            .await;
                    }
                    until(2000, || log.lock().unwrap().len() == 4).await;
                    let first = format!("{:?}", log.lock().unwrap());

                    let log2 = Arc::new(Mutex::new(Vec::new()));
                    let base = Instant::now();
                    // The timer waits for the one at +400, and the one at +100 is added after.
                    timer
                        .add_async(TimedEvent::once(base + ms(400), Say(log2.clone(), "z")))
                        .await;
                    tokio::time::sleep(ms(30)).await;
                    timer
                        .add_async(TimedEvent::once(base + ms(100), Say(log2.clone(), "y")))
                        .await;
                    until(2000, || log2.lock().unwrap().len() == 2).await;
                    let second = format!("{:?}", log2.lock().unwrap());

                    // An event that is already due runs at once.
                    let log3 = Arc::new(Mutex::new(Vec::new()));
                    let past = Instant::now();
                    timer
                        .add_async(TimedEvent::once(past, Say(log3.clone(), "now")))
                        .await;
                    until(2000, || log3.lock().unwrap().len() == 1).await;
                    vec![first, second, format!("{:?}", log3.lock().unwrap())]
                })
            }

            /// An event that runs once, one defused before it runs, one defused after, the fuse and
            /// the handle.
            pub fn once_and_defuse() -> Vec<String> {
                runtime().block_on(async {
                    let timer = Timer::new(false);
                    let mut out = Vec::new();

                    let c = counter();
                    let ev = TimedEvent::once(Instant::now() + ms(40), Count(c.clone()));
                    let handle = ev.get_handle();
                    out.push(format!("fresh fused={} handle={handle:?}", ev.is_fused()));
                    out.push(debug_of(&ev));
                    timer.add_async(ev).await;
                    until(2000, || n(&c) == 1).await;
                    tokio::time::sleep(ms(150)).await;
                    out.push(format!("ran {} handle={handle:?}", n(&c)));
                    // Defusing an event that has run, and one whose event is gone, is nothing.
                    handle.clone().defuse();
                    handle.defuse();

                    let d = counter();
                    let ev = TimedEvent::once(Instant::now() + ms(80), Count(d.clone()));
                    let handle = ev.get_handle();
                    let again = ev.get_handle();
                    handle.defuse();
                    out.push(format!(
                        "defused fused={} handle={again:?} {}",
                        ev.is_fused(),
                        debug_of(&ev)
                    ));
                    timer.add_async(ev).await;
                    tokio::time::sleep(ms(300)).await;
                    out.push(format!("defused ran {}", n(&d)));
                    out
                })
            }

            /// A periodic event runs again and again until it is defused.
            pub fn periodic() -> Vec<String> {
                runtime().block_on(async {
                    let timer = Timer::new(false);
                    let c = counter();
                    let ev = TimedEvent::periodic(ms(40), Count(c.clone()));
                    let handle = ev.get_handle();
                    let shown = debug_of(&ev);
                    timer.add_async(ev).await;
                    // A periodic event waits one interval before its first run: this one has a long
                    // interval and has not run when the short one has run three times.
                    let long = counter();
                    let slow = TimedEvent::periodic(ms(1500), Count(long.clone()));
                    let slow_handle = slow.get_handle();
                    timer.add_async(slow).await;
                    let three = until(1000, || n(&c) >= 3).await;
                    let waited = n(&long);
                    slow_handle.defuse();
                    handle.clone().defuse();
                    handle.defuse();
                    // Let a run that had begun end, then no more may come.
                    tokio::time::sleep(ms(200)).await;
                    let after = n(&c);
                    tokio::time::sleep(ms(300)).await;
                    vec![
                        shown,
                        format!(
                            "three={three} first run waited={} stopped={}",
                            waited == 0,
                            n(&c) == after
                        ),
                    ]
                })
            }

            /// Stop and start, in the synchronous and the asynchronous forms.
            pub fn stop_start() -> Vec<String> {
                runtime().block_on(async {
                    let mut out = Vec::new();
                    let mut timer = Timer::new(false);
                    out.push(format!("{timer:?}"));

                    // An event due while the timer is stopped runs when it is started.
                    let c = counter();
                    timer.add(TimedEvent::once(Instant::now() + ms(150), Count(c.clone())));
                    // The timer takes the event from the channel into its heap, which stays when the
                    // timer is stopped. An event still in the channel when it is stopped is lost with
                    // the channel, in both crates, and what a stop that follows an add at once finds
                    // is a race of the two: so the stop waits for the add to be taken.
                    tokio::time::sleep(ms(40)).await;
                    timer.stop();
                    timer.stop();
                    out.push(format!("stopped {timer:?}"));
                    tokio::time::sleep(ms(300)).await;
                    out.push(format!("while stopped {}", n(&c)));
                    timer.start(false);
                    timer.start(false);
                    out.push(format!("started {timer:?}"));
                    let ran = until(3000, || n(&c) == 1).await;
                    tokio::time::sleep(ms(100)).await;
                    out.push(format!("after start {ran} {}", n(&c)));

                    // An event added while the timer is stopped is lost.
                    timer.stop();
                    let d = counter();
                    timer.add(TimedEvent::once(Instant::now() + ms(20), Count(d.clone())));
                    timer.start(false);
                    tokio::time::sleep(ms(300)).await;
                    out.push(format!("added while stopped {}", n(&d)));

                    // The same, asynchronously and with the task spawned blocking.
                    timer.stop_async().await;
                    out.push(format!("async stopped {timer:?}"));
                    timer.start_async(true).await;
                    let e = counter();
                    timer
                        .add_async(TimedEvent::once(Instant::now() + ms(30), Count(e.clone())))
                        .await;
                    let ran = until(3000, || n(&e) == 1).await;
                    out.push(format!("spawned blocking {ran} {}", n(&e)));
                    out
                })
            }

            /// A timer made with the task spawned blocking, a default one, and a clone.
            pub fn made() -> Vec<String> {
                runtime().block_on(async {
                    let mut out = Vec::new();
                    for (label, timer) in [
                        ("blocking", Timer::new(true)),
                        ("default", Timer::default()),
                        ("plain", Timer::new(false)),
                    ] {
                        let c = counter();
                        timer.add(TimedEvent::once(Instant::now() + ms(30), Count(c.clone())));
                        let cloned = timer.clone();
                        let d = counter();
                        cloned.add(TimedEvent::once(Instant::now() + ms(60), Count(d.clone())));
                        let both = until(3000, || n(&c) == 1 && n(&d) == 1).await;
                        out.push(format!("{label} {both} {timer:?} {cloned:?}"));
                    }
                    out
                })
            }

            /// A timer made outside a runtime panics, with these words.
            pub fn outside_runtime() -> Vec<String> {
                vec![
                    format!("{:?}", panic_text(|| Timer::new(false))),
                    format!("{:?}", panic_text(|| Timer::new(true))),
                    format!("{:?}", panic_text(Timer::default)),
                ]
            }

            /// The equality and the order of events, and the order a heap gives them in.
            pub fn ordering() -> Vec<String> {
                let base = Instant::now();
                let ev = |at: u64| TimedEvent::once(base + ms(at), Count(counter()));
                let mut out = Vec::new();
                for (a, b) in [(10, 20), (20, 10), (10, 10), (0, 5000)] {
                    let (x, y) = (ev(a), ev(b));
                    out.push(format!(
                        "{a} {b}: eq {} cmp {:?} partial {:?} lt {} gt {}",
                        x == y,
                        x.cmp(&y),
                        x.partial_cmp(&y),
                        x < y,
                        x > y
                    ));
                }
                // Equal only by the time: a periodic event and a once event of the same instant.
                let periodic = TimedEvent::periodic(ms(10), Count(counter()));
                let clone = periodic.clone();
                out.push(format!("clone eq {}", periodic == clone));
                // The order a heap gives them in: each popped event is told apart from references
                // of the same instants by the equality, which is the time.
                let offsets = [10u64, 20, 30, 40, 50];
                let references: Vec<TimedEvent> = offsets.iter().map(|at| ev(*at)).collect();
                let mut heap = std::collections::BinaryHeap::new();
                for at in [30u64, 10, 50, 20, 40] {
                    heap.push(ev(at));
                }
                let mut order = Vec::new();
                while let Some(e) = heap.pop() {
                    let which = references.iter().position(|r| *r == e).unwrap();
                    order.push(format!("{}ms", offsets[which]));
                }
                out.push(order.join(","));
                out
            }

            /// A clone of an event that is alive when the event is due, and what the timer does
            /// after it: the events added before and after it.
            pub fn shared_future() -> Vec<String> {
                QUIET.store(true, Ordering::SeqCst);
                let out = runtime().block_on(async {
                    let timer = Timer::new(false);
                    let (a, b, later) = (counter(), counter(), counter());
                    let ev = TimedEvent::once(Instant::now() + ms(40), Count(a.clone()));
                    // The clone is kept: the future of the event is shared when it is due.
                    let kept = ev.clone();
                    timer.add_async(ev).await;
                    timer
                        .add_async(TimedEvent::once(Instant::now() + ms(200), Count(b.clone())))
                        .await;
                    // Long past the second event.
                    tokio::time::sleep(ms(700)).await;
                    timer
                        .add_async(TimedEvent::once(
                            Instant::now() + ms(20),
                            Count(later.clone()),
                        ))
                        .await;
                    tokio::time::sleep(ms(300)).await;
                    drop(kept);
                    vec![format!(
                        "shared={} waiting={} added later={}",
                        n(&a),
                        n(&b),
                        n(&later)
                    )]
                });
                QUIET.store(false, Ordering::SeqCst);
                out
            }

            /// An event cloned and the clone dropped before it is due runs, since the future is
            /// not shared when it matters.
            pub fn clone_dropped() -> Vec<String> {
                runtime().block_on(async {
                    let timer = Timer::new(false);
                    let c = counter();
                    let ev = TimedEvent::once(Instant::now() + ms(150), Count(c.clone()));
                    let clone = ev.clone();
                    timer.add_async(ev).await;
                    drop(clone);
                    let ran = until(3000, || n(&c) == 1).await;
                    vec![format!("{ran} {}", n(&c))]
                })
            }
        }
    };
}

timer_cases!(up, up_util);
timer_cases!(wz, wz_util);

#[test]
fn both_crates_run_events_in_the_order_they_are_due() {
    let _g = serial();
    let (u, w) = (up::order(), wz::order());
    assert_eq!(u, w);
    assert_eq!(u[0], "[\"a\", \"b\", \"c\", \"d\"]");
    assert_eq!(u[1], "[\"y\", \"z\"]");
    assert_eq!(u[2], "[\"now\"]");
}

#[test]
fn both_crates_run_an_event_once_and_keep_a_defused_one_from_running() {
    let _g = serial();
    let (u, w) = (up::once_and_defuse(), wz::once_and_defuse());
    assert_eq!(u, w);
    assert!(
        u[0].starts_with("fresh fused=true handle=TimedHandle { is_live: true }"),
        "{u:?}"
    );
    // The event is dropped after it ran, so the handle says it is not alive.
    assert!(
        u[2].contains("ran 1") && u[2].contains("is_live: false"),
        "{u:?}"
    );
    assert!(u[3].starts_with("defused fused=false"), "{u:?}");
    assert_eq!(u[4], "defused ran 0");
}

#[test]
fn both_crates_repeat_a_periodic_event_until_it_is_defused() {
    let _g = serial();
    let (u, w) = (up::periodic(), wz::periodic());
    assert_eq!(u, w);
    assert_eq!(u[1], "three=true first run waited=true stopped=true");
    assert!(u[0].contains("period: Some(40ms)"), "{u:?}");
}

#[test]
fn both_crates_stop_and_start_the_timer_alike() {
    let _g = serial();
    let (u, w) = (up::stop_start(), wz::stop_start());
    assert_eq!(u, w);
    assert_eq!(
        u[0],
        "Timer { events: \"..\", has_sleep_sender: true, has_event_sender: true }"
    );
    assert!(u[1].contains("has_sleep_sender: false") && u[1].contains("has_event_sender: false"));
    assert_eq!(u[2], "while stopped 0");
    assert!(u[3].contains("has_sleep_sender: true"), "{u:?}");
    assert_eq!(u[4], "after start true 1");
    assert_eq!(u[5], "added while stopped 0");
    assert_eq!(u[7], "spawned blocking true 1");
}

#[test]
fn both_crates_make_a_timer_alike() {
    let _g = serial();
    let (u, w) = (up::made(), wz::made());
    assert_eq!(u, w);
    assert!(u.iter().all(|r| r.contains(" true Timer")), "{u:?}");
}

#[test]
fn both_crates_refuse_to_make_a_timer_outside_a_runtime_in_the_same_words() {
    let _g = serial();
    let (u, w) = (up::outside_runtime(), wz::outside_runtime());
    assert_eq!(u, w);
    assert!(
        u[0].starts_with("Some(") && u[0].contains("reactor"),
        "{u:?}"
    );
    // `spawn_blocking` is the first thing it asks for, which is a runtime too.
    assert!(u[1].starts_with("Some("), "{u:?}");
}

#[test]
fn both_crates_order_events_by_their_time_and_hold_them_equal_by_it() {
    let _g = serial();
    let (u, w) = (up::ordering(), wz::ordering());
    assert_eq!(u, w);
    // The order is the reverse of the time, so a heap gives the earliest first.
    assert!(u[0].contains("cmp Greater"), "{u:?}");
    assert!(u[1].contains("cmp Less"), "{u:?}");
    assert!(u[2].contains("eq true cmp Equal"), "{u:?}");
    assert_eq!(u[5], "10ms,20ms,30ms,40ms,50ms");
}

#[test]
fn a_clone_of_an_event_that_is_alive_when_it_is_due_ends_the_timer_upstream_and_not_wz() {
    let _g = serial();
    // The event whose clone is dropped before it is due is not a class: both run it.
    assert_eq!(up::clone_dropped(), wz::clone_dropped());
    assert_eq!(up::clone_dropped(), vec!["true 1".to_string()]);
    // With the clone alive, upstream's timer ends: nothing after it runs, not the event that was
    // waiting and not the one added later. wz drops the shared event and goes on.
    let (u, w) = (up::shared_future(), wz::shared_future());
    assert_eq!(
        u,
        vec!["shared=0 waiting=0 added later=0".to_string()],
        "{u:?}"
    );
    assert_eq!(
        w,
        vec!["shared=0 waiting=1 added later=1".to_string()],
        "{w:?}"
    );
}

/// The control: the comparison is on text, so a scenario that differs gives text that differs.
#[test]
fn the_comparison_sees_a_scenario_that_differs() {
    let _g = serial();
    assert_ne!(wz::order()[0], wz::order()[1]);
    assert_ne!(wz::ordering()[0], wz::ordering()[1]);
}
