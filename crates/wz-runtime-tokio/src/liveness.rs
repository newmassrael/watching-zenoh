// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Whether the node's long-running loops still turn, and what each one is doing when it does not.
//!
//! A loop that serves every face of a node (it accepts, opens, routes and ticks) and stops inside
//! its own thread stops the node without a line: the code that would log is the code that
//! stopped. A peer then sees a link that is accepted and never answered, and the operator sees a
//! log that ends. What a stop is made of (a lock, a wait for room on a link, a call that does not
//! return) can be read only while the process is still stopped, from outside the loop.
//!
//! So each such loop holds a [`Heartbeat`]. It says when the loop enters a step of work
//! ([`Heartbeat::turn`]) and when it rests, waiting for an event with nothing to do
//! ([`Heartbeat::rest`]); a loop that awaits its sources wraps that await in
//! [`Heartbeat::polled`], which is busy while a source is polled and resting once the poll has
//! returned pending. A stop is time spent busy: a loop that rests for an hour because nothing
//! happens is not stopped, and a loop that is inside one poll of one source for a minute is. One
//! watcher thread per process, a plain thread outside every async runtime so that it runs when
//! every worker of a runtime is blocked, reads the heartbeats. A loop that has been busy in one
//! step for [`stall_after`] is reported once, at WARN, with:
//!
//! - the step it last entered;
//! - what its owner's probe says (a router's probe reads its routing tables' lock: who holds it
//!   and how long its oldest writer has waited);
//! - every thread of the process, by name, scheduler state and, on Linux, the kernel function it
//!   sleeps in (`/proc/self/task/<tid>/wchan`), which is what tells a lock from a socket from a
//!   sleep without a debugger.
//!
//! The report is repeated, at the same level, every four [`stall_after`] for as long as the stop
//! lasts, and a loop that turns again is reported at INFO with how long it did not. A loop that
//! keeps turning is never reported, so a quiet node logs nothing.
//!
//! The judgement is a pure function of the clock (`Watched::judge`), tested without sleeping;
//! the thread only feeds it the time.
//!
//! The threshold is process-wide and set by the host ([`set_stall_after`]). A host that runs
//! sessions sets it to half the lease, so that a stop is reported while the sessions it holds can
//! still be told apart from the ones it has already lost.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use crate::sync::PlainMutex;

/// The threshold until a host sets one: half of the ten-second lease every upstream preset
/// starts with (`commons/zenoh-config/src/defaults.rs` @ `lease: 10_000,`).
pub const DEFAULT_STALL_AFTER: Duration = Duration::from_secs(5);

/// The shortest threshold [`set_stall_after`] takes: a pass of a loop that serves many faces is
/// measured in milliseconds, and a threshold under one would report a loop that is working.
pub const MIN_STALL_AFTER: Duration = Duration::from_millis(50);

/// What a loop's owner can say about the loop when it stops, called on the watcher's thread. It
/// must not wait for anything the loop may hold: read atomics and lock states, never take a lock.
pub type Probe = Arc<dyn Fn() -> String + Send + Sync>;

/// The most threads one report names. A node has a few dozen; a process that has many more
/// is reported by the first ones and the count of the others.
const MAX_THREADS_REPORTED: usize = 128;

/// The process's monotonic origin of the turn times, so that a turn time is a number that an
/// atomic holds.
fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// Nanoseconds since [`epoch`], never 0, so that 0 can mean "never".
fn now_ns() -> u64 {
    u64::try_from(epoch().elapsed().as_nanos())
        .unwrap_or(u64::MAX)
        .max(1)
}

/// The step value of a loop that rests: it waits for an event and does no work.
const RESTING: usize = usize::MAX;

/// One loop's beat, shared by the loop that turns it and the watcher that reads it.
struct Beat {
    name: String,
    steps: &'static [&'static str],
    /// The index in `steps` of the step the loop last entered, or [`RESTING`].
    step: AtomicUsize,
    /// When the loop last entered a step or began to rest, in [`now_ns`].
    turned_at: AtomicU64,
    probe: Option<Probe>,
}

impl Beat {
    fn step_name(&self) -> &'static str {
        match self.step.load(Ordering::Relaxed) {
            RESTING => "waiting for an event",
            step => self.steps.get(step).copied().unwrap_or("an unnamed step"),
        }
    }
}

/// A loop's heartbeat: [`turn`](Self::turn) it once per pass. Dropping it takes the loop off the
/// watcher, as a loop that has ended is not one that stopped.
pub struct Heartbeat(Arc<Beat>);

impl Heartbeat {
    /// A heartbeat for the loop `name`, whose passes enter one of `steps`, watched by the
    /// process's watcher (started by the first heartbeat). `probe` is what the report adds about
    /// the loop's owner.
    pub fn register(
        name: impl Into<String>,
        steps: &'static [&'static str],
        probe: Option<Probe>,
    ) -> Self {
        let heartbeat = Self::unwatched(name, steps, probe);
        if let Some(watcher) = Watcher::process() {
            watcher.watch(&heartbeat);
        }
        heartbeat
    }

    fn unwatched(
        name: impl Into<String>,
        steps: &'static [&'static str],
        probe: Option<Probe>,
    ) -> Self {
        Self(Arc::new(Beat {
            name: name.into(),
            steps,
            step: AtomicUsize::new(RESTING),
            turned_at: AtomicU64::new(now_ns()),
            probe,
        }))
    }

    /// The loop is entering `step` (an index in the steps it was registered with) and is busy
    /// until it enters another or rests. Two relaxed stores: the watcher needs each value to be
    /// one the loop wrote, not the two to be from the same pass.
    pub fn turn(&self, step: usize) {
        debug_assert!(
            step < self.0.steps.len(),
            "step {step} is not one of the loop's"
        );
        self.0.step.store(step, Ordering::Relaxed);
        self.0.turned_at.store(now_ns(), Ordering::Relaxed);
    }

    /// The loop waits for an event and does no work: however long it rests, it is not stopped.
    pub fn rest(&self) {
        self.0.step.store(RESTING, Ordering::Relaxed);
        self.0.turned_at.store(now_ns(), Ordering::Relaxed);
    }

    /// `future`, with the loop busy in `step` while it is polled and resting once a poll has
    /// returned pending: the shape of a loop that awaits its sources, where a poll that does not
    /// return is a stop and a pending that lasts is not. `future` is `Unpin` so that wrapping it
    /// costs no allocation on a loop's every pass: pin it in place (`tokio::pin!`) and pass the
    /// `Pin<&mut _>`.
    pub fn polled<F: Future + Unpin>(&self, step: usize, future: F) -> Polled<'_, F> {
        Polled {
            heartbeat: self,
            step,
            future,
        }
    }
}

/// [`Heartbeat::polled`]'s future.
pub struct Polled<'a, F> {
    heartbeat: &'a Heartbeat,
    step: usize,
    future: F,
}

impl<F: Future + Unpin> Future for Polled<'_, F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = &mut *self;
        this.heartbeat.turn(this.step);
        let polled = Pin::new(&mut this.future).poll(cx);
        if polled.is_pending() {
            this.heartbeat.rest();
        }
        polled
    }
}

/// What the watcher knows of one loop beyond its beat: whether it is stopped, since when, and
/// when the stop was last reported. Only the watcher's thread touches it.
struct Watched {
    beat: Weak<Beat>,
    /// The turn time the loop had when it was first reported stopped, or `None` while it turns.
    stalled_from: Option<u64>,
    /// When the stop was last reported.
    reported_at: u64,
}

/// What one look at a loop finds.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// It turns, or it has not turned for less than the threshold.
    Turning,
    /// It is stopped and it was reported recently enough: nothing to say.
    StillStalled,
    /// It has not turned for this long: report it (the first report, or a reminder).
    Stalled { for_ns: u64, first: bool },
    /// It turned again after not turning for this long.
    TurnedAgain { after_ns: u64 },
}

impl Watched {
    /// Look at a loop that last entered a step or began to rest at `turned_at`, at time `now`,
    /// against `stall_after`; `resting` when it rests. A loop busy in one step for the threshold is
    /// stopped: reported when it reaches it and again every four thresholds after that report.
    /// Its end (a new step, or rest) is reported once, with how long the loop did not turn. A
    /// resting loop is never stopped.
    fn judge(&mut self, turned_at: u64, resting: bool, now: u64, stall_after: u64) -> Verdict {
        let still = now.saturating_sub(turned_at);
        match self.stalled_from {
            Some(from) if turned_at != from || resting => {
                self.stalled_from = None;
                Verdict::TurnedAgain {
                    after_ns: turned_at.saturating_sub(from),
                }
            }
            Some(_) => {
                if now.saturating_sub(self.reported_at) >= stall_after.saturating_mul(4) {
                    self.reported_at = now;
                    Verdict::Stalled {
                        for_ns: still,
                        first: false,
                    }
                } else {
                    Verdict::StillStalled
                }
            }
            None if !resting && still >= stall_after => {
                self.stalled_from = Some(turned_at);
                self.reported_at = now;
                Verdict::Stalled {
                    for_ns: still,
                    first: true,
                }
            }
            None => Verdict::Turning,
        }
    }
}

/// The threshold every loop of the process is judged by, in nanoseconds.
fn threshold() -> &'static AtomicU64 {
    static STALL_AFTER: AtomicU64 = AtomicU64::new(0);
    &STALL_AFTER
}

/// The threshold the process's loops are judged by.
pub fn stall_after() -> Duration {
    match threshold().load(Ordering::Relaxed) {
        0 => DEFAULT_STALL_AFTER,
        ns => Duration::from_nanos(ns),
    }
}

/// Judge every loop of the process by `after` from now on, never by less than
/// [`MIN_STALL_AFTER`]. The host sets it once, before or after its loops start.
pub fn set_stall_after(after: Duration) {
    let after = after.max(MIN_STALL_AFTER);
    threshold().store(
        u64::try_from(after.as_nanos()).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
}

/// The loops a watcher reads.
struct Watcher {
    watched: PlainMutex<Vec<Watched>>,
}

impl Watcher {
    fn new() -> Self {
        Self {
            watched: PlainMutex::new(Vec::new()),
        }
    }

    /// The process's watcher, its thread started on the first call; `None` when the thread could
    /// not be started, which is said once and leaves the loops unwatched rather than the node
    /// unstarted.
    fn process() -> Option<&'static Watcher> {
        static WATCHER: OnceLock<Option<&'static Watcher>> = OnceLock::new();
        *WATCHER.get_or_init(|| {
            let watcher: &'static Watcher = Box::leak(Box::new(Watcher::new()));
            let started = std::thread::Builder::new()
                .name(String::from("wz-liveness"))
                .spawn(move || loop {
                    let after = stall_after();
                    std::thread::sleep((after / 4).max(MIN_STALL_AFTER / 4));
                    for line in watcher.look(now_ns(), after) {
                        line.log();
                    }
                });
            match started {
                Ok(_) => Some(watcher),
                Err(e) => {
                    log::warn!(
                        "liveness: the watcher thread did not start ({e}); a loop of this \
                         process that stops will not be reported"
                    );
                    None
                }
            }
        })
    }

    fn watch(&self, heartbeat: &Heartbeat) {
        self.watched.with(|watched| {
            watched.push(Watched {
                beat: Arc::downgrade(&heartbeat.0),
                stalled_from: None,
                reported_at: 0,
            });
        });
    }

    /// Look at every loop at `now` and say what is to be said, forgetting the loops that ended.
    /// The probes are called and the threads read after the list is let go, so that a probe that
    /// is slow holds no registration up.
    fn look(&self, now: u64, stall_after: Duration) -> Vec<Report> {
        let stall_after = u64::try_from(stall_after.as_nanos()).unwrap_or(u64::MAX);
        let found: Vec<(Arc<Beat>, Verdict)> = self.watched.with(|watched| {
            let mut found = Vec::new();
            watched.retain_mut(|one| {
                let Some(beat) = one.beat.upgrade() else {
                    return false;
                };
                let verdict = one.judge(
                    beat.turned_at.load(Ordering::Relaxed),
                    beat.step.load(Ordering::Relaxed) == RESTING,
                    now,
                    stall_after,
                );
                if !matches!(verdict, Verdict::Turning | Verdict::StillStalled) {
                    found.push((beat, verdict));
                }
                true
            });
            found
        });
        if found.is_empty() {
            return Vec::new();
        }
        let threads = threads_now();
        found
            .into_iter()
            .map(|(beat, verdict)| Report::of(&beat, verdict, &threads))
            .collect()
    }
}

/// What a look says about one loop, ready to log.
#[derive(Debug)]
struct Report {
    warn: bool,
    text: String,
}

impl Report {
    fn of(beat: &Beat, verdict: Verdict, threads: &str) -> Self {
        match verdict {
            Verdict::Stalled { for_ns, first } => {
                let probe = beat
                    .probe
                    .as_ref()
                    .map(|probe| format!("; {}", probe()))
                    .unwrap_or_default();
                Self {
                    warn: true,
                    text: format!(
                        "liveness: loop '{}' has not turned for {:.3} s{}; it is in step '{}'{probe}; \
                         threads: {threads}",
                        beat.name,
                        Duration::from_nanos(for_ns).as_secs_f64(),
                        if first { "" } else { " and is still stopped" },
                        beat.step_name(),
                    ),
                }
            }
            Verdict::TurnedAgain { after_ns } => Self {
                warn: false,
                text: format!(
                    "liveness: loop '{}' turned again after {:.3} s without turning",
                    beat.name,
                    Duration::from_nanos(after_ns).as_secs_f64(),
                ),
            },
            Verdict::Turning | Verdict::StillStalled => Self {
                warn: false,
                text: String::new(),
            },
        }
    }

    fn log(&self) {
        if self.warn {
            log::warn!("{}", self.text);
        } else {
            log::info!("{}", self.text);
        }
    }
}

/// The process's threads as one line: `tid name state wchan` for each, from `/proc/self/task`.
/// On a system without it, says so.
fn threads_now() -> String {
    #[cfg(target_os = "linux")]
    {
        let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
            return String::from("(unreadable: /proc/self/task)");
        };
        let mut tids: Vec<u64> = tasks
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
            .collect();
        tids.sort_unstable();
        let total = tids.len();
        let mut line: Vec<String> = tids
            .into_iter()
            .take(MAX_THREADS_REPORTED)
            .map(|tid| {
                let read = |file: &str| {
                    std::fs::read_to_string(format!("/proc/self/task/{tid}/{file}"))
                        .map(|text| text.trim().to_owned())
                        .unwrap_or_else(|_| String::from("?"))
                };
                let name = read("comm");
                // `stat` is `tid (comm) state ...`; the name may hold spaces and parentheses, so
                // the state is the first field after the last ')'.
                let state = read("stat")
                    .rsplit_once(')')
                    .and_then(|(_, rest)| rest.split_whitespace().next().map(str::to_owned))
                    .unwrap_or_else(|| String::from("?"));
                let wchan = match read("wchan").as_str() {
                    "" | "0" => String::from("-"),
                    other => other.to_owned(),
                };
                format!("[{tid} {name} {state} {wchan}]")
            })
            .collect();
        if total > MAX_THREADS_REPORTED {
            line.push(format!("(and {} more)", total - MAX_THREADS_REPORTED));
        }
        line.join(" ")
    }
    #[cfg(not(target_os = "linux"))]
    {
        String::from("(not read on this system)")
    }
}

/// What every live loop of the process is doing now, for a host that answers a question about
/// it and for a test: the loop's name, the step it last entered, and how long ago it turned.
pub fn loops_now() -> Vec<(String, &'static str, Duration)> {
    let Some(watcher) = Watcher::process() else {
        return Vec::new();
    };
    let now = now_ns();
    watcher.watched.with(|watched| {
        watched
            .iter()
            .filter_map(|one| one.beat.upgrade())
            .map(|beat| {
                (
                    beat.name.clone(),
                    beat.step_name(),
                    Duration::from_nanos(
                        now.saturating_sub(beat.turned_at.load(Ordering::Relaxed)),
                    ),
                )
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const STEPS: &[&str] = &["polling", "tick"];
    const MS: u64 = 1_000_000;

    fn watched() -> Watched {
        Watched {
            beat: Weak::new(),
            stalled_from: None,
            reported_at: 0,
        }
    }

    /// A loop that turns within the threshold is never reported, however long it runs; nor is a
    /// loop that rests, however long it rests.
    #[test]
    fn a_turning_or_resting_loop_is_never_reported() {
        let mut one = watched();
        for pass in 0..1000u64 {
            let turned = pass * 10 * MS;
            assert_eq!(
                one.judge(turned, false, turned + 99 * MS, 100 * MS),
                Verdict::Turning
            );
        }
        assert_eq!(
            one.judge(0, true, 3_600_000 * MS, 100 * MS),
            Verdict::Turning,
            "an hour of rest is not a stop"
        );
    }

    /// A stop that ends in rest (the step returned, and the loop found nothing more to do) is
    /// ended by it, once.
    #[test]
    fn a_stop_that_ends_in_rest_is_ended_once() {
        let mut one = watched();
        let after = 100 * MS;
        assert!(matches!(
            one.judge(0, false, 200 * MS, after),
            Verdict::Stalled { first: true, .. }
        ));
        assert_eq!(
            one.judge(250 * MS, true, 260 * MS, after),
            Verdict::TurnedAgain { after_ns: 250 * MS }
        );
        assert_eq!(one.judge(250 * MS, true, 900 * MS, after), Verdict::Turning);
    }

    /// A loop that stops is reported once when it reaches the threshold, not again until four
    /// thresholds later, then again; and its turning again is reported once with the time it did
    /// not turn, after which it is a turning loop.
    #[test]
    fn a_stop_is_reported_at_the_threshold_reminded_and_ended() {
        let mut one = watched();
        let stopped_at = 1_000 * MS;
        let after = 100 * MS;
        assert_eq!(
            one.judge(stopped_at, false, stopped_at + 99 * MS, after),
            Verdict::Turning
        );
        assert_eq!(
            one.judge(stopped_at, false, stopped_at + 100 * MS, after),
            Verdict::Stalled {
                for_ns: 100 * MS,
                first: true
            }
        );
        assert_eq!(
            one.judge(stopped_at, false, stopped_at + 300 * MS, after),
            Verdict::StillStalled
        );
        assert_eq!(
            one.judge(stopped_at, false, stopped_at + 499 * MS, after),
            Verdict::StillStalled
        );
        assert_eq!(
            one.judge(stopped_at, false, stopped_at + 500 * MS, after),
            Verdict::Stalled {
                for_ns: 500 * MS,
                first: false
            }
        );
        let turned = stopped_at + 3_100 * MS;
        assert_eq!(
            one.judge(turned, false, turned + MS, after),
            Verdict::TurnedAgain {
                after_ns: 3_100 * MS
            }
        );
        assert_eq!(
            one.judge(turned, false, turned + 2 * MS, after),
            Verdict::Turning
        );
    }

    /// A watcher reports a heartbeat that stops with its step, its probe and the threads, says
    /// nothing while it keeps turning, reports its turning again at INFO, and forgets it once the
    /// heartbeat is dropped. A watcher of its own, so that the process's threshold and thread do
    /// not decide what this test sees.
    #[test]
    fn a_watcher_reports_a_stopped_loop_with_its_step_probe_and_threads() {
        let watcher = Watcher::new();
        let probe: Probe = Arc::new(|| String::from("routing tables: held for writing"));
        let heartbeat = Heartbeat::unwatched("face loop test", STEPS, Some(probe));
        watcher.watch(&heartbeat);
        let after = Duration::from_millis(100);

        heartbeat.turn(1);
        let turned = heartbeat.0.turned_at.load(Ordering::Relaxed);
        assert!(watcher.look(turned + 50 * MS, after).is_empty());

        let reports = watcher.look(turned + 150 * MS, after);
        assert_eq!(reports.len(), 1, "{reports:?}");
        let report = &reports[0];
        assert!(report.warn);
        assert!(
            report
                .text
                .starts_with("liveness: loop 'face loop test' has not turned for 0.150 s;"),
            "{}",
            report.text
        );
        assert!(
            report.text.contains("it is in step 'tick'"),
            "{}",
            report.text
        );
        assert!(
            report.text.contains("; routing tables: held for writing;"),
            "{}",
            report.text
        );
        #[cfg(target_os = "linux")]
        assert!(
            report.text.contains(&format!("[{}", std::process::id())),
            "the main thread of the process is named: {}",
            report.text
        );

        heartbeat.turn(0);
        let again = heartbeat.0.turned_at.load(Ordering::Relaxed);
        let reports = watcher.look(again + MS, after);
        assert_eq!(reports.len(), 1, "{reports:?}");
        assert!(!reports[0].warn);
        assert!(
            reports[0]
                .text
                .starts_with("liveness: loop 'face loop test' turned again after "),
            "{}",
            reports[0].text
        );

        drop(heartbeat);
        assert!(watcher.look(again + 10_000 * MS, after).is_empty());
        assert!(watcher.watched.with(|watched| watched.is_empty()));
    }

    /// A polled future keeps the loop in its step while its poll runs, and the loop rests once the
    /// poll returns pending; a poll that returns ready leaves the loop busy, for the step the
    /// loop enters next to name.
    #[test]
    fn a_polled_future_is_busy_inside_its_poll_and_rests_when_pending() {
        struct Nothing;
        impl std::task::Wake for Nothing {
            fn wake(self: Arc<Self>) {}
        }
        let waker = std::task::Waker::from(Arc::new(Nothing));
        let mut cx = Context::from_waker(&waker);

        let heartbeat = Heartbeat::unwatched("polled", STEPS, None);
        let step_seen_inside = Arc::new(AtomicUsize::new(RESTING));
        let mut polls = 0;
        let beat = Arc::clone(&heartbeat.0);
        let seen = Arc::clone(&step_seen_inside);
        let source = std::future::poll_fn(move |_| {
            seen.store(beat.step.load(Ordering::Relaxed), Ordering::Relaxed);
            polls += 1;
            if polls == 1 {
                Poll::Pending
            } else {
                Poll::Ready(7)
            }
        });
        let mut source = std::pin::pin!(source);
        let mut polled = heartbeat.polled(0, source.as_mut());

        assert!(Pin::new(&mut polled).poll(&mut cx).is_pending());
        assert_eq!(
            step_seen_inside.load(Ordering::Relaxed),
            0,
            "busy inside the poll"
        );
        assert_eq!(
            heartbeat.0.step.load(Ordering::Relaxed),
            RESTING,
            "resting once pending"
        );

        assert_eq!(Pin::new(&mut polled).poll(&mut cx), Poll::Ready(7));
        assert_eq!(
            heartbeat.0.step.load(Ordering::Relaxed),
            0,
            "busy past a ready poll"
        );
    }

    /// The threshold never goes under its floor, so a host that passes zero (a lease of zero, a
    /// config that says nothing) does not report every loop that is working; and a host's value
    /// above the floor is the one the loops are judged by. Put back to the default at the end: the
    /// process's watcher reads it, and only its log lines depend on it.
    #[test]
    fn the_threshold_keeps_its_floor() {
        set_stall_after(Duration::ZERO);
        assert_eq!(stall_after(), MIN_STALL_AFTER);
        set_stall_after(Duration::from_millis(7_500));
        assert_eq!(stall_after(), Duration::from_millis(7_500));
        set_stall_after(DEFAULT_STALL_AFTER);
        assert_eq!(stall_after(), DEFAULT_STALL_AFTER);
    }
}
