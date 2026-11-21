// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! What the pico C ABI does when memory runs out, and how much memory its traffic takes.
//!
//! Two instruments, both over the program's own transport (an in-memory pipe, no socket), on the
//! engine the build has, and both run by Layer S, never by a default `cargo test` (every test is
//! `#[ignore]`d):
//!
//! * **A failed allocation at every point of a call.** For `z_open`, `z_declare_subscriber`,
//!   `z_declare_queryable`, `z_declare_publisher`, `z_put` and `z_get`: a run with no failure
//!   counts the allocations the process makes while the call runs (N), and then for every n from
//!   1 until a run makes fewer than n, a run of its own whose n-th allocation fails. Each run is a
//!   process of its own (this executable, started again on one test with the point in its
//!   environment), because a failed allocation may end the process, and a process must be judged
//!   from outside then. A run ends in one of three ways: the call returned (its code, and once the
//!   sessions are closed whether every closure was dropped, both transports were let go and the
//!   process holds no more allocations than the run with no failure); the process ended in Rust's
//!   allocation-failure handler (it aborts, with its message on stderr); or anything else (a
//!   signal, a failed assertion, a run that did not end in time), which fails every build.
//! * **The allocations of traffic between open sessions.** Once both sessions are open and
//!   their routes are made, puts (and gets) are counted: how many allocations the process made
//!   for them and how many bytes those asked for. The count is a process of its own too.
//!
//! A run is the library and nothing more: the tokio runtime's lock-order checker, an instrument
//! of a debug build that allocates a stack under std's backtrace lock, is off in it (`run_child`).
//!
//! What a build is held to depends on its memory, which `MEMORY_TAKEN_AT_OPEN` states. A build
//! that takes a session's memory at `z_open` and none after answers every failed allocation with
//! a named error and leaves nothing behind, and its traffic allocates nothing; both are asserted
//! there. A heap build allocates as it runs and ends the process in the handler when an
//! allocation fails; there each instrument measures and prints, and asserts what holds of every
//! build (no other end of a run, no panic, the counter sees the heap's allocations).
//!
//! The allocator and the two sessions over the pipe are `support/pipe_pair.rs`'s, which the
//! no-heap measurement (`no_heap_after_open.rs`) shares; the allocator is installed below as this
//! executable's own (`#[global_allocator]`), which is why the file is an executable of its own.

use std::fmt::Write as _;
use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use wz_capi_pico::result::Z_ERR_SYSTEM_OUT_OF_MEMORY;
use wz_capi_pico::{
    z_config_move, z_declare_publisher, z_open, z_owned_publisher_t, z_owned_queryable_t,
    z_owned_session_t, z_owned_subscriber_t, z_publisher_move, z_queryable_move, z_session_loan,
    z_subscriber_move, z_undeclare_publisher, z_undeclare_queryable, z_undeclare_subscriber,
    z_view_keyexpr_loan, ZResult, Z_CONFIG_CONNECT_KEY, Z_OK,
};

#[path = "support/pipe_pair.rs"]
mod pipe_pair;

use pipe_pair::{
    close_window, config_over, count_panics, declare_queryable, declare_subscriber, get,
    open_window, payload, put, query_closure, reply_closure, sample_closure, view, wait_for,
    Injecting, Pair, DATA_KEY, DECLARED_KEY, LIVE_ALLOCATIONS, PANICS, WAIT_BOUND,
};

/// Whether this build takes a session's memory at `z_open` and none after. Then a failed
/// allocation is answered with a named error and leaves nothing behind, and traffic between open
/// sessions allocates nothing, and the tests below assert both. Both engines of this crate take
/// their memory from the heap as a session runs, where a failed allocation ends the process in
/// Rust's allocation-failure handler and every message allocates, so the tests measure and print
/// that and assert what holds of every build. A fixed-memory build sets this from its feature.
const MEMORY_TAKEN_AT_OPEN: bool = false;

/// The codes a call may answer a failed allocation with: pico's own for it
/// (`_Z_ERR_SYSTEM_OUT_OF_MEMORY`).
const NAMED_ALLOCATION_ERRORS: [ZResult; 1] = [Z_ERR_SYSTEM_OUT_OF_MEMORY];

// ---------------------------------------------------------------------------------------------
// The allocator, counting every call and failing one on request (`support/pipe_pair.rs`).

#[global_allocator]
static ALLOCATOR: Injecting = Injecting;

/// The fewest allocations the process held while it settled: the lowest count seen, once no
/// lower one has been seen for `quiet`, or at `longest`. A thread that is ending frees what it
/// held as it ends, so a single reading taken at once would count it.
fn settled_allocations(quiet: Duration, longest: Duration) -> isize {
    let start = Instant::now();
    let mut lowest = LIVE_ALLOCATIONS.load(Ordering::SeqCst);
    let mut lowest_at = start;
    while start.elapsed() < longest && lowest_at.elapsed() < quiet {
        std::thread::sleep(Duration::from_millis(20));
        let now = LIVE_ALLOCATIONS.load(Ordering::SeqCst);
        if now < lowest {
            lowest = now;
            lowest_at = Instant::now();
        }
    }
    lowest
}

// ---------------------------------------------------------------------------------------------
// The calls a failed allocation is put into.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Open,
    DeclareSubscriber,
    DeclareQueryable,
    DeclarePublisher,
    Put,
    Get,
}

impl Call {
    const ALL: [Call; 6] = [
        Call::Open,
        Call::DeclareSubscriber,
        Call::DeclareQueryable,
        Call::DeclarePublisher,
        Call::Put,
        Call::Get,
    ];

    fn name(self) -> &'static str {
        match self {
            Call::Open => "z_open",
            Call::DeclareSubscriber => "z_declare_subscriber",
            Call::DeclareQueryable => "z_declare_queryable",
            Call::DeclarePublisher => "z_declare_publisher",
            Call::Put => "z_put",
            Call::Get => "z_get",
        }
    }

    /// The test that sweeps this call, which each of its runs is started as.
    fn test_name(self) -> &'static str {
        match self {
            Call::Open => "z_open_meets_a_failed_allocation_at_every_point_of_its_call",
            Call::DeclareSubscriber => {
                "z_declare_subscriber_meets_a_failed_allocation_at_every_point_of_its_call"
            }
            Call::DeclareQueryable => {
                "z_declare_queryable_meets_a_failed_allocation_at_every_point_of_its_call"
            }
            Call::DeclarePublisher => {
                "z_declare_publisher_meets_a_failed_allocation_at_every_point_of_its_call"
            }
            Call::Put => "z_put_meets_a_failed_allocation_at_every_point_of_its_call",
            Call::Get => "z_get_meets_a_failed_allocation_at_every_point_of_its_call",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|call| call.name() == name)
    }
}

/// The variable that starts a run: `<call>:<point>`, the point 0 for the run with no failure.
const RUN_VARIABLE: &str = "WZ_ALLOC_FAULT_RUN";
/// The line a run prints its verdict on.
const VERDICT_PREFIX: &str = "allocation-fault-run:";

/// What Rust's allocation-failure handler writes before it aborts the process.
fn ended_in_the_allocation_failure_handler(stderr: &str) -> bool {
    stderr
        .lines()
        .any(|line| line.contains("memory allocation of ") && line.contains(" bytes failed"))
}

/// The code a run that aborted exits with: what a shell gives an abort.
#[cfg(unix)]
const ABORT_EXIT: libc::c_int = 134;

/// End the process at once when it aborts, with `ABORT_EXIT`: the handler's abort would otherwise
/// leave a core dump for every one of a sweep's thousands of runs. The handler calls `_exit` and
/// nothing else, which is async-signal-safe.
#[cfg(unix)]
fn end_at_once_on_abort() {
    extern "C" fn on_abort(_signal: libc::c_int) {
        // SAFETY: `_exit` is async-signal-safe and ends the process without running anything.
        unsafe { libc::_exit(ABORT_EXIT) }
    }
    // The handler's address, through a function pointer: a function item is not cast to an
    // integer directly.
    let handler: extern "C" fn(libc::c_int) = on_abort;
    // SAFETY: the handler calls one async-signal-safe function.
    unsafe { libc::signal(libc::SIGABRT, handler as libc::sighandler_t) };
}

#[cfg(not(unix))]
fn end_at_once_on_abort() {}

/// One run of `call` whose `point`-th allocation fails (none for 0), in this process: the
/// sessions the call needs, the call in the window, what it made undone, everything closed, and
/// the verdict printed for the process that started this one.
fn run_once(call: Call, point: u64) {
    count_panics();
    end_at_once_on_abort();
    unsafe {
        let mut pair = Pair::open(call != Call::Open);
        let counts = Arc::clone(&pair.counts);
        let (rc, seen) = match call {
            Call::Open => {
                let mut cfg = config_over(Z_CONFIG_CONNECT_KEY, pair.dialling_transport);
                let mut session: z_owned_session_t = std::mem::zeroed();
                open_window(point);
                let rc = z_open(&mut session, z_config_move(&mut cfg), std::ptr::null());
                let seen = close_window();
                if rc == Z_OK {
                    pair.dialler = Some(session);
                }
                (rc, seen)
            }
            Call::DeclareSubscriber => {
                let mut closure = sample_closure(&counts);
                let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
                open_window(point);
                let rc =
                    declare_subscriber(pair.dialler(), DECLARED_KEY, &mut closure, &mut subscriber);
                let seen = close_window();
                if rc == Z_OK {
                    z_undeclare_subscriber(z_subscriber_move(&mut subscriber));
                }
                (rc, seen)
            }
            Call::DeclareQueryable => {
                let mut closure = query_closure(&counts);
                let mut queryable: z_owned_queryable_t = std::mem::zeroed();
                open_window(point);
                let rc =
                    declare_queryable(pair.dialler(), DECLARED_KEY, &mut closure, &mut queryable);
                let seen = close_window();
                if rc == Z_OK {
                    z_undeclare_queryable(z_queryable_move(&mut queryable));
                }
                (rc, seen)
            }
            Call::DeclarePublisher => {
                let ke = view(DATA_KEY);
                let mut publisher: z_owned_publisher_t = std::mem::zeroed();
                open_window(point);
                let rc = z_declare_publisher(
                    z_session_loan(pair.dialler()),
                    &mut publisher,
                    z_view_keyexpr_loan(&ke),
                    std::ptr::null(),
                );
                let seen = close_window();
                if rc == Z_OK {
                    z_undeclare_publisher(z_publisher_move(&mut publisher));
                }
                (rc, seen)
            }
            Call::Put => {
                let mut bytes = payload();
                open_window(point);
                let rc = put(pair.dialler(), &mut bytes);
                (rc, close_window())
            }
            Call::Get => {
                let over = counts.gets_over.load(Ordering::SeqCst);
                let mut closure = reply_closure(&counts);
                open_window(point);
                let rc = get(pair.dialler(), &mut closure);
                let seen = close_window();
                // Taken or refused, the get ends: its closure's drop comes once either way.
                let _ = wait_for(WAIT_BOUND, || {
                    counts.gets_over.load(Ordering::SeqCst) > over
                });
                (rc, seen)
            }
        };
        let (balanced, dropped) = pair.close();
        // What the process holds once everything is closed, read where it is judged: a run whose
        // call returned after its failure, and the run with no failure it is held to.
        let held = if seen.fired || point == 0 {
            settled_allocations(Duration::from_millis(300), Duration::from_secs(3))
        } else {
            0
        };
        println!(
            "{VERDICT_PREFIX} fired={} rc={rc} allocations={} held={held} balanced={} \
             dropped={} panics={}",
            u8::from(seen.fired),
            seen.allocations,
            u8::from(balanced),
            u8::from(dropped),
            PANICS.load(Ordering::SeqCst),
        );
    }
}

/// What one run printed.
#[derive(Clone, Copy, Debug)]
struct Verdict {
    fired: bool,
    rc: ZResult,
    allocations: u64,
    held: isize,
    balanced: bool,
    dropped: bool,
    panics: usize,
}

fn parse_verdict(stdout: &str) -> Option<Verdict> {
    let line = verdict_line(stdout, VERDICT_PREFIX)?;
    Some(Verdict {
        fired: field(line, "fired")? == "1",
        rc: field(line, "rc")?.parse().ok()?,
        allocations: field(line, "allocations")?.parse().ok()?,
        held: field(line, "held")?.parse().ok()?,
        balanced: field(line, "balanced")? == "1",
        dropped: field(line, "dropped")? == "1",
        panics: field(line, "panics")?.parse().ok()?,
    })
}

/// What follows `prefix` on the line of `stdout` that carries it. libtest may have written the
/// test's name on that line before it.
fn verdict_line<'a>(stdout: &'a str, prefix: &str) -> Option<&'a str> {
    stdout
        .lines()
        .find_map(|line| line.find(prefix).map(|at| &line[at + prefix.len()..]))
}

/// The value of `name=value` among the words of `line`.
fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|word| word.strip_prefix(name)?.strip_prefix('='))
}

/// How a run ended.
#[derive(Debug)]
enum Outcome {
    /// The call returned, and the run printed what it saw.
    Returned(Verdict),
    /// The process ended in Rust's allocation-failure handler.
    EndedInTheHandler,
    /// Any other end: a signal, a failed assertion of the run's own, no verdict, no end in time.
    Broken(String),
}

/// How long one run may take: two sessions over memory, one call, everything closed.
const RUN_BOUND: Duration = Duration::from_secs(60);

fn drain(pipe: Option<impl Read + Send + 'static>) -> JoinHandle<String> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut bytes);
        }
        String::from_utf8_lossy(&bytes).into_owned()
    })
}

#[cfg(unix)]
fn signal_of(status: &ExitStatus) -> Option<i32> {
    std::os::unix::process::ExitStatusExt::signal(status)
}

#[cfg(not(unix))]
fn signal_of(_status: &ExitStatus) -> Option<i32> {
    None
}

/// The last lines of `text`, for a report.
fn tail(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(12)..].join("\n    ")
}

/// How a process this test started ended, read from outside.
struct Ended {
    /// `None` when it did not end within `RUN_BOUND` and was killed.
    status: Option<ExitStatus>,
    stdout: String,
    stderr: String,
}

/// Start this executable again on the test `test_name` alone, with `request` in `RUN_VARIABLE`,
/// and wait for it to end.
///
/// The run holds the library and nothing more: the tokio runtime's lock-order checker, an
/// instrument of a debug build, is off in it. On, it captures a stack for each lock order new to
/// the process, under std's backtrace lock and on the global allocator, so a failure injected
/// there sends Rust's allocation-failure handler after the lock its own thread holds, and the run
/// waits for itself instead of ending; and what it allocates is not the library's. The handler
/// prints no backtrace either, which would only slow thousands of runs.
fn run_child(test_name: &str, request: &str) -> Ended {
    let exe = std::env::current_exe().expect("the test executable has a path");
    let mut child = Command::new(exe)
        .args([
            test_name,
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(RUN_VARIABLE, request)
        .env("WZ_LOCK_ORDER", "off")
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("a run starts");
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let deadline = Instant::now() + RUN_BOUND;
    let status = loop {
        match child.try_wait().expect("a run can be waited on") {
            Some(status) => break Some(status),
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    Ended {
        status,
        stdout: stdout.join().expect("the run's stdout is read"),
        stderr: stderr.join().expect("the run's stderr is read"),
    }
}

/// Whether `status` is the end of a process that aborted: the code its abort handler exits with,
/// or the signal itself.
#[cfg(unix)]
fn ended_by_abort(status: &ExitStatus) -> bool {
    status.code() == Some(ABORT_EXIT) || signal_of(status) == Some(libc::SIGABRT)
}

#[cfg(not(unix))]
fn ended_by_abort(status: &ExitStatus) -> bool {
    !status.success()
}

/// How a run of a sweep ended.
fn outcome(ended: Ended) -> Outcome {
    let Ended {
        status,
        stdout,
        stderr,
    } = ended;
    match status {
        None => Outcome::Broken(format!(
            "did not end within {RUN_BOUND:?}; stderr:\n    {}",
            tail(&stderr)
        )),
        Some(status) if status.success() => match parse_verdict(&stdout) {
            Some(verdict) => Outcome::Returned(verdict),
            None => Outcome::Broken(format!(
                "ended without its verdict; stdout:\n    {}",
                tail(&stdout)
            )),
        },
        Some(status)
            if ended_by_abort(&status) && ended_in_the_allocation_failure_handler(&stderr) =>
        {
            Outcome::EndedInTheHandler
        }
        Some(status) => Outcome::Broken(format!(
            "ended with {status} (signal {:?}); stderr:\n    {}",
            signal_of(&status),
            tail(&stderr)
        )),
    }
}

/// How many runs go at once: `WZ_ALLOC_FAULT_JOBS`, or the machine's parallelism.
fn jobs() -> usize {
    match std::env::var("WZ_ALLOC_FAULT_JOBS") {
        Ok(text) => text
            .trim()
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("WZ_ALLOC_FAULT_JOBS={text:?} is not a number"))
            .clamp(1, 64),
        Err(_) => std::thread::available_parallelism().map_or(4, usize::from),
    }
}

/// What the runs of a sweep came to.
#[derive(Default)]
struct Tally {
    in_the_handler: usize,
    named_errors: usize,
    absorbed: usize,
    not_reached: usize,
    failures: Vec<String>,
}

impl Tally {
    /// Judge the run of `point` against the run with no failure.
    fn judge(&mut self, call: Call, point: u64, outcome: Outcome, reference: &Verdict) {
        let mut broke = Vec::new();
        match outcome {
            Outcome::Broken(why) => broke.push(why),
            Outcome::EndedInTheHandler if MEMORY_TAKEN_AT_OPEN => {
                broke.push("the process ended in the allocation-failure handler".to_owned());
            }
            Outcome::EndedInTheHandler => self.in_the_handler += 1,
            Outcome::Returned(verdict) => {
                if verdict.panics != 0 {
                    broke.push(format!("{} panic(s)", verdict.panics));
                }
                if !verdict.balanced {
                    broke.push("a closure the library was handed was not dropped".to_owned());
                }
                if !verdict.dropped {
                    broke.push("a transport was not let go".to_owned());
                }
                if !verdict.fired {
                    if verdict.rc != Z_OK {
                        broke.push(format!(
                            "with no allocation failed the call returned {}",
                            verdict.rc
                        ));
                    }
                    self.not_reached += 1;
                } else {
                    if verdict.rc != Z_OK && !NAMED_ALLOCATION_ERRORS.contains(&verdict.rc) {
                        broke.push(format!(
                            "returned {}, not a named allocation error ({NAMED_ALLOCATION_ERRORS:?})",
                            verdict.rc
                        ));
                    }
                    if verdict.held > reference.held {
                        broke.push(format!(
                            "left {} allocation(s) behind once closed",
                            verdict.held - reference.held
                        ));
                    }
                    if verdict.rc == Z_OK {
                        self.absorbed += 1;
                    } else {
                        self.named_errors += 1;
                    }
                }
            }
        }
        for why in broke {
            self.failures
                .push(format!("{} at {point}: {why}", call.name()));
        }
    }
}

/// The test of `call`: a run of this process started by the sweep, or the sweep.
fn sweep(call: Call) {
    if let Ok(request) = std::env::var(RUN_VARIABLE) {
        let (name, point) = request
            .split_once(':')
            .unwrap_or_else(|| panic!("{RUN_VARIABLE}={request:?} is not <call>:<point>"));
        let started_as = Call::from_name(name)
            .unwrap_or_else(|| panic!("{RUN_VARIABLE}={request:?} names no call"));
        assert_eq!(
            started_as, call,
            "a run of {name} was started as the test of {call:?}"
        );
        let point = point
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("{RUN_VARIABLE}={request:?}: the point is not a number"));
        run_once(call, point);
        return;
    }

    let engine = if cfg!(feature = "engine-tokio") {
        "tokio engine"
    } else {
        "cooperative engine"
    };
    let reference = match outcome(run_child(call.test_name(), &format!("{}:0", call.name()))) {
        Outcome::Returned(verdict) => verdict,
        other => panic!(
            "{}: the run with no failure did not return: {other:?}",
            call.name()
        ),
    };
    assert!(
        !reference.fired && reference.rc == Z_OK,
        "{}: with no failure the call returns Z_OK: {reference:?}",
        call.name()
    );
    assert!(
        reference.balanced && reference.dropped && reference.panics == 0,
        "{}: the run with no failure leaves every closure and transport dropped and no panic: \
         {reference:?}",
        call.name()
    );
    if !MEMORY_TAKEN_AT_OPEN {
        assert!(
            reference.allocations > 0,
            "{}: a heap build allocates in the call, and a count of 0 means the counter sees \
             nothing",
            call.name()
        );
    }

    // Every point the run with no failure reached, then on past it until a run makes fewer
    // allocations than its point: the count moves a little from run to run, with the threads.
    let reach = reference.allocations;
    let last = reach + reach.max(256);
    let jobs = jobs();
    let mut tally = Tally::default();
    let mut next = 1u64;
    let mut end = None;
    while end.is_none() {
        assert!(
            next <= last,
            "{}: a run still met its failing allocation at {last}, past the {reach} the run \
             with no failure made",
            call.name()
        );
        let points: Vec<u64> = (next..=last).take(jobs).collect();
        next += points.len() as u64;
        let runs: Vec<(u64, JoinHandle<Outcome>)> = points
            .iter()
            .map(|&point| {
                let request = format!("{}:{point}", call.name());
                let run =
                    std::thread::spawn(move || outcome(run_child(call.test_name(), &request)));
                (point, run)
            })
            .collect();
        for (point, run) in runs {
            let outcome = run.join().expect("a run's reader ends");
            let ended_here = matches!(&outcome, Outcome::Returned(verdict) if !verdict.fired);
            tally.judge(call, point, outcome, &reference);
            // The points of a batch come in order, so the first that ends is the least.
            if ended_here && point > reach && end.is_none() {
                end = Some(point);
            }
        }
    }
    let end = end.expect("the loop ends on an end");

    let mut report = String::new();
    let _ = write!(
        report,
        "{} ({engine}): {reach} allocation(s) in the call with none failed, {} held once closed; \
         points 1 to {} run: ended in the allocation-failure handler {}, returned a named error \
         {}, returned Z_OK {}, not reached {}",
        call.name(),
        reference.held,
        next - 1,
        tally.in_the_handler,
        tally.named_errors,
        tally.absorbed,
        tally.not_reached,
    );
    eprintln!("{report}; the first point no run reached: {end}");
    assert!(
        tally.failures.is_empty(),
        "{} run(s) of {} broke the contract:\n  {}",
        tally.failures.len(),
        call.name(),
        tally.failures.join("\n  ")
    );
}

// ---------------------------------------------------------------------------------------------
// Traffic between open sessions.

/// How many messages are exchanged before the count, so that what the library makes on the first
/// exchanges (a route, a buffer grown to its size) is made, and how many are counted.
const WARM_UP: usize = 20;
const COUNTED: usize = 200;

#[derive(Clone, Copy, Debug)]
enum Traffic {
    Puts,
    Gets,
}

/// One message of `traffic` from the dialler, waited for to its end.
unsafe fn exchange(pair: &Pair, traffic: Traffic) {
    match traffic {
        Traffic::Puts => {
            let heard = pair.counts.heard.load(Ordering::SeqCst);
            let mut bytes = payload();
            assert_eq!(put(pair.dialler(), &mut bytes), Z_OK, "a put is taken");
            assert!(
                wait_for(WAIT_BOUND, || pair.counts.heard.load(Ordering::SeqCst)
                    > heard),
                "a put did not cross within {WAIT_BOUND:?}"
            );
        }
        Traffic::Gets => {
            let replies = pair.counts.replies.load(Ordering::SeqCst);
            let over = pair.counts.gets_over.load(Ordering::SeqCst);
            let mut closure = reply_closure(&pair.counts);
            assert_eq!(get(pair.dialler(), &mut closure), Z_OK, "a get is taken");
            assert!(
                wait_for(WAIT_BOUND, || pair.counts.gets_over.load(Ordering::SeqCst)
                    > over),
                "a get did not end within {WAIT_BOUND:?}"
            );
            assert!(
                pair.counts.replies.load(Ordering::SeqCst) > replies,
                "a get between open sessions is answered"
            );
        }
    }
}

/// The line a traffic run prints its count on.
const TRAFFIC_PREFIX: &str = "traffic-count:";

impl Traffic {
    fn name(self) -> &'static str {
        match self {
            Traffic::Puts => "puts",
            Traffic::Gets => "gets",
        }
    }

    /// The test that counts this traffic, which its run is started as.
    fn test_name(self) -> &'static str {
        match self {
            Traffic::Puts => "puts_between_open_sessions_are_counted_for_their_allocations",
            Traffic::Gets => "gets_between_open_sessions_are_counted_for_their_allocations",
        }
    }
}

/// The run of `traffic`, in a process of its own as every run of this file is (`run_child`):
/// the pair opened, the warm-up, the counted messages, everything closed, the count printed.
fn measure_traffic(traffic: Traffic) {
    count_panics();
    let seen = unsafe {
        let pair = Pair::open(true);
        for _ in 0..WARM_UP {
            exchange(&pair, traffic);
        }
        std::thread::sleep(Duration::from_millis(200));
        open_window(0);
        for _ in 0..COUNTED {
            exchange(&pair, traffic);
        }
        let seen = close_window();
        let (balanced, dropped) = pair.close();
        assert!(balanced, "every closure the library was handed is dropped");
        assert!(dropped, "both transports are let go");
        seen
    };
    assert_eq!(PANICS.load(Ordering::SeqCst), 0, "a thread panicked");
    println!(
        "{TRAFFIC_PREFIX} allocations={} bytes={}",
        seen.allocations, seen.bytes
    );
}

/// The test of `traffic`: its run, started by the test, or the test.
fn count_traffic(traffic: Traffic) {
    if let Ok(request) = std::env::var(RUN_VARIABLE) {
        assert_eq!(
            request,
            traffic.name(),
            "a run of {request} was started as the test of {traffic:?}"
        );
        measure_traffic(traffic);
        return;
    }

    let engine = if cfg!(feature = "engine-tokio") {
        "tokio engine"
    } else {
        "cooperative engine"
    };
    let ended = run_child(traffic.test_name(), traffic.name());
    let counted = match ended.status {
        Some(status) if status.success() => verdict_line(&ended.stdout, TRAFFIC_PREFIX),
        _ => None,
    };
    let Some(line) = counted else {
        panic!(
            "the {traffic:?} run did not end with its count ({:?}); stdout:\n    {}\nstderr:\n    {}",
            ended.status,
            tail(&ended.stdout),
            tail(&ended.stderr)
        );
    };
    let number = |name: &str| -> u64 {
        field(line, name)
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("the {traffic:?} count has no {name}: {line:?}"))
    };
    let allocations = number("allocations");
    let bytes = number("bytes");
    eprintln!(
        "{traffic:?} between open sessions ({engine}): {allocations} allocation(s) of {bytes} \
         bytes for {COUNTED} messages, {:.1} a message",
        allocations as f64 / COUNTED as f64,
    );
    if MEMORY_TAKEN_AT_OPEN {
        assert_eq!(
            allocations, 0,
            "{traffic:?} between open sessions allocate nothing in a fixed-memory build"
        );
    } else {
        assert!(
            allocations > 0,
            "a heap build allocates for its {traffic:?}, and a count of 0 means the counter sees \
             nothing"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The tests.

#[test]
#[ignore = "a run of a process per failing allocation; Layer S runs via --ignored"]
fn z_open_meets_a_failed_allocation_at_every_point_of_its_call() {
    sweep(Call::Open);
}

#[test]
#[ignore = "a run of a process per failing allocation; Layer S runs via --ignored"]
fn z_declare_subscriber_meets_a_failed_allocation_at_every_point_of_its_call() {
    sweep(Call::DeclareSubscriber);
}

#[test]
#[ignore = "a run of a process per failing allocation; Layer S runs via --ignored"]
fn z_declare_queryable_meets_a_failed_allocation_at_every_point_of_its_call() {
    sweep(Call::DeclareQueryable);
}

#[test]
#[ignore = "a run of a process per failing allocation; Layer S runs via --ignored"]
fn z_declare_publisher_meets_a_failed_allocation_at_every_point_of_its_call() {
    sweep(Call::DeclarePublisher);
}

#[test]
#[ignore = "a run of a process per failing allocation; Layer S runs via --ignored"]
fn z_put_meets_a_failed_allocation_at_every_point_of_its_call() {
    sweep(Call::Put);
}

#[test]
#[ignore = "a run of a process per failing allocation; Layer S runs via --ignored"]
fn z_get_meets_a_failed_allocation_at_every_point_of_its_call() {
    sweep(Call::Get);
}

#[test]
#[ignore = "counts the allocations of traffic between open sessions; Layer S runs via --ignored"]
fn puts_between_open_sessions_are_counted_for_their_allocations() {
    count_traffic(Traffic::Puts);
}

#[test]
#[ignore = "counts the allocations of traffic between open sessions; Layer S runs via --ignored"]
fn gets_between_open_sessions_are_counted_for_their_allocations() {
    count_traffic(Traffic::Gets);
}
