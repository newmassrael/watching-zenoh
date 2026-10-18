// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The cost of one forwarded message, against how many subscribers a `--router-hat` router holds and
//! how fast they come and go (`docs/router-data-plane-scaling.md`, sections 1 and 5).
//!
//! ## What this is, and what it does not assert
//!
//! A measurement. It starts the demo as a router, connects N sessions to it from other processes, each
//! subscribing to its own key and publishing to its neighbour's, holds the offered load at the same
//! number of messages per second whatever N is, and reads the router's CPU time from `/proc` and the
//! number of messages it forwarded from its own log. Then it prints microseconds of CPU per message.
//! Rows that differ in N and in nothing else are what make the number mean something.
//!
//! No timing is asserted, for the reason `run-ci.sh`'s decode-cost lane gives: a wall-clock or CPU
//! ceiling on a shared runner is a flake generator. What is asserted is the population, so that a run
//! which measured something other than the data plane says so instead of printing a confident number:
//! every session connected, none was refused, nobody went DOWN in a steady window, and the router
//! forwarded at least 80% of what was offered. The structural claims about the data plane are held by
//! counters in the router's own tests, which are exact.
//!
//! ## Reading the output
//!
//! Run with `--nocapture`. The columns are the CPU the router used per forwarded message, the messages
//! per second it forwarded, and the share of the offered load that arrived. The number is only
//! comparable with another row of the same run: the host, the build, and the load are all in it.
//!
//! Opt-in (`#[ignore]`): it needs the demo built with `router-hat-router`, and holds a few hundred to
//! a couple of thousand local connections for about a minute per row. The name carries `wz_router` so
//! Layer E's sweep does not adopt it.

#![cfg(target_os = "linux")]

use std::collections::VecDeque;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, project_root, ChildGuard,
};

/// The offered load, in messages per second, held constant across rows.
const OFFERED_PER_S: u64 = 8_000;
/// The niceness a starved router runs at, against hogs at the default.
const ROUTER_NICE: i32 = 10;
/// The measurement window.
const WINDOW: Duration = Duration::from_secs(20);
/// The client processes the population is split across.
const CLIENT_PROCESSES: usize = 4;
/// The sessions a churn process holds, and how long it lives.
const CHURN_SESSIONS: usize = 4;
const CHURN_LIFETIME: Duration = Duration::from_secs(8);
/// A churn process is started this often: 4 processes a second is 16 sessions a second.
const CHURN_EVERY: Duration = Duration::from_millis(250);
/// `/proc/<pid>/stat` counts CPU time in USER_HZ, which is 100 on every architecture Rust targets.
const USER_HZ: f64 = 100.0;

/// The release build of the demo. A measurement of a debug build is a number about something else,
/// so unlike the fixtures that only need a working demo this one does not fall back to `target/debug`.
fn release_demo_binary() -> PathBuf {
    let demo = project_root().join("crates/target/release/wz-ap-demo");
    assert!(
        demo.is_file(),
        "{} not found; build it with `cargo build --release -p wz-ap-demo --no-default-features \
         --features preset-ap-client,router-hat-router`",
        demo.display()
    );
    demo
}

/// The build this measures is the server build: the router hat, and without the io_uring runtime,
/// whose per-connection registered buffers would be the thing measured instead.
fn assert_is_server_build(banner: &str) {
    assert!(
        banner.contains("router-hat-router"),
        "the demo was not built with `router-hat-router`: {banner}"
    );
    assert!(
        !banner.contains("runtime-tokio-uring"),
        "the demo was built with `runtime-tokio-uring`, whose 32 MiB per-face buffer region would \
         be what this measures: {banner}"
    );
}

/// What the router's own log has said so far.
struct Router {
    guard: ChildGuard,
    port: u16,
    up: Arc<AtomicUsize>,
    down: Arc<AtomicUsize>,
    refused: Arc<AtomicUsize>,
    pushes: Arc<AtomicU64>,
}

/// Run `demo` with `args` under a shell that raises the soft open-files limit to the hard one first
/// and then `exec`s it, so the process this returns is the demo itself (its `/proc` entry is read).
/// A router holding two thousand sessions needs more descriptors than a default login shell allows.
/// With `pin`, the demo runs on that one core at a lower priority (`taskset` and `nice`, which also
/// `exec`): the scheduler shares a core between THREADS, and the demo has several busy ones, so
/// without the lower priority three hogs would still leave it most of the core.
fn command_with_raised_limit(demo: &Path, args: &[&str], pin: Option<usize>) -> Command {
    let mut command = Command::new("sh");
    let script = match pin {
        Some(core) => format!(
            "ulimit -n \"$(ulimit -Hn)\" 2>/dev/null; \
             exec nice -n {ROUTER_NICE} taskset -c {core} \"$0\" \"$@\""
        ),
        None => "ulimit -n \"$(ulimit -Hn)\" 2>/dev/null; exec \"$0\" \"$@\"".to_string(),
    };
    command.arg("-c").arg(script).arg(demo).args(args);
    command
}

/// The highest core this process may run on, from the kernel's own list (`0-31`, `0,2-5`, ...).
fn last_allowed_core() -> usize {
    let status = fs::read_to_string("/proc/self/status").expect("/proc/self/status");
    let list = status
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
        .expect("Cpus_allowed_list")
        .trim();
    list.split(',')
        .filter_map(|part| part.rsplit('-').next()?.parse::<usize>().ok())
        .max()
        .expect("a core in the allowed list")
}

/// A process that burns one core flat out on `core`, to take CPU from whatever else runs there, as a
/// neighbour does on a shared host.
fn spawn_cpu_hog(core: usize) -> ChildGuard {
    let child = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "exec taskset -c {core} sh -c 'while :; do :; done'"
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("a CPU hog starts");
    ChildGuard::wrap("cpu hog", child)
}

/// The port the router says it listens on, from its log line.
fn listening_port(line: &str) -> Option<u16> {
    let rest = line.split("listening on 127.0.0.1:").nth(1)?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// The running total in `forwarded mesh data (N push(es))`.
fn forwarded_pushes(line: &str) -> Option<u64> {
    let rest = line.split("forwarded mesh data (").nth(1)?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn spawn_router(demo: &Path, pin: Option<usize>) -> Router {
    let mut child = command_with_raised_limit(
        demo,
        &["--router-hat", "127.0.0.1:0", "--max-sessions", "20000"],
        pin,
    )
    .env("RUST_LOG", "info")
    .stdout(Stdio::null())
    .stderr(Stdio::piped())
    .spawn()
    .expect("the demo starts as a router");
    let stderr = child.stderr.take().expect("the router's stderr is piped");
    let guard = ChildGuard::wrap("wz-ap-demo router-hat", child);

    let up = Arc::new(AtomicUsize::new(0));
    let down = Arc::new(AtomicUsize::new(0));
    let refused = Arc::new(AtomicUsize::new(0));
    let pushes = Arc::new(AtomicU64::new(0));
    let (port_tx, port_rx) = mpsc::channel();
    {
        let (up, down, refused, pushes) = (
            Arc::clone(&up),
            Arc::clone(&down),
            Arc::clone(&refused),
            Arc::clone(&pushes),
        );
        thread::spawn(move || {
            let mut port_tx = Some(port_tx);
            let mut banner = String::new();
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if line.contains("BUILD FEATURES =") {
                    banner = line.clone();
                }
                if let Some(port) = listening_port(&line) {
                    if let Some(tx) = port_tx.take() {
                        let _ = tx.send((port, banner.clone()));
                    }
                }
                if line.contains(" UP (peer ") {
                    up.fetch_add(1, Ordering::Relaxed);
                } else if line.contains(" DOWN (peer ") {
                    down.fetch_add(1, Ordering::Relaxed);
                } else if line.contains("REFUSED") {
                    refused.fetch_add(1, Ordering::Relaxed);
                } else if let Some(total) = forwarded_pushes(&line) {
                    pushes.store(total, Ordering::Relaxed);
                }
            }
        });
    }
    let (port, banner) = port_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the router said which port it listens on");
    assert_is_server_build(&banner);
    Router {
        guard,
        port,
        up,
        down,
        refused,
        pushes,
    }
}

/// A `--sessions` document of `count` sessions numbered from `first`, out of `total`: each subscribes
/// to its own key and publishes to the next one's every `period_ms`, `publishes` times.
fn steady_document(
    first: usize,
    count: usize,
    total: usize,
    port: u16,
    period_ms: u64,
    publishes: u64,
    after_ms: u64,
) -> String {
    let mut out = String::from("{ sessions: [\n");
    for i in first..first + count {
        let next = (i + 1) % total;
        out.push_str(&format!(
            "  {{ name: \"dev_{i}\", mode: \"client\", transport: \"unicast\", zid: \"{:x}\",\n\
             \x20   connect: {{ endpoints: [\"tcp/127.0.0.1:{port}\"] }},\n\
             \x20   driver: [ {{ role: \"subscribe\", key: \"mesh/dev_{i}\" }},\n\
             \x20             {{ role: \"publish\", key: \"mesh/dev_{next}\", payload: \"hello-world-0123456789\", \
             period_ms: {period_ms}, count: {publishes}, after_ms: {after_ms} }} ] }},\n",
            0x10_0000 + i,
        ));
    }
    out.push_str("] }\n");
    out
}

/// A document for one churn process: sessions that subscribe to a key of their own and publish nothing.
fn churn_document(generation: usize, port: u16) -> String {
    let mut out = String::from("{ sessions: [\n");
    for j in 0..CHURN_SESSIONS {
        out.push_str(&format!(
            "  {{ name: \"ch_{generation}_{j}\", mode: \"client\", transport: \"unicast\", zid: \"{:x}\",\n\
             \x20   connect: {{ endpoints: [\"tcp/127.0.0.1:{port}\"] }},\n\
             \x20   driver: [ {{ role: \"subscribe\", key: \"mesh/ch_{generation}_{j}\" }} ] }},\n",
            0x80_0000 + generation * 8 + j,
        ));
    }
    out.push_str("] }\n");
    out
}

fn spawn_sessions(demo: &Path, document: &Path, label: &str) -> ChildGuard {
    let child = command_with_raised_limit(
        demo,
        &["--sessions", document.to_str().expect("a UTF-8 path")],
        None,
    )
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .expect("the demo starts a sessions document");
    ChildGuard::wrap(label.to_string(), child)
}

/// The router process's user plus system CPU time, in seconds.
fn cpu_seconds(pid: u32) -> f64 {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).expect("the router's /proc entry");
    // The command name is parenthesised and may hold spaces; the fields start after its closing one.
    let after = stat.rfind(')').expect("the command name closes");
    let fields: Vec<&str> = stat[after + 2..].split_whitespace().collect();
    let utime: f64 = fields[11].parse().expect("utime");
    let stime: f64 = fields[12].parse().expect("stime");
    (utime + stime) / USER_HZ
}

/// What a run holds fixed.
#[derive(Clone, Copy)]
struct Scenario {
    subscribers: usize,
    /// Short-lived sessions join and leave through the window at 16 a second.
    churn: bool,
    /// Messages per second all the publishers offer together.
    offered: u64,
    /// The router runs on one core, at a lower priority, shared with this many CPU hogs that start
    /// once every session is in. `None` leaves it the host.
    starved_by: Option<usize>,
}

/// What one window measured.
struct Window {
    seconds: f64,
    cpu_s: f64,
    forwarded: u64,
    down: usize,
    offered: u64,
    /// Sessions that came up during the window, and how many the churn started in it.
    admitted: usize,
    attempted: usize,
}

impl Window {
    fn micros_per_message(&self) -> f64 {
        1e6 * self.cpu_s / self.forwarded.max(1) as f64
    }
    fn messages_per_second(&self) -> f64 {
        self.forwarded as f64 / self.seconds
    }
    fn delivered_share(&self) -> f64 {
        self.messages_per_second() / self.offered as f64
    }
}

/// Connect the scenario's sessions to a fresh router, hold its offered load for a window, and read
/// the router's CPU and what it forwarded.
fn measure(scenario: Scenario) -> Window {
    let Scenario {
        subscribers,
        churn,
        offered,
        starved_by,
    } = scenario;
    assert_eq!(
        subscribers % CLIENT_PROCESSES,
        0,
        "the population splits evenly over the client processes"
    );
    let demo = release_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let core = starved_by.map(|_| last_allowed_core());
    let mut router = spawn_router(&demo, core);
    let router_pid = router.guard.child_mut().id();
    let dir = tempfile::tempdir().expect("a directory for the sessions documents");

    // Publishing must outlast settle plus window plus a margin, whenever a session came up.
    let period_ms = (subscribers as u64 * 1000 / offered).max(1);
    let after_ms: u64 = 2_000;
    let settle = Duration::from_millis(after_ms) + Duration::from_secs(4);
    let publishes = (settle + WINDOW + Duration::from_secs(60)).as_millis() as u64 / period_ms;
    let per_process = subscribers / CLIENT_PROCESSES;
    let mut clients = Vec::new();
    for p in 0..CLIENT_PROCESSES {
        let path = dir.path().join(format!("steady-{p}.json5"));
        fs::write(
            &path,
            steady_document(
                p * per_process,
                per_process,
                subscribers,
                router.port,
                period_ms,
                publishes,
                after_ms,
            ),
        )
        .expect("write the sessions document");
        clients.push(spawn_sessions(&demo, &path, "wz-ap-demo sessions"));
    }

    let up_deadline = Instant::now() + Duration::from_secs(60 + subscribers as u64 / 20);
    while router.up.load(Ordering::Relaxed) < subscribers {
        assert!(
            Instant::now() < up_deadline,
            "only {} of {subscribers} sessions came up (refused {}, went DOWN {})",
            router.up.load(Ordering::Relaxed),
            router.refused.load(Ordering::Relaxed),
            router.down.load(Ordering::Relaxed),
        );
        thread::sleep(Duration::from_millis(200));
    }
    thread::sleep(settle);

    // A starved router takes its CPU away only now, after every session is in and the load is
    // flowing, so what the window measures is the links under overload and not whether a router that
    // is short of CPU can still admit sessions (which is its own question).
    let hogs: Vec<ChildGuard> = core
        .into_iter()
        .flat_map(|core| (0..starved_by.unwrap_or(0)).map(move |_| spawn_cpu_hog(core)))
        .collect();

    let (cpu_before, pushes_before, down_before, up_before) = (
        cpu_seconds(router_pid),
        router.pushes.load(Ordering::Relaxed),
        router.down.load(Ordering::Relaxed),
        router.up.load(Ordering::Relaxed),
    );
    let started = Instant::now();
    let mut waves: VecDeque<(Instant, ChildGuard)> = VecDeque::new();
    let mut generation = 0;
    while started.elapsed() < WINDOW {
        if churn {
            generation += 1;
            let path = dir.path().join(format!("churn-{generation}.json5"));
            fs::write(&path, churn_document(generation, router.port))
                .expect("write the churn document");
            waves.push_back((
                Instant::now(),
                spawn_sessions(&demo, &path, "wz-ap-demo churn"),
            ));
            while waves
                .front()
                .is_some_and(|(born, _)| born.elapsed() >= CHURN_LIFETIME)
            {
                waves.pop_front();
            }
        }
        thread::sleep(CHURN_EVERY);
    }
    let window = Window {
        seconds: started.elapsed().as_secs_f64(),
        cpu_s: cpu_seconds(router_pid) - cpu_before,
        forwarded: router.pushes.load(Ordering::Relaxed) - pushes_before,
        down: router.down.load(Ordering::Relaxed) - down_before,
        offered,
        admitted: router.up.load(Ordering::Relaxed) - up_before,
        attempted: generation * CHURN_SESSIONS,
    };
    drop(waves);
    drop(clients);
    drop(hogs);

    // The population: a run that failed any of this measured something other than the data plane.
    assert_eq!(
        router.refused.load(Ordering::Relaxed),
        0,
        "the router refused sessions; the run measured its session bound"
    );
    if !churn {
        assert_eq!(
            window.down, 0,
            "{} faces went DOWN in a steady window; the run measured a collapse",
            window.down
        );
    }
    // A starved router is overloaded on purpose, so how much it forwards is the answer there and
    // not a precondition; that no face went DOWN is what is asserted, above.
    if starved_by.is_none() {
        assert!(
            window.delivered_share() >= 0.8,
            "the router forwarded {:.0}% of the offered load; the run measured an overload",
            100.0 * window.delivered_share()
        );
    }
    window
}

#[test]
#[ignore = "opt-in measurement: spawns wz-ap-demo built with router-hat-router, holds up to 2048 local sessions; run with --ignored --nocapture"]
fn wz_router_hat_cost_per_message_against_subscribers_and_churn() {
    let rows = [
        (256, false),
        (1024, false),
        (2048, false),
        (256, true),
        (1024, true),
    ];
    eprintln!(
        "\nrouter CPU per forwarded message, offered {OFFERED_PER_S} messages/s, window {}s",
        WINDOW.as_secs()
    );
    eprintln!(
        "{:>11} {:>22} {:>12} {:>10} {:>9}",
        "subscribers", "churn (16 sessions/s)", "us/message", "msg/s", "arrived"
    );
    for (subscribers, churn) in rows {
        let w = measure(Scenario {
            subscribers,
            churn,
            offered: OFFERED_PER_S,
            starved_by: None,
        });
        eprintln!(
            "{subscribers:>11} {:>22} {:>12.1} {:>10.0} {:>8.0}%",
            if churn { "on" } else { "off" },
            w.micros_per_message(),
            w.messages_per_second(),
            100.0 * w.delivered_share(),
        );
    }
}

/// I4 — a router that is overloaded AND short of CPU keeps its links. It runs on one core, at a lower
/// priority, with three busy processes sharing that core, and is offered several times what it then
/// forwards; this is the shape of a burstable micro VM under steal. What is asserted is the count of
/// faces that went DOWN in the window (zero): the control plane (keepalive, lease) is not starved by
/// the data it is shedding. How much it forwards is printed, not asserted.
#[test]
#[ignore = "opt-in measurement: spawns wz-ap-demo built with router-hat-router and four CPU hogs, holds 2048 local sessions; run with --ignored --nocapture"]
fn wz_router_hat_keeps_its_links_when_overloaded_and_short_of_cpu() {
    let offered = 40_000;
    let w = measure(Scenario {
        subscribers: 2048,
        churn: false,
        offered,
        starved_by: Some(3),
    });
    eprintln!(
        "\nstarved router (one shared core, lower priority), 2048 subscribers, offered {offered} messages/s: \
         forwarded {:.0} messages/s ({:.0}% of offered), {} faces went DOWN",
        w.messages_per_second(),
        100.0 * w.delivered_share(),
        w.down,
    );
}

/// The same starved, overloaded router asked for something else: whether it still admits sessions that
/// arrive. Sixteen short-lived sessions a second knock on a router that has a fraction of a core and
/// 2048 busy faces; the count admitted out of the count attempted is printed, not asserted, because
/// what a router in that state SHOULD admit is a design question this run puts a number to.
#[test]
#[ignore = "opt-in measurement: spawns wz-ap-demo built with router-hat-router and four CPU hogs, holds 2048 local sessions; run with --ignored --nocapture"]
fn wz_router_hat_admission_when_overloaded_and_short_of_cpu() {
    let offered = 40_000;
    let w = measure(Scenario {
        subscribers: 2048,
        churn: true,
        offered,
        starved_by: Some(3),
    });
    eprintln!(
        "\nstarved router, 2048 subscribers, offered {offered} messages/s, 16 sessions/s knocking: \
         admitted {} of {} attempted in {:.0}s",
        w.admitted, w.attempted, w.seconds,
    );
}
