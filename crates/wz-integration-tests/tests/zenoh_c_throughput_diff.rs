// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A THROUGHPUT DIFFERENTIAL: the same upstream program, on the real library and on wz.
//!
//! Upstream's `z_pub_thr.c` and `z_sub_thr.c` are compiled UNMODIFIED against `libzenohc`
//! and against wz's `libwz_capi_c`, so the only thing that differs between two runs is
//! which implementation answers the `z_*` calls. A run is a subscriber that listens and a
//! publisher that dials it over loopback TCP, scouting off, congestion control `block` (the
//! example's own choice); the subscriber prints the rate of each round of `-n` messages.
//! That is a product-level number for the thing a replacement is judged on first, and until
//! this file nothing in the tree measured wz against anything.
//!
//! ## Four combinations, because one pair cannot say which side is slow
//!
//! Publisher and subscriber are chosen independently, so the four runs are reference to
//! reference (the baseline), wz publishing to the reference, the reference publishing to wz,
//! and wz to wz. The mixed two double as a wire-compatibility check in each direction, and
//! they localise a gap: if wz is slow only when it publishes, the cost is on its send path;
//! if only when it subscribes, on its receive and delivery path.
//!
//! ## What it asserts, and what it deliberately does not
//!
//! It asserts that EVERY combination measured something: a library that cannot carry the
//! traffic, or an example that no longer links, fails here. It does NOT assert a ratio. A
//! floor chosen before there is a measured distribution is a number written to be passed, and
//! this machine is shared (the build host held a load average above 20 on 32 cores while this
//! was designed), so the first job of the file is to print what the runs do, over several
//! interleaved repetitions, so that a floor can be taken from data and pinned in its own
//! change.
//!
//! ## How the noise is kept out of the comparison
//!
//! * the combinations take turns inside every repetition, and the order rotates by one each
//!   repetition, so a slow stretch of the host lands on all of them and a warm cache does
//!   not always favour the same one;
//! * the wz library is the RELEASE build, like the reference (see
//!   `wz_capi_c_release_cdylib`), and the file refuses to run on a stale one;
//! * each figure is the MEDIAN of every round of every repetition of its combination, with
//!   the minimum and maximum beside it, because the mean of a distribution with a stall in
//!   it describes the stall;
//! * beside every rate is what a message COSTS in CPU, per process. A rate is the host's
//!   answer as much as the library's: measured on a loaded build host, the same wz
//!   publisher ran at about 50,000 msg/s under the build tool's CPU weight and at over
//!   500,000 outside it, because it hands every frame to another thread and each hand-off
//!   waits for a core. CPU per message does not move with that wait.
//!
//! Sizes: a small message (header-bound), a kilobyte (the usual application size) and 64 KiB
//! (bandwidth-bound). `WZ_PERF_REPS` sets the repetitions (default 3).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    compile_zenoh_c_example, read_captured, wait_for_tcp_accept_alive, wz_capi_c_release_cdylib,
    zenoh_c_oracle, ChildGuard, PortReservation,
};

/// Rounds the subscriber prints per run. It prints one more than it is asked for before it
/// exits, so this is also the least number of figures a run must produce.
const ROUNDS: usize = 3;
/// How long a run gets to print its rounds before it is declared dead.
const RUN_BUDGET: Duration = Duration::from_secs(120);
/// How long the listener gets to accept.
const LISTEN_BUDGET: Duration = Duration::from_secs(15);
/// The payload sizes, in bytes.
const SIZES: [usize; 3] = [8, 1024, 65536];

/// Messages per round for a payload of `size` bytes: about 128 MiB per round, bounded so a
/// tiny message does not make a round last minutes and a large one does not make it a blink.
fn messages_per_round(size: usize) -> usize {
    ((128 * 1024 * 1024) / size).clamp(2_000, 500_000)
}

/// Which implementation answers the `z_*` calls.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Arm {
    Reference,
    Wz,
}

impl Arm {
    fn tag(self) -> &'static str {
        match self {
            Arm::Reference => "ref",
            Arm::Wz => "wz",
        }
    }
}

/// The two executables of one arm.
struct Pair {
    publisher: PathBuf,
    subscriber: PathBuf,
}

fn compile_pair(arm: Arm, dir: &Path, include: &Path, examples: &Path, libdir: &Path) -> Pair {
    let link = match arm {
        Arm::Reference => "zenohc",
        Arm::Wz => "wz_capi_c",
    };
    let build = |example: &str| -> PathBuf {
        compile_zenoh_c_example(example, dir, include, examples, libdir, link).unwrap_or_else(
            |diag| {
                panic!(
                    "upstream {example}.c does not link against the {} library\n{diag}",
                    arm.tag()
                )
            },
        )
    };
    Pair {
        publisher: build("z_pub_thr"),
        subscriber: build("z_sub_thr"),
    }
}

/// The rate figures a subscriber printed: every line of the form `<float> msg/s` that is not
/// the closing summary.
fn rates_in(output: &str) -> Vec<f64> {
    output
        .lines()
        .filter(|line| line.ends_with(" msg/s") && !line.contains("Stats being dropped"))
        .filter_map(|line| line.trim_end_matches(" msg/s").trim().parse::<f64>().ok())
        .collect()
}

/// What each thread of `pid` is doing: its name, state, CPU ticks, and the kernel function it
/// sleeps in. A process that burns CPU in one thread and a process whose threads all sleep
/// look the same in a process-wide total.
fn threads_of(pid: u32) -> String {
    let mut lines = Vec::new();
    if let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) {
        for task in tasks.flatten() {
            let dir = task.path();
            let stat = std::fs::read_to_string(dir.join("stat")).unwrap_or_default();
            let fields: Vec<&str> = stat.split_whitespace().collect();
            let wchan = std::fs::read_to_string(dir.join("wchan")).unwrap_or_default();
            lines.push(format!(
                "  tid {} {} state {} utime {} stime {} wchan {}",
                fields.first().copied().unwrap_or("?"),
                fields.get(1).copied().unwrap_or("?"),
                fields.get(2).copied().unwrap_or("?"),
                fields.get(13).copied().unwrap_or("?"),
                fields.get(14).copied().unwrap_or("?"),
                wchan.trim(),
            ));
        }
    }
    lines.sort();
    lines.join("\n")
}

/// Run one publisher against one subscriber once and return what it measured.
fn run_once(publisher: &Path, subscriber: &Path, size: usize) -> Run {
    let reservation = PortReservation::pick();
    let port = reservation.port();
    let listen = format!("tcp/127.0.0.1:{port}");

    let capture = tempfile::tempfile().expect("tempfile for the subscriber's stdout");
    let mut log = capture.try_clone().expect("dup the capture handle");
    let errors = tempfile::tempfile().expect("tempfile for the subscriber's stderr");
    let mut error_log = errors.try_clone().expect("dup the stderr handle");
    // `stdbuf` makes the subscriber's rate lines reach the capture as they are
    // printed. Into a file its `printf` is block-buffered, so a pair that is
    // slow (or stuck) shows an empty capture until the process exits, and a run
    // that measured something reads the same as one that measured nothing.
    // `stdbuf` replaces itself with the subscriber, so the pid is the same.
    let sub = Command::new("stdbuf")
        .arg("-oL")
        .arg(subscriber)
        .args(["-m", "peer", "-l", &listen, "--no-multicast-scouting"])
        .args(["-s", &ROUNDS.to_string()])
        .args(["-n", &messages_per_round(size).to_string()])
        .stdout(Stdio::from(capture))
        .stderr(Stdio::from(errors))
        .spawn()
        .expect("spawn the throughput subscriber");
    let mut sub = ChildGuard::wrap("z_sub_thr", sub);
    wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_BUDGET)
        .unwrap_or_else(|why| panic!("the subscriber never accepted on {listen}: {why}"));
    drop(reservation);

    let publisher = Command::new(publisher)
        .args(["-m", "peer", "-e", &listen, "--no-multicast-scouting"])
        .arg(size.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the throughput publisher");
    let publisher_pid = publisher.id();
    let _publisher = ChildGuard::wrap("z_pub_thr", publisher);

    let started = Instant::now();
    // What a run that measured too little leaves to be read: how it ended, how
    // long it ran, and what the subscriber said on each stream. A bare count of
    // rates cannot tell a hang from a crash from a wrong flag.
    let diagnosis = |sub: &mut ChildGuard,
                     log: &mut std::fs::File,
                     error_log: &mut std::fs::File,
                     seen: &[f64]| {
        let pid = sub.child_mut().id();
        // The two things that tell an idle process from a busy one, and a
        // connection nobody reads from one that is flowing: the subscriber's CPU
        // time and thread count, and the socket queues of the link on its port.
        let cpu = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        let cpu_ticks: Vec<&str> = cpu.split_whitespace().skip(13).take(2).collect();
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        let status: Vec<&str> = status
            .lines()
            .filter(|l| l.starts_with("Threads") || l.contains("ctxt_switches"))
            .collect();
        let sockets = Command::new("ss")
            .args([
                "-tn",
                "-o",
                &format!("( sport = :{port} or dport = :{port} )"),
            ])
            .output_bounded()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        eprintln!(
            "throughput-diff: a run at {size} B measured {} of {ROUNDS} rate(s) after {:?}; \
             subscriber status {:?}; utime/stime ticks {cpu_ticks:?}; {status:?}\n\
             --- sockets on the port ---\n{sockets}\n\
             --- subscriber threads ---\n{}\n--- publisher threads ---\n{}\n\
             --- subscriber stdout ---\n{}\n--- subscriber stderr ---\n{}",
            seen.len(),
            started.elapsed(),
            sub.child_mut().try_wait(),
            threads_of(pid),
            threads_of(publisher_pid),
            read_captured(log),
            read_captured(error_log),
        );
    };
    let subscriber_pid = sub.child_mut().id();
    // The CPU both processes spent between the first rate line and the last one,
    // over the messages those rounds carried: what a message COSTS, which a
    // shared host does not change. Wall-clock rates move with whatever else runs
    // on the machine (a thread that must be woken per message waits for a core
    // each time, and under load that wait is the whole rate), so the rate says
    // how the host was and this says what the library does.
    let mut window_start: Option<(u64, u64)> = None;
    let mut cpu_cost = None;
    loop {
        let seen = rates_in(&read_captured(&mut log));
        if window_start.is_none() && !seen.is_empty() {
            window_start = cpu_ticks(publisher_pid).zip(cpu_ticks(subscriber_pid));
        }
        if seen.len() >= ROUNDS {
            if let (Some((pub_from, sub_from)), Some(pub_to), Some(sub_to)) = (
                window_start,
                cpu_ticks(publisher_pid),
                cpu_ticks(subscriber_pid),
            ) {
                let messages = ((ROUNDS - 1) * messages_per_round(size)) as f64;
                let per_message = |ticks: u64| ticks as f64 * US_PER_TICK / messages;
                cpu_cost = Some(CpuCost {
                    publisher_us: per_message(pub_to.saturating_sub(pub_from)),
                    subscriber_us: per_message(sub_to.saturating_sub(sub_from)),
                });
            }
            return Run {
                rates: seen,
                cpu_cost,
            };
        }
        if let Ok(Some(_)) = sub.child_mut().try_wait() {
            // The subscriber exits after its last round; whatever it printed is final.
            let seen = rates_in(&read_captured(&mut log));
            if seen.len() < ROUNDS {
                diagnosis(&mut sub, &mut log, &mut error_log, &seen);
            }
            return Run {
                rates: seen,
                cpu_cost: None,
            };
        }
        if started.elapsed() > RUN_BUDGET {
            diagnosis(&mut sub, &mut log, &mut error_log, &seen);
            return Run {
                rates: seen,
                cpu_cost: None,
            };
        }
        // Short, because the window's edges are read at this pace: a round of a
        // fast pair lasts a few hundred milliseconds.
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The microseconds one `/proc/<pid>/stat` tick stands for (`USER_HZ` is 100 on Linux).
const US_PER_TICK: f64 = 10_000.0;

/// User plus system CPU ticks of every thread of `pid`, or `None` once the process is gone.
fn cpu_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name is parenthesised and may hold spaces; the numbered fields follow it.
    let after_name = stat.rsplit_once(')')?.1;
    let mut fields = after_name.split_whitespace();
    // `utime` and `stime` are fields 14 and 15; the name was 2, the state is 3.
    let utime: u64 = fields.nth(11)?.parse().ok()?;
    let stime: u64 = fields.next()?.parse().ok()?;
    Some(utime + stime)
}

/// What one run measured: the subscriber's rate lines, and the CPU each side spent per message.
struct Run {
    rates: Vec<f64>,
    cpu_cost: Option<CpuCost>,
}

/// CPU time per message, in microseconds, summed over all threads of each process.
#[derive(Clone, Copy)]
struct CpuCost {
    publisher_us: f64,
    subscriber_us: f64,
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).expect("rates are finite"));
    let n = values.len();
    if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    }
}

/// [`median`] of values that may be absent: `0.0` for none, which the report prints as no figure.
fn median_or_zero(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        median(values)
    }
}

/// `value` as a multiple of `baseline`, `0.0` when either is unmeasured.
fn ratio(value: f64, baseline: f64) -> f64 {
    if value > 0.0 && baseline > 0.0 {
        value / baseline
    } else {
        0.0
    }
}

#[test]
#[ignore = "binary-dep e2e (zenoh-c oracle + the release cdylib); Layer P runs via --ignored"]
fn capi_c_throughput_examples_measured_on_libzenohc_and_on_wz() {
    let (include, ref_libdir, examples) = zenoh_c_oracle().unwrap_or_else(|| {
        panic!(
            "the zenoh-c oracle is absent: this measurement has nothing to compare wz with \
             (Layer P with WZ_P_REQUIRE fails instead of skipping)"
        )
    });
    let wz_lib = wz_capi_c_release_cdylib();
    let wz_libdir = wz_lib.parent().expect("cdylib has a parent").to_path_buf();

    let repetitions: usize = std::env::var("WZ_PERF_REPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(3);

    let dir = tempfile::tempdir().expect("a build directory");
    let ref_dir = dir.path().join("reference");
    let wz_dir = dir.path().join("wz");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    std::fs::create_dir_all(&wz_dir).expect("wz build dir");
    let reference = compile_pair(Arm::Reference, &ref_dir, &include, &examples, &ref_libdir);
    let wz = compile_pair(Arm::Wz, &wz_dir, &include, &examples, &wz_libdir);
    let pair_of = |arm: Arm| {
        if arm == Arm::Reference {
            &reference
        } else {
            &wz
        }
    };

    // (publisher, subscriber); the first is the baseline every ratio is taken against.
    let combos = [
        (Arm::Reference, Arm::Reference),
        (Arm::Wz, Arm::Reference),
        (Arm::Reference, Arm::Wz),
        (Arm::Wz, Arm::Wz),
    ];

    println!(
        "throughput-diff: {repetitions} repetition(s) x {ROUNDS} round(s) per combination, \
         combinations rotate, loopback tcp, scouting off, congestion control block"
    );
    let mut summary = Vec::new();
    for size in SIZES {
        let mut rates: Vec<Vec<f64>> = vec![Vec::new(); combos.len()];
        let mut publisher_cost: Vec<Vec<f64>> = vec![Vec::new(); combos.len()];
        let mut subscriber_cost: Vec<Vec<f64>> = vec![Vec::new(); combos.len()];
        for rep in 0..repetitions {
            for turn in 0..combos.len() {
                let index = (turn + rep) % combos.len();
                let (publisher, subscriber) = combos[index];
                let run = run_once(
                    &pair_of(publisher).publisher,
                    &pair_of(subscriber).subscriber,
                    size,
                );
                assert!(
                    run.rates.len() >= ROUNDS,
                    "publisher {} to subscriber {} at {size} B printed {} rate(s) where \
                     {ROUNDS} were owed: the pair could not carry the traffic, or the \
                     example's output changed",
                    publisher.tag(),
                    subscriber.tag(),
                    run.rates.len()
                );
                rates[index].extend(run.rates);
                if let Some(cost) = run.cpu_cost {
                    publisher_cost[index].push(cost.publisher_us);
                    subscriber_cost[index].push(cost.subscriber_us);
                }
            }
        }
        let baseline = median(&mut rates[0].clone());
        let baseline_cost = (
            median_or_zero(&mut publisher_cost[0].clone()),
            median_or_zero(&mut subscriber_cost[0].clone()),
        );
        for (index, (publisher, subscriber)) in combos.iter().enumerate() {
            let values = &mut rates[index];
            let lo = values.iter().cloned().fold(f64::INFINITY, f64::min);
            let hi = values.iter().cloned().fold(0.0, f64::max);
            let mid = median(values);
            let pub_cost = median_or_zero(&mut publisher_cost[index]);
            let sub_cost = median_or_zero(&mut subscriber_cost[index]);
            println!(
                "throughput-diff: {size:>6} B  pub {:<3} -> sub {:<3}  median {:>12.0} msg/s \
                 [{:.0}..{:.0}]  vs ref->ref {:.3}   cpu/msg pub {:.2} us ({:.1}x)  sub {:.2} us ({:.1}x)",
                publisher.tag(),
                subscriber.tag(),
                mid,
                lo,
                hi,
                mid / baseline,
                pub_cost,
                ratio(pub_cost, baseline_cost.0),
                sub_cost,
                ratio(sub_cost, baseline_cost.1),
            );
            summary.push(format!(
                "{size}B {}>{}={:.3}",
                publisher.tag(),
                subscriber.tag(),
                mid / baseline
            ));
        }
    }
    println!(
        "throughput-diff: cpu/msg is the CPU one message costs each process (all threads, user plus \
         system) between the first and last rate line; it does not move with the host's load, the \
         msg/s above does"
    );
    println!(
        "throughput-diff: medians vs ref->ref: {}",
        summary.join("  ")
    );
}
