// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2159 (open-debt item 229) — a node told to give up finitely GIVES UP, and a
//! node told nothing keeps running.
//!
//! ## What item 229 was
//!
//! `connect/{timeout_ms,exit_on_failure}` and the `listen/*` twins had been
//! unhonoured since the reader existed, and the item's own reading of why is
//! correct and worth keeping: a peer's upstream defaults are `-1` (never give
//! up) and `false` (never die of it), and wz already did exactly that. So the
//! DEFAULT axis was parity, and what was missing was every NON-default —
//! "finitely give up, and exit". The item recorded that wz had no lifecycle
//! substrate to hang that on. It did not, and `wz::runtime_tokio::startup_phase`
//! is the one this round built.
//!
//! ## Why a process test, and why it asserts an EXIT STATUS
//!
//! Every joint below the process is provable on its own and all of them were
//! green while the file was inert — open-debt item 479's class. The JSON5 leaf
//! parses (`zenoh_config`'s unit tests), the policy resolves
//! (`startup_phase`'s), the expansion emits the flags
//! (`args::stock_config_tests`). What no unit test can reach is the claim the
//! item is actually about, which is about a PROCESS: it stops, or it does not.
//!
//! And the status has to be read, not merely "it died". A node that panicked,
//! that refused its argv, or that failed for any other reason also stops, and
//! an operator's supervisor cannot act on "stopped". So the fatal arms assert
//! [`give_up_code`] — the demo's own [`STARTUP_PHASE_EXIT_CODE`], read out of
//! the source rather than copied here — which is distinct from the `1` a fault
//! carries and the `2` an argv refusal does.
//!
//! ## The control arms are the other half, and they are the DEFAULT
//!
//! Three arms here assert a node is STILL RUNNING. That is not a weaker
//! assertion than the fatal ones — it is the half that keeps this round from
//! having quietly changed what a stock peer does. wz's behaviour before this
//! round is upstream's default column, and a change that made an unconfigured
//! node give up would be a regression no fatal-arm test could see.
//!
//! ⚠ A liveness arm must never `wait()` on the child: these nodes run until a
//! signal, so waiting is a hang rather than a failure. Every arm here polls
//! `try_wait` against a budget and kills the child itself.
//!
//! ## Scope, named rather than left implicit
//!
//! `routing-peer`, because the two MESH run-modes are the wz hosts that own a
//! bind phase and a dial phase together, and `--peer` is the one this build
//! reaches. The `--router-hat` arm takes the identical bundle through the
//! identical helpers (`ConnectPhaseWatch`, `bind_all_endpoints`,
//! `mesh_exit_code`); what is NOT covered here is that it is wired to them,
//! which `args::stock_config_tests`' role-parity sweep asks of every honoured
//! key for both roles.

#![cfg(feature = "routing-peer")]

use std::io::Read;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// How long a fatal arm gets to actually exit, over and above its own budget.
/// Generous against a loaded build machine; only a FAILING arm pays it, because
/// the poll returns as soon as the child is gone.
const EXIT_SLACK: Duration = Duration::from_secs(20);

/// How long a liveness arm watches a node that must NOT stop.
///
/// Comfortably longer than the 1000 ms first re-dial wait of zenoh's default
/// schedule, so a node that gave up on its first refusal has had time to do it.
const LIVENESS_WATCH: Duration = Duration::from_millis(2500);

/// The demo's own exit status for a startup phase that gave up, read out of the
/// source it is declared in.
///
/// `include_str!` rather than a literal `3` here, for the R2140 rule: a test
/// carrying its own copy of a contract cannot notice the contract moving. The
/// two would then disagree silently, and the disagreement is exactly what these
/// arms exist to detect.
fn give_up_code() -> i32 {
    const SOURCE: &str = include_str!("../src/runner.rs");
    const NEEDLE: &str = "pub(crate) const STARTUP_PHASE_EXIT_CODE: u8 = ";
    let tail = SOURCE
        .split_once(NEEDLE)
        .unwrap_or_else(|| panic!("runner.rs no longer declares `{NEEDLE}`; re-anchor this test"))
        .1;
    let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
    digits
        .parse()
        .unwrap_or_else(|e| panic!("STARTUP_PHASE_EXIT_CODE is not a number ({e}): {digits:?}"))
}

/// A TCP port to DIAL that nothing is listening on: bound to learn the number,
/// then released.
///
/// ⚠ R2178 (open-debt item 553) — THIS IS A DIAL TARGET AND NEVER A LISTEN
/// ADDRESS, and the split is the repair rather than a naming preference. A
/// released number belongs to nobody: between this call and the demo's own
/// syscall the kernel may hand it to anyone. It did — R2175's push was refused
/// because BOTH listen endpoints of one arm came back `Address already in use
/// (os error 98)`, and the second of those was this port.
///
/// A dial target survives that window and a listen address cannot, which is
/// why one helper could not serve both. The worst a stolen number does to a
/// dial is let the connection SUCCEED, and no arm here reads that; for a
/// listen address, binding IS the assertion. [`listen_arg`] is where the
/// distinction is enforced instead of remembered.
fn dial_target_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port to learn and release");
    let port = listener.local_addr().expect("a readable address").port();
    drop(listener);
    port
}

/// A port that is OCCUPIED for as long as the returned listener is held.
///
/// Held by this test process rather than by a second demo, because what the
/// bind phase needs is an address it cannot have — the cheapest and most
/// deterministic source of that is a socket this process already owns.
fn occupied_port() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port to hold");
    let port = listener.local_addr().expect("a readable address").port();
    (listener, port)
}

/// How one listen endpoint gets its address — and the only two ways this
/// binary is allowed to name one.
///
/// Both keep the promise a listen address makes. A number that was learned and
/// released keeps neither, which is the whole of open-debt item 553.
enum ListenSpec {
    /// A port THIS PROCESS holds for the arm's duration. Nothing else can take
    /// it and the demo cannot have it, so the bind must FAIL — deterministically,
    /// because the holder is a socket this process owns.
    Held(u16),
    /// No number at all: the kernel picks a free port at bind time, so there is
    /// no window in which the choice can go stale. The bind must SUCCEED.
    KernelAssigned,
}

/// The `--peer` value. EVERY listen address this binary names is built here.
///
/// The chokepoint IS the mechanism. A rule written in a doc comment is one the
/// next author reads only if they happen to look at this function; a rule that
/// every `--peer` must route through here is one
/// [`no_listen_address_is_built_from_a_released_port`] can fail on. That test
/// reads this file's own source, in the same idiom [`give_up_code`] already
/// uses to read `runner.rs`.
fn listen_arg(specs: &[ListenSpec]) -> String {
    specs
        .iter()
        .map(|spec| match spec {
            ListenSpec::Held(port) => format!("tcp/127.0.0.1:{port}"),
            ListenSpec::KernelAssigned => String::from("tcp/127.0.0.1:0"),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Spawn the demo with `args`, stderr piped.
fn spawn(args: &[String]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_wz-ap-demo"))
        .args(args)
        // Pinned rather than inherited: the demo's logger defaults to `info`
        // only when RUST_LOG is unset, and a developer running the suite with
        // `RUST_LOG=warn` would otherwise see these arms fail for their shell's
        // reason rather than the code's.
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the demo binary runs")
}

/// Everything the child wrote, after it is no longer running.
fn transcript(child: &mut Child) -> String {
    let mut buf = String::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut buf);
    }
    buf
}

/// Run `args` and assert the node EXITS, returning `(status, elapsed, stderr)`.
///
/// `try_wait` in a poll loop rather than `wait`, and the child is killed if the
/// budget passes: a regression here is a node that does not stop, and `wait`
/// would turn that into a hung suite instead of a failed assertion.
fn assert_exits(case: &str, args: &[String], within: Duration) -> (i32, Duration, String) {
    let mut child = spawn(args);
    let started = Instant::now();
    let deadline = started + within + EXIT_SLACK;
    let status = loop {
        match child.try_wait().expect("the child's status is readable") {
            Some(status) => break Some(status),
            None if Instant::now() >= deadline => break None,
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    let elapsed = started.elapsed();
    let Some(status) = status else {
        let _ = child.kill();
        let _ = child.wait();
        let seen = transcript(&mut child);
        panic!(
            "{case}: the node was still running after {elapsed:?} and had to be killed.\n\
             argv = {args:?}\n--- transcript ---\n{seen}"
        );
    };
    let seen = transcript(&mut child);
    let code = status.code().unwrap_or_else(|| {
        panic!("{case}: the node was killed by a signal rather than exiting\n{seen}")
    });
    (code, elapsed, seen)
}

/// Run `args` and assert the node is STILL RUNNING after [`LIVENESS_WATCH`],
/// then kill it and return its transcript.
fn assert_still_running(case: &str, args: &[String]) -> String {
    let mut child = spawn(args);
    let deadline = Instant::now() + LIVENESS_WATCH;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("the child's status is readable") {
            let seen = transcript(&mut child);
            panic!(
                "{case}: the node STOPPED ({status}) and nothing asked it to. This is the \
                 default column of upstream's own table, so a node that gives up here is a \
                 regression in what a stock peer does.\n\
                 argv = {args:?}\n--- transcript ---\n{seen}"
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    transcript(&mut child)
}

fn argv(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| String::from(*s)).collect()
}

/// A subscriber keyexpr, because the demo refuses an invocation that asks for
/// no application behaviour at all — and a subscriber needs no `--value`
/// partner, so the argv stays as short as the case allows.
const APP: [&str; 2] = ["--subscribe", "demo/**"];

// ── ① the CONNECT phase, bounded and fatal ──────────────────────────────────

/// A finite `connect/timeout_ms` with `exit_on_failure: true` produces a node
/// that gives up AT the budget and exits with the give-up status.
///
/// The budget is asserted as a WINDOW rather than a ceiling: a node that exited
/// immediately would satisfy "it stopped within 800 ms" while proving that the
/// budget reached nothing. What this arm is about is that a bound the operator
/// wrote is the bound the node ran.
#[test]
fn a_bounded_connect_phase_gives_up_and_exits() {
    let target = format!("tcp/127.0.0.1:{}", dial_target_port());
    let listen = listen_arg(&[ListenSpec::KernelAssigned]);
    let (code, elapsed, seen) = assert_exits(
        "bounded connect phase",
        &argv(&[
            "--peer",
            &listen,
            "--connect",
            &target,
            "--connect-timeout",
            "800",
            "--connect-exit-on-failure",
            "true",
            "--connect-retry",
            "200,200,1",
        ])
        .into_iter()
        .chain(APP.iter().map(|s| String::from(*s)))
        .collect::<Vec<_>>(),
        Duration::from_millis(800),
    );
    assert_eq!(
        code,
        give_up_code(),
        "a phase that gave up as configured must be distinguishable from a fault \
         (1) and from an argv refusal (2)\n--- transcript ---\n{seen}"
    );
    assert!(
        elapsed >= Duration::from_millis(700),
        "the node stopped after {elapsed:?}, before its own 800ms budget — the \
         budget reached nothing\n--- transcript ---\n{seen}"
    );
    assert!(
        seen.contains("arm=RetryThenFail"),
        "the resolved policy is not the one the flags asked for\n{seen}"
    );
}

/// ② THE CONTROL — the same node with the clause omitted keeps running.
///
/// This is upstream's peer default (`timeout_ms: -1`, `exit_on_failure: false`)
/// and wz's behaviour before this round, so it is what a regression would break
/// first. The dial target is dead in both arms: the ONLY difference is the two
/// words the operator did or did not write.
#[test]
fn an_unbounded_connect_phase_keeps_the_node_running() {
    let target = format!("tcp/127.0.0.1:{}", dial_target_port());
    let listen = listen_arg(&[ListenSpec::KernelAssigned]);
    let seen = assert_still_running(
        "default connect phase",
        &argv(&["--peer", &listen, "--connect", &target])
            .into_iter()
            .chain(APP.iter().map(|s| String::from(*s)))
            .collect::<Vec<_>>(),
    );
    assert!(
        seen.contains("timeout_ms=-1 exit_on_failure=false arm=RetryInBackground"),
        "an unconfigured peer must resolve upstream's own default column\n{seen}"
    );
}

// ── ③ the LISTEN phase, fatal by default ────────────────────────────────────

/// An address that cannot be bound ends the node, and the status says the
/// listen phase is why.
///
/// `listen/exit_on_failure` defaults to `true` for every mode upstream, so this
/// arm is the DEFAULT being honoured rather than a non-default being reached —
/// which is why it names no flag. What moved this round is the STATUS: before
/// it, this exited `1` and was indistinguishable from any other fault.
#[test]
fn an_unbindable_listen_endpoint_ends_the_node() {
    let (held, occupied) = occupied_port();
    let listen = listen_arg(&[ListenSpec::Held(occupied), ListenSpec::KernelAssigned]);
    let (code, _, seen) = assert_exits(
        "unbindable listen endpoint",
        &argv(&["--peer", &listen])
            .into_iter()
            .chain(APP.iter().map(|s| String::from(*s)))
            .collect::<Vec<_>>(),
        Duration::from_millis(0),
    );
    drop(held);
    assert_eq!(
        code,
        give_up_code(),
        "a listener that cannot bind is a startup phase giving up, not an \
         unclassified fault\n--- transcript ---\n{seen}"
    );
    assert!(
        seen.contains("listen phase gave up"),
        "the diagnostic must name the phase\n{seen}"
    );
}

/// ④ THE CONTROL — `listen/exit_on_failure: false` comes up on what DID bind.
///
/// The bidirectional half of the arm above: same two addresses, same occupied
/// one, and the node lives. It is also where this key's own residue is
/// observable — the node reports which address it did NOT get, because a node
/// that came up on half its addresses in silence is the failure
/// `bind_all_endpoints` exists to prevent.
#[test]
fn a_non_fatal_listen_phase_comes_up_on_what_bound() {
    let (held, occupied) = occupied_port();
    let listen = listen_arg(&[ListenSpec::Held(occupied), ListenSpec::KernelAssigned]);
    let seen = assert_still_running(
        "non-fatal listen phase",
        &argv(&["--peer", &listen, "--listen-exit-on-failure", "false"])
            .into_iter()
            .chain(APP.iter().map(|s| String::from(*s)))
            .collect::<Vec<_>>(),
    );
    drop(held);
    assert!(
        seen.contains("arm=OnceThenSkip"),
        "the resolved listen policy is not the one the flag asked for\n{seen}"
    );
    assert!(
        seen.contains("came up on 1 of 2 listen endpoint(s)"),
        "a node that came up on a SUBSET must say which address it did not \
         get\n{seen}"
    );
}

/// ⑤ `listen/timeout_ms` with `listen/retry` RE-BINDS, and gives up at the
/// budget.
///
/// The arm that separates the budget from the schedule: upstream's own
/// `add_listener_retry` is reached only when the listen budget is non-zero, and
/// the wait it applies comes from the listen retry block. A node that honoured
/// the budget and ignored the schedule would still exit at 1200 ms, so the
/// attempt COUNT is asserted too.
#[test]
fn a_bounded_listen_phase_re_binds_before_it_gives_up() {
    let (held, occupied) = occupied_port();
    let (code, elapsed, seen) = assert_exits(
        "bounded listen phase",
        &argv(&[
            "--peer",
            &listen_arg(&[ListenSpec::Held(occupied)]),
            "--listen-timeout",
            "1200",
            "--listen-retry",
            "300,300,1",
        ])
        .into_iter()
        .chain(APP.iter().map(|s| String::from(*s)))
        .collect::<Vec<_>>(),
        Duration::from_millis(1200),
    );
    drop(held);
    assert_eq!(code, give_up_code(), "--- transcript ---\n{seen}");
    assert!(
        elapsed >= Duration::from_millis(1100),
        "the node stopped after {elapsed:?}, before its own 1200ms budget\n{seen}"
    );
    let attempts = seen.matches("re-binding").count();
    assert!(
        attempts >= 2,
        "1200ms at a 300ms cadence must re-bind more than once; saw {attempts} \
         retry line(s). A budget honoured without a schedule would exit at the \
         same moment having tried once\n--- transcript ---\n{seen}"
    );
}

// ── the invocation item 229 is actually about ───────────────────────────────

/// ① from a FILE — `wz-ap-demo --config their.json5`, the operator writing the
/// two keys and nothing else.
///
/// The whole chain in one process: JSON5 leaf, mode-dependent resolution,
/// expansion, argv parse, resolved policy, watchdog, exit status. Every joint
/// of it was provable separately while the file was inert, which is the state
/// item 229 recorded.
#[cfg(feature = "zenoh-config")]
#[test]
fn a_config_file_that_says_exit_on_failure_produces_a_node_that_exits() {
    let fixture = Fixture::new("configured");
    let path = fixture.write(
        "z.json5",
        &format!(
            r#"{{ mode: "peer",
                  listen: {{ endpoints: ["tcp/127.0.0.1:0"] }},
                  connect: {{ endpoints: ["tcp/127.0.0.1:{}"],
                             timeout_ms: 800,
                             exit_on_failure: true,
                             retry: {{ period_init_ms: 200, period_max_ms: 200,
                                      period_increase_factor: 1 }} }},
                  scouting: {{ multicast: {{ enabled: false }} }} }}"#,
            dial_target_port()
        ),
    );
    let (code, elapsed, seen) = assert_exits(
        "--config with the lifecycle clause",
        &argv(&["--config", &path.display().to_string()])
            .into_iter()
            .chain(APP.iter().map(|s| String::from(*s)))
            .collect::<Vec<_>>(),
        Duration::from_millis(800),
    );
    assert_eq!(code, give_up_code(), "--- transcript ---\n{seen}");
    assert!(
        elapsed >= Duration::from_millis(700),
        "the node stopped after {elapsed:?}, before the file's own budget\n{seen}"
    );
    // The keys reached a flag rather than being read and dropped, on the
    // SHIPPING binary's own words — the half `args::stock_config_tests` cannot
    // see, because it reads the argv the expansion builds rather than what the
    // binary did with it.
    let applied = seen
        .lines()
        .find(|l| l.contains("APPLIED [") && !l.contains("NOT APPLIED"))
        .unwrap_or_else(|| panic!("no APPLIED line in the demo's report\n{seen}"));
    for key in ["connect/timeout_ms", "connect/exit_on_failure"] {
        assert!(
            applied.contains(key),
            "{key} must be reported applied by the binary that ran it\n{applied}"
        );
    }
}

/// ② from a FILE — the SAME document with the clause deleted.
///
/// Two runs of one binary differing in one block. If the node's fate does not
/// move between this arm and the one above, the file reached nothing whatever
/// the config report says.
#[cfg(feature = "zenoh-config")]
#[test]
fn a_config_file_without_the_clause_leaves_the_node_running() {
    let fixture = Fixture::new("default");
    let path = fixture.write(
        "z.json5",
        &format!(
            r#"{{ mode: "peer",
                  listen: {{ endpoints: ["tcp/127.0.0.1:0"] }},
                  connect: {{ endpoints: ["tcp/127.0.0.1:{}"] }},
                  scouting: {{ multicast: {{ enabled: false }} }} }}"#,
            dial_target_port()
        ),
    );
    let seen = assert_still_running(
        "--config without the lifecycle clause",
        &argv(&["--config", &path.display().to_string()])
            .into_iter()
            .chain(APP.iter().map(|s| String::from(*s)))
            .collect::<Vec<_>>(),
    );
    assert!(
        seen.contains("timeout_ms=-1 exit_on_failure=false"),
        "a document that says nothing must resolve upstream's default column\n{seen}"
    );
}

/// A directory of this test's own, removed on the way out.
///
/// `cfg`-ed on the set of its consumers — the two `--config` arms — rather than
/// `allow(dead_code)`d, which is this crate's rule for exactly this shape: an
/// allow would keep compiling after the last caller went away.
#[cfg(feature = "zenoh-config")]
struct Fixture {
    dir: std::path::PathBuf,
}

#[cfg(feature = "zenoh-config")]
impl Fixture {
    fn new(case: &str) -> Fixture {
        let dir =
            std::env::temp_dir().join(format!("wz-startup-phase-{}-{case}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a temp directory for this case");
        Fixture { dir }
    }

    fn write(&self, name: &str, source: &str) -> std::path::PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, source).expect("the fixture file");
        path
    }
}

#[cfg(feature = "zenoh-config")]
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ── ⑦ the RULE item 553 bought, as a predicate rather than a paragraph ───────

/// R2178 (open-debt item 553) — no listen address in this binary is built from
/// a port that was learned and released.
///
/// # Why this reads source instead of running the arms
///
/// The defect it guards is a RACE. [`dial_target_port`] hands back a number the
/// kernel may give to anyone before the demo binds it, so the arm that used one
/// as a listen address failed only sometimes: R2175's push was refused by it,
/// and re-running the same commit passed 7 of 7. A test that merely runs the
/// arms therefore reports green on a tree that still carries the defect —
/// the shape this workspace calls a population that cannot fail.
///
/// What CAN be judged on every run is the property the fix established: the
/// address never comes from a released number at all. That is a fact about this
/// file's text, so the text is what is read — the idiom [`give_up_code`] already
/// uses on `runner.rs`, turned on this file.
///
/// # Three rules, because any two of them leave a route back in
///
/// Rule 1 alone accepts `&listen` by name, so a `let listen = format!(..)` would
/// pass it. Rules 1 and 2 together still accept
/// `ListenSpec::Held(dial_target_port())`, which is the defect exactly. Each is
/// therefore checked and reported separately rather than folded into one sweep.
#[test]
fn no_listen_address_is_built_from_a_released_port() {
    const SOURCE: &str = include_str!("startup_phase_lifecycle_binary.rs");

    let mut peer_values = 0usize;
    let mut listen_bindings = 0usize;
    let mut held_args = 0usize;
    let mut failures: Vec<String> = Vec::new();

    let raw_lines: Vec<&str> = SOURCE.lines().collect();
    // A token inside a COMMENT is prose about the rule, not an instance of it.
    // Stripping comments is how this gate avoids the defect R2175 hit, where a
    // paragraph DESCRIBING the marker syntax was parsed as a marker — and it
    // has to be done by what the text IS, because an exclusion list keyed on a
    // word is the escape hatch this workspace refuses. (`//` inside a string
    // literal would be cut too; this file has none, and a future one would show
    // up as a finding rather than as a silent skip.)
    let lines: Vec<&str> = raw_lines
        .iter()
        .map(|l| match l.find("//") {
            Some(at) => &l[..at],
            None => *l,
        })
        .collect();

    for (i, line) in lines.iter().enumerate() {
        // RULE 1 — every `--peer` value is a `listen_arg` result. The value sits
        // on the same line in the inline `argv` form and on the next line in the
        // multi-line one; both shapes occur here, so both are resolved.
        //
        // An occurrence preceded by a BACKSLASH is this gate quoting the token
        // rather than passing it, which is a fact about the character before it
        // and not about which line it is on.
        let quoted = line.split("\"--peer\"").next().unwrap_or("");
        if line.contains("\"--peer\"") && !quoted.ends_with('\\') {
            peer_values += 1;
            let same = line.split("\"--peer\"").nth(1).unwrap_or("");
            let value = if same.trim().len() > 1 {
                same
            } else {
                lines.get(i + 1).copied().unwrap_or("")
            };
            if !(value.contains("&listen") || value.contains("listen_arg(")) {
                failures.push(finding(
                    i,
                    "a `--peer` value that is not a `listen_arg` result",
                    value,
                ));
            }
        }

        // RULE 2 — every `listen` binding comes from `listen_arg`.
        if line.trim_start().starts_with("let listen =") {
            listen_bindings += 1;
            let tail = if line.trim_end().ends_with('=') {
                lines.get(i + 1).copied().unwrap_or("")
            } else {
                line
            };
            if !tail.contains("listen_arg(") {
                failures.push(finding(
                    i,
                    "a `listen` binding that is not a `listen_arg` result",
                    tail,
                ));
            }
        }

        // RULE 3 — `ListenSpec::Held` carries only a port THIS PROCESS holds.
        //
        // Two occurrences are NOT constructions and are told apart by what they
        // are rather than by where they sit: one preceded by a quote is a string
        // this gate scans WITH, and one followed by `=>` is the destructuring
        // arm inside `listen_arg` itself. Both would otherwise make the gate red
        // on the very file it was written for, which is how it first ran.
        let mut cursor = 0usize;
        while let Some(at) = line[cursor..].find("ListenSpec::Held(") {
            let start = cursor + at;
            let after = &line[start + "ListenSpec::Held(".len()..];
            cursor = start + "ListenSpec::Held(".len();
            if line[..start].ends_with('"') {
                continue;
            }
            let arg = after.split(')').next().unwrap_or("");
            let tail = after
                .split_once(')')
                .map(|(_, t)| t.trim_start())
                .unwrap_or("");
            if tail.starts_with("=>") {
                continue;
            }
            held_args += 1;
            if arg.trim() != "occupied" {
                failures.push(finding(
                    i,
                    "a held listen port that is not the one `occupied_port` \
                     returns — a released number cannot keep the promise a \
                     listen address makes",
                    arg,
                ));
            }
        }
    }

    // A shrunken population must FAIL, not pass: a rename that emptied one of
    // these rules would otherwise read as compliance. The floors are per-rule
    // rather than a total, because a total hides a shift between its parts.
    //
    // ⚠ They are COLLECTED alongside the findings rather than asserted before
    // them, and that ordering was bought by a mutation. Asserting the floors
    // first made this gate UNDER-REPORT: a mutation that both bypassed
    // `listen_arg` and removed a `Held` construction reported only the floor,
    // so the rule it actually broke went unnamed. Under-reporting is the one
    // defect a gate in this workspace may not have.
    let floors = [
        (peer_values, 5usize, "`--peer` value(s)"),
        (listen_bindings, 4, "`let listen =` binding(s)"),
        (held_args, 3, "held-port construction(s)"),
    ];
    for (reached, floor, what) in floors {
        if reached < floor {
            failures.push(format!(
                "  this gate reached {reached} {what} and was written against \
                 {floor}; it has stopped reading what it names, or a skip \
                 above swallowed one"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "open-debt item 553 is back in this file:\n{}",
        failures.join("\n")
    );
}

/// One finding, with the source line that produced it.
///
/// Findings are COLLECTED rather than asserted where they are found: an arm
/// that panics leaves the later rules unmeasured, and unmeasured must not read
/// as passed.
fn finding(index: usize, what: &str, text: &str) -> String {
    format!(
        "  startup_phase_lifecycle_binary.rs:{}: {what}\n    {}",
        index + 1,
        text.trim()
    )
}
