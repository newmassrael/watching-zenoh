// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y512 — §5.21 `routing-interest-pending-gc`, witnessed as a real zenoh-pico
//! `z_get_liveliness` that a watching-zenoh peer UNWEDGES after its GATEWAY goes silent.
//!
//! Item 751 step 7 moved the broker from the single-net peer forwarder to the region-hat
//! forwarder (`docs/peer-region-hats.md`), and with it the rule of WHO is asked: the pin's peer
//! hat propagates a client's interest to the faces whose remote bound is south, the gateways
//! (`zenoh/src/net/routing/hat/peer/interests.rs` @ `.filter(|f| f.remote_bound.is_south())`),
//! and to no other peer, because wz peers flood their declarations. So the upstream that can
//! wedge a client is a ROUTER, and the arms below use a wz `--router-hat` for it; a wz PEER
//! upstream is asked nothing, which two arms show from the other side.
//!
//! ## The observable, and why a foreign client is the only honest witness
//!
//! zenoh-pico's CURRENT interest carries **no timeout of its own**. `z_liveliness_get`
//! discards the parameter outright — `_ZP_UNUSED(timeout_ms); // Current interest
//! in pico don't support timeout` (`vendor/zenoh-pico/src/net/liveliness.c:348`) —
//! so the terminating `DeclareFinal` is the ONLY thing that can close its FIFO
//! handler and let `z_get_liveliness` return from its `z_recv` loop
//! (`examples/unix/c11/z_get_liveliness.c:54-66`). **Process exit IS the wire
//! observable.** That is not a proxy for the property; it is the property, read
//! off a foreign implementation that has no other way out.
//!
//! ## Arms on ONE binary, differing in ONE fixture variable each
//!
//! - [`wz_peer_gc_terminates_a_pico_liveliness_get_when_its_gateway_goes_silent`] — THE ATOM.
//!   A peer with a router upstream, the router `SIGSTOP`ped *before* pico asks, so it holds its
//!   TCP link open and answers nothing. pico still returns, at the GC deadline, and the peer
//!   reports the GC reaped exactly one entry.
//! - [`wz_peer_answers_a_pico_liveliness_get_promptly_with_a_live_gateway`] — the same topology
//!   with the router RUNNING. pico returns promptly and the GC counter stays **0**: the unwind
//!   came from the router's own `DeclareFinal`, so the arm above cannot be re-read as "the
//!   broker always reaps".
//! - [`wz_peer_does_not_ask_a_silent_peer_upstream`] — a frozen PEER upstream. It is not a
//!   gateway, so nothing is asked of it and pico is answered promptly from the peer's own table.
//! - [`wz_peer_without_an_upstream_answers_a_pico_liveliness_get_inline`] — `--connect` omitted.
//!   With no upstream face there is nothing to propagate to and the final is emitted inline. The
//!   control that says the delay in the first arm is the PENDING TABLE and not something the
//!   broker build does to every interest.
//!
//! ## The confound, named: face-down is a THIRD retirement path
//!
//! A `SIGSTOP`ped router also stops sending KeepAlives, so its session lease
//! (`lease_ms: 10000`, printed in the demo's own config banner) eventually expires
//! and the face-down drain finalizes the client too. That is correct behaviour —
//! `drain_face` is zenoh's `finalize_pending_interests` — but it means "pico
//! returned" is only the GC's doing while the GC deadline is well inside the
//! lease. So the fixture sets `--interest-timeout 2500` and asserts a LOWER bound
//! on the elapsed time as well as an upper one: the return must be later than a
//! prompt answer and earlier than the lease. Both bounds are protocol constants,
//! not scheduling races — a frozen process cannot answer early, and the lease
//! cannot expire in under 10s.
//!
//! The bounds were measured on the single-net peer forwarder, which this arm was written
//! against: live upstream `0.15s`, frozen upstream `3.24s` (deadline 2500ms + one 100ms tick
//! window + startup), no upstream `0.15s`, and with the tick sweep disabled alone the frozen
//! arm moved to `8.89s`, onto the lease path. They are the same protocol constants here.
//!
//! Requires: wz-ap-demo built with `--features routing-peer,router-hat-router,routing-interest-pending-gc`
//! and the zenoh-pico CLI. Layer E6's lane owns that build.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::bounded::BoundedStatus as _;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, graceful_terminate, listen_port, read_captured,
    wait_for_exit, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
};

/// The keyexpr pico solicits. RESTRICTED (a literal prefix + `**`).
const GET_KEYEXPR: &str = "group1/**";

/// The interest deadline the GC arm sets, in milliseconds.
const INTEREST_TIMEOUT_MS: u64 = 2500;

/// How soon a client's current interest must be answered when nothing is waited for. Well under
/// the 2.5s deadline and the 10s session lease, so a return inside it can come only from an
/// answer that waited on no one.
const PROMPT: Duration = Duration::from_millis(1_500);

/// Upper bound on an arm that is answered without waiting for anything.
const PROMPT_ARM_BUDGET: Duration = Duration::from_secs(5);

/// Upper bound on the GC arm, under the 10 s lease so a return cannot come from the face-down
/// path.
const GC_ARM_BUDGET: Duration = Duration::from_secs(8);

/// The GC must not fire before the deadline it was given, less a margin for the clock's phase.
const GC_FLOOR: Duration = Duration::from_millis(2_400);

/// What a node is run as.
#[derive(Clone, Copy)]
enum Kind {
    Peer,
    RouterHat,
}

impl Kind {
    fn flag(self) -> &'static str {
        match self {
            Kind::Peer => "--peer",
            Kind::RouterHat => "--router-hat",
        }
    }

    fn listening(self) -> &'static str {
        match self {
            Kind::Peer => "peer: listening on 127.0.0.1:",
            Kind::RouterHat => "router-hat: listening on 127.0.0.1:",
        }
    }
}

struct Node {
    guard: ChildGuard,
    stderr: File,
    port: u16,
}

/// Spawn a node of `kind` on an ephemeral port, optionally dialing `connect` and given
/// `extra` arguments. Returns once it is listening.
fn spawn(label: &str, kind: Kind, connect: Option<u16>, extra: &[&str]) -> Node {
    let stderr = tempfile::tempfile().expect("tempfile for node stderr");
    let writer = stderr.try_clone().expect("dup node stderr handle");
    let mut reader = stderr;
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let mut cmd = Command::new(&demo);
    cmd.args([kind.flag(), "127.0.0.1:0"]);
    let dial;
    if let Some(port) = connect {
        dial = format!("127.0.0.1:{port}");
        cmd.args(["--connect", &dial]);
    }
    cmd.args(extra);
    let mut guard = ChildGuard::wrap(
        label.to_string(),
        cmd.env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo"),
    );
    let captured = wait_for_substring(&mut reader, kind.listening(), Duration::from_secs(5))
        .unwrap_or_else(|c| {
            let _ = guard.child_mut().kill();
            let _ = guard.child_mut().wait();
            panic!(
                "wz-ap-demo did not bind a listener within 5s (is the binary built with \
                 --features routing-peer,router-hat-router?)\n--- {label} stderr ---\n{c}"
            );
        });
    let port = listen_port(&captured);
    Node {
        guard,
        stderr: reader,
        port,
    }
}

impl Node {
    fn signal(&mut self, sig: &str) {
        let pid = self.guard.child_mut().id().to_string();
        let status = Command::new("kill")
            .arg(sig)
            .arg(&pid)
            .status_bounded()
            .expect("kill(1) is available");
        assert!(status.success(), "kill {sig} {pid} failed");
    }

    /// Terminate the demo and return everything it logged, so the caller can read the
    /// interest-broker witness line out of it.
    fn finish(mut self) -> String {
        graceful_terminate(self.guard.child_mut(), Duration::from_secs(5));
        read_captured(&mut self.stderr)
    }
}

/// Run `z_get_liveliness` against `port` and return `(exited_within_budget,
/// elapsed, captured)`. A pico that never returns is KILLED at the budget rather
/// than left to hang the lane; that timeout IS the negative observable, so it is
/// reported, never silently swallowed.
fn run_pico_get(port: u16, budget: Duration) -> (bool, Duration, String) {
    let stdout = tempfile::tempfile().expect("tempfile for pico stdout");
    let writer = stdout.try_clone().expect("dup pico stdout handle");
    let mut reader = stdout;
    // The clock starts at SPAWN, deliberately, and the bounds absorb pico's start-up. Gating it
    // on pico's own "Sending liveliness query" banner is WRONG here: that banner goes to a
    // redirected stdout, which glibc block-buffers, so it becomes visible only when the process
    // exits — a clock gated on it measures ~0 for every arm. Start-up is ~0.15s against a 1.5s
    // floor and a 2.5s deadline, so folding it in costs no margin.
    let started = Instant::now();
    let mut guard = ChildGuard::wrap(
        "z_get_liveliness".to_string(),
        Command::new(zenoh_pico_cli_binary("z_get_liveliness"))
            .args([
                "-k",
                GET_KEYEXPR,
                "-m",
                "client",
                "-e",
                &format!("tcp/127.0.0.1:{port}"),
            ])
            .stderr(Stdio::from(writer.try_clone().expect("dup stderr handle")))
            .stdout(Stdio::from(writer))
            .spawn()
            .expect("spawn zenoh-pico z_get_liveliness"),
    );
    let exited = wait_for_exit(guard.child_mut(), budget).is_ok();
    let elapsed = started.elapsed();
    if !exited {
        let _ = guard.child_mut().kill();
        let _ = guard.child_mut().wait();
    }
    (exited, elapsed, read_captured(&mut reader))
}

/// A gateway that holds its link open and answers nothing does not wedge a foreign client.
///
/// pico cannot time a current interest out itself (`liveliness.c:348`), so its return is the
/// `DeclareFinal` arriving and nothing else. The peer brokered the interest to its gateway and
/// owes the final by the unwind; the gateway is `SIGSTOP`ped, so only the GC can pay it.
// wz-proves: routing-interest-pending-gc wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,router-hat-router + zenoh-pico z_get_liveliness); Layer E6 runs via --ignored"]
fn wz_peer_gc_terminates_a_pico_liveliness_get_when_its_gateway_goes_silent() {
    let mut gateway = spawn("router-hat gateway", Kind::RouterHat, None, &[]);
    let timeout = INTEREST_TIMEOUT_MS.to_string();
    let mut peer = spawn(
        "peer",
        Kind::Peer,
        Some(gateway.port),
        &["--interest-timeout", &timeout],
    );
    let mesh = wait_for_substring(&mut peer.stderr, "face 0 UP", Duration::from_secs(10))
        .unwrap_or_else(|c| panic!("the peer never linked to its gateway\n{c}"));
    assert!(
        mesh.contains("whatami Some(Router)"),
        "the upstream face must be a ROUTER face, the gateway the peer brokers to.\n{mesh}"
    );

    gateway.signal("-STOP");
    let (exited, elapsed, pico_out) = run_pico_get(peer.port, GC_ARM_BUDGET);
    gateway.signal("-CONT");

    let peer_log = peer.finish();
    let _ = gateway.finish();

    assert!(
        exited,
        "z_get_liveliness never returned within {GC_ARM_BUDGET:?} against a silent gateway: \
         the GC did not finalize the client, and pico has no timeout of its own to rescue it.\n\
         --- z_get_liveliness stdout ---\n{pico_out}\n--- peer stderr ---\n{peer_log}"
    );
    assert!(
        elapsed >= GC_FLOOR,
        "z_get_liveliness returned after {elapsed:?}, before the {INTEREST_TIMEOUT_MS}ms deadline: \
         the client was finalized by something other than the GC.\n--- peer stderr ---\n{peer_log}"
    );
    assert!(
        peer_log.contains("1 reaped by the GC"),
        "the peer's own broker line does not report the GC reaping the silent gateway's entry.\n\
         --- peer stderr ---\n{peer_log}"
    );
}

/// The gateway RUNNING: the same client is answered promptly and the GC reaps nothing.
///
/// Without this arm the one above could be re-read as "the broker always reaps"; here the
/// unwind comes from the gateway's own final.
// wz-proves: routing-interest-pending-gc wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,router-hat-router + zenoh-pico z_get_liveliness); Layer E6 runs via --ignored"]
fn wz_peer_answers_a_pico_liveliness_get_promptly_with_a_live_gateway() {
    let gateway = spawn("router-hat gateway", Kind::RouterHat, None, &[]);
    let timeout = INTEREST_TIMEOUT_MS.to_string();
    let mut peer = spawn(
        "peer",
        Kind::Peer,
        Some(gateway.port),
        &["--interest-timeout", &timeout],
    );
    let _ = wait_for_substring(&mut peer.stderr, "face 0 UP", Duration::from_secs(10));

    let (exited, elapsed, pico_out) = run_pico_get(peer.port, PROMPT_ARM_BUDGET);
    let peer_log = peer.finish();
    let _ = gateway.finish();

    assert!(
        exited,
        "z_get_liveliness never returned within {PROMPT_ARM_BUDGET:?} against a LIVE gateway.\n\
         --- z_get_liveliness stdout ---\n{pico_out}\n--- peer stderr ---\n{peer_log}"
    );
    assert!(
        elapsed < PROMPT,
        "a live gateway's peer answered in {elapsed:?}, at or past the prompt bound.\n\
         --- peer stderr ---\n{peer_log}"
    );
    assert!(
        peer_log.contains("0 reaped by the GC"),
        "the GC reaped an entry although the gateway answered: the unwind did not come from the \
         gateway's own final.\n--- peer stderr ---\n{peer_log}"
    );
}

/// A silent PEER upstream is not asked, so it cannot wedge anyone.
///
/// The pin sends an interest on to gateways and not to peers, whose declarations arrive by
/// flood. A frozen peer therefore changes nothing: pico is answered from the peer's own table,
/// inside [`PROMPT`], where a broker that asked every upstream needed its whole deadline.
// wz-proves: none -- the pin's WHO-IS-ASKED rule seen from the peer side, a control for the
// gateway arms above; it claims no atom of its own.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,router-hat-router + zenoh-pico z_get_liveliness); Layer E6 runs via --ignored"]
fn wz_peer_does_not_ask_a_silent_peer_upstream() {
    let mut upstream = spawn("peer upstream", Kind::Peer, None, &[]);
    let timeout = INTEREST_TIMEOUT_MS.to_string();
    let mut peer = spawn(
        "peer",
        Kind::Peer,
        Some(upstream.port),
        &["--interest-timeout", &timeout],
    );
    let mesh = wait_for_substring(&mut peer.stderr, "face 0 UP", Duration::from_secs(10))
        .unwrap_or_else(|c| panic!("the peer never linked to its upstream\n{c}"));
    assert!(
        mesh.contains("whatami Some(Peer)"),
        "the upstream face must be a PEER face, which is not a gateway.\n{mesh}"
    );

    upstream.signal("-STOP");
    let (exited, elapsed, pico_out) = run_pico_get(peer.port, PROMPT_ARM_BUDGET);
    upstream.signal("-CONT");

    let peer_log = peer.finish();
    let _ = upstream.finish();

    assert!(
        exited,
        "z_get_liveliness never returned within {PROMPT_ARM_BUDGET:?} against a silent peer \
         upstream: the client's current interest was not answered.\n\
         --- z_get_liveliness stdout ---\n{pico_out}\n--- peer stderr ---\n{peer_log}"
    );
    assert!(
        elapsed < PROMPT,
        "z_get_liveliness took {elapsed:?} against a silent PEER upstream: the peer waited on a \
         face the pin does not ask.\n--- peer stderr ---\n{peer_log}"
    );
}

/// The control: the SAME binary with no upstream at all answers inline.
///
/// With no upstream face there is nothing to propagate to, so this arm is the baseline the arms
/// above are measured against: the answer's time does not depend on there being an upstream at
/// all unless that upstream is a gateway.
// wz-proves: none -- control arm for the arms above; it shows the answer does not depend on an
// upstream face existing, and claims no atom of its own.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,router-hat-router + zenoh-pico z_get_liveliness); Layer E6 runs via --ignored"]
fn wz_peer_without_an_upstream_answers_a_pico_liveliness_get_inline() {
    let peer = spawn("solo", Kind::Peer, None, &[]);

    let (exited, elapsed, pico_out) = run_pico_get(peer.port, PROMPT_ARM_BUDGET);
    let peer_log = peer.finish();

    assert!(
        exited,
        "z_get_liveliness never returned against a peer with no upstream.\n\
         --- z_get_liveliness stdout ---\n{pico_out}\n--- peer stderr ---\n{peer_log}"
    );
    assert!(
        elapsed < PROMPT,
        "an upstream-less peer took {elapsed:?} to answer.\n--- peer stderr ---\n{peer_log}"
    );
}
