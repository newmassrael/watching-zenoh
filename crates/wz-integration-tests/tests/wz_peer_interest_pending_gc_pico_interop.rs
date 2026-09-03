// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y512 — §5.21 `routing-interest-pending-gc`, witnessed as a real zenoh-pico
//! `z_get_liveliness` that a watching-zenoh peer UNWEDGES after its upstream goes
//! silent.
//!
//! ## Why this atom needed a build, not a better test
//!
//! R311y508 proposed this atom as a `FOREIGN_NON_OBSERVABLE` denominator
//! exclusion, argued from a correct direct read: zenoh populates
//! `pending_current_interests` in exactly two hats
//! (`zenoh/src/net/routing/hat/client/interests.rs` @ `pending_current_interests`
//! and `zenoh/src/net/routing/hat/peer/interests.rs`
//! @ `pending_current_interests`), the hats wz mirrored held no pending table at
//! all, and in the only role wz HAD the mechanism the GC's output went to the
//! LOCAL app. The exclusion carried its own re-open trigger, named rather than
//! left implicit: *"the only role whose unwind DOES cross the wire is zenoh's
//! p2p_peer hat brokering a DOWNSTREAM client's current interest, where `src_face`
//! is a remote face; wz implements no p2p_peer-shaped broker, and if one is ever
//! built this exclusion is wrong and must come out."*
//!
//! R311y512 built it. `LinkstateForwarder` now propagates a CLIENT face's CURRENT
//! token interest to every upstream face, holds one
//! [`PendingCurrentInterests`](wz::runtime_tokio::interest_broker::PendingCurrentInterests)
//! entry per propagated copy, and withholds the client's terminating
//! `DeclareFinal` until the LAST upstream answers — with the tick sweep as the
//! backstop when one never does.
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
//! ## Three arms on ONE binary, differing in ONE fixture variable each
//!
//! Every arm drives the SAME `wz-ap-demo` build. Nothing here is separated by a
//! feature flag, so no arm can pass because a different binary was measured
//! (`BUILD FEATURES` is asserted anyway, so a lane that forgot the feature fails
//! loudly instead of silently).
//!
//! - [`wz_peer_gc_terminates_a_pico_liveliness_get_when_the_upstream_goes_silent`]
//!   — THE ATOM. Broker peer with a live upstream; the upstream is `SIGSTOP`ped
//!   *before* pico asks, so it holds its TCP link open and answers nothing. pico
//!   still returns, and the broker reports the GC reaped exactly one entry.
//! - [`wz_peer_unwinds_a_pico_liveliness_get_on_the_upstream_final`] — the same
//!   topology with the upstream RUNNING. pico returns promptly and the GC counter
//!   stays **0**: the unwind came from the upstream's own `DeclareFinal`, so the
//!   arm above cannot be re-read as "the broker always reaps".
//! - [`wz_peer_without_an_upstream_answers_a_pico_liveliness_get_inline`] — the
//!   same binary with `--connect` omitted. With no upstream face there is nothing
//!   to propagate to, `propagate_current_interest` returns 0, and the final is
//!   emitted inline exactly as before this round. The control that says the delay
//!   in arm 1 is the PENDING TABLE and not something the broker build does to
//!   every interest.
//!
//! ## The confound, named: face-down is a THIRD retirement path
//!
//! A `SIGSTOP`ped peer also stops sending KeepAlives, so its session lease
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
//! MEASURED while building, all three arms repeated: live upstream `0.15s`,
//! frozen upstream `3.24s` (deadline 2500ms + one 100ms tick window + startup),
//! no upstream `0.15s`. The damage probe — the tick sweep disabled and nothing
//! else — moved the frozen arm from `3.24s` to `8.89s`, i.e. onto the lease path,
//! with the demo's own log showing `face 0 DOWN (Terminated)` at that instant.
//! So the 2.5s..8s window separates the GC from every other way out.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    graceful_terminate, listen_port, read_captured, wait_for_exit, wait_for_substring,
    wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
};

/// The keyexpr pico solicits. RESTRICTED (a literal prefix + `**`), because the
/// broker deliberately declines to propagate a match-all interest — the dump legs
/// decline it too, so brokering one would ask upstream a question this node could
/// not itself answer.
const GET_KEYEXPR: &str = "group1/**";

/// zenoh's `routing.interests.timeout` for this fixture, in milliseconds. Chosen
/// to sit well inside the 10s session lease so the GC, not the face-down drain,
/// is what terminates the frozen arm.
const INTEREST_TIMEOUT_MS: u64 = 2500;

/// Upper bound on the frozen arm. Below the 10s lease by a wide margin, so a pass
/// cannot have come from the face-down path.
const FROZEN_ARM_BUDGET: Duration = Duration::from_secs(8);

/// Lower bound on the frozen arm. A frozen process cannot answer, so nothing can
/// terminate the client before the GC deadline; this floor only rejects a build
/// where the broker never held the interest at all.
const FROZEN_ARM_FLOOR: Duration = Duration::from_millis(1_500);

/// Upper bound on an arm that is answered without waiting for anything.
const PROMPT_ARM_BUDGET: Duration = Duration::from_secs(5);

/// Spawn a `--peer` demo on an ephemeral port, optionally dialing `connect` and
/// optionally shortening the brokered-interest timeout. Returns its guard, its
/// stderr handle, and the port it actually bound.
fn spawn_peer(label: &str, connect: Option<u16>, interest_timeout_ms: Option<u64>) -> Peer {
    let stderr = tempfile::tempfile().expect("tempfile for peer stderr");
    let writer = stderr.try_clone().expect("dup peer stderr handle");
    let mut reader = stderr;
    let mut cmd = Command::new(wz_ap_demo_binary());
    cmd.args(["--peer", "127.0.0.1:0"]);
    let dial;
    if let Some(port) = connect {
        dial = format!("127.0.0.1:{port}");
        cmd.args(["--connect", &dial]);
    }
    let timeout_arg;
    if let Some(ms) = interest_timeout_ms {
        timeout_arg = ms.to_string();
        cmd.args(["--interest-timeout", &timeout_arg]);
    }
    let mut guard = ChildGuard::wrap(
        format!("interest-broker peer {label}"),
        cmd.env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo --peer"),
    );
    let captured = wait_for_substring(
        &mut reader,
        "peer: listening on 127.0.0.1:",
        Duration::from_secs(5),
    )
    .unwrap_or_else(|c| {
        let _ = guard.child_mut().kill();
        let _ = guard.child_mut().wait();
        panic!(
            "wz-ap-demo did not bind a peer listener within 5s (is the binary built with \
             --features routing-peer,routing-interest-pending-gc?)\n\
             --- peer {label} stderr ---\n{c}"
        );
    });
    // The BUILD-FEATURES gate. Every feature-set lane writes the SAME artifact
    // path, so a stale binary from a neighbouring lane is the standing hazard here;
    // the demo prints its own closure and this reads it rather than trusting the
    // lane's build line.
    assert!(
        captured.contains("routing-interest-pending-gc"),
        "peer {label} was built WITHOUT routing-interest-pending-gc — this lane would \
         measure the wrong binary.\n--- BUILD FEATURES line ---\n{captured}"
    );
    let port = listen_port(&captured);
    Peer {
        guard,
        stderr: reader,
        port,
    }
}

struct Peer {
    guard: ChildGuard,
    stderr: File,
    port: u16,
}

impl Peer {
    fn pid(&mut self) -> String {
        self.guard.child_mut().id().to_string()
    }

    fn signal(&mut self, sig: &str) {
        let pid = self.pid();
        let status = Command::new("kill")
            .arg(sig)
            .arg(&pid)
            .status()
            .expect("kill(1) is available");
        assert!(status.success(), "kill {sig} {pid} failed");
    }

    /// Terminate the demo and return everything it logged, so the caller can read
    /// the interest-broker witness line out of it.
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
    // The clock starts at SPAWN, deliberately, and the bounds absorb pico's
    // start-up. Gating it on pico's own "Sending liveliness query" banner is the
    // obvious refinement and it is WRONG here: that banner goes to a redirected
    // stdout, which glibc block-buffers, so it becomes visible only when the
    // process exits — a clock gated on it measures ~0 for every arm regardless of
    // what the broker did. (Measured: the frozen arm read `16.409µs` that way while
    // the broker's own log showed the GC had reaped its entry.) Start-up is ~0.15s
    // against a 1.5s floor and a 2.5s deadline, so folding it in costs no margin.
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

/// Parse the `reaped by the GC` count out of the demo's own broker witness line.
fn gc_reaped(captured: &str) -> u64 {
    let line = captured
        .lines()
        .find(|l| l.contains("peer: interest broker;"))
        .unwrap_or_else(|| {
            panic!("the broker witness line is absent — the peer was not built with the atom's feature.\n--- peer stderr ---\n{captured}")
        });
    let (before, _) = line
        .rsplit_once(" reaped by the GC")
        .expect("the witness line ends with the GC count");
    before
        .rsplit(", ")
        .next()
        .expect("a count precedes `reaped by the GC`")
        .trim()
        .parse()
        .expect("the GC count is a number")
}

/// THE ATOM: an upstream that holds its link open and answers nothing leaves a
/// brokered interest pending, and the GC finalizes the foreign client anyway.
///
/// pico cannot time this out itself (`liveliness.c:348`), so its return is the
/// `DeclareFinal` arriving and nothing else. The `>= FROZEN_ARM_FLOOR` bound is
/// what makes it the BROKER's return rather than an inline one, and the
/// `< FROZEN_ARM_BUDGET` bound is what keeps the 10s lease's face-down drain out
/// of the claim.
// wz-proves: routing-interest-pending-gc wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,routing-interest-pending-gc + zenoh-pico z_get_liveliness); Layer E6 runs via --ignored"]
fn wz_peer_gc_terminates_a_pico_liveliness_get_when_the_upstream_goes_silent() {
    let mut upstream = spawn_peer("upstream", None, None);
    let broker = spawn_peer("broker", Some(upstream.port), Some(INTEREST_TIMEOUT_MS));
    // The mesh face must exist BEFORE the upstream is frozen, else there is no
    // upstream to propagate to and this degrades into the inline arm.
    let mut broker = broker;
    let mesh = wait_for_substring(&mut broker.stderr, "face 0 UP", Duration::from_secs(10))
        .unwrap_or_else(|c| panic!("the broker never linked to its upstream\n{c}"));
    assert!(mesh.contains("whatami Some(Peer)"), "the upstream face must be a PEER face — a client face is a leaf and is never brokered to.\n{mesh}");

    upstream.signal("-STOP");
    let (exited, elapsed, pico_out) = run_pico_get(broker.port, FROZEN_ARM_BUDGET);
    upstream.signal("-CONT");

    let broker_log = broker.finish();
    let _ = upstream.finish();

    assert!(
        exited,
        "z_get_liveliness never returned within {FROZEN_ARM_BUDGET:?}: the brokered \
         interest was never finalized, so the foreign client is wedged. pico has no \
         timeout of its own to rescue it.\n--- z_get_liveliness stdout ---\n{pico_out}\n\
         --- broker stderr ---\n{broker_log}"
    );
    assert!(
        elapsed >= FROZEN_ARM_FLOOR,
        "z_get_liveliness returned in {elapsed:?}, sooner than the {INTEREST_TIMEOUT_MS}ms \
         GC deadline — the interest was answered INLINE, so it was never brokered and \
         this arm proves nothing.\n--- broker stderr ---\n{broker_log}"
    );
    assert_eq!(
        gc_reaped(&broker_log),
        1,
        "the GC must have reaped exactly the one propagated interest; any other count \
         means the client's return came from a different path.\n--- broker stderr ---\n{broker_log}"
    );
}

/// The upstream RUNNING: the same topology unwinds on the upstream's own
/// `DeclareFinal`, with the GC counter untouched.
///
/// Without this arm the one above could be re-read as "the broker reaps every
/// interest it holds"; `0 reaped` here says the sweep fires only when an upstream
/// actually went silent.
// wz-proves: routing-interest-pending-gc wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,routing-interest-pending-gc + zenoh-pico z_get_liveliness); Layer E6 runs via --ignored"]
fn wz_peer_unwinds_a_pico_liveliness_get_on_the_upstream_final() {
    let upstream = spawn_peer("upstream", None, None);
    let mut broker = spawn_peer("broker", Some(upstream.port), Some(INTEREST_TIMEOUT_MS));
    let _ = wait_for_substring(&mut broker.stderr, "face 0 UP", Duration::from_secs(10));

    let (exited, elapsed, pico_out) = run_pico_get(broker.port, PROMPT_ARM_BUDGET);
    let broker_log = broker.finish();
    let _ = upstream.finish();

    assert!(
        exited,
        "z_get_liveliness never returned within {PROMPT_ARM_BUDGET:?} against a LIVE \
         upstream — the multihop unwind never delivered the client's DeclareFinal.\n\
         --- z_get_liveliness stdout ---\n{pico_out}\n--- broker stderr ---\n{broker_log}"
    );
    assert!(
        elapsed < FROZEN_ARM_FLOOR,
        "a live upstream answered in {elapsed:?}, at or past the GC floor — the unwind \
         is riding the timeout instead of the upstream's reply.\n\
         --- broker stderr ---\n{broker_log}"
    );
    assert_eq!(
        gc_reaped(&broker_log),
        0,
        "a live upstream answered, so the GC must have reaped NOTHING.\n\
         --- broker stderr ---\n{broker_log}"
    );
}

/// The control: the SAME binary with no upstream at all answers inline, exactly as
/// it did before this round.
///
/// `propagate_current_interest` returns 0 when there is no non-client face, so the
/// caller still owes the client its final on the spot — zenoh's `Arc::into_inner`
/// succeeding immediately when the propagation loop placed no copy. This is what
/// makes the frozen arm's delay attributable to the PENDING TABLE rather than to
/// something the broker build does to every interest it sees.
///
/// `none` is honest: alone this arm witnesses no atom — it witnesses that its two
/// siblings' behaviour is caused by having an upstream. Declared rather than left
/// silent because A4-4 rejects a silent corpus test.
// wz-proves: none -- control arm for the two above; it shows the brokering (and so
// the GC) is caused by an upstream face existing, and claims no atom of its own.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,routing-interest-pending-gc + zenoh-pico z_get_liveliness); Layer E6 runs via --ignored"]
fn wz_peer_without_an_upstream_answers_a_pico_liveliness_get_inline() {
    let broker = spawn_peer("solo", None, Some(INTEREST_TIMEOUT_MS));

    let (exited, elapsed, pico_out) = run_pico_get(broker.port, PROMPT_ARM_BUDGET);
    let broker_log = broker.finish();

    assert!(
        exited,
        "z_get_liveliness never returned against a peer with no upstream — the inline \
         DeclareFinal regressed.\n--- z_get_liveliness stdout ---\n{pico_out}\n\
         --- peer stderr ---\n{broker_log}"
    );
    assert!(
        elapsed < FROZEN_ARM_FLOOR,
        "an upstream-less peer took {elapsed:?} to answer — it brokered an interest it \
         had nowhere to send, which would wedge every client behind a leaf node.\n\
         --- peer stderr ---\n{broker_log}"
    );
    assert_eq!(
        gc_reaped(&broker_log),
        0,
        "nothing was propagated, so nothing can have been reaped.\n\
         --- peer stderr ---\n{broker_log}"
    );
}
