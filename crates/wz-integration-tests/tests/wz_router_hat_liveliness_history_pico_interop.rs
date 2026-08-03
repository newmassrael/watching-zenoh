// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y463 — `liveliness-historical-samples`, witnessed as a real zenoh-pico
//! liveliness subscriber being replayed a token that EXISTED BEFORE ITS SESSION
//! DID, by a watching-zenoh router-hat node.
//!
//! ## The atom's observable, and why the topology is the whole proof
//!
//! `liveliness-historical-samples` is the RESPONDER half of liveliness history:
//! not "a subscriber asked for history" (that is `liveliness-history`, proven at
//! R311y354 in the opposite direction) but "wz REPLAYED the tokens it already
//! held when a foreign subscriber asked with the CURRENT bit set". Its observable
//! is therefore a token declared STRICTLY BEFORE the asking subscriber's session
//! existed — and owning that precondition is what picks every process here.
//!
//! Two topologies do NOT own it, and R311y461 measured both:
//!
//! - A single-session ACCEPTOR (`wz-e2e-liveliness-token --listen --token`)
//!   cannot: wz holds its own token in a PER-SESSION observer declared at
//!   Established, so the token can never pre-exist the session that asks. The
//!   sample counts there are flaky AND the arms overlap (history ON `1 1 1 1 2 1`,
//!   OFF `1 0 1 1 1 1` over six runs each), because the same token also arrives by
//!   wz's proactive push and by pico replaying its OWN `_remote_tokens` cache
//!   (`vendor/zenoh-pico/src/net/liveliness.c:133-163`).
//! - A `--peer` node cannot either, and for a reason worth stating plainly because
//!   R311y461 got it wrong: `--peer` builds a `LinkstateForwarder`
//!   (`wz-ap-demo/src/runner.rs:2465`), which — **when this file was written** —
//!   had NO client-token plane at all: its only two mentions of one were comments
//!   pointing AT the router's, and the entire plane (`ingest_client_token`,
//!   `dump_interest_tokens`, `push_future_token`) belonged to `RouterForwarder`,
//!   which only `run_router_hat_until` constructs (`runner.rs:3602`). R311y461
//!   read that plane, measured zero deliveries against a `--peer` node, and
//!   concluded the atom "needs code". It did not: it needed the node kind that
//!   owned the plane.
//!
//!   **CORRECTION (R311y512): the sentence above is no longer true in the present
//!   tense, and leaving it would be exactly the stale-prose defect this project
//!   keeps catching.** R311y509 BUILT the peer's client-token plane in both tiers
//!   and R311y509a witnessed it with a real pico
//!   (`wz_peer_liveliness_token_pico_interop.rs`), so a `--peer` node now answers a
//!   CURRENT token interest too. This file's choice of a `--router-hat` node still
//!   stands — it is the topology whose client-leaf fold this leg exercises — but
//!   the JUSTIFICATION above is history, not a live constraint.
//!
//! So: a **router-hat** node (its banner says "dual-tier RouterForwarder"), pico A
//! holding the token, pico B subscribing afterwards. The token is a CLIENT-face
//! token in wz's `client_tokens`, and the reply is the SLICE-4 fold that makes it
//! visible to another client's interest.
//!
//! ## The pair, and why one arm alone would prove nothing
//!
//! `New alive token` is what pico logs for ANY token, so a lone green would not
//! separate "the pre-existing token was replayed" from "some token arrived". The
//! arms differ in ONE pico flag:
//!
//! - [`wz_router_hat_replays_a_pico_token_to_a_history_subscriber`] — `-h` ON: the
//!   sample arrives carrying pico A's exact literal.
//! - [`wz_router_hat_without_history_replays_nothing`] — `-h` omitted, identical
//!   fixture: nothing arrives.
//!
//! That flag is exactly the CURRENT bit on the wire —
//! `history ? (CURRENT|FUTURE) : FUTURE` at
//! `vendor/zenoh-pico/src/net/liveliness.c:196-205` — and wz gates the replay on
//! that same bit (`interest.c()`), so the pair says the replay is caused by the
//! atom and not by the token existing. Arm A also IS arm B's non-vacuity control:
//! the same binary's subscriber demonstrably receives, so B's silence is the flag.
//!
//! Measured before this file was written, 5 runs per arm on fresh ports:
//! history ON `1 1 1 1 1`, history OFF `0 0 0 0 0`. Exactly ONE sample, never two
//! — the count itself confirms the precondition is owned, since a token that
//! pre-exists the subscriber's session is not proactively pushed to it and pico's
//! own cache is empty when the subscriber is declared.
//!
//! ## Build variant — this lane must OWN it
//!
//! Requires `--features router-hat-router,routing-token-tables`. `routing-peer`
//! does NOT pull `routing-token-tables` (`crates/wz/Cargo.toml:473` vs `:857`), so
//! the Layer E6 demo binary has the whole plane compiled OUT and this proof placed
//! there would pass vacuously. Both test fns carry the `wz_router` token so Layer
//! E's catch-all sweep skips them (libtest matches the FUNCTION name), which the
//! R311y455 naming gate also enforces for this basename.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, listen_port, read_captured, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard,
};

/// The literal pico A declares, and the exact string the replay must carry. B's
/// filter is a WILDCARD, so a sample naming THIS token is a real intersect against
/// a real declaration and never an echo of the request.
const PICO_TOKEN: &str = "group1/pico-token";
const SUB_FILTER: &str = "group1/**";

/// How long the positive arm waits for the replay. Generous against the measured
/// latency: every one of the 5 positive runs landed inside a 4s window.
const SAMPLE_TIMEOUT: Duration = Duration::from_secs(15);

/// How long the twin waits before concluding the replay never came. ANCHORED, not
/// picked: it is twice the window the positive arm was measured to land inside, so
/// the twin cannot pass merely by being asked sooner than its sibling was.
const NO_SAMPLE_WINDOW: Duration = Duration::from_secs(8);

/// Spawn the router-hat demo on an ephemeral port and read the bound port back out
/// of its own listen log. The router-hat banner is the one that names
/// "dual-tier RouterForwarder" — the forwarder that owns the client-token plane.
fn spawn_router_hat() -> (ChildGuard, File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for router-hat stderr");
    let writer = stderr.try_clone().expect("dup router-hat stderr handle");
    let mut reader = stderr;
    let mut guard = ChildGuard::wrap(
        "liveliness-history router-hat".to_string(),
        Command::new(wz_ap_demo_binary())
            .args(["--router-hat", "127.0.0.1:0", "--subscribe", "**"])
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo --router-hat"),
    );
    let captured = wait_for_substring(
        &mut reader,
        "router-hat: listening on 127.0.0.1:",
        Duration::from_secs(5),
    )
    .unwrap_or_else(|c| {
        let _ = guard.child_mut().kill();
        let _ = guard.child_mut().wait();
        panic!(
            "wz-ap-demo did not bind a router-hat listener within 5s (is the binary \
             built with --features router-hat-router,routing-token-tables?)\n\
             --- router-hat stderr ---\n{c}"
        );
    });
    let port = listen_port(&captured);
    (guard, reader, port)
}

/// One arm of the pair. The ORDER is the atom: pico A's token is gated on A's OWN
/// declaration banner, so it provably exists before pico B is spawned at all — a
/// sleep here would leave "the token was late" and "history did nothing" looking
/// identical from B's side.
fn run_arm(history: bool) -> String {
    let (mut hat, mut hat_reader, port) = spawn_router_hat();
    let endpoint = format!("tcp/127.0.0.1:{port}");

    let a_stdout = tempfile::tempfile().expect("tempfile for z_liveliness stdout");
    let a_writer = a_stdout.try_clone().expect("dup z_liveliness handle");
    let mut a_reader = a_stdout;
    let mut pico_a = ChildGuard::wrap(
        "z_liveliness token holder (zenoh-pico)".to_string(),
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(zenoh_pico_cli_binary("z_liveliness"))
            .args([
                "-k", PICO_TOKEN, "-t", "30", "-e", &endpoint, "-m", "client",
            ])
            .stdout(Stdio::from(a_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_liveliness via stdbuf"),
    );

    // z_liveliness prints this AFTER `z_liveliness_declare_token` returns
    // (examples/unix/c11/z_liveliness.c), so it is the token EXISTING, not the
    // process merely starting. NEITHER arm means anything without it.
    if let Err(captured) = wait_for_substring(
        &mut a_reader,
        "Press CTRL-C to undeclare liveliness token",
        Duration::from_secs(10),
    ) {
        let _ = pico_a.child_mut().kill();
        let _ = hat.child_mut().kill();
        panic!(
            "z_liveliness never declared '{PICO_TOKEN}' within 10s. The positive arm \
             would have nothing to replay and the twin would pass on an empty world.\n\
             --- z_liveliness stdout ---\n{captured}"
        );
    }

    let b_stdout = tempfile::tempfile().expect("tempfile for z_sub_liveliness stdout");
    let b_writer = b_stdout.try_clone().expect("dup z_sub_liveliness handle");
    let mut b_reader = b_stdout;
    let mut cmd = Command::new("stdbuf");
    cmd.args(["-oL", "-eL"])
        .arg(zenoh_pico_cli_binary("z_sub_liveliness"))
        .args(["-k", SUB_FILTER, "-e", &endpoint, "-m", "client", "-n", "1"]);
    if history {
        // The ONE difference between the arms: `-h` sets `history`, which is the
        // CURRENT bit on the outbound Interest and nothing else.
        cmd.arg("-h");
    }
    let mut pico_b = ChildGuard::wrap(
        "z_sub_liveliness subscriber (zenoh-pico)".to_string(),
        cmd.stdout(Stdio::from(b_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_sub_liveliness via stdbuf"),
    );

    let expected = format!("New alive token ('{PICO_TOKEN}')");
    let outcome = if history {
        wait_for_substring(&mut b_reader, &expected, SAMPLE_TIMEOUT)
    } else {
        // The twin cannot "wait for nothing": it sleeps its bound, then reads
        // whatever landed. Anything present is a real replay and a real failure.
        std::thread::sleep(NO_SAMPLE_WINDOW);
        Ok(String::new())
    };

    let mut b_captured = read_captured(&mut b_reader);
    if let Ok(seen) = &outcome {
        b_captured = format!("{seen}{b_captured}");
    }
    let a_captured = read_captured(&mut a_reader);
    let _ = pico_b.child_mut().kill();
    let _ = pico_b.child_mut().wait();
    let _ = pico_a.child_mut().kill();
    let _ = pico_a.child_mut().wait();
    graceful_terminate(hat.child_mut(), Duration::from_secs(5));
    let hat_captured = read_captured(&mut hat_reader);

    if history && outcome.is_err() {
        panic!(
            "history=true, and pico A's pre-existing token was NOT replayed. Expected \
             {expected:?} — A had declared '{PICO_TOKEN}' to the router-hat before B \
             was spawned (gated on A's own banner), so neither the token nor the \
             session can explain this.\n\
             --- z_sub_liveliness stdout ---\n{b_captured}\n\
             --- z_liveliness stdout ---\n{a_captured}\n\
             --- router-hat stderr ---\n{hat_captured}"
        );
    }
    b_captured
}

/// THE ATOM: a token that existed before the subscriber's session is replayed to a
/// foreign `history = true` liveliness subscriber, carrying its exact literal.
// wz-proves: liveliness-historical-samples pico->wz
// wz-proves: routing-token-tables pico->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,routing-token-tables + zenoh-pico z_liveliness / z_sub_liveliness); Layer E6i runs via --ignored"]
fn wz_router_hat_replays_a_pico_token_to_a_history_subscriber() {
    let captured = run_arm(true);
    let expected = format!("New alive token ('{PICO_TOKEN}')");
    assert!(
        captured.contains(&expected),
        "the replay arrived but not with pico A's token — expected {expected:?}.\n\
         --- z_sub_liveliness stdout ---\n{captured}"
    );
}

/// The twin, and the arm that makes the claim above the ATOM's rather than the
/// subscriber's. Identical fixture, one pico flag removed.
///
/// `none` is honest, not an omission: alone this arm witnesses no atom — it
/// witnesses that the sibling's sample is caused by `history`. Declared rather
/// than left silent because A4-4 rejects a silent corpus test.
///
/// (Spelled only in the `//` marker line, never in this prose: A4 parses the
/// token wherever it appears, so naming it here would read as a second,
/// malformed declaration.)
// wz-proves: none -- anti-vacuity twin for the history arm above; it shows the
// replay is caused by the CURRENT bit `-h` sets and claims no atom of its own.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,routing-token-tables + zenoh-pico z_liveliness / z_sub_liveliness); Layer E6i runs via --ignored"]
fn wz_router_hat_without_history_replays_nothing() {
    let captured = run_arm(false);
    assert!(
        !captured.contains("New alive token"),
        "history=false is FUTURE-ONLY, but a token declared BEFORE the subscriber was \
         replayed anyway. Either `-h` no longer gates the CURRENT bit, or the sibling \
         test's green is not evidence of this atom at all — it would pass with history \
         off too.\n--- z_sub_liveliness stdout ---\n{captured}"
    );
}
