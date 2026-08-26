// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y450 — FOREIGN-INTEROP §5.18 `time-hlc` FORWARD-PATH STAMP: a wz
//! `--router-hat` relays an UN-timestamped `Put` and ADDS a node-HLC timestamp to
//! it, which a real zenoh-pico `z_sub_attachment` decodes and prints.
//!
//! ## What this proves that no existing test does
//!
//! `wz_timestamp_to_pico_zsub.rs` proves the PUBLISHER-set timestamp reaches pico
//! (`Session::publish` with `with_timestamp`). That path never involves a clock —
//! the caller supplies the value. This test proves the other direction of the
//! §5.18 seam: nobody supplies a timestamp, and the ROUTER mints one on the
//! forward path. The two are different code (`build_msg_put_with_meta` vs
//! `NodeHlc::treat_timestamp` + `set_push_timestamp`) reached by different
//! callers, so the existing proof does not cover this one.
//!
//! zenoh's counterpart is the `treat_timestamp!` macro at
//! `zenoh/src/net/routing/dispatcher/pubsub.rs:328` (definition at `:176-210`),
//! and the ROLE GATE is what makes a router the node that does it: zenoh ships
//! `timestamping.enabled: { router: true, peer: false, client: false }`
//! (`DEFAULT_CONFIG.json5:206`), so a peer relaying the same Put adds nothing.
//! wz mirrors that map in `wz_runtime_tokio::node_clock::TimestampingEnabled`.
//!
//! ## Why the assertion discriminates
//!
//! Three facts have to hold at once, and each is independently verifiable:
//!
//! 1. THE PUT LEAVES THE PUBLISHER BARE. `wz-ap-demo`'s publisher builds
//!    `PublishOptions::default().with_reliability(Reliability::Reliable)`
//!    (`wz-ap-demo/src/tasks.rs:678`) and the string `with_timestamp` does not
//!    occur anywhere in that crate — so no demo run-mode can set one. The Put on
//!    the publisher->router hop therefore has `MsgPut.timestamp == None`.
//! 2. PICO PRINTS THE LINE ONLY WHEN A TIMESTAMP IS PRESENT.
//!    `vendor/zenoh-pico/examples/unix/c11/z_sub_attachment.c` guards it on
//!    `if (ts != NULL)`, so the witness is a POSITIVE discriminator: no
//!    timestamp, no line, and this test fails loudly rather than silently
//!    passing.
//! 3. THE ONLY HOP BETWEEN THEM IS THE ROUTER. The topology is a STAR with no
//!    autoconnect — neither client knows the other's address — so the sample
//!    pico receives can only have crossed `route_push`.
//!
//! Together: a `with timestamp:` line at the pico end means the wz router added
//! it. Deleting the stamp from `route_push` reds this test; so does building the
//! router WITHOUT `time-hlc`, which is the same assertion from the other side
//! (the negative twin below runs exactly that build).
//!
//! ## What this does NOT prove — stated because the gap is easy to overclaim
//!
//! The `treat_timestamp` ABSORB branch (an inbound timestamp fed to the node
//! clock via `uhlc::update_with_timestamp`) is NOT witnessed here and cannot be
//! witnessed by this harness at all. Every oracle in the inventory runs on this
//! one host with one system clock, so an inbound timestamp is never far enough
//! ahead to leave uhlc's 500 ms drift bound, and the Ok arm deliberately does
//! nothing to the message. Driving it would need a foreign publisher able to emit
//! a FUTURE timestamp, and none of `z_put` / `z_pub` / `z_pub_attachment` /
//! `z_advanced_pub` / zenohd does (each stamps its own now, or not at all). The
//! branch is unit-covered in `node_clock`'s tests, which construct the future
//! timestamp directly — that is a wz-side proof, not a cross-impl one, and the
//! atom is claimed `partial` for exactly this reason.
//!
//! ## Harness shape
//!
//! Mirrors `wz_router_hat_pico_interop.rs` (ephemeral-port router-hat, retried
//! pico client, router-side `learned a client sub` BARRIER before the publisher
//! spawns, graceful router terminate for the latched witnesses). The deltas are
//! `z_sub_attachment` instead of `z_sub`, a publisher that sets NO timestamp, and
//! the `with timestamp:` assertion.
//!
//! Requires: wz-ap-demo built with `--features router-hat-router,time-hlc` AND the
//! zenoh-pico CLI (`scripts/build-zenoh-pico-cli.sh` -> `target/zenoh-pico-cli/`).
//! run-ci's Layer E8t owns both builds. The test fn carries the `wz_router_hat_`
//! prefix so the default Layer E sweep's `--skip wz_router` excludes it from the
//! arbitrary-feature binary run.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_on_ephemeral_port, spawn_subscribed_zsub,
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
};

/// The pico witness. `z_sub_attachment` prints `with timestamp: <ntp64-u64>` only
/// when the delivered sample carries one.
const TIMESTAMP_WITNESS: &str = "with timestamp:";
const RECEIVED_WITNESS: &str = ">> [Subscriber] Received";
const PUBLISH_KEY: &str = "demo/hlc";
const SUB_KEY: &str = "demo/**";
const PUBLISH_VALUE: &str = "bare-put-stamped-by-wz-router";

/// The outcome of one publisher -> router -> pico run: what pico printed, plus the
/// router's stderr for diagnosis.
struct RelayOutcome {
    pico_stdout: String,
    router_stderr: String,
    saw_sample: bool,
}

/// Drive the whole star topology once, against a demo binary built with whatever
/// features the caller's lane compiled, and return what pico saw.
///
/// Shared by the POSITIVE test (the router stamps) and its NEGATIVE twin (the
/// router does not), because the only difference between them is the assertion —
/// running the same topology both ways is what makes the positive result
/// attributable to the stamp rather than to the topology.
fn relay_a_bare_put() -> RelayOutcome {
    relay_a_bare_put_with(&[])
}

/// [`relay_a_bare_put`] with EXTRA argv words on the router-hat.
///
/// R2112 (open-debt items 102 + 210) — the third leg needs the same topology on
/// the SAME build with one flag added, so the router's argv is the parameter and
/// nothing else moves. Everything downstream — the pico client, the barrier, the
/// publisher, the witnesses — is shared, which is what makes a difference in the
/// outcome attributable to the flag.
fn relay_a_bare_put_with(router_extra: &[&str]) -> RelayOutcome {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub_attachment");

    // The wz router-hat binds first so the pico client + the wz publisher can dial
    // its ephemeral port.
    let mut router_argv: Vec<&str> = vec!["--router-hat", "127.0.0.1:0"];
    router_argv.extend_from_slice(router_extra);
    let router_stderr = tempfile::tempfile().expect("tempfile for router stderr");
    let (mut r_guard, mut r_reader, port) = spawn_on_ephemeral_port(
        &demo,
        &router_argv,
        "router-hat: listening on 127.0.0.1:",
        "router-hat",
        router_stderr,
    );
    let endpoint = format!("tcp/127.0.0.1:{port}");

    // pico z_sub_attachment: a CLIENT of the wz router, subscribed and ready.
    let (mut z_sub_child, mut z_sub_reader) =
        spawn_subscribed_zsub(&z_sub, SUB_KEY, &endpoint, "the wz router-hat", || {
            tempfile::tempfile().expect("tempfile for z_sub_attachment stdout")
        });

    // BARRIER (not a race): wait until the ROUTER logs it installed the pico's
    // DeclareSubscriber in client_subs before spawning the publisher, so the Put
    // burst cannot outrun declare-propagation.
    wait_for_substring(
        &mut r_reader,
        "router-hat: learned a client sub",
        Duration::from_secs(10),
    )
    .unwrap_or_else(|c| {
        let _ = z_sub_child.child_mut().kill();
        let _ = z_sub_child.child_mut().wait();
        let _ = r_guard.child_mut().kill();
        let _ = r_guard.child_mut().wait();
        panic!(
            "router-hat never logged it learned the pico client subscription within \
             10s — the pico DeclareSubscriber did not reach the router's \
             client_subs\n--- router-hat stderr ---\n{c}"
        )
    });

    // wz-ap-demo: a WhatAmI::Client of the same router emitting a Put burst that
    // carries NO timestamp (see fact 1 in the module note). Any timestamp pico
    // reports therefore did not come from here.
    let pub_stderr = tempfile::tempfile().expect("tempfile for wz publisher stderr");
    let pub_writer = pub_stderr
        .try_clone()
        .expect("dup wz publisher stderr handle");
    let mut pub_reader = pub_stderr;
    let mut pub_child = ChildGuard::wrap(
        "wz-ap-demo (--connect wz-router --publish, no timestamp)".to_string(),
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--publish")
            .arg(PUBLISH_KEY)
            .arg("--value")
            .arg(PUBLISH_VALUE)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(pub_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect wz-router --publish"),
    );

    let received = wait_for_substring(&mut z_sub_reader, RECEIVED_WITNESS, Duration::from_secs(15));

    let _ = pub_child.child_mut().kill();
    let _ = pub_child.child_mut().wait();
    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    // Graceful (SIGTERM) so the router flushes its LATCHED shutdown witnesses.
    graceful_terminate(r_guard.child_mut(), Duration::from_secs(5));

    let router_stderr = read_captured(&mut r_reader);
    let pub_captured = read_captured(&mut pub_reader);
    let pico_stdout = read_captured(&mut z_sub_reader);
    eprintln!("--- router-hat stderr ---\n{router_stderr}");
    eprintln!("--- wz publisher stderr ---\n{pub_captured}");
    eprintln!("--- pico z_sub_attachment stdout ---\n{pico_stdout}");

    RelayOutcome {
        saw_sample: received.is_ok(),
        pico_stdout,
        router_stderr,
    }
}

/// wz publisher (no timestamp) -> wz router-hat (`time-hlc`) -> pico
/// `z_sub_attachment`: the router's node HLC stamps the relayed Put, and the
/// foreign subscriber decodes the timestamp.
// wz-proves: time-hlc wz->pico partial
// wz-proves: router-hat-router wz->pico partial
// wz-proves: pubsub-timestamp wz->pico partial
// wz-proves: pubsub-put wz->pico
// wz-proves: codec-push wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,time-hlc + zenoh-pico z_sub_attachment); Layer E8t runs via --ignored"]
fn wz_router_hat_hlc_stamps_a_bare_put_for_pico_zsub_attachment() {
    let outcome = relay_a_bare_put();

    assert!(
        outcome.saw_sample,
        "pico z_sub_attachment never logged '{RECEIVED_WITNESS}' within 15s — the \
         wz publisher's Put did not route through the wz router-hat to the foreign \
         subscriber, so the timestamp assertion below would be vacuous\n--- pico \
         stdout ---\n{}\n--- router-hat stderr ---\n{}",
        outcome.pico_stdout, outcome.router_stderr
    );
    // The routed sample must carry the publisher's exact key + payload, so the
    // timestamp we go on to assert belongs to THIS Put and not to a stale line.
    assert!(
        outcome
            .pico_stdout
            .contains(&format!("'{PUBLISH_KEY}': '{PUBLISH_VALUE}'")),
        "the pico subscriber received a sample, but not wz's '{PUBLISH_KEY}' Put with \
         payload '{PUBLISH_VALUE}'\n--- pico stdout ---\n{}",
        outcome.pico_stdout
    );
    // THE PROOF: the publisher set no timestamp, the only hop was the router, and
    // pico prints this line only when the sample carries one.
    assert!(
        outcome.pico_stdout.contains(TIMESTAMP_WITNESS),
        "pico received the Put but printed no '{TIMESTAMP_WITNESS}' line — the wz \
         router-hat relayed the sample WITHOUT adding a node-HLC timestamp, so the \
         §5.18 forward-path stamp did not reach the foreign wire\n--- pico stdout \
         ---\n{}\n--- router-hat stderr ---\n{}",
        outcome.pico_stdout,
        outcome.router_stderr
    );
}

/// R2112 (open-debt items 102 + 210) — the CONFIG twin: the SAME build, the SAME
/// topology, and a router-hat told `--timestamping false` must deliver the Put
/// and print NO timestamp line.
///
/// ## What this proves that the build twin below does not
///
/// The `time-hlc` twin varies a CARGO FEATURE, so it answers "is the clock
/// compiled in". This one varies an ARGV WORD on the identical binary, which is
/// the question an operator actually asks: `timestamping: { enabled: false }` in
/// a stock zenoh document is an ordinary choice — the publishers already stamp,
/// so the router must not re-stamp — and a real zenohd honours it
/// (`config.timestamping().enabled().get(whatami)`,
/// `zenoh/src/net/runtime/mod.rs:147`). Until R2112 wz's reader parsed the key
/// and every construction path passed `TimestampingEnabled::default()` literally,
/// so the wz router stamped anyway and this witness printed the line.
///
/// It is also the only leg that binds the DEMO's wiring rather than the library's:
/// the unit tests in `router_forward` / `linkstate_forward` construct the
/// forwarder directly, so they would stay green if `run_router_hat_until` dropped
/// the map on the floor between the flag and the constructor. This one spawns the
/// shipped binary and reads a FOREIGN decoder's stdout, so every hop from argv to
/// wire is inside the assertion.
///
/// The positive leg above is what makes it attributable: same binary, same
/// topology, one flag, opposite outcome.
// wz-proves: none -- the CONFIG-AXIS attribution half of the positive leg above.
// It asserts the ABSENCE of a timestamp on a build whose clock IS compiled in,
// which witnesses no atom (nothing was exercised on the wire), so claiming one
// here would inflate the proof count with a test that proves code is NOT running.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,time-hlc + zenoh-pico z_sub_attachment); Layer E8t runs via --ignored"]
fn wz_router_hat_told_not_to_timestamp_relays_a_bare_put_unstamped() {
    let outcome = relay_a_bare_put_with(&["--timestamping", "false"]);

    assert!(
        outcome.saw_sample,
        "pico z_sub_attachment never logged '{RECEIVED_WITNESS}' within 15s — the \
         config twin must still ROUTE the Put, otherwise its absent timestamp \
         proves nothing about the config key\n--- pico stdout ---\n{}\n--- \
         router-hat stderr ---\n{}",
        outcome.pico_stdout, outcome.router_stderr
    );
    assert!(
        !outcome.pico_stdout.contains(TIMESTAMP_WITNESS),
        "a router-hat told `--timestamping false` printed a '{TIMESTAMP_WITNESS}' \
         line at the pico end — zenoh's `timestamping.enabled` did not reach the \
         forward-path gate, so wz stamps where a stock zenohd would relay \
         bare\n--- pico stdout ---\n{}\n--- router-hat stderr ---\n{}",
        outcome.pico_stdout,
        outcome.router_stderr
    );
}

/// The NEGATIVE twin: the SAME topology through a router built WITHOUT `time-hlc`
/// must deliver the Put and print NO timestamp line.
///
/// This is what makes the positive test's result attributable. Without it, a
/// `with timestamp:` line could in principle come from anywhere in the path — the
/// demo, the router's non-HLC code, a pico default — and the positive assertion
/// alone cannot tell those apart. Running the identical topology with the clock
/// compiled out isolates the stamp as the only difference.
///
/// Its own build is what makes it honest, and it is why Layer E8t builds the demo
/// TWICE: a contract about a build VARIANT needs a lane that owns that build.
// wz-proves: none -- the ATTRIBUTION half of the positive leg above, not a proof of
// its own: it asserts the ABSENCE of a timestamp on a build with the clock compiled
// out. A negative result witnesses no atom (nothing was exercised), so claiming one
// here would inflate the proof count with a test that proves code is NOT running.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router WITHOUT time-hlc + zenoh-pico z_sub_attachment); Layer E8t runs via --ignored"]
fn wz_router_hat_without_time_hlc_relays_a_bare_put_unstamped() {
    let outcome = relay_a_bare_put();

    assert!(
        outcome.saw_sample,
        "pico z_sub_attachment never logged '{RECEIVED_WITNESS}' within 15s — the \
         negative twin must still ROUTE the Put, otherwise its absent timestamp \
         proves nothing about the stamp\n--- pico stdout ---\n{}\n--- router-hat \
         stderr ---\n{}",
        outcome.pico_stdout, outcome.router_stderr
    );
    assert!(
        !outcome.pico_stdout.contains(TIMESTAMP_WITNESS),
        "a router built WITHOUT `time-hlc` printed a '{TIMESTAMP_WITNESS}' line at \
         the pico end — so the timestamp the positive test asserts is NOT attributable \
         to the node HLC, and something else in the path is stamping\n--- pico stdout \
         ---\n{}\n--- router-hat stderr ---\n{}",
        outcome.pico_stdout,
        outcome.router_stderr
    );
}
