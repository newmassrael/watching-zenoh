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
//! ## R2624 — THIS SECTION USED TO SAY THE INBOUND ARMS WERE UNWITNESSABLE, AND
//! IT WAS WRONG
//!
//! The claim, kept here because the correction is worth more than a clean file:
//! the `treat_timestamp` ABSORB branch "is NOT witnessed here and cannot be
//! witnessed by this harness at all", because driving it "would need a foreign
//! publisher able to emit a FUTURE timestamp, and none of `z_put` / `z_pub` /
//! `z_pub_attachment` / `z_advanced_pub` / zenohd does".
//!
//! That is a HAND-WRITTEN LIST OF FIVE BINARIES standing in for a population.
//! The population is not the examples upstream happens to ship — it is what
//! upstream's API can be made to do, and upstream's publisher builder takes an
//! arbitrary `uhlc::Timestamp`
//! (`zenoh/src/api/builders/publisher.rs` @ `fn timestamp<TS: Into<Option<uhlc::Timestamp>>>(self, timestamp: TS) -> Self {`).
//! The capability was never missing; the example that calls it was.
//!
//! So both inbound arms are witnessed below, against `oracles/future-stamp` — a
//! wz-authored oracle LINKED against the pinned zenoh, whose `--offset-ms`
//! chooses which arm runs. What remains unwitnessed is the `drop_future_timestamp:
//! true` arm, and that is because wz does not IMPLEMENT it, which is a different
//! and honest reason. The atom is `partial` for exactly that.
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
    assert_demo_binary_newer_than_sources, graceful_terminate, read_captured,
    spawn_on_ephemeral_port, spawn_subscribed_zsub, wait_for_substring, wz_ap_demo_binary,
    wz_zenoh_oracle_binary, zenoh_pico_cli_binary, ChildGuard,
};

/// The pico witness. `z_sub_attachment` prints `with timestamp: <ntp64-u64>` only
/// when the delivered sample carries one.
const TIMESTAMP_WITNESS: &str = "with timestamp:";
const RECEIVED_WITNESS: &str = ">> [Subscriber] Received";
const PUBLISH_KEY: &str = "demo/hlc";
const SUB_KEY: &str = "demo/**";
const PUBLISH_VALUE: &str = "bare-put-stamped-by-wz-router";

/// R2623 — which implementation publishes the bare Put.
///
/// A PARAMETER rather than a second topology, deliberately: every other hop --
/// the router argv, the pico subscriber, the barrier, the witnesses -- has to be
/// identical for the two publishers to be comparable at all, and a copied
/// harness drifts. This is the same reason `relay_a_bare_put_with` takes the
/// router's extra argv rather than forking.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Publisher {
    /// `wz-ap-demo --publish`. wz on the publishing end as well as the routing
    /// one, which is what the original three legs run.
    Wz,
    /// A real zenoh-pico `z_put`. FOREIGN on the publishing end, so the only wz
    /// in the path is the router itself.
    Pico,
    /// R2624 — the wz-AUTHORED oracle built against the PINNED upstream zenoh,
    /// publishing a Put whose timestamp is offset from the session's own clock
    /// by `offset_ms`.
    ///
    /// This is the only publisher that can select WHICH arm of
    /// `treat_timestamp` runs, because the arm is chosen by how far ahead the
    /// inbound timestamp is against uhlc's 500 ms drift bound. Inside the bound
    /// the router ABSORBS and relays the value unchanged; beyond it the router
    /// REPLACES with its own now. No upstream example can drive either, since
    /// none lets the timestamp be chosen at all.
    UpstreamStamped { offset_ms: i64 },
}

/// The outcome of one publisher -> router -> pico run: what pico printed, plus the
/// router's stderr for diagnosis.
struct RelayOutcome {
    pico_stdout: String,
    router_stderr: String,
    saw_sample: bool,
    /// R2624 — what the PUBLISHER printed. The inbound-timestamp legs compare
    /// the value they sent against the value pico received, so the publisher's
    /// own output is evidence rather than diagnosis: without it a leg could only
    /// assert that SOME timestamp arrived, which both arms satisfy.
    publisher_stdout: String,
}

/// Drive the whole star topology once, against a demo binary built with whatever
/// features the caller's lane compiled, and return what pico saw.
///
/// Shared by the POSITIVE test (the router stamps) and its NEGATIVE twin (the
/// router does not), because the only difference between them is the assertion —
/// running the same topology both ways is what makes the positive result
/// attributable to the stamp rather than to the topology.
fn relay_a_bare_put() -> RelayOutcome {
    relay_a_bare_put_from(Publisher::Wz, &[])
}

/// [`relay_a_bare_put`] with EXTRA argv words on the router-hat, publishing from
/// wz. Kept so the two pre-R2623 callers read unchanged.
fn relay_a_bare_put_with(router_extra: &[&str]) -> RelayOutcome {
    relay_a_bare_put_from(Publisher::Wz, router_extra)
}

/// [`relay_a_bare_put`] with EXTRA argv words on the router-hat.
///
/// R2112 (open-debt items 102 + 210) — the third leg needs the same topology on
/// the SAME build with one flag added, so the router's argv is the parameter and
/// nothing else moves. Everything downstream — the pico client, the barrier, the
/// publisher, the witnesses — is shared, which is what makes a difference in the
/// outcome attributable to the flag.
///
/// R2623 — the PUBLISHER joined the router argv as a parameter, for the leg that
/// takes wz off the publishing end entirely.
fn relay_a_bare_put_from(publisher: Publisher, router_extra: &[&str]) -> RelayOutcome {
    let demo = wz_ap_demo_binary();
    // R2623 — every leg in this file spawns the router through here, so the
    // staleness check belongs here rather than in four places.
    //
    // It is load-bearing in THIS file specifically: three of the four legs are
    // attribution twins that vary the ROUTER BUILD (`time-hlc` compiled in or
    // out) or its argv, and they read the verdict out of a foreign subscriber's
    // stdout. A demo not rebuilt between the two builds reports the previous
    // one, which turns an attribution twin green for the wrong reason -- a
    // control coming back green, which is a finding about the control read as a
    // pass.
    assert_demo_binary_newer_than_sources(&demo);
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

    // THE PUBLISHER. Either way it emits a Put carrying NO timestamp, so any
    // timestamp pico reports did not come from here (see fact 1 in the module
    // note for wz; for pico, `vendor/zenoh-pico/examples/unix/c11/z_put.c`
    // contains the string `timestamp` zero times).
    let pub_stderr = tempfile::tempfile().expect("tempfile for publisher output");
    let pub_writer = pub_stderr.try_clone().expect("dup publisher output handle");
    let mut pub_reader = pub_stderr;
    let mut pub_child = match publisher {
        Publisher::Wz => ChildGuard::wrap(
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
        ),
        // One-shot: open -> declare keyexpr -> put -> exit. Spawned through
        // `stdbuf` for the same reason the routes leg does it — pico's stdout is
        // a pipe here, so it would otherwise be block-buffered and the exit
        // could race the flush.
        Publisher::Pico => ChildGuard::wrap(
            "zenoh-pico z_put (-> wz router-hat, no timestamp)".to_string(),
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(zenoh_pico_cli_binary("z_put"))
                .args([
                    "-k",
                    PUBLISH_KEY,
                    "-v",
                    PUBLISH_VALUE,
                    "-e",
                    &endpoint,
                    "-m",
                    "client",
                ])
                .stdout(Stdio::from(
                    pub_writer.try_clone().expect("dup z_put stdout handle"),
                ))
                .stderr(Stdio::from(pub_writer))
                .spawn()
                .expect("spawn zenoh-pico z_put via stdbuf"),
        ),
        // R2624 — one-shot like z_put: open -> put with the chosen timestamp ->
        // close -> exit. `stdbuf` for the same buffering reason.
        Publisher::UpstreamStamped { offset_ms } => ChildGuard::wrap(
            format!("wz-oracle-future-stamp (offset_ms={offset_ms} -> wz router-hat)"),
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(wz_zenoh_oracle_binary("future-stamp"))
                .args([
                    "--endpoint",
                    &endpoint,
                    "--key",
                    PUBLISH_KEY,
                    "--value",
                    PUBLISH_VALUE,
                    "--offset-ms",
                    &offset_ms.to_string(),
                ])
                .stdout(Stdio::from(
                    pub_writer.try_clone().expect("dup oracle stdout handle"),
                ))
                .stderr(Stdio::from(pub_writer))
                .spawn()
                .expect("spawn wz-oracle-future-stamp via stdbuf"),
        ),
    };

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
        publisher_stdout: pub_captured,
    }
}

/// R2624 — the `ntp64=<u64>` the publisher says it SENT.
fn sent_ntp64(outcome: &RelayOutcome) -> u64 {
    parse_ntp64(
        &outcome.publisher_stdout,
        "future-stamp: sending timestamp ntp64=",
    )
    .unwrap_or_else(|| {
        panic!(
            "the oracle never printed the timestamp it sent, so there is \
                 nothing to compare against\n--- publisher ---\n{}",
            outcome.publisher_stdout
        )
    })
}

/// R2624 — the `with timestamp: <u64>` pico says it RECEIVED.
///
/// zenoh-pico's `z_sub_attachment` prints the raw NTP64 as a decimal u64
/// (`vendor/zenoh-pico/examples/unix/c11/z_sub_attachment.c`), which is the same
/// unit the oracle prints, so the two are directly comparable without either
/// side formatting a date.
fn received_ntp64(outcome: &RelayOutcome) -> u64 {
    parse_ntp64(&outcome.pico_stdout, TIMESTAMP_WITNESS).unwrap_or_else(|| {
        panic!(
            "pico received the sample but printed no parsable '{TIMESTAMP_WITNESS}' \
             value\n--- pico stdout ---\n{}",
            outcome.pico_stdout
        )
    })
}

/// First run of decimal digits after `needle`, as a u64.
fn parse_ntp64(haystack: &str, needle: &str) -> Option<u64> {
    let tail = haystack.split(needle).nth(1)?;
    let digits: String = tail
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
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

/// R2623 — the FULLY FOREIGN leg: a real zenoh-pico `z_put` publishes a bare Put,
/// a wz `--router-hat` stamps it, and a real zenoh-pico `z_sub_attachment` decodes
/// the timestamp. wz is the only non-pico hop in the path.
///
/// ## Why this leg exists, and what it refutes
///
/// `time-hlc`'s reason carried a residual saying the auto-stamp's foreign witness
/// "is still non-discriminating because neither upstream can be made to publish
/// through wz's router-role session". That premise is FALSE against this tree and
/// was false before this round: `wz_router_routes_pico_interop.rs` already routes
/// a real pico `z_pub` and a real pico `z_put` through a wz `--router`. The
/// capability was never missing; no leg had combined it with the timestamp
/// assertion.
///
/// The difference this makes is not decorative. The three legs above all put wz
/// on the PUBLISHING end, so each of them proves "wz's router stamps what wz's
/// publisher sent" — and a shared wz assumption about the bare-Put encoding sits
/// on both ends of that claim. Here the Put is encoded by zenoh-pico and decoded
/// by zenoh-pico; the only thing wz contributes is the stamp, which is exactly
/// the thing under test.
///
/// The attribution twins above cover this leg too, because they vary the ROUTER
/// (its `time-hlc` feature, its `--timestamping` flag) and the router is shared.
// wz-proves: time-hlc pico->wz partial
// wz-proves: router-hat-router pico->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,time-hlc + zenoh-pico z_put/z_sub_attachment); Layer E8t runs via --ignored"]
fn wz_router_hat_hlc_stamps_a_bare_pico_put_for_pico_zsub_attachment() {
    let outcome = relay_a_bare_put_from(Publisher::Pico, &[]);

    assert!(
        outcome.saw_sample,
        "pico z_sub_attachment never logged '{RECEIVED_WITNESS}' within 15s — the \
         pico z_put did not route through the wz router-hat to the pico \
         subscriber, so the timestamp assertion below would be vacuous\n--- pico \
         stdout ---\n{}\n--- router-hat stderr ---\n{}",
        outcome.pico_stdout, outcome.router_stderr
    );
    assert!(
        outcome
            .pico_stdout
            .contains(&format!("'{PUBLISH_KEY}': '{PUBLISH_VALUE}'")),
        "the pico subscriber received a sample, but not the pico z_put's \
         '{PUBLISH_KEY}' Put with payload '{PUBLISH_VALUE}'\n--- pico stdout ---\n{}",
        outcome.pico_stdout
    );
    // THE PROOF: pico's z_put sets no timestamp, the only hop was the wz router,
    // and pico prints this line only when the sample carries one. Both ends are
    // foreign, so nothing wz encodes is being read back by wz.
    assert!(
        outcome.pico_stdout.contains(TIMESTAMP_WITNESS),
        "a real pico z_put routed through the wz router-hat reached a real pico \
         subscriber with no '{TIMESTAMP_WITNESS}' line — the §5.18 forward-path \
         stamp does not apply to a FOREIGN publisher's Put, which the wz-published \
         legs above cannot see\n--- pico stdout ---\n{}\n--- router-hat stderr \
         ---\n{}",
        outcome.pico_stdout,
        outcome.router_stderr
    );
}

/// R2624 — the ABSORB arm: a timestamp INSIDE uhlc's drift bound is taken into
/// the node clock and the message is relayed UNCHANGED.
///
/// wz returns early on the Ok arm (`crates/wz-runtime-tokio/src/node_clock.rs`
/// @ `                    .update_with_timestamp(&to_uhlc_timestamp(&inbound))`),
/// mirroring zenoh, which absorbs at `pubsub.rs:184` and leaves the sample
/// alone. So the discriminating observable is EQUALITY: what pico receives must
/// be the exact value the foreign publisher sent, to the bit.
///
/// Paired with the REPLACE leg below, which is the same binary, the same
/// topology and the same assertion shape with ONE NUMBER changed — and the
/// opposite outcome. Neither leg alone separates "wz relayed the timestamp" from
/// "wz stamped its own and happened to look right"; together they pin both arms.
// wz-proves: time-hlc zenoh->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,time-hlc + oracles/future-stamp + zenoh-pico z_sub_attachment); Layer E8t runs via --ignored"]
fn wz_router_hat_absorbs_an_upstream_timestamp_inside_the_drift_bound() {
    // 100 ms: comfortably inside the 500 ms bound, and far enough above clock
    // jitter on one host that it cannot land on the wrong side by accident.
    let outcome = relay_a_bare_put_from(Publisher::UpstreamStamped { offset_ms: 100 }, &[]);

    assert!(
        outcome.saw_sample,
        "pico z_sub_attachment never logged '{RECEIVED_WITNESS}' within 15s — the \
         upstream-linked oracle's Put did not route through the wz router-hat, so \
         the timestamp comparison below would be vacuous\n--- pico stdout ---\n{}\n\
         --- publisher ---\n{}\n--- router-hat stderr ---\n{}",
        outcome.pico_stdout, outcome.publisher_stdout, outcome.router_stderr
    );
    let sent = sent_ntp64(&outcome);
    let received = received_ntp64(&outcome);
    assert_eq!(
        received, sent,
        "a timestamp {}ms ahead is INSIDE uhlc's 500ms drift bound, so wz must \
         absorb it into the node clock and relay the sample untouched — pico \
         received a DIFFERENT value, which is the REPLACE arm running where \
         ABSORB belongs\n--- publisher ---\n{}\n--- pico stdout ---\n{}",
        100, outcome.publisher_stdout, outcome.pico_stdout
    );
}

/// R2624 — the REPLACE arm: a timestamp BEYOND the drift bound is rejected by
/// uhlc and wz re-stamps with its own now.
///
/// This is zenoh's shipped `drop_future_timestamp: false` behaviour
/// (`DEFAULT_CONFIG.json5:207-209`, "messages with timestamps in the future are
/// retimestamped"), and until this leg its only witness was a wz-side unit test
/// (`node_clock.rs` @ `        fn an_inbound_timestamp_beyond_the_drift_bound_is_replaced() {`)
/// which constructs the future timestamp in-process — a wz-side proof, not a
/// cross-impl one.
///
/// The observable is STRICTLY SMALLER, not merely different: the replacement is
/// the router's own clock reading, which is necessarily behind a timestamp that
/// was rejected for being too far ahead. Asserting only inequality would also
/// pass for a router that corrupted the value.
// wz-proves: time-hlc zenoh->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,time-hlc + oracles/future-stamp + zenoh-pico z_sub_attachment); Layer E8t runs via --ignored"]
fn wz_router_hat_replaces_an_upstream_timestamp_beyond_the_drift_bound() {
    // 10s: two orders of magnitude past the 500ms bound, the same margin the
    // wz-side unit test uses, so this does not sit near a threshold.
    let outcome = relay_a_bare_put_from(Publisher::UpstreamStamped { offset_ms: 10_000 }, &[]);

    assert!(
        outcome.saw_sample,
        "pico z_sub_attachment never logged '{RECEIVED_WITNESS}' within 15s — a \
         router that DROPPED the future-stamped message would look like this, and \
         wz implements the `drop_future_timestamp: false` arm, so the sample must \
         still arrive\n--- pico stdout ---\n{}\n--- publisher ---\n{}\n--- \
         router-hat stderr ---\n{}",
        outcome.pico_stdout, outcome.publisher_stdout, outcome.router_stderr
    );
    let sent = sent_ntp64(&outcome);
    let received = received_ntp64(&outcome);
    assert!(
        received < sent,
        "a timestamp 10s ahead is BEYOND uhlc's 500ms drift bound, so wz must \
         re-stamp it with its own now — pico received {received}, which is not \
         behind the {sent} the oracle sent. Equal means wz absorbed a timestamp \
         uhlc should have rejected; greater means something else stamped it\n\
         --- publisher ---\n{}\n--- pico stdout ---\n{}",
        outcome.publisher_stdout,
        outcome.pico_stdout
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
