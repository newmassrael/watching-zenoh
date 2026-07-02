// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! P4 §5.21 router — CROSS-IMPL validation of the wz router-hat against a real
//! zenoh-pico client.
//!
//! Every §5.21 test to date (`wz_router_hat_mesh.rs`) pairs the dual-mesh
//! `RouterForwarder` with wz PEERS / CLIENTS — the router's wire plane is proven,
//! but only against ITSELF. This pairs it with the embedded C implementation
//! (`zenoh-pico`): a real pico client can subscribe THROUGH the router-hat and
//! receive a wz publisher's `Put`. It is the pico analog of `wz_to_zenohd_router.rs`
//! leg 2 (which routed wz -> zenohd -> pico through the REFERENCE router): here wz's
//! OWN `--router-hat` replaces zenohd as the mediating router, so a wz publisher's
//! `Put` routes wz-client -> [wz router-hat] -> pico `z_sub`. This is the router
//! daemon's FIRST cross-impl (non-wz) proof — ONE direction of ONE plane. It does NOT
//! close cross-impl: the reverse data direction (pico-pub -> wz-sub), the query /
//! reply plane, liveliness, router-native (non-`client_subs`) subscribers, and
//! multi-router federation to pico all stay wz<->wz-only and are NOT exercised here
//! (each is a separate leg, as `wz_to_zenohd_router.rs`'s nine legs are for zenohd).
//!
//! Topology (a STAR through the wz router, no autoconnect): the pico `z_sub` dials
//! the router as a `-m client`, landing in the router's `client_subs`; the wz
//! `--connect --publish` node dials the router as a `WhatAmI::Client` too. The
//! router's `route_push` block 3 (`deliver_to_client_subscribers`) is what carries
//! the wz Put to the pico client subscriber — the only path (neither client knows
//! the other's address). The pico subscriber's *client-side* declare is confirmed
//! before the wz publisher starts; delivery is then carried NOT by a strict
//! router-confirmed barrier (the router emits no "learned a client sub" witness) but
//! by BURST TOLERANCE — the publisher's TCP connect + handshake gap plus a 5x200ms
//! Put burst span far more than the localhost declare-propagation window, so a Put
//! lands after the router installs the subscription (the same race-covered-by-burst
//! mechanism the zenohd sibling relies on).
//!
//! Requires: wz-ap-demo built with `--features router-hat-router` (the router
//! binary — one binary also serves the `--connect --publish` wz client) AND the
//! zenoh-pico CLI (`scripts/build-zenoh-pico-cli.sh` -> `target/zenoh-pico-cli/`).
//! run-ci's Layer E8 builds the demo and SKIPs if the pico CLI is absent; the test
//! runs on the `--ignored` lane like the other binary-dep e2es. The test fn carries
//! the `wz_router_hat_` prefix so the default Layer E sweep's `--skip wz_router`
//! excludes it from the arbitrary-feature binary run.

use std::fs::File;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard,
};

/// Parse the bound port from the router-hat's `listening on 127.0.0.1:<port>` log —
/// the ephemeral-port read-back that lets the pico `z_sub` + the wz publisher dial
/// this router without a reserved-port allocation.
fn listen_port(captured: &str) -> u16 {
    let marker = "listening on 127.0.0.1:";
    let rest = captured
        .split(marker)
        .nth(1)
        .unwrap_or_else(|| panic!("no '{marker}' in:\n{captured}"));
    rest.chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap_or_else(|e| panic!("unparseable port after '{marker}': {e}\n{captured}"))
}

/// Spawn the wz `--router-hat` node on an ephemeral port and return it once bound,
/// with its stderr reader and the read-back port. Presents wire `WhatAmI::Router`.
fn spawn_router_hat(label: &str) -> (ChildGuard, File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for router stderr");
    let writer = stderr.try_clone().expect("dup router stderr handle");
    let mut reader = stderr;
    let mut guard = ChildGuard::wrap(
        label.to_string(),
        Command::new(wz_ap_demo_binary())
            .args(["--router-hat", "127.0.0.1:0"])
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {label}: {e}")),
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
            "{label} did not bind within 5s (is the binary built with \
             --features router-hat-router?)\n--- {label} stderr ---\n{c}"
        )
    });
    let port = listen_port(&captured);
    (guard, reader, port)
}

/// Spawn a zenoh-pico `z_sub` as a CLIENT of the wz router, returned once its
/// session is OPEN and the subscriber DECLARED (`"Declaring Subscriber on"`).
///
/// Two robustness details, both learned from the sibling `wz_to_zenohd_router.rs`
/// and confirmed against this router:
///   * `stdbuf -oL -eL` forces line buffering — pico's CLI block-buffers stdout when
///     it is not a TTY, so without this its `Received` line never reaches the file
///     until exit (the subscribe/receive would look like it never happened).
///   * pico's `z_sub` is a one-shot that prints `"Unable to open session!"` and
///     exits if its open transiently fails, and it does NOT self-retry — so under
///     full-run-ci load the orchestrator respawns it. The transient sits at the
///     pico<->router OPEN handshake boundary; the retry tolerates it at either end.
///     The wz router side has shown no independent flake in the wz<->wz E2E suite,
///     and this test's standalone repeats pass zero-flake (WITH the retry in place).
fn spawn_subscribed_pico_zsub(z_sub: &Path, sub_key: &str, endpoint: &str) -> (ChildGuard, File) {
    const ATTEMPTS: usize = 6;
    for attempt in 1..=ATTEMPTS {
        let out = tempfile::tempfile().expect("tempfile for z_sub stdout");
        let out_writer = out.try_clone().expect("dup z_sub stdout handle");
        let mut out_reader = out;
        let mut child = ChildGuard::wrap(
            "z_sub client (zenoh-pico)".to_string(),
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(z_sub)
                .args(["-k", sub_key, "-e", endpoint, "-m", "client"])
                .stdout(Stdio::from(out_writer))
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn z_sub via stdbuf"),
        );
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let cap = read_captured(&mut out_reader);
            if cap.contains("Declaring Subscriber on") {
                return (child, out_reader); // session open + subscriber declared
            }
            if cap.contains("Unable to open session") || Instant::now() >= deadline {
                break; // transient open failure / timeout -> respawn
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
        eprintln!("pico z_sub open attempt {attempt}/{ATTEMPTS} did not subscribe; retrying");
    }
    panic!("pico z_sub failed to open a session to the wz router-hat after {ATTEMPTS} attempts");
}

/// wz publisher -> wz router-hat -> pico `z_sub`: the wz router routes a wz client's
/// `Put` to a real zenoh-pico client subscriber — the §5.21 router's first
/// cross-impl (foreign-client) data-plane proof.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router + zenoh-pico z_sub); Layer E8 runs via --ignored"]
fn wz_router_hat_routes_wz_publish_to_pico_zsub() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let publish_key = "demo/pico";
    let sub_key = "demo/**";
    let publish_value = "hello-pico-via-wz-router";

    // The wz router-hat binds first so the pico client + the wz publisher can dial
    // its ephemeral port.
    let (mut r_guard, mut r_reader, port) = spawn_router_hat("router-hat");
    let endpoint = format!("tcp/127.0.0.1:{port}");

    // pico z_sub: a CLIENT of the wz router, subscribed and ready (retried past any
    // transient one-shot open). Its CLIENT-SIDE declare precedes the publisher spawn;
    // that alone does not prove the router installed the sub in client_subs, so
    // delivery rests on BURST TOLERANCE — the publisher's connect+handshake gap plus
    // the 5x200ms Put burst outlast the localhost declare propagation (the same
    // mechanism the zenohd sibling leg 2 relies on), not on a strict barrier.
    let (mut z_sub_child, mut z_sub_reader) =
        spawn_subscribed_pico_zsub(&z_sub, sub_key, &endpoint);

    // wz-ap-demo: a WhatAmI::Client of the same wz router that emits a Put burst on
    // `demo/pico`. The router's route_push delivers it to the pico client subscriber
    // (deliver_to_client_subscribers) — the only path (neither client knows the
    // other's address).
    let pub_stderr = tempfile::tempfile().expect("tempfile for wz publisher stderr");
    let pub_writer = pub_stderr
        .try_clone()
        .expect("dup wz publisher stderr handle");
    let mut pub_reader = pub_stderr;
    let mut pub_child = ChildGuard::wrap(
        "wz-ap-demo (--connect wz-router --publish)".to_string(),
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--publish")
            .arg(publish_key)
            .arg("--value")
            .arg(publish_value)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(pub_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect wz-router --publish"),
    );

    // The pico subscriber must RECEIVE the wz publisher's Put, routed through the wz
    // router-hat — the cross-impl data-plane proof.
    let received_substr = ">> [Subscriber] Received";
    let received = wait_for_substring(&mut z_sub_reader, received_substr, Duration::from_secs(15));

    // The pico one-shot + the wz publisher are killed directly; the router is
    // graceful_terminate'd (SIGTERM) so it flushes its LATCHED shutdown witnesses
    // (`forwarded mesh data` on data_seen > 0). A SIGKILL would skip them, and this
    // ~0.1 s test can finish before the router's 250 ms app-tick in-run witness fires
    // — so the router-transit assertion below needs the graceful path.
    let _ = pub_child.child_mut().kill();
    let _ = pub_child.child_mut().wait();
    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    graceful_terminate(r_guard.child_mut(), Duration::from_secs(5));

    let r_captured = read_captured(&mut r_reader);
    let pub_captured = read_captured(&mut pub_reader);
    let z_sub_captured = read_captured(&mut z_sub_reader);
    eprintln!("--- router-hat stderr ---\n{r_captured}");
    eprintln!("--- wz publisher stderr ---\n{pub_captured}");
    eprintln!("--- pico z_sub stdout ---\n{z_sub_captured}");

    let received_text = received.unwrap_or_else(|c| {
        panic!(
            "pico z_sub never logged '{received_substr}' within 15s — wz's Put did \
             not route through the wz router-hat to the foreign pico subscriber\n--- \
             pico z_sub stdout ---\n{c}\n--- router-hat stderr ---\n{r_captured}\n--- \
             wz publisher stderr ---\n{pub_captured}"
        )
    });
    // The routed sample must carry BOTH the publisher's keyexpr and its exact payload
    // — a green "Received" line alone could be a stale artifact, but the unique
    // payload pins THIS wz publisher's Put crossing the router to pico.
    assert!(
        received_text.contains(&format!("'{publish_key}': '{publish_value}'")),
        "the pico subscriber received a sample, but not wz's '{publish_key}' Put with \
         payload '{publish_value}' — the routed key/value did not match\n--- pico \
         z_sub stdout ---\n{received_text}"
    );
    // Transit pin: the wz router's OWN data counter rose (it counts every inbound
    // Push before routing), so the Put transited THROUGH the router — not around it
    // (the pico client and the wz publisher never knew each other's address). This is
    // the same `forwarded mesh data` witness the wz<->wz data tests assert on.
    assert!(
        r_captured.contains("router-hat: forwarded mesh data"),
        "the wz router-hat never forwarded a Push — the wz Put did not transit it, so \
         the delivery to pico did not exercise the router's data route\n--- \
         router-hat stderr ---\n{r_captured}"
    );
}
