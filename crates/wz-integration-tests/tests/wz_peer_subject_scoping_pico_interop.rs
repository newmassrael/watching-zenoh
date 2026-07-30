// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y453 — FOREIGN-INTEROP §5.16 SUBJECT SCOPING (`interfaces` /
//! `link_protocols`): the same real zenoh-pico `z_pub` burst, against two
//! watching-zenoh peers that differ in EXACTLY ONE thing — the subject the
//! downsampling rule is narrowed to — is throttled by one and untouched by the
//! other.
//!
//! ## Why an A/B, not a control
//!
//! The sibling `wz_peer_downsampling_pico_interop` leg already proves the rate
//! limit fires. What THIS leg has to prove is that the SUBJECT axis decides
//! whether a rule governs a face at all — and the only way to show a filter is
//! doing the deciding is to change nothing but the filter. Both peers here run
//! the same keyexpr, the same frequency, the same burst; one names the subject
//! the pico face actually has, the other names a subject it does not. The
//! admitted count separates them:
//!
//! - narrowed to the face's own subject → **1** of [`PICO_PUB_COUNT`] admitted
//! - narrowed to a subject the face lacks → **all** admitted, the rule inert
//!
//! A single-peer test could not distinguish "the subject axis works" from "the
//! rule was never installed".
//!
//! ## What the interface arm additionally proves
//!
//! pico dials `tcp/127.0.0.1:<port>`, so the wz peer's accepted link is a TCP
//! socket whose LOCAL address is loopback. For the `--downsample-interface lo`
//! arm to throttle at all, `link_interfaces::interface_names_for` must have
//! resolved that address to `lo` through a real `getifaddrs` call at link open.
//! That is the live-resolution claim of R311y453 witnessed end to end by a
//! foreign peer — not by a unit test asserting against the same syscall.
//!
//! Requires the binary built with `--features routing-peer`; Layer E6 builds
//! `routing-peer,adminspace-write`.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, listen_port, read_captured, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard,
};

/// How many Puts pico's `z_pub` emits (`z_pub.c:135-137`), at one per second
/// (`z_pub.c:96-99`).
const PICO_PUB_COUNT: u32 = 3;

/// The rule's rate, slow enough that its interval spans the whole burst — so a
/// GOVERNED face is admitted exactly once. Derived from pico's cadence as in the
/// sibling leg, not picked.
const DOWNSAMPLE_FREQ_HZ: f64 = 1.0 / (10.0 * PICO_PUB_COUNT as f64);

/// The keyexpr the rule governs.
const GOVERNED_KEY: &str = "demo/rate";

/// A NIC name no host has, for the negative arm of the `interfaces` axis. The
/// `zz-` prefix and the digit suffix keep it outside every real naming scheme
/// (`eth*`, `en*`, `wl*`, `lo`, `docker*`, `veth*`).
const ABSENT_NIC: &str = "zz-nonexistent0";

/// Spawn a `--peer` demo on an ephemeral port and wait until it binds.
fn spawn_peer(label: &str, args: &[&str]) -> (ChildGuard, File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for peer stderr");
    let writer = stderr.try_clone().expect("dup peer stderr handle");
    let mut reader = stderr;
    let mut guard = ChildGuard::wrap(
        label.to_string(),
        Command::new(wz_ap_demo_binary())
            .args(args)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {label}: {e}")),
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
            "{label} did not bind within 5s (is the binary built with \
             --features routing-peer?)\n--- {label} stderr ---\n{c}"
        );
    });
    let port = listen_port(&captured);
    (guard, reader, port)
}

/// Drive pico's `z_pub` at `addr` for a bounded burst and block until it exits.
fn pico_burst(key: &str, addr: &str) {
    let bin = zenoh_pico_cli_binary("z_pub");
    let endpoint = format!("tcp/{addr}");
    let count = PICO_PUB_COUNT.to_string();
    let mut child = ChildGuard::wrap(
        format!("z_pub client (zenoh-pico) {key}"),
        Command::new(&bin)
            .args([
                "-k", key, "-v", "burst", "-e", &endpoint, "-m", "client", "-n", &count,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn z_pub: {e}")),
    );
    let _ = child.child_mut().wait();
}

/// Run ONE arm: spawn a peer with `scope_args` appended to the shared
/// downsampling knobs, drive the pico burst at it, and return how many data
/// pushes its shutdown summary reports.
fn admitted_pushes(label: &str, scope_args: &[&str]) -> String {
    let freq = DOWNSAMPLE_FREQ_HZ.to_string();
    let mut args = vec![
        "--peer",
        "127.0.0.1:0",
        "--subscribe",
        "**",
        "--downsample",
        GOVERNED_KEY,
        "--downsample-freq",
        &freq,
    ];
    args.extend_from_slice(scope_args);
    let (mut guard, mut reader, port) = spawn_peer(label, &args);
    pico_burst(GOVERNED_KEY, &format!("127.0.0.1:{port}"));
    // Give the last put time to be adjudicated before the shutdown summary.
    let _ = wait_for_substring(&mut reader, "received mesh data", Duration::from_secs(20));
    std::thread::sleep(Duration::from_millis(500));
    graceful_terminate(guard.child_mut(), Duration::from_secs(5));
    let captured = read_captured(&mut reader);
    eprintln!("--- {label} stderr ---\n{captured}");
    captured
}

/// Assert an arm's shutdown summary reports exactly `n` admitted data pushes.
fn assert_admitted(captured: &str, n: u32, label: &str, why: &str) {
    let needle = format!("{n} data push(es) received");
    assert!(
        captured.contains(&needle),
        "{label}: expected exactly {n} admitted data push(es) — {why}.\n\
         --- {label} stderr ---\n{captured}"
    );
}

/// leg (R311y453) — the `link_protocols` SUBJECT axis, cross-impl. pico dials
/// TCP; a rule narrowed to `tcp` governs that face, and the identical rule
/// narrowed to `vsock` does not.
// wz-proves: access-downsampling pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer + zenoh-pico z_pub CLI); Layer E6 runs via --ignored"]
fn wz_peer_link_protocol_scoped_rule_governs_only_the_protocol_pico_dials() {
    // pico dials tcp/... , so a tcp-scoped rule GOVERNS this face -> throttled.
    let tcp = admitted_pushes("subject-tcp", &["--downsample-link-protocol", "tcp"]);
    assert_admitted(
        &tcp,
        1,
        "subject-tcp",
        "pico dials TCP, so a tcp-scoped rule governs the face and the burst is \
         rate-limited to its first put",
    );

    // The SAME rule scoped to a protocol this face does not speak is inert.
    let vsock = admitted_pushes("subject-vsock", &["--downsample-link-protocol", "vsock"]);
    assert_admitted(
        &vsock,
        PICO_PUB_COUNT,
        "subject-vsock",
        "a vsock-scoped rule must not govern a TCP face — every put of the burst \
         is admitted, which is what makes the tcp arm above attributable to the \
         SUBJECT axis and not to the rate limit alone",
    );
}

/// leg (R311y453) — the `interfaces` SUBJECT axis, cross-impl, and with it the
/// LIVE `getifaddrs` resolution: the peer only throttles if it actually resolved
/// its accepted loopback socket to the `lo` interface at link open.
// wz-proves: access-downsampling pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer + zenoh-pico z_pub CLI); Layer E6 runs via --ignored"]
fn wz_peer_interface_scoped_rule_governs_only_the_nic_the_link_resolved_to() {
    // The accepted TCP link's local address is 127.0.0.1, which getifaddrs
    // resolves to `lo` — so an lo-scoped rule GOVERNS this face.
    let lo = admitted_pushes("subject-lo", &["--downsample-interface", "lo"]);
    assert_admitted(
        &lo,
        1,
        "subject-lo",
        "the accepted loopback link must have resolved to the `lo` NIC through a \
         real getifaddrs call, so an lo-scoped rule governs it",
    );

    // The SAME rule scoped to a NIC no host has is inert. This is also the
    // three-state check the module claims: the resolution SUCCEEDED and simply
    // did not contain this name, which is a definite non-match — not the
    // could-not-determine state, which would be fail-closed and throttle.
    let absent = admitted_pushes(
        "subject-absent-nic",
        &["--downsample-interface", ABSENT_NIC],
    );
    assert_admitted(
        &absent,
        PICO_PUB_COUNT,
        "subject-absent-nic",
        "a rule scoped to a NIC the link is not on must be inert; throttling here \
         would mean the resolver reported could-not-determine (fail-closed) rather \
         than a definite empty match",
    );
}
