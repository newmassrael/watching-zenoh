// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y454 — §5.2 locator — CROSS-IMPL validation that a wz QUIC ACCEPTOR HONOURS
//! the `#iface=<name>` locator tail on the LISTEN side (`locator-iface`,
//! zenohd->wz direction).
//!
//! Until R311y454 only the DIAL half bound its socket to the named NIC: quinn's
//! convenience `Endpoint::server` owns the UDP socket it binds and exposes no
//! bind-device hook, so `bind_quic` took no iface at all and said so in a comment
//! (`session_open.rs`, pre-R311y454). `quic_server_endpoint` now pre-binds the
//! socket, applies `SO_BINDTODEVICE`, and hands it to `quinn::Endpoint::new` —
//! the same route zenoh takes (`zenoh-link-quic/src/unicast.rs:408-427`, via
//! `Endpoint::new_with_abstract_socket`).
//!
//! ## Why this is an A/B on the SAME dial, not a feature-presence test
//!
//! A listener pinned to `lo` and dialled over loopback proves nothing on its own:
//! it succeeds identically if the iface parameter is a silent no-op. So both arms
//! run the IDENTICAL real zenohd dial against an IDENTICAL wz acceptor, differing
//! in ONE token — the device named in the listen locator:
//!
//! | arm | wz listen locator | zenohd dial | expected |
//! |---|---|---|---|
//! | A | `quic/127.0.0.1:0#iface=lo` | `quic/127.0.0.1:<port>` | session Established |
//! | B | `quic/127.0.0.1:0#iface=<non-lo NIC>` | identical | NO session Established |
//!
//! `SO_BINDTODEVICE` makes the kernel deliver only packets that ARRIVED on the
//! named device (`man 7 socket`: "If a socket is bound to an interface, only
//! packets received from that particular interface are processed by the socket").
//! A datagram to `127.0.0.1` arrives on `lo`, so arm B's socket never sees
//! zenohd's Initial packet and the handshake cannot start.
//!
//! ## What makes arm B a TIGHT negative rather than a slow one
//!
//! The precondition is asserted intact, so "nothing happened" cannot pass for the
//! wrong reason:
//!
//! - `bind(127.0.0.1)` SUCCEEDS with a foreign device bound — no `EADDRNOTAVAIL` —
//!   so `Endpoint::local_addr` still yields the ephemeral port and the demo still
//!   logs its readiness line. Arm B is structurally identical to arm A right up to
//!   the one string.
//! - The `(quic)` listen tag is asserted in BOTH arms: the quic accept path bound
//!   in both, so arm B is a delivery failure and not a bind failure.
//! - A real zenohd is actively dialling throughout arm B's window.
//!
//! ## Why the device name is discovered, never hardcoded
//!
//! `lo` is the only interface name guaranteed on every host, and it is arm A's.
//! Arm B needs SOME name that is not `lo`; it does not need a working one — a DOWN
//! device is fine, since `SO_BINDTODEVICE` binds it and loopback traffic still
//! never arrives there. So the name comes from `/sys/class/net`, which needs no
//! default route, no `ip` binary and no feature gate. A host with only `lo`
//! PANICS rather than skipping: a skipped arm is a green test that proved nothing.
//!
//! ## Why zenohd, and why no pico hop
//!
//! zenoh-pico is not built with quic — `vendor/zenoh-pico/src/link/transport/`
//! carries only `bt`, `common`, `serial`, `tcp`, `udp` — so the foreign quic
//! dialer must be a real zenohd. The sibling `wz_quic_acceptor_zenohd_interop`
//! routes a pico `z_put` across the link as well; that is deliberately NOT
//! repeated here. Established-vs-not IS the discriminator, and a routed Put would
//! add a second foreign binary and two more failure modes without adding
//! discrimination.
//!
//! ## What this does NOT prove
//!
//! The multicast half of `locator-iface` (`IP_MULTICAST_IF` + the join's
//! `imr_interface`) is NOT foreign-observable on a single host, so it is proven
//! wz-internally instead. `IP_MULTICAST_ALL` defaults to 1, so a wildcard-bound
//! socket receives group traffic joined ANYWHERE on the host; the foreign peer's
//! own join supplies the device-level membership, and both stacks must
//! wildcard-bind with `SO_REUSEADDR`/`SO_REUSEPORT` to co-exist on one host at all
//! (pico does so unconditionally,
//! `vendor/zenoh-pico/src/link/transport/udp/udp_multicast_posix.c:180,185`; wz
//! matches it in `UdpDriver::bind_multicast_v4`). Measured, not reasoned: with a
//! peer co-joined on a real NIC, a `lo`-joined socket still receives that NIC's
//! group traffic. Observing the pin would need two link domains (two hosts, or
//! netns with `CAP_NET_ADMIN`). Hence the `partial` claim below.
//!
//! Requires: `wz-ap-demo` built with `--features quic,locator-iface`, and the
//! reference `zenohd` (STOCK build — quic is in zenoh's default features). Runs on
//! the `--ignored` Layer Z lane; the `zenohd` substring in the fn name keeps the
//! default Layer E sweep's `--skip zenohd` from running it against an
//! arbitrary-feature binary.

use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_on_ephemeral_port, spawn_zenohd_quic_dialer,
    wait_for_substring, wz_ap_demo_binary,
};
use wz_runtime_tokio_test_support::localhost_cert_key_pem;

/// Removes the throwaway cert / key / dialer-config files on drop, so an early
/// panic (before the normal teardown) does not leak them — the same hygiene guard
/// as the sibling quic acceptor test.
struct TempFiles(Vec<String>);
impl Drop for TempFiles {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// The name of a host network interface that is NOT `lo`, for arm B.
///
/// Read from `/sys/class/net` rather than from the routing table: arm B needs only
/// a device that EXISTS, not one that works, so a default route is not required
/// and a DOWN device is a perfectly good answer (`SO_BINDTODEVICE` accepts it, and
/// loopback traffic still never arrives on it). Sorted, so the arm is reproducible
/// on a host whose directory order is not.
///
/// PANICS on a `lo`-only host. That is deliberate: the alternative is skipping arm
/// B, and a skipped arm reports green while proving nothing.
fn a_non_loopback_interface_name() -> String {
    let mut names: Vec<String> = std::fs::read_dir("/sys/class/net")
        .expect("read /sys/class/net — this lane needs a Linux host with sysfs")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "lo")
        .collect();
    names.sort();
    let name = names.into_iter().next().unwrap_or_else(|| {
        panic!(
            "no non-loopback interface in /sys/class/net; arm B of this A/B needs a \
             device name that is not `lo` (it need not be up), and skipping it would \
             report green while proving nothing"
        )
    });
    assert_ne!(
        name, "lo",
        "arm B's device must differ from arm A's `lo`, or the two arms collapse into one"
    );
    name
}

/// One arm: spawn a wz quic acceptor whose listen locator names `iface`, let a real
/// zenohd dial it, and report `(the demo's captured stderr, whether the wz session
/// reached Established within `budget`)`.
fn run_arm(iface: &str, cert_path: &str, key_path: &str, budget: Duration) -> (String, bool) {
    let demo = wz_ap_demo_binary();
    let listen = format!("quic/127.0.0.1:0#iface={iface}");
    let wz_stderr = tempfile::tempfile().expect("tempfile for wz acceptor stderr");
    // The readiness line is required in BOTH arms — see the module doc: the bind
    // succeeds even when the bound device cannot receive the dial, and that is
    // exactly what makes arm B a delivery negative rather than a bind failure.
    let (mut wz_guard, mut wz_reader, quic_port) = spawn_on_ephemeral_port(
        &demo,
        &[
            "--listen",
            &listen,
            "--quic-cert",
            cert_path,
            "--quic-key",
            key_path,
            "--key",
            "demo/quic-iface-honor",
            "--on-remote-subscriber-log",
        ],
        "wz accept: listening on 127.0.0.1:",
        "wz quic acceptor (#iface=)",
        wz_stderr,
    );

    let wz_quic_endpoint = format!("quic/127.0.0.1:{quic_port}");
    let (mut zenohd, _zenohd_tcp_port) = spawn_zenohd_quic_dialer(&wz_quic_endpoint, cert_path);

    let established = wait_for_substring(&mut wz_reader, "session Established", budget).is_ok();

    graceful_terminate(zenohd.child_mut(), Duration::from_secs(5));
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    (read_captured(&mut wz_reader), established)
}

/// A real zenohd dials the SAME wz quic acceptor twice, differing only in the
/// device its listen locator names: `lo` establishes, a non-`lo` NIC does not.
// R311y454 — `partial`: this witnesses the LISTEN-side `SO_BINDTODEVICE` honor for
// the quic family. The atom also covers the dial side (proven wz<->wz since
// R311y236) and the udp-multicast interface pin, which is not foreign-observable on
// a single host (see the module doc's IP_MULTICAST_ALL note). One seam of a
// dial+listen x 6-scheme + multicast atom is `partial`, not `full`.
// wz-proves: locator-iface zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features quic,locator-iface + zenohd); runs via --ignored"]
fn wz_quic_acceptor_honours_listen_iface_against_zenohd() {
    let other_iface = a_non_loopback_interface_name();

    // wz's self-signed `localhost` cert+key: the cert wz PRESENTS as the quic
    // acceptor AND the root zenohd trusts (a self-signed leaf is its own root).
    // Shared by both arms — they run sequentially.
    let (cert_pem, key_pem) = localhost_cert_key_pem();
    let base = std::env::temp_dir().join(format!("wz-quic-iface-{}", std::process::id()));
    let cert_path = format!("{}.cert.pem", base.display());
    let key_path = format!("{}.key.pem", base.display());
    std::fs::write(&cert_path, &cert_pem).expect("write wz quic cert pem");
    std::fs::write(&key_path, &key_pem).expect("write wz quic key pem");
    let _cleanup = TempFiles(vec![
        cert_path.clone(),
        key_path.clone(),
        format!("{cert_path}.dialer.zenohd.json5"),
    ]);

    // ── ARM A (calibration): pinned to `lo`, the device loopback traffic arrives
    //    on. Must establish — otherwise the pin is over-restrictive and arm B's
    //    silence would prove nothing.
    let (arm_a_log, arm_a_established) =
        run_arm("lo", &cert_path, &key_path, Duration::from_secs(10));
    eprintln!("--- ARM A (#iface=lo) wz stderr ---\n{arm_a_log}");

    // ── ARM B (the discriminator): pinned to a device the dial cannot arrive on.
    //    Same binary, same dial, same cert — one token different. A longer window
    //    than arm A, so "not yet" cannot be mistaken for "never".
    let (arm_b_log, arm_b_established) =
        run_arm(&other_iface, &cert_path, &key_path, Duration::from_secs(14));
    eprintln!("--- ARM B (#iface={other_iface}) wz stderr ---\n{arm_b_log}");

    // Both arms BOUND the quic accept path: arm B's failure is delivery, not bind.
    for (arm, log) in [("A (lo)", &arm_a_log), ("B (non-lo)", &arm_b_log)] {
        assert!(
            log.contains("(quic)"),
            "arm {arm}: wz never logged a '(quic)' listen line, so the quic accept arm \
             did not bind and this arm cannot speak to the iface honor at all.\n\
             --- wz stderr ---\n{log}"
        );
    }

    assert!(
        arm_a_established,
        "arm A: a wz quic acceptor pinned to `lo` did not complete the handshake with a \
         real zenohd dialling 127.0.0.1 within 10s. Loopback traffic DOES arrive on `lo`, \
         so this is the pin being over-restrictive — not evidence about arm B.\n\
         --- wz stderr ---\n{arm_a_log}"
    );
    assert!(
        !arm_b_established,
        "arm B: a wz quic acceptor pinned to `{other_iface}` STILL completed the \
         handshake with a zenohd dialling 127.0.0.1. A datagram to 127.0.0.1 arrives on \
         `lo`, so a listener bound to `{other_iface}` must never see it — the \
         `#iface=` tail was not honoured on the LISTEN side (a no-op parameter, or a \
         device-bound socket that quinn then did not use).\n\
         --- wz stderr ---\n{arm_b_log}"
    );
}
