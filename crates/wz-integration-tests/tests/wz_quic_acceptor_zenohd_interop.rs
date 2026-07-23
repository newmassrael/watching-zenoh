// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y401 — §5.1 transport / §5.2 locator — CROSS-IMPL validation of the wz QUIC
//! ACCEPTOR (`transport-link-quic`, zenohd->wz direction).
//!
//! The QUIC twin of `wz_tls_acceptor_zenohd_interop`. The existing
//! `wz_to_zenohd_router.rs` quic legs prove the wz quic DIALER (wz `--connect
//! quic/...` against zenohd's `quic/` listener — `transport-link-quic wz->zenohd`).
//! The REVERSE — a foreign peer DIALING a wz `quic/...` acceptor — had no proof:
//! wz's QUIC pipeline primitives (`bind_quic` / `accept_quic_on`) were proven
//! wz<->wz by `wz_runtime_tokio::quic_e2e`, but no session-open ACCEPT SEAM existed
//! and no INDEPENDENT impl had ever dialed it. R311y401 wired the seam as a uniform
//! `BoundListener::Quic` arm (mirroring the tls acceptor): `bind_locator`'s
//! `Proto::Quic` binds a QUIC server `Endpoint` carrying the `ServerConfig` (from
//! `AcceptConfig.quic`, the accept mirror of `DialConfig.quic`), and `accept_raw`
//! takes the connection ARRIVAL while `handshake` runs the QUIC crypto: R311y401
//! wired the seam with the crypto inline; R311y404 split it into the deferred
//! `accept_quic_incoming` / `complete_quic_accept` halves (the tls-style split that
//! makes quic mesh-capable). This is that cross-impl proof.
//!
//! Vehicle: the vendored zenoh-pico CLI is not built with quic, so a real
//! **zenohd** is the foreign quic dialer. Topology (a STAR through zenohd):
//!
//!   pico `z_put` --tcp--> zenohd --quic--> wz `--listen quic/...` (subscriber)
//!
//! zenohd DIALS the wz quic acceptor (`-e quic/<wz>`), trusting wz's self-signed
//! `localhost` cert via `root_ca_certificate` (chain-of-trust is load-bearing — a
//! wrong CA fails the handshake) and disabling SAN matching with
//! `verify_name_on_connect: false` for the by-IP dial. zenoh's QUIC link reads this
//! from the SAME `transport.link.tls` config block as the tls link (no separate quic
//! cert block). A pico `z_put` on zenohd's tcp listener routes through zenohd and
//! ACROSS the quic link into the wz acceptor's subscriber. The pico publisher never
//! speaks quic and never knows wz's address, so the wz subscriber firing witnesses
//! that (1) wz accepted a real foreign **quic** session (the zenoh handshake
//! completed over a CA-verified QUIC/TLS-1.3 server handshake) and (2) data crossed
//! that quic link into wz.
//!
//! Discriminator (binds to the quic acceptor, not the shared tcp accept): a
//! `wz-ap-demo` built WITHOUT the `quic` feature rejects a `quic/...` listen with a
//! typed `Unsupported` ("quic acceptor requires the transport-link-quic feature") —
//! it never binds, so there is no acceptor for zenohd to dial and the subscriber
//! never fires. Only `--features quic` compiles the `BoundListener::Quic` accept
//! path. The unique keyexpr + payload length pin THIS Put crossing the quic link.
//!
//! Requires: `wz-ap-demo` built with `--features quic`, the reference `zenohd`
//! (STOCK build — quic is in zenoh's default features, no special oracle, unlike the
//! vsock/unixpipe oracles), AND the zenoh-pico CLI (`z_put`). Runs on the `--ignored`
//! Layer Z lane; the `zenohd` substring in the fn name keeps the default Layer E
//! sweep's `--skip zenohd` from running it against an arbitrary-feature binary.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_on_ephemeral_port, spawn_zenohd_quic_dialer,
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary,
};
use wz_runtime_tokio_test_support::localhost_cert_key_pem;

const KEYEXPR: &str = "demo/quic-acceptor-fwd";
const PUBLISH_VALUE: &str = "hello-quic-acceptor-via-zenohd";

/// Removes the throwaway cert / key / dialer-config files on drop, so an early
/// panic (before the normal teardown) does not leak them — the same hygiene guard
/// as the tls acceptor test (R311y375 review obs#3).
struct TempFiles(Vec<String>);
impl Drop for TempFiles {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// pico `z_put` -> zenohd (tcp) -> wz `--listen quic/...` (quic): a real zenohd
/// dials the wz QUIC acceptor, and a pico publisher's Put routes across that quic
/// link to the wz subscriber — the `transport-link-quic` atom's first cross-impl
/// proof in the zenohd->wz (acceptor) direction, and the exercise that makes the new
/// `BoundListener::Quic` accept seam reachable from an independent impl.
// wz-proves: transport-link-quic zenohd->wz
// wz-proves: session-unicast-open zenohd->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features quic + zenohd + zenoh-pico z_put); runs via --ignored"]
fn wz_quic_acceptor_receives_pico_put_via_zenohd() {
    let demo = wz_ap_demo_binary();
    let z_put = zenoh_pico_cli_binary("z_put");

    // ── wz's self-signed `localhost` cert+key: the cert wz PRESENTS as the quic
    //    acceptor AND the root zenohd trusts (a self-signed leaf is its own root).
    let (cert_pem, key_pem) = localhost_cert_key_pem();
    let base = std::env::temp_dir().join(format!("wz-quic-acc-{}", std::process::id()));
    let cert_path = format!("{}.cert.pem", base.display());
    let key_path = format!("{}.key.pem", base.display());
    std::fs::write(&cert_path, &cert_pem).expect("write wz quic cert pem");
    std::fs::write(&key_path, &key_pem).expect("write wz quic key pem");
    // RAII cleanup on any unwind; the dialer helper writes `<cert>.dialer.zenohd.json5`.
    let _cleanup = TempFiles(vec![
        cert_path.clone(),
        key_path.clone(),
        format!("{cert_path}.dialer.zenohd.json5"),
    ]);

    // ── wz acceptor: bind an EPHEMERAL quic port presenting the cert, subscribe on
    //    KEYEXPR. QUIC binds a real UDP socket -> a real IP address, so the bound
    //    port reads back from "wz accept: listening on 127.0.0.1:<port> (quic)" just
    //    like the tcp/tls family (unlike the non-IP unixsock/vsock acceptors).
    let wz_stderr = tempfile::tempfile().expect("tempfile for wz acceptor stderr");
    let (mut wz_guard, mut wz_reader, quic_port) = spawn_on_ephemeral_port(
        &demo,
        &[
            "--listen",
            "quic/127.0.0.1:0",
            "--quic-cert",
            &cert_path,
            "--quic-key",
            &key_path,
            "--key",
            KEYEXPR,
            "--on-remote-subscriber-log",
        ],
        "wz accept: listening on 127.0.0.1:",
        "wz quic acceptor",
        wz_stderr,
    );

    // ── zenohd: DIAL the wz quic acceptor over quic (trusting wz's cert), listen on
    //    tcp for the pico pub. quic_port is a UDP port; the zenohd tcp listener uses
    //    a distinct TCP port (different protocol namespace, no collision).
    let zenohd_tcp_port = quic_port.wrapping_add(1).max(1024);
    let wz_quic_endpoint = format!("quic/127.0.0.1:{quic_port}");
    let mut zenohd = spawn_zenohd_quic_dialer(&wz_quic_endpoint, zenohd_tcp_port, &cert_path);

    // Cross-impl witness #1: the wz acceptor completed the QUIC (TLS-1.3) + zenoh
    // handshake with the real zenohd dialer. Since R311y404 QUIC DEFERS its crypto
    // handshake off the accept path (`complete_quic_accept` in the spawned open
    // future, the tls-style split that makes quic mesh-capable); "session Established"
    // is the transport-agnostic handshake-completion witness this test pins.
    let established = wait_for_substring(
        &mut wz_reader,
        "session Established",
        Duration::from_secs(10),
    );

    // ── pico z_put on zenohd's tcp listener: routes through zenohd and across the
    //    quic link to the wz subscriber. One-shot (declare keyexpr -> put -> exit).
    let put_stdout = tempfile::tempfile().expect("tempfile for z_put stdout");
    let mut put_child = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_put)
        .args([
            "-k",
            KEYEXPR,
            "-v",
            PUBLISH_VALUE,
            "-e",
            &format!("tcp/127.0.0.1:{zenohd_tcp_port}"),
            "-m",
            "client",
        ])
        .stdout(Stdio::from(put_stdout))
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn z_put via stdbuf");

    // Cross-impl witness #2: the wz subscriber fired on the routed Put — data crossed
    // the quic link into wz. The unique keyexpr + payload length pin THIS put.
    let fired = wait_for_substring(&mut wz_reader, "SUBSCRIBER FIRED", Duration::from_secs(15));

    let _ = put_child.kill();
    let _ = put_child.wait();
    graceful_terminate(zenohd.child_mut(), Duration::from_secs(5));
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    // cert/key/dialer-config removed by `_cleanup`'s Drop.

    let wz_captured = read_captured(&mut wz_reader);
    eprintln!("--- wz quic acceptor stderr ---\n{wz_captured}");

    // Positive transport witness (family parity with the udp/tls acceptor legs): the
    // demo logged the `(quic)` listen line — the quic accept arm bound, not a silent
    // tcp fallback. `spawn_on_ephemeral_port` already required the "listening on
    // 127.0.0.1:" prefix; this pins the transport TAG.
    assert!(
        wz_captured.contains("(quic)"),
        "wz never logged a '(quic)' listen line — the quic accept arm did not bind.\n\
         --- wz stderr ---\n{wz_captured}"
    );
    established.unwrap_or_else(|c| {
        panic!(
            "wz never logged 'session Established' within 10s — the wz quic acceptor did not \
             complete the QUIC + zenoh handshake with the zenohd dialer.\n--- wz stderr ---\n{c}"
        )
    });
    let fired_text = fired.unwrap_or_else(|c| {
        panic!(
            "wz never logged 'SUBSCRIBER FIRED' within 15s — the pico Put did not route through \
             zenohd and across the quic link to the wz acceptor's subscriber.\n\
             --- wz stderr ---\n{c}"
        )
    });

    assert!(
        fired_text.contains(KEYEXPR),
        "the wz subscriber fired, but not on the agreed keyexpr '{KEYEXPR}'.\n\
         --- wz stderr ---\n{fired_text}"
    );
    assert!(
        fired_text.contains(&format!("payload_len={}", PUBLISH_VALUE.len())),
        "the wz subscriber fired on '{KEYEXPR}', but not with the expected payload length {}.\n\
         --- wz stderr ---\n{fired_text}",
        PUBLISH_VALUE.len()
    );
}
