// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y408 — §5.1 transport / §5.2 locator — CROSS-IMPL validation of the wz
//! QUIC-DATAGRAM ACCEPTOR (`transport-link-quic-datagram`, zenohd->wz direction).
//!
//! The DATAGRAM twin of `wz_quic_acceptor_zenohd_interop` (R311y401). The existing
//! `quic_datagram_e2e` proves the wz quic-datagram DATA plane wz<->wz through the
//! LOW-LEVEL `accept_quic_datagram_on` primitive, but no session-open ACCEPT SEAM
//! existed and no INDEPENDENT impl had ever dialed it. R311y408 wired the seam as a
//! uniform `BoundListener::QuicDatagram` arm (mirroring the quic acceptor):
//! `bind_locator`'s `Proto::QuicDatagram` binds a QUIC server `Endpoint` carrying
//! the `ServerConfig` (from `AcceptConfig.quic`, the SAME cert as the reliable-quic
//! backend — zenoh shares the `transport.link.tls` block across both quic links),
//! `accept_raw` takes the cheap connection ARRIVAL (`accept_quic_incoming`, shared
//! with the stream backend), and `handshake` runs the DEFERRED crypto
//! (`complete_quic_datagram_accept`, which drops the `accept_bi` — datagrams open no
//! stream). That deferral makes the datagram acceptor MESH-CAPABLE (proven wz<->wz by
//! the `mesh_accept_loop_holds_two_quic_datagram_peers` unit); THIS file is the
//! ONE-SHOT cross-impl acceptor proof — a single foreign dialer reaches the accept
//! seam and data crosses, the datagram twin of the y401 `wz_quic_acceptor` leg, NOT a
//! mesh proof.
//!
//! Vehicle: the vendored zenoh-pico CLI is not built with quic, so a real **zenohd**
//! is the foreign quic-datagram dialer. Topology (a STAR through zenohd):
//!
//!   pico `z_put` --tcp--> zenohd --quic-datagram--> wz `--listen quic-datagram/...`
//!
//! zenohd DIALS the wz datagram acceptor. zenoh does NOT give the datagram link a
//! distinct scheme — its locator prefix is `"quic"` (same as reliable quic) and the
//! DATAGRAM link is selected by the reliability metadata `rel`:
//! `quic/<wz>?rel=0` is best-effort, which zenoh's `LinkKind::try_from` routes to
//! `QuicDatagram` (both features on). So the wz side names its acceptor
//! `quic-datagram/<addr>` (a DISTINCT wz scheme) while zenohd dials the SAME UDP
//! endpoint as `quic/<wz>?rel=0`; on the wire it is one QUIC/TLS-1.3 handshake, then
//! DATAGRAM frames (no stream). zenohd trusts wz's self-signed `localhost` cert via
//! `root_ca_certificate` (chain-of-trust is load-bearing) and disables SAN matching
//! with `verify_name_on_connect: false` for the by-IP dial. A pico `z_put` on
//! zenohd's tcp listener routes through zenohd and ACROSS the quic-datagram link into
//! the wz acceptor's subscriber. The pico publisher never speaks quic and never knows
//! wz's address, so the wz subscriber firing witnesses that (1) wz accepted a real
//! foreign **quic-datagram** session (the CA-verified QUIC/TLS-1.3 handshake
//! completed and the RFC9221 datagram data plane came up) and (2) data crossed that
//! link into wz.
//!
//! Discriminator (binds to the quic-datagram accept seam, not the reliable-quic
//! acceptor or the shared tcp accept): a `wz-ap-demo` built WITHOUT the
//! `quic-datagram` feature rejects a `quic-datagram/...` listen with a typed
//! `Unsupported` ("quic-datagram acceptor requires the transport-link-quic-datagram
//! feature") — it never binds, so there is no acceptor for zenohd to dial and the
//! subscriber never fires. Only `--features quic-datagram` compiles the
//! `BoundListener::QuicDatagram` accept path (it implies `quic`, sharing the cert
//! plumbing). The unique keyexpr + payload length pin THIS Put crossing the datagram
//! link.
//!
//! Requires: `wz-ap-demo` built with `--features quic-datagram`, the reference
//! `zenohd` (STOCK build — quic-datagram is in zenoh's default features, no special
//! oracle, unlike the vsock/unixpipe oracles), AND the zenoh-pico CLI (`z_put`).
//! Runs on the `--ignored` Layer Z lane; the `zenohd` substring in the fn name keeps
//! the default Layer E sweep's `--skip zenohd` from running it against an
//! arbitrary-feature binary.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_on_ephemeral_port, spawn_zenohd_quic_datagram_dialer,
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary,
};
use wz_runtime_tokio_test_support::localhost_cert_key_pem;

const KEYEXPR: &str = "demo/quic-datagram-acceptor-fwd";
const PUBLISH_VALUE: &str = "hello-quic-datagram-acceptor-via-zenohd";

/// Removes the throwaway cert / key / dialer-config files on drop, so an early
/// panic (before the normal teardown) does not leak them — the same hygiene guard
/// as the quic acceptor test (R311y375 review obs#3).
struct TempFiles(Vec<String>);
impl Drop for TempFiles {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// pico `z_put` -> zenohd (tcp) -> wz `--listen quic-datagram/...` (quic-datagram): a
/// real zenohd dials the wz QUIC-DATAGRAM acceptor, and a pico publisher's Put routes
/// across that datagram link to the wz subscriber — the `transport-link-quic-datagram`
/// atom's first cross-impl proof in the zenohd->wz (acceptor) direction, and the
/// exercise that makes the new `BoundListener::QuicDatagram` accept seam reachable
/// from an independent impl.
// wz-proves: transport-link-quic-datagram zenohd->wz
// wz-proves: session-unicast-open zenohd->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features quic-datagram + zenohd + zenoh-pico z_put); runs via --ignored"]
fn wz_quic_datagram_acceptor_receives_pico_put_via_zenohd() {
    let demo = wz_ap_demo_binary();
    let z_put = zenoh_pico_cli_binary("z_put");

    // ── wz's self-signed `localhost` cert+key: the cert wz PRESENTS as the
    //    quic-datagram acceptor AND the root zenohd trusts (a self-signed leaf is
    //    its own root). Datagrams reuse the SAME server cert as reliable quic.
    let (cert_pem, key_pem) = localhost_cert_key_pem();
    let base = std::env::temp_dir().join(format!("wz-quic-dgram-acc-{}", std::process::id()));
    let cert_path = format!("{}.cert.pem", base.display());
    let key_path = format!("{}.key.pem", base.display());
    std::fs::write(&cert_path, &cert_pem).expect("write wz quic-datagram cert pem");
    std::fs::write(&key_path, &key_pem).expect("write wz quic-datagram key pem");
    // RAII cleanup on any unwind; the dialer helper writes `<cert>.dialer.zenohd.json5`.
    let _cleanup = TempFiles(vec![
        cert_path.clone(),
        key_path.clone(),
        format!("{cert_path}.dialer.zenohd.json5"),
    ]);

    // ── wz acceptor: bind an EPHEMERAL quic-datagram port presenting the cert,
    //    subscribe on KEYEXPR. quic-datagram binds a real UDP socket -> a real IP
    //    address, so the bound port reads back from "wz accept: listening on
    //    127.0.0.1:<port> (quic-datagram)" just like the tcp/tls/quic family.
    let wz_stderr = tempfile::tempfile().expect("tempfile for wz acceptor stderr");
    let (mut wz_guard, mut wz_reader, quic_port) = spawn_on_ephemeral_port(
        &demo,
        &[
            "--listen",
            "quic-datagram/127.0.0.1:0",
            "--quic-cert",
            &cert_path,
            "--quic-key",
            &key_path,
            "--key",
            KEYEXPR,
            "--on-remote-subscriber-log",
        ],
        "wz accept: listening on 127.0.0.1:",
        "wz quic-datagram acceptor",
        wz_stderr,
    );

    // ── zenohd: DIAL the wz quic-datagram acceptor over quic/<wz>?rel=0 (trusting
    //    wz's cert), listen on tcp for the pico pub.
    // R311y411 CORRECTION: `+1` is NOT collision-free. It is an ordinary
    // ephemeral-range port that another process may already hold — usually a
    // TIME_WAIT remnant of this lane's own client sockets, since zenohd sets no
    // SO_REUSEADDR — and zenohd then exits 255 with `Address already in use`
    // before accepting (measured 1-in-30 on the mesh quic-datagram lane). The
    // race-free replacement is `spawn_zenohd_dialer_on_ephemeral_tcp` (zenohd
    // binds :0; the test reads the kernel-assigned port back from its
    // announcement). Migrating this caller is carried work, not done here.
    let zenohd_tcp_port = quic_port.wrapping_add(1).max(1024);
    let wz_datagram_addr = format!("127.0.0.1:{quic_port}");
    let mut zenohd =
        spawn_zenohd_quic_datagram_dialer(&wz_datagram_addr, zenohd_tcp_port, &cert_path);

    // Cross-impl witness #1: the wz acceptor completed the QUIC (TLS-1.3) + zenoh
    // handshake with the real zenohd dialer. quic-datagram DEFERS its crypto handshake
    // off the accept path (`complete_quic_datagram_accept` in the spawned open future,
    // the split that makes the datagram acceptor mesh-capable); "session Established"
    // is the transport-agnostic handshake-completion witness this test pins.
    let established = wait_for_substring(
        &mut wz_reader,
        "session Established",
        Duration::from_secs(10),
    );

    // ── pico z_put on zenohd's tcp listener: routes through zenohd and across the
    //    quic-datagram link to the wz subscriber. One-shot (declare keyexpr -> put ->
    //    exit).
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
    // the quic-datagram link into wz. The unique keyexpr + payload length pin THIS put.
    let fired = wait_for_substring(&mut wz_reader, "SUBSCRIBER FIRED", Duration::from_secs(15));

    let _ = put_child.kill();
    let _ = put_child.wait();
    graceful_terminate(zenohd.child_mut(), Duration::from_secs(5));
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    // cert/key/dialer-config removed by `_cleanup`'s Drop.

    let wz_captured = read_captured(&mut wz_reader);
    eprintln!("--- wz quic-datagram acceptor stderr ---\n{wz_captured}");

    // Positive transport witness (family parity with the quic/udp/tls acceptor legs):
    // the demo logged the `(quic-datagram)` listen line — the quic-datagram accept arm
    // bound, not a silent reliable-quic or tcp fallback. `spawn_on_ephemeral_port`
    // already required the "listening on 127.0.0.1:" prefix; this pins the transport TAG.
    assert!(
        wz_captured.contains("(quic-datagram)"),
        "wz never logged a '(quic-datagram)' listen line — the quic-datagram accept arm \
         did not bind.\n--- wz stderr ---\n{wz_captured}"
    );
    // Datagram-SPECIFIC accept witness: the acceptor logged the "quic-datagram server
    // handshake" completion note (`AcceptedLink::QuicDatagram` server_handshake_note),
    // pinning the DATAGRAM accept arm's deferred handshake specifically — a tighter
    // witness than the generic "(quic-datagram)" bind tag or "session Established".
    assert!(
        wz_captured.contains("quic-datagram server handshake"),
        "wz never logged the 'quic-datagram server handshake' accept note — the deferred \
         datagram accept handshake did not run.\n--- wz stderr ---\n{wz_captured}"
    );
    established.unwrap_or_else(|c| {
        panic!(
            "wz never logged 'session Established' within 10s — the wz quic-datagram acceptor \
             did not complete the QUIC + zenoh handshake with the zenohd dialer.\n\
             --- wz stderr ---\n{c}"
        )
    });
    let fired_text = fired.unwrap_or_else(|c| {
        panic!(
            "wz never logged 'SUBSCRIBER FIRED' within 15s — the pico Put did not route through \
             zenohd and across the quic-datagram link to the wz acceptor's subscriber.\n\
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
