// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Cross-impl validation of wz's QUIC link with the mixed-reliability datagram
//! companion (`mixed_rel=1`), against a real zenohd dialing a wz acceptor.
//!
//! Topology (a star through zenohd):
//!
//!   pico `z_put` --tcp--> zenohd --quic?mixed_rel=1--> wz `--listen` (subscriber)
//!
//! Both ends ask for `mixed_rel=1`, so each offers only the protocols with the
//! companion (`zenoh-ms-mr`, `zenoh-mr`) and a session opens only if the two
//! negotiate one of them: a wz acceptor that still refused or did not serve the
//! companion never binds or never completes ALPN.
//!
//! The leg then holds the session idle for longer than wz's lease before the
//! put. Upstream runs the companion as a link of its own with its own receive
//! lease, and a companion that hears nothing for that lease ends the pair with
//! it (`io/zenoh-transport/src/unicast/universal/transport.rs` @
//! `// Associated link must also be closed. run both close calls, return whichever failed first`).
//! Nothing else rides the companion here (the put is reliable, and so are the
//! declarations), so the put reaching wz after the idle window proves that wz
//! kept the companion alive by its own keepalives; without them zenohd closes the
//! link at the lease and the subscriber never fires.
//!
//! `#[ignore]` (binary-dep e2e): needs `wz-ap-demo --features quic`, the stock
//! zenohd (QUIC and its companion are in zenoh's default features) and the
//! zenoh-pico CLI `z_put`. Runs on the `--ignored` Layer Z lane; the `zenohd`
//! substring in the fn name keeps the default Layer E sweep's `--skip zenohd`
//! from running it.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_on_ephemeral_port, spawn_zenohd_quic_dialer,
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary,
};
use wz_runtime_tokio_test_support::localhost_cert_key_pem;

const KEYEXPR: &str = "demo/quic-mixed-rel";
const PUBLISH_VALUE: &str = "hello-quic-mixed-reliability-via-zenohd";

/// Past the 10 s lease both wz and zenohd advertise by default, with margin.
const IDLE_PAST_LEASE: Duration = Duration::from_secs(13);

/// Removes the throwaway cert / key / dialer-config files on drop, so an early
/// panic does not leak them.
struct TempFiles(Vec<String>);
impl Drop for TempFiles {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// zenohd dials a wz `quic/...?mixed_rel=1` acceptor; the session stays up past
/// the lease with only keepalives on the companion, and a pico Put routed
/// through zenohd then reaches the wz subscriber.
// wz-proves: transport-link-quic zenohd->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features quic + zenohd + zenoh-pico z_put); runs via --ignored"]
fn wz_quic_mixed_reliability_acceptor_outlives_the_lease_via_zenohd() {
    let demo = wz_ap_demo_binary();
    let z_put = zenoh_pico_cli_binary("z_put");

    let (cert_pem, key_pem) = localhost_cert_key_pem();
    let base = std::env::temp_dir().join(format!("wz-quic-mr-{}", std::process::id()));
    let cert_path = format!("{}.cert.pem", base.display());
    let key_path = format!("{}.key.pem", base.display());
    std::fs::write(&cert_path, &cert_pem).expect("write wz quic cert pem");
    std::fs::write(&key_path, &key_pem).expect("write wz quic key pem");
    let _cleanup = TempFiles(vec![
        cert_path.clone(),
        key_path.clone(),
        format!("{cert_path}.dialer.zenohd.json5"),
    ]);

    let wz_stderr = tempfile::tempfile().expect("tempfile for wz acceptor stderr");
    let (mut wz_guard, mut wz_reader, quic_port) = spawn_on_ephemeral_port(
        &demo,
        &[
            "--listen",
            "quic/127.0.0.1:0?mixed_rel=1",
            "--quic-cert",
            &cert_path,
            "--quic-key",
            &key_path,
            "--key",
            KEYEXPR,
        ],
        "wz accept: listening on 127.0.0.1:",
        "wz quic mixed-reliability acceptor",
        wz_stderr,
    );

    let wz_quic_endpoint = format!("quic/127.0.0.1:{quic_port}?mixed_rel=1");
    let (mut zenohd, zenohd_tcp_port) = spawn_zenohd_quic_dialer(&wz_quic_endpoint, &cert_path);

    let established = wait_for_substring(
        &mut wz_reader,
        "session Established",
        Duration::from_secs(10),
    );

    // The idle window: only keepalives cross either line while it runs.
    if established.is_ok() {
        std::thread::sleep(IDLE_PAST_LEASE);
    }

    let put_stdout = tempfile::tempfile().expect("tempfile for z_put stdout");
    let mut put_child = established.is_ok().then(|| {
        Command::new("stdbuf")
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
            .stdout(Stdio::from(
                put_stdout.try_clone().expect("dup stdout handle"),
            ))
            .stderr(Stdio::from(
                put_stdout.try_clone().expect("dup stderr handle"),
            ))
            .spawn()
            .expect("spawn z_put via stdbuf")
    });

    let fired = wait_for_substring(&mut wz_reader, "SUBSCRIBER FIRED", Duration::from_secs(15));

    if let Some(child) = put_child.as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
    graceful_terminate(zenohd.child_mut(), Duration::from_secs(5));
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));

    let wz_captured = read_captured(&mut wz_reader);
    eprintln!("--- wz quic mixed-reliability acceptor stderr ---\n{wz_captured}");

    assert!(
        wz_captured.contains("(quic)"),
        "wz never logged a '(quic)' listen line — the quic accept arm did not bind.\n\
         --- wz stderr ---\n{wz_captured}"
    );
    established.unwrap_or_else(|c| {
        panic!(
            "wz never logged 'session Established' within 10s — zenohd and wz did not \
             negotiate a mixed-reliability protocol over QUIC.\n--- wz stderr ---\n{c}"
        )
    });
    let fired_text = fired.unwrap_or_else(|c| {
        panic!(
            "wz never logged 'SUBSCRIBER FIRED' within 15s of a put sent {}s after \
             Established — the link did not outlive the lease, which is what a companion \
             left without keepalives does.\n--- wz stderr ---\n{c}",
            IDLE_PAST_LEASE.as_secs()
        )
    });
    assert!(
        fired_text.contains(KEYEXPR),
        "the wz subscriber fired, but not on '{KEYEXPR}'.\n{fired_text}"
    );
    assert!(
        fired_text.contains(&format!("payload_len={}", PUBLISH_VALUE.len())),
        "the wz subscriber fired on '{KEYEXPR}', but not with payload length {}.\n{fired_text}",
        PUBLISH_VALUE.len()
    );
}
