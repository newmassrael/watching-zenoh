// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.1 transport / §5.2 locator — CROSS-IMPL validation of the wz TLS ACCEPTOR
//! (`transport-link-tls`, zenohd->wz direction).
//!
//! The TLS twin of `wz_ws_acceptor_zenohd_interop`. The existing
//! `wz_to_zenohd_router.rs` proves the wz tls DIALER (wz `--connect tls/...`
//! against zenohd's `tls/` listener — `transport-link-tls wz->zenohd`). The
//! REVERSE — a foreign peer DIALING a wz `tls/...` acceptor — had no proof until
//! R311y375 wired the tls acceptor as a uniform `BoundListener::Tls` arm:
//! `bind_locator`'s `Proto::Tls` binds plain TCP + carries the `ServerConfig`
//! (from `AcceptConfig.tls`, the accept mirror of `DialConfig.tls`), and
//! `accept_bound` runs the rustls SERVER handshake (`accept_tls`) over the
//! accepted stream — the acceptor twin of `dial_locator`'s
//! `Proto::Tls => dial_tls`.
//!
//! Vehicle: the vendored zenoh-pico CLI is not built with tls, so a real
//! **zenohd** is the foreign tls dialer. Topology (a STAR through zenohd):
//!
//!   pico `z_put` --tcp--> zenohd --tls--> wz `--listen tls/...` (subscriber)
//!
//! zenohd DIALS the wz tls acceptor (`-e tls/<wz>`), trusting wz's self-signed
//! `localhost` cert via `root_ca_certificate` (the cert-chain trust is
//! load-bearing — a wrong CA fails the handshake) and DISABLING SAN hostname
//! matching with `verify_name_on_connect: false` so the by-IP dial verifies the
//! chain-of-trust ONLY, not the name. (This is a dialer-side accommodation for a
//! `localhost` cert reached by IP; note it is NOT the same as wz's own dialer,
//! which decouples dial-IP from a STILL-verified `localhost` SAN — disabling the
//! name check is weaker than wz's decoupling, but the CA trust wz's acceptor
//! proves is untouched.) A pico `z_put` on zenohd's tcp listener routes through
//! zenohd and ACROSS the tls link into the wz acceptor's subscriber. The pico
//! publisher never speaks tls and never knows wz's address, so the wz subscriber
//! firing witnesses that (1) wz accepted a real foreign **tls** session (the
//! zenoh handshake completed over a CA-verified rustls server handshake) and (2)
//! data crossed that tls link into wz.
//!
//! Discriminator (binds to the tls acceptor, not the shared tcp accept): a
//! `wz-ap-demo` built WITHOUT the `tls` feature rejects a `tls/...` listen with a
//! typed `Unsupported` — it never binds, so there is no acceptor for zenohd to
//! dial and the subscriber never fires. Only `--features tls` compiles the rustls
//! accept path.
//!
//! Requires: `wz-ap-demo` built with `--features tls`, the reference `zenohd`,
//! AND the zenoh-pico CLI (`z_put`). Runs on the `--ignored` lane; the `wz_tls_`
//! fn prefix keeps the default Layer E sweep from catching it.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_on_ephemeral_port, spawn_zenohd_tls_dialer,
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary,
};
use wz_runtime_tokio_test_support::localhost_cert_key_pem;

const KEYEXPR: &str = "demo/tls-acceptor-fwd";
const PUBLISH_VALUE: &str = "hello-tls-acceptor-via-zenohd";

/// Removes the throwaway cert / key / dialer-config files on drop, so an early
/// panic (e.g. a spawn failure BEFORE the normal teardown) does not leak them
/// (R311y375 review obs#3). The PEMs are self-signed `localhost` throwaways, so
/// the leak was hygiene-only, but a Drop guard runs on ANY unwind.
struct TempFiles(Vec<String>);
impl Drop for TempFiles {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// pico `z_put` -> zenohd (tcp) -> wz `--listen tls/...` (tls): a real zenohd
/// dials the wz TLS acceptor, and a pico publisher's Put routes across that tls
/// link to the wz subscriber — the `transport-link-tls` atom's first cross-impl
/// proof in the zenohd->wz (acceptor) direction.
// R311y422 — the SAME run is the locator atom's witness: the `--listen
// tls/...` string above is parsed by wz's OWN grammar (locator.rs Proto::Tls) before
// any socket exists, so a zenohd that connects proves wz read the foreign-
// facing locator form correctly. A4-5 containment is exempt for a
// FOUNDATIONAL atom (it names no cfg site), so this claim rests on that
// reading, not on the audit -- verified by hand at R311y422.
// wz-proves: transport-link-tls zenohd->wz
// wz-proves: locator-tls zenohd->wz
// wz-proves: session-unicast-open zenohd->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features tls + zenohd + zenoh-pico z_put); runs via --ignored"]
fn wz_tls_acceptor_receives_pico_put_via_zenohd() {
    let demo = wz_ap_demo_binary();
    let z_put = zenoh_pico_cli_binary("z_put");

    // ── wz's self-signed `localhost` cert+key: the cert wz PRESENTS as the tls
    //    acceptor AND the root zenohd trusts (a self-signed leaf is its own root).
    //    A process-unique path avoids collision with parallel Layer runs.
    let (cert_pem, key_pem) = localhost_cert_key_pem();
    let base = std::env::temp_dir().join(format!("wz-tls-acc-{}", std::process::id()));
    let cert_path = format!("{}.cert.pem", base.display());
    let key_path = format!("{}.key.pem", base.display());
    std::fs::write(&cert_path, &cert_pem).expect("write wz tls cert pem");
    std::fs::write(&key_path, &key_pem).expect("write wz tls key pem");
    // RAII cleanup: removed on any unwind, incl a spawn panic below (obs#3). The
    // dialer helper writes `<cert>.dialer.zenohd.json5` beside the cert.
    let _cleanup = TempFiles(vec![
        cert_path.clone(),
        key_path.clone(),
        format!("{cert_path}.dialer.zenohd.json5"),
    ]);

    // ── wz acceptor: bind an EPHEMERAL tls port presenting the cert, subscribe on
    //    KEYEXPR. Blocks on accept until zenohd dials; the bound port is read back
    //    from "wz accept: listening on 127.0.0.1:<port> (tls)".
    let wz_stderr = tempfile::tempfile().expect("tempfile for wz acceptor stderr");
    let (mut wz_guard, mut wz_reader, tls_port) = spawn_on_ephemeral_port(
        &demo,
        &[
            "--listen",
            "tls/127.0.0.1:0",
            "--tls-cert",
            &cert_path,
            "--tls-key",
            &key_path,
            "--key",
            KEYEXPR,
            "--on-remote-subscriber-log",
        ],
        "wz accept: listening on 127.0.0.1:",
        "wz tls acceptor",
        wz_stderr,
    );

    // ── zenohd: DIAL the wz tls acceptor over tls (trusting wz's cert), listen on
    //    tcp for the pico pub.
    let wz_tls_endpoint = format!("tls/127.0.0.1:{tls_port}");
    let (mut zenohd, zenohd_tcp_port) = spawn_zenohd_tls_dialer(&wz_tls_endpoint, &cert_path);

    // Cross-impl witness #1: the wz acceptor completed the rustls server handshake
    // + zenoh handshake with the real zenohd dialer.
    let handshaked = wait_for_substring(
        &mut wz_reader,
        "tls server handshake",
        Duration::from_secs(10),
    );
    let established = wait_for_substring(
        &mut wz_reader,
        "session Established",
        Duration::from_secs(10),
    );

    // ── pico z_put on zenohd's tcp listener: routes through zenohd and across the
    //    tls link to the wz subscriber. One-shot (declare keyexpr -> put -> exit).
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

    // Cross-impl witness #2: the wz subscriber fired on the routed Put — data
    // crossed the tls link into wz. The unique keyexpr + payload length pin THIS
    // put (the fire log reports `payload_len`, not the value).
    let fired = wait_for_substring(&mut wz_reader, "SUBSCRIBER FIRED", Duration::from_secs(15));

    let _ = put_child.kill();
    let _ = put_child.wait();
    graceful_terminate(zenohd.child_mut(), Duration::from_secs(5));
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    // cert/key/dialer-config removed by `_cleanup`'s Drop (obs#3).

    let wz_captured = read_captured(&mut wz_reader);
    eprintln!("--- wz tls acceptor stderr ---\n{wz_captured}");

    handshaked.unwrap_or_else(|c| {
        panic!("wz never logged 'tls server handshake' within 10s — the zenohd tls dial did not complete the rustls server handshake on the wz acceptor\n--- wz stderr ---\n{c}")
    });
    established.unwrap_or_else(|c| {
        panic!("wz never logged 'session Established' within 10s — the wz tls acceptor did not complete the zenoh handshake with the zenohd dialer\n--- wz stderr ---\n{c}")
    });
    let fired_text = fired.unwrap_or_else(|c| {
        panic!(
            "wz never logged 'SUBSCRIBER FIRED' within 15s — the pico Put did not route through \
             zenohd and across the tls link to the wz acceptor's subscriber\n--- wz stderr ---\n{c}"
        )
    });

    assert!(
        fired_text.contains(KEYEXPR),
        "the wz subscriber fired, but not on the agreed keyexpr '{KEYEXPR}'\n--- wz stderr ---\n{fired_text}"
    );
    assert!(
        fired_text.contains(&format!("payload_len={}", PUBLISH_VALUE.len())),
        "the wz subscriber fired on '{KEYEXPR}', but not with the expected payload length {}\n--- wz stderr ---\n{fired_text}",
        PUBLISH_VALUE.len()
    );
}
