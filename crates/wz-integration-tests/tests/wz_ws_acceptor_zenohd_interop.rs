// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.1 transport / §5.2 locator — CROSS-IMPL validation of the wz WebSocket
//! ACCEPTOR (`transport-link-ws`, zenohd->wz direction).
//!
//! The existing `wz_to_zenohd_router.rs` proves the wz ws DIALER (wz `--connect
//! ws/...` against zenohd's `ws/` listener — `transport-link-ws wz->zenohd`). The
//! REVERSE — a foreign peer DIALING a wz `ws/...` acceptor — had no proof because
//! wz's accept side was TCP-only (`bind_locator` returned `Unsupported` for every
//! non-tcp scheme). R311y374 wires the ws acceptor: `bind_locator`'s ws arm binds
//! plain TCP and `accept_locator` runs the RFC6455 SERVER upgrade (`accept_ws`)
//! over the accepted stream — the acceptor twin of `dial_locator`'s
//! `Proto::Ws => dial_ws` client upgrade.
//!
//! Vehicle: zenoh-pico has NO ws client (`z_sub -e ws/...` returns "Unable to
//! open session!"), so a real **zenohd** is the only available foreign ws dialer.
//! Topology (a STAR through zenohd):
//!
//!   pico `z_put` --tcp--> zenohd --ws--> wz `--listen ws/...` (subscriber)
//!
//! zenohd DIALS the wz ws acceptor (`-e ws/<wz>`) and also listens on tcp for the
//! pico publisher; a pico `z_put` on that tcp listener routes through zenohd and
//! ACROSS the ws link to the wz acceptor, whose subscriber fires. The pico
//! publisher never speaks ws and never knows wz's address, so the wz subscriber
//! firing is a definitive witness that (1) wz accepted a real foreign **ws**
//! session (the zenohd dial completed the RFC6455 upgrade + zenoh handshake) and
//! (2) data crossed that ws link into wz.
//!
//! Discriminator (binds to the ws acceptor, not the shared tcp accept): a
//! `wz-ap-demo` built WITHOUT the `ws` feature rejects a `ws/...` listen with a
//! typed `Unsupported` ("listen/accept is wired only for tcp") — it never binds,
//! so there is no acceptor for zenohd to dial and the subscriber never fires.
//! Only `--features ws` compiles the RFC6455 accept path.
//!
//! Requires: `wz-ap-demo` built with `--features ws`, the reference `zenohd`, AND
//! the zenoh-pico CLI (`z_put`). Runs on the `--ignored` lane like the other
//! binary-dep e2es; the `wz_ws_` fn prefix keeps the default Layer E sweep's
//! `--skip wz_router` etc. from catching it against an arbitrary-feature binary.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_on_ephemeral_port, spawn_zenohd_ws_dialer,
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary,
};

const KEYEXPR: &str = "demo/ws-acceptor-fwd";
const PUBLISH_VALUE: &str = "hello-ws-acceptor-via-zenohd";

/// pico `z_put` -> zenohd (tcp) -> wz `--listen ws/...` (ws): a real zenohd dials
/// the wz WebSocket acceptor, and a pico publisher's Put routes across that ws
/// link to the wz subscriber — the `transport-link-ws` atom's first cross-impl
/// proof in the zenohd->wz (acceptor) direction.
// wz-proves: transport-link-ws zenohd->wz
// wz-proves: session-unicast-open zenohd->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features ws + zenohd + zenoh-pico z_put); runs via --ignored"]
fn wz_ws_acceptor_receives_pico_put_via_zenohd() {
    let demo = wz_ap_demo_binary();
    let z_put = zenoh_pico_cli_binary("z_put");

    // ── wz acceptor: bind an EPHEMERAL ws port, subscribe on KEYEXPR. Blocks on
    //    accept until zenohd dials; `spawn_on_ephemeral_port` reads the bound port
    //    back from the "wz accept: listening on 127.0.0.1:<port> (ws)" line (the
    //    "(ws)" suffix follows the digits, so the port parse is unaffected).
    let wz_stderr = tempfile::tempfile().expect("tempfile for wz acceptor stderr");
    let (mut wz_guard, mut wz_reader, ws_port) = spawn_on_ephemeral_port(
        &demo,
        &[
            "--listen",
            "ws/127.0.0.1:0",
            "--key",
            KEYEXPR,
            "--on-remote-subscriber-log",
        ],
        "wz accept: listening on 127.0.0.1:",
        "wz ws acceptor",
        wz_stderr,
    );

    // ── zenohd: DIAL the wz ws acceptor over ws, listen on tcp for the pico pub.
    //    Its tcp listener port is fixed relative to the wz port so parallel runs
    //    (each on a distinct ephemeral wz port) never collide.
    let zenohd_tcp_port = ws_port.wrapping_add(1).max(1024);
    let wz_ws_endpoint = format!("ws/127.0.0.1:{ws_port}");
    let mut zenohd = spawn_zenohd_ws_dialer(&wz_ws_endpoint, zenohd_tcp_port);

    // Cross-impl witness #1: the wz acceptor completed the ws upgrade + zenoh
    // handshake with the real zenohd dialer (RFC6455 server upgrade then
    // Established). This ALONE proves transport-link-ws / session-unicast-open in
    // the zenohd->wz direction.
    let upgraded = wait_for_substring(&mut wz_reader, "ws server upgrade", Duration::from_secs(10));
    let established = wait_for_substring(
        &mut wz_reader,
        "session Established",
        Duration::from_secs(10),
    );

    // ── pico z_put on zenohd's tcp listener: routes through zenohd and across the
    //    ws link to the wz subscriber. One-shot (declare keyexpr -> put -> exit).
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
    // crossed the ws link into wz. The unique keyexpr + the payload LENGTH
    // (asserted below) pin THIS put (the fire log carries `payload_len`, not the
    // value itself).
    let fired = wait_for_substring(&mut wz_reader, "SUBSCRIBER FIRED", Duration::from_secs(15));

    let _ = put_child.kill();
    let _ = put_child.wait();
    graceful_terminate(zenohd.child_mut(), Duration::from_secs(5));
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));

    let wz_captured = read_captured(&mut wz_reader);
    eprintln!("--- wz ws acceptor stderr ---\n{wz_captured}");

    upgraded.unwrap_or_else(|c| {
        panic!("wz never logged 'ws server upgrade' within 10s — the zenohd ws dial did not complete the RFC6455 server upgrade on the wz acceptor\n--- wz stderr ---\n{c}")
    });
    established.unwrap_or_else(|c| {
        panic!("wz never logged 'session Established' within 10s — the wz ws acceptor did not complete the zenoh handshake with the zenohd dialer\n--- wz stderr ---\n{c}")
    });
    let fired_text = fired.unwrap_or_else(|c| {
        panic!(
            "wz never logged 'SUBSCRIBER FIRED' within 15s — the pico Put did not route through \
             zenohd and across the ws link to the wz acceptor's subscriber\n--- wz stderr ---\n{c}"
        )
    });

    // The fired sample must carry the agreed keyexpr AND the routed Put's payload
    // length — a bare "SUBSCRIBER FIRED" could in principle be a stale artifact,
    // but the unique keyexpr plus the exact `payload_len` pin THIS pico Put
    // crossing the ws link (the fire log reports `payload_len`, not the value).
    assert!(
        fired_text.contains(KEYEXPR),
        "the wz subscriber fired, but not on the agreed keyexpr '{KEYEXPR}'\n--- wz stderr ---\n{fired_text}"
    );
    assert!(
        fired_text.contains(&format!("payload_len={}", PUBLISH_VALUE.len())),
        "the wz subscriber fired on '{KEYEXPR}', but not with the expected payload length {} \
         (the routed Put's payload was truncated or replaced)\n--- wz stderr ---\n{fired_text}",
        PUBLISH_VALUE.len()
    );
}
