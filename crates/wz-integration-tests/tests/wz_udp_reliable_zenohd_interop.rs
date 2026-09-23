// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2810 — §5.1 transport — CROSS-IMPL validation of wz's RELIABLE UDP link
//! (`udp/...?rel=1`, `transport-link-udp-reliable`) against a real zenohd, in
//! BOTH directions.
//!
//! Upstream's udp link has three variants and selects the third, the reliable
//! one, with the `rel` metadata key: it is the QUIC stream link under a
//! PLAINTEXT session
//! (`io/zenoh-links/zenoh-link-udp/src/reliability.rs` @ `pub(crate) struct LinkUnicastQuicUnsecure {`,
//! `io/zenoh-link-commons/src/quic/plaintext.rs` @ `struct NoOpEncryptionKeys<T>(T);`). R2798 built wz's plaintext
//! session and proved it on the wire against wz itself; R2810 routed the
//! `rel=1` locator to it on both the dial and the listen side. Neither says a
//! foreign zenoh can talk to it — a wz-to-wz pair would agree on a mistake
//! both ends share (an ALPN, a no-op key shape, a stream id). These two legs
//! put zenohd on the far end:
//!
//!   1. zenohd -> wz:  pico `z_pub` --tcp--> zenohd --udp?rel=1--> wz `--listen`
//!   2. wz -> zenohd:  wz `--connect udp?rel=1` --> zenohd --tcp--> pico `z_sub`
//!
//! In each the pico client never speaks udp and never learns wz's address, so a
//! delivery can only have crossed the reliable udp hop.
//!
//! DISCRIMINATORS, per leg:
//! - wz's own log names the variant (`udp-reliable`), which the demo derives from
//!   the link it actually built — so a regression that dialed or bound the
//!   DATAGRAM link would fail the assertion even if something still flowed.
//!   The datagram link cannot flow here anyway: the two variants do not
//!   interoperate (a QUIC endpoint reads a plain zenoh datagram as a malformed
//!   packet, and the datagram demux reads a QUIC packet as a malformed batch),
//!   which is why the marker in the locator decides whether a session opens at
//!   all.
//! - Feature-gate RED: a demo built WITHOUT `udp-reliable` refuses both the
//!   `rel=1` listen and the `rel=1` dial as `Unsupported` ("requires the
//!   transport-link-udp-reliable feature"), so neither leg can fire.
//!
//! `#[ignore]` (binary-dep e2e): needs the STOCK zenohd (the udp link, reliable
//! variant included, is in zenoh's default features — its udp crate depends on
//! `zenoh-link-commons` with `unsecure_quic` unconditionally) AND the zenoh-pico
//! CLIs. Runs on the `--ignored` Layer Z lane; the `zenohd` substring in each fn
//! name keeps the default Layer E sweep's `--skip zenohd` from running it.

use std::process::{Command, Stdio};
use std::time::Duration;

use std::path::PathBuf;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, spawn_on_ephemeral_port,
    spawn_publishing_zpub, spawn_subscribed_zsub, spawn_zenohd_dialer_on_ephemeral_tcp,
    spawn_zenohd_listeners, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary,
    zenohd_binary, ChildGuard, PortReservation,
};

/// The demo both legs run, checked newer than its sources. Both legs read
/// their verdict from a foreign process fed by the demo's reliable udp link,
/// so a stale demo would answer for a link the tree no longer builds.
fn demo_binary() -> PathBuf {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    demo
}

/// Leg 1 — a real zenohd DIALS wz's reliable udp listener, and a pico Put routes
/// across that link into wz's subscriber.
// wz-proves: transport-link-udp zenohd->wz
#[test]
#[ignore = "binary-dep e2e: needs zenohd (stock) + zenoh-pico z_pub; runs via --ignored"]
fn wz_udp_reliable_acceptor_receives_pico_put_via_zenohd() {
    const SUB_FILTER: &str = "demo/udprel/**";
    const PUBLISH_KEY: &str = "demo/udprel/acc";
    const PUBLISH_VALUE: &str = "hello-udp-reliable-acceptor-via-zenohd";

    let demo = demo_binary();
    let z_pub = zenoh_pico_cli_binary("z_pub");

    // The `(udp-reliable)` suffix follows the port digits on the listen line, so
    // the port parse is unaffected; a demo without the backend never logs it and
    // `spawn_on_ephemeral_port` panics (the feature-gate discriminator).
    let wz_stderr = tempfile::tempfile().expect("tempfile for wz acceptor stderr");
    let (mut wz_guard, mut wz_reader, port) = spawn_on_ephemeral_port(
        &demo,
        &["--listen", "udp/127.0.0.1:0?rel=1", "--key", SUB_FILTER],
        "wz accept: listening on 127.0.0.1:",
        "wz reliable udp acceptor",
        wz_stderr,
    );

    let wz_endpoint = format!("udp/127.0.0.1:{port}?rel=1");
    let (mut zenohd, tcp_port) = spawn_zenohd_dialer_on_ephemeral_tcp(
        &zenohd_binary(),
        "zenohd (reliable udp dialer)",
        Some(&wz_endpoint),
        &[],
        None,
    );
    let tcp_endpoint = format!("tcp/127.0.0.1:{tcp_port}");

    let established = wait_for_substring(
        &mut wz_reader,
        "session Established",
        Duration::from_secs(10),
    );
    let declared = established.is_ok().then(|| {
        wait_for_substring(
            &mut wz_reader,
            "DECLARED ROUTED SUBSCRIBER",
            Duration::from_secs(10),
        )
    });
    let z_pub_child = matches!(&declared, Some(Ok(_))).then(|| {
        spawn_publishing_zpub(
            &z_pub,
            PUBLISH_KEY,
            PUBLISH_VALUE,
            &tcp_endpoint,
            "zenohd-udp-reliable",
            || tempfile::tempfile().expect("tempfile for z_pub stdout"),
        )
    });
    let fired = wait_for_substring(&mut wz_reader, "SUBSCRIBER FIRED", Duration::from_secs(15));

    if let Some(mut c) = z_pub_child {
        let _ = c.child_mut().kill();
        let _ = c.child_mut().wait();
    }
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    let _ = wz_guard.child_mut().kill();
    let _ = wz_guard.child_mut().wait();

    let wz_captured = read_captured(&mut wz_reader);
    eprintln!("--- wz reliable udp acceptor stderr ---\n{wz_captured}");

    assert!(
        wz_captured.contains("(udp-reliable)"),
        "wz never logged a '(udp-reliable)' listen line — the acceptor was not the \
         reliable udp variant.\n--- wz stderr ---\n{wz_captured}"
    );
    established.unwrap_or_else(|c| {
        panic!(
            "wz never logged 'session Established' within 10s — zenohd's `rel=1` dial did \
             not complete a zenoh handshake with wz's reliable udp listener.\n--- wz stderr ---\n{c}"
        )
    });
    declared
        .expect("the declare wait runs once the session is Established")
        .unwrap_or_else(|c| {
            panic!("wz never logged 'DECLARED ROUTED SUBSCRIBER'.\n--- wz stderr ---\n{c}")
        });
    let fired_text = fired.unwrap_or_else(|c| {
        panic!(
            "wz never logged 'SUBSCRIBER FIRED' within 15s — the pico Put did not cross \
             zenohd's reliable udp link into wz.\n--- wz stderr ---\n{c}"
        )
    });
    assert!(
        fired_text.contains(PUBLISH_KEY),
        "the wz subscriber fired, but not on '{PUBLISH_KEY}'.\n{fired_text}"
    );
}

/// Leg 2 — wz DIALS a real zenohd's reliable udp listener, and wz's Put routes
/// across that link and on to a pico subscriber.
// wz-proves: transport-link-udp wz->zenohd
#[test]
#[ignore = "binary-dep e2e: needs zenohd (stock) + zenoh-pico z_sub; runs via --ignored"]
fn wz_publish_routes_through_zenohd_to_pico_zsub_over_udp_reliable() {
    let demo = demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let (tcp_res, udp_port) = PortReservation::pick_pair();
    let tcp_port = tcp_res.port();
    let tcp_endpoint = format!("tcp/127.0.0.1:{tcp_port}");
    let publish_key = "demo/udprel";
    let publish_value = "hello-from-wz-over-udp-reliable";

    // zenohd listens on tcp (for pico and the readiness gates) and on the
    // reliable udp variant (for wz). The handshake-ready probe is a wz tcp dial,
    // which is enough: both listeners come up in the same startup step.
    let mut zenohd = spawn_zenohd_listeners(
        &[
            tcp_endpoint.clone(),
            format!("udp/127.0.0.1:{udp_port}?rel=1"),
        ],
        tcp_port,
        &format!("127.0.0.1:{tcp_port}"),
        || tempfile::tempfile().expect("tempfile for readiness probe stderr"),
    );
    drop(tcp_res);

    let (mut z_sub_child, mut z_sub_reader) =
        spawn_subscribed_zsub(&z_sub, "demo/**", &tcp_endpoint, "zenohd", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });

    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr.try_clone().expect("dup wz-ap-demo stderr");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect udp?rel=1/zenohd --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("udp/127.0.0.1:{udp_port}?rel=1"))
            .arg("--publish")
            .arg(publish_key)
            .arg("--value")
            .arg(publish_value)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect udp?rel=1"),
    );

    let received_substr = ">> [Subscriber] Received";
    let received = wait_for_substring(&mut z_sub_reader, received_substr, Duration::from_secs(10));

    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    let demo_captured = read_captured(&mut demo_stderr_reader);
    let z_sub_captured = read_captured(&mut z_sub_reader);
    eprintln!("--- wz-ap-demo stderr ---\n{demo_captured}");
    eprintln!("--- z_sub stdout ---\n{z_sub_captured}");

    let received_text = received.unwrap_or_else(|c| {
        panic!(
            "z_sub did not log '{received_substr}' within 10s — wz's Put did not cross the \
             reliable udp link into zenohd.\n--- z_sub ---\n{c}\n--- wz-ap-demo ---\n{demo_captured}"
        )
    });
    assert!(
        received_text.contains(publish_key) && received_text.contains(publish_value),
        "z_sub received, but not wz's sample.\n{received_text}"
    );
    // The demo logs the transport of the link it DIALED, derived from the link
    // value, so this names the variant rather than inferring it from the port.
    assert!(
        demo_captured.contains("over udp-reliable transport"),
        "wz's dial was not the reliable udp variant (expected 'over udp-reliable \
         transport').\n--- wz-ap-demo stderr ---\n{demo_captured}"
    );
}
