// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `transport/link/tls/close_link_on_expiration` -- whether a `tls/` dialer ends its link when
//! the listener's certificate chain expires, one config document handed to zenohd with `-c` and
//! to the wz demo with `--config`.
//!
//! ## Upstream's rule
//!
//! A dialer whose configuration says `true` arms a task with the expiry of the chain the listener
//! presented and closes the link when it fires (`io/zenoh-links/zenoh-link-tls/src/unicast.rs` @
//! `if client_config.tls_close_link_on_expiration {`); with `false`, upstream's default, a link
//! outlives the certificate it was opened under. A dial after the expiry is refused by the
//! certificate check itself, so a closed link stays closed.
//!
//! ## The observer
//!
//! The listener is a stock zenohd presenting a certificate that expires a few seconds after it
//! is made, and it is the same in every run; only the dialer changes. Its own adminspace says
//! which sessions it holds and over which links (`@/<zid>/router`, read by a separate querier
//! over its `tcp/` listener), so the verdict is zenohd's account of the link and not the
//! dialer's: a `tls/` link listed before the expiry, and listed or not some seconds after it.
//!
//! Each document is run by zenohd first, which must keep the link without the key and lose it
//! with the key, and then by the demo, which must do what zenohd did.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, demo_log_filter, line_with, read_captured,
    spawn_zenohd_tcp_tls, wait_for_substring, wz_ap_demo_binary, zenohd_binary, ChildGuard,
    PortReservation,
};
use wz_runtime_tokio_test_support::loopback_cert_key_pem_expiring_at;

/// How long the listener's certificate is valid from the moment it is made: room for zenohd to
/// start, pass its readiness probe and be dialed, with the expiry still ahead.
const LIFETIME: Duration = Duration::from_secs(20);

/// How long before the expiry the dialer's link must be listed, so the listing is the link the
/// certificate was valid for.
const LISTED_BEFORE_EXPIRY: Duration = Duration::from_secs(3);

/// How long after the expiry the listener is asked again: the close is immediate, and a redial
/// the expired certificate refuses fits in it many times.
const READ_AFTER_EXPIRY: Duration = Duration::from_secs(5);

/// The two dialers handed the document.
#[derive(Clone, Copy, Debug)]
enum Dialer {
    Zenohd,
    Wz,
}

/// What the listener said about one dialer: whether its `tls/` link was listed before the expiry,
/// and whether it was listed after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Seen {
    listed_before: bool,
    listed_after: bool,
}

/// The dialer's document: a client dialing the listener's `tls/` endpoint, no scouting, the
/// listener's certificate as its root, and the key when `close` states it.
fn dialer_document(tls_port: u16, root_ca: &Path, close: Option<bool>) -> String {
    let close = match close {
        Some(close) => format!(", close_link_on_expiration: {close}"),
        None => String::new(),
    };
    format!(
        r#"{{ mode: "client", connect: {{ endpoints: ["tls/127.0.0.1:{tls_port}"] }},
  scouting: {{ multicast: {{ enabled: false }} }},
  transport: {{ link: {{ tls: {{ root_ca_certificate: "{}"{close} }} }} }} }}"#,
        root_ca.display()
    )
}

/// The dialer's command on `document`. The demo is given `--key` so it stays up as a subscriber
/// after its session opens, as zenohd stays up.
fn dialer_command(dialer: Dialer, document: &Path) -> Command {
    match dialer {
        Dialer::Zenohd => {
            let mut cmd = Command::new(zenohd_binary());
            cmd.arg("-c")
                .arg(document)
                .args(["--rest-http-port", "none"]);
            cmd
        }
        Dialer::Wz => {
            let mut cmd = Command::new(wz_ap_demo_binary());
            cmd.arg("--config")
                .arg(document)
                .args(["--key", "demo/tls-expiry/**"])
                .env("RUST_LOG", demo_log_filter());
            cmd
        }
    }
}

/// GET `@/*/router` off the listening zenohd over its `tcp/` port with a wz `--query` client and
/// return the reply body, unescaped. A third process, so the listing is zenohd's own account.
fn zenohd_admin_report(tcp_port: u16) -> String {
    const REPLY_NEEDLE: &str = "REPLY RECEIVED";
    let stderr = tempfile::tempfile().expect("tempfile for the admin querier's stderr");
    let writer = stderr.try_clone().expect("dup the admin querier's stderr");
    let mut reader = stderr;
    let mut querier = ChildGuard::wrap(
        "wz-ap-demo (zenohd adminspace querier)",
        Command::new(wz_ap_demo_binary())
            .arg("--connect")
            .arg(format!("127.0.0.1:{tcp_port}"))
            .arg("--query")
            .arg("@/*/router")
            .arg("--on-query-reply-log")
            .env("RUST_LOG", demo_log_filter())
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn the adminspace querier"),
    );
    let captured = wait_for_substring(&mut reader, REPLY_NEEDLE, Duration::from_secs(20));
    let _ = querier.child_mut().kill();
    let _ = querier.child_mut().wait();
    let captured =
        captured.unwrap_or_else(|e| panic!("zenohd never answered the @/*/router GET: {e}"));
    let line = line_with(&captured, REPLY_NEEDLE)
        .unwrap_or_else(|| panic!("no {REPLY_NEEDLE} line in the querier capture:\n{captured}"));
    line.replace("\\\"", "\"")
}

/// Whether the listening zenohd lists a session over a `tls/` link. The querier's own session is
/// over `tcp/`, and a link's ends are the only `src`/`dst` fields of the report.
fn tls_link_listed(tcp_port: u16) -> bool {
    let report = zenohd_admin_report(tcp_port);
    report.contains("\"dst\":\"tls/") || report.contains("\"src\":\"tls/")
}

/// One run: a fresh certificate expiring [`LIFETIME`] from now, a zenohd listening under it, and
/// `dialer` on the document with `close`. Returns what the listener listed, and the dialer's
/// output for a failure message.
fn observe(dialer: Dialer, close: Option<bool>) -> (Seen, String) {
    let dir = tempfile::tempdir().expect("a directory for the certificate and the document");
    let expiry = SystemTime::now() + LIFETIME;
    let deadline = Instant::now() + LIFETIME;
    let (cert_pem, key_pem) = loopback_cert_key_pem_expiring_at(expiry);
    let cert: PathBuf = dir.path().join("listener.cert.pem");
    let key: PathBuf = dir.path().join("listener.key.pem");
    std::fs::write(&cert, cert_pem).expect("write the certificate");
    std::fs::write(&key, key_pem).expect("write the key");

    let (tcp_reservation, tls_port) = PortReservation::pick_pair();
    let tcp_port = tcp_reservation.port();
    let mut listener = spawn_zenohd_tcp_tls(
        tcp_port,
        tls_port,
        cert.to_str().expect("a text path"),
        key.to_str().expect("a text path"),
        || tempfile::tempfile().expect("tempfile for the readiness probe's stderr"),
    );
    drop(tcp_reservation);

    let document = dir.path().join("dialer.json5");
    std::fs::write(&document, dialer_document(tls_port, &cert, close))
        .expect("write the dialer's document");
    let capture = tempfile::tempfile().expect("tempfile for the dialer's output");
    let mut log = capture.try_clone().expect("dup the capture handle");
    let mut dialing = ChildGuard::wrap(
        format!("{dialer:?} dialing tls/127.0.0.1:{tls_port}"),
        dialer_command(dialer, &document)
            .stdout(Stdio::from(capture.try_clone().expect("dup stdout")))
            .stderr(Stdio::from(capture))
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {dialer:?}: {e}")),
    );

    let mut listed_before = false;
    while Instant::now() + LISTED_BEFORE_EXPIRY < deadline {
        if tls_link_listed(tcp_port) {
            listed_before = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let listed_after = if listed_before {
        std::thread::sleep(deadline.saturating_duration_since(Instant::now()) + READ_AFTER_EXPIRY);
        tls_link_listed(tcp_port)
    } else {
        false
    };

    let _ = dialing.child_mut().kill();
    let _ = dialing.child_mut().wait();
    let _ = listener.child_mut().kill();
    let _ = listener.child_mut().wait();
    (
        Seen {
            listed_before,
            listed_after,
        },
        read_captured(&mut log),
    )
}

/// A dialer told `close_link_on_expiration: true` loses its `tls/` link when the listener's
/// certificate expires and one told nothing keeps it, on wz as on zenohd, judged by the listening
/// zenohd's adminspace.
///
/// # Control
///
/// The document without the key runs first on each implementation: the link outlives the
/// certificate, so its loss under the key is the key's and not the certificate check's.
// wz-proves: transport-link-tls zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (zenohd + wz-ap-demo built with tls and zenoh-config); Layer Z runs via --ignored"]
fn a_tls_dialer_closes_on_the_listeners_expiry_only_when_told_to_as_zenohd_does() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let kept = Seen {
        listed_before: true,
        listed_after: true,
    };
    let closed = Seen {
        listed_before: true,
        listed_after: false,
    };
    for (close, expected) in [(None, kept), (Some(true), closed)] {
        // The ADJUDICATOR first: zenohd on the same document must do what upstream's rule says,
        // or this host cannot show the key and wz's half would prove nothing.
        let (by_zenohd, zenohd_log) = observe(Dialer::Zenohd, close);
        assert_eq!(
            by_zenohd, expected,
            "close_link_on_expiration {close:?}: zenohd as the dialer showed {by_zenohd:?}, not \
             upstream's rule\n--- zenohd ---\n{zenohd_log}"
        );
        let (by_wz, wz_log) = observe(Dialer::Wz, close);
        assert_eq!(
            by_wz, by_zenohd,
            "close_link_on_expiration {close:?}: with the same document the wz demo showed \
             {by_wz:?} where zenohd showed {by_zenohd:?}\n--- wz ---\n{wz_log}"
        );
    }
}
