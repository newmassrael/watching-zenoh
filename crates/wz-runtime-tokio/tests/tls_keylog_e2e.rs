// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-link-tls",
    feature = "transport-link-tls-keylog",
    feature = "transport-unicast"
))]

//! R311y578 (G10) — wz can WITNESS its own encrypted transport.
//!
//! The standing R311y534 debt is *TLS written but unwitnessed*: every other
//! wz transport can be read back off a capture, and an encrypted one is
//! ciphertext to all of it, so the TLS path was proven only by "the handshake
//! completed and the bytes arrived".
//!
//! This drives a REAL wz-to-wz session to Established over loopback TLS with
//! `SSLKEYLOGFILE` set, and asserts the exported file is the NSS key-log
//! format Wireshark's `tls.keylog_file` preference consumes — right labels,
//! right field count, right hex widths — and that the two ends' secrets
//! AGREE, which is what makes them the keys to THIS session rather than
//! plausible hex.
//!
//! Its own test binary because `SSLKEYLOGFILE` is process-global and rustls
//! samples it once per `KeyLogFile`; a sibling test in the same process would
//! either race it or silently inherit it.

use std::io::Write;

use wz_runtime_tokio::tls_config::{client_config_from_pem, server_config_from_pem};
use wz_runtime_tokio::tls_keylog::{keylog_armed, keylog_supported, KEYLOG_ENV};
use wz_runtime_tokio_test_support::localhost_cert_key_pem;

mod tls_harness;

/// One parsed key-log line.
struct LogLine {
    label: String,
    client_random: String,
    secret: String,
}

fn parse(contents: &str) -> Vec<LogLine> {
    contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut f = l.split_whitespace();
            LogLine {
                label: f.next().unwrap_or_default().to_string(),
                client_random: f.next().unwrap_or_default().to_string(),
                secret: f.next().unwrap_or_default().to_string(),
            }
        })
        .collect()
}

fn is_lower_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A wz-to-wz TLS session exports its session keys in NSS key-log format.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tls_session_exports_its_keys_in_nss_format() {
    assert!(
        keylog_supported(),
        "this binary is gated on the feature, so support is a precondition"
    );

    let dir = std::env::temp_dir().join(format!("wz-keylog-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join("keys.log");
    // Create the file empty so the "nothing was written" arm below can tell an
    // empty log from a missing one.
    std::fs::File::create(&path)
        .expect("create the key log")
        .flush()
        .expect("flush");

    // Set BEFORE any config is built: rustls resolves the variable once, when
    // `KeyLogFile` is constructed.
    std::env::set_var(KEYLOG_ENV, &path);
    assert!(
        keylog_armed(),
        "feature + environment together are what arm the export"
    );

    let (cert_pem, key_pem) = localhost_cert_key_pem();
    // Through the PRODUCTION builders — the ones that install the sink. A
    // hand-built rustls config would prove nothing about wz's own path.
    let server_config = server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), None)
        .expect("server config from pem");
    let client_config = client_config_from_pem(
        cert_pem.as_bytes(),
        None,
        wz_runtime_tokio::tls_config::ServerNameVerification::Verify,
    )
    .expect("client config from pem");

    let (opened_acc, opened_init) =
        tls_harness::open_both_to_established(server_config, client_config).await;
    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established over tls"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established over tls"
    );
    opened_init.drain_to_close().await;
    opened_acc.drain_to_close().await;

    let contents = std::fs::read_to_string(&path).expect("read the key log");
    let lines = parse(&contents);
    assert!(
        !lines.is_empty(),
        "the handshake exported nothing; the sink is not installed on the production builders"
    );

    // TLS 1.3 derives four traffic secrets across the handshake, and BOTH ends
    // ran through wz's builders, so every one of them is present.
    for label in [
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
    ] {
        assert!(
            lines.iter().any(|l| l.label == label),
            "{label} is missing from the key log:\n{contents}"
        );
    }

    // The FORMAT, which is what makes the file consumable by anything else:
    // three whitespace-separated fields, a 32-byte client random, a hex secret.
    for l in &lines {
        assert_eq!(
            l.client_random.len(),
            64,
            "{}: client_random is 32 bytes of hex, got {:?}",
            l.label,
            l.client_random
        );
        assert!(
            is_lower_hex(&l.client_random) && is_lower_hex(&l.secret),
            "{}: fields must be lowercase hex",
            l.label
        );
        // A TLS 1.3 traffic secret is one hash length: 32 or 48 bytes.
        assert!(
            matches!(l.secret.len(), 64 | 96),
            "{}: secret is {} hex chars, expected 64 or 96",
            l.label,
            l.secret.len()
        );
    }

    // THE assertion that makes these the keys to THIS session: both peers ran
    // through wz's own config builders, so each secret appears twice — once
    // from the client's derivation and once from the server's — with the SAME
    // value. Hex that merely looked well-formed would not agree.
    let mut agreed = 0;
    for label in [
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
    ] {
        let mut secrets: Vec<&str> = lines
            .iter()
            .filter(|l| l.label == label)
            .map(|l| l.secret.as_str())
            .collect();
        secrets.sort_unstable();
        secrets.dedup();
        assert_eq!(
            secrets.len(),
            1,
            "{label} was logged with disagreeing values: {secrets:?}"
        );
        assert_eq!(
            lines.iter().filter(|l| l.label == label).count(),
            2,
            "{label} is logged once by each end of the session"
        );
        agreed += 1;
    }
    assert_eq!(agreed, 4);

    // And a single client_random across the whole file: one session, one log.
    let mut randoms: Vec<&str> = lines.iter().map(|l| l.client_random.as_str()).collect();
    randoms.sort_unstable();
    randoms.dedup();
    assert_eq!(
        randoms.len(),
        1,
        "one session was driven, so one client random: {randoms:?}"
    );

    // ── The NEGATIVE arm. Same build, same builders, same handshake, with the
    //    environment variable UNSET: nothing is exported. Without this, the
    //    export above could be unconditional, which is exactly the failure the
    //    two-condition design exists to prevent. ──
    std::env::remove_var(KEYLOG_ENV);
    assert!(!keylog_armed(), "disarmed with the variable gone");
    let unset_path = dir.join("must-stay-empty.log");
    std::fs::File::create(&unset_path).expect("create the second log");

    let (cert_pem2, key_pem2) = localhost_cert_key_pem();
    let server2 = server_config_from_pem(cert_pem2.as_bytes(), key_pem2.as_bytes(), None)
        .expect("server config 2");
    let client2 = client_config_from_pem(
        cert_pem2.as_bytes(),
        None,
        wz_runtime_tokio::tls_config::ServerNameVerification::Verify,
    )
    .expect("client config 2");
    let (acc2, init2) = tls_harness::open_both_to_established(server2, client2).await;
    assert!(
        init2.actions.trace_snapshot().record_established_at >= 1,
        "the disarmed session still establishes — the gate must not break TLS"
    );
    init2.drain_to_close().await;
    acc2.drain_to_close().await;

    assert_eq!(
        std::fs::read_to_string(&unset_path).expect("read the second log"),
        "",
        "with SSLKEYLOGFILE unset nothing is exported"
    );
    // ...and the FIRST log did not grow either: the second session's configs
    // were built after the variable was removed, so they hold an inert sink.
    assert_eq!(
        std::fs::read_to_string(&path).expect("re-read the first log"),
        contents,
        "the disarmed session appended nothing to the earlier log"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
