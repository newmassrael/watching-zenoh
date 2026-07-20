// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R4c §5.16 — wz <-> zenohd PUBKEY auth WIRE interop. The cross-impl proof for
//! the R4b pubkey method, bounded by a zenoh UPSTREAM limitation: this proves
//! that a REAL zenohd 1.5.0 DECODES wz's pubkey InitSyn (ZPublicKey = two LE
//! ZBufs {n, e}) byte-for-byte, while documenting that stock zenohd cannot
//! complete a pubkey handshake with ANY client.
//!
//! ## Why no Established (the upstream limitation, direct-read confirmed)
//!
//! zenohd is launched with `transport/auth/pubkey` keys (a PKCS#1 keypair,
//! generated here with `openssl genrsa -traditional`), which per `pubkey.rs`
//! `recv_init_syn` makes auth MANDATORY. But `from_config` builds
//! `AuthPubKey::new`, whose `lookup` is `Some(HashSet::new())` — a Some(EMPTY)
//! set that REJECTS every key (`pubkey.rs:566-570`: `if !lookup.contains(key) {
//! bail!("Unauthorized PubKey") }`). `known_keys_file` is an unimplemented
//! `@TODO: populate lookup file`, and `disable_lookup()` (the only accept-any
//! path) is `pub(crate)` — unreachable from config. So stock zenohd admits NO
//! pubkey client; a success-path (Established) cross-impl is impossible upstream.
//! (The earlier "empty lookup accepts all" reading was wrong; direct-read of the
//! source is the arbiter.)
//!
//! ## What IS proven (the achievable interop)
//!
//! wz dials with a fresh ephemeral keypair; zenohd DECODES the InitSyn ZPublicKey
//! and rejects only at the lookup, logging `PubKey extension - Recv InitSyn.
//! Unauthorized PubKey.` (the bail at `:569` is PAST the decode at `:561`) — NOT
//! a `Decoding error`. That single witness proves wz's pubkey wire is
//! canonical-router decodable. wz-as-initiator relays the challenge opaque, so it
//! needs no key of zenohd's. If a future zenoh implements `known_keys_file`, this
//! test should be promoted to assert Established (the wire already interoperates).
//!
//! ## Untested direction (disclosed gap)
//!
//! pubkey is MUTUAL, but only the wz-initiator -> zenohd-responder direction is
//! exercised here. The reverse (zenohd-initiator -> wz-responder) is NOT
//! cross-impl-proven — it would need zenohd to DIAL wz with pubkey configured,
//! which the in-process harness does not set up. The wz responder logic is
//! proven wz<->wz (`pubkey_handshake_e2e`); its cross-impl half is a known gap.
//!
//! `#[ignore]` (binary-dep e2e): needs `target/zenohd/zenohd` (set
//! `WZ_ZENOHD_BIN` or run `scripts/build-zenohd.sh`) + `openssl` on PATH. Run via
//! Layer Z / `--ignored`.

use std::process::{Command, Stdio};
use std::time::Duration;

use tempfile::NamedTempFile;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_tcp_accept_alive, zenohd_binary, ChildGuard,
    PortReservation, ZENOHD_TCP_ACCEPT_BUDGET,
};
use wz_runtime_tokio::extauth_pubkey::{generate_keypair, PubKeyMethod};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_open::{
    connect_and_open_session_with_auth, DialConfig, OpenError, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::zenohd_interop_session_init_params;
use wz_session_core::auth_dispatch::AuthDispatch;
use wz_session_core::locator::parse_any_locator;

const ITER_CAP: usize = 256;
/// wz's ephemeral initiator key — 512-bit for keygen speed (the wire is
/// key-size-agnostic; zenohd rejects every key at its un-populatable lookup
/// regardless, so the size only affects keygen time, not the decode this proves).
const WZ_KEY_BITS: usize = 512;

/// Generate a PKCS#1 RSA keypair for zenohd with `openssl`, written to two
/// tempfiles: the private key (`BEGIN RSA PRIVATE KEY`) and the PKCS#1 public key
/// (`BEGIN RSA PUBLIC KEY`, via `-RSAPublicKey_out`) — the exact formats zenoh's
/// `RsaPrivateKey/RsaPublicKey::read_pkcs1_pem_file` expect. Returns both
/// tempfiles (kept alive; dropping deletes the files zenohd reads).
fn generate_zenohd_pkcs1_keypair() -> (NamedTempFile, NamedTempFile) {
    let priv_pem = NamedTempFile::new().expect("zenohd private-key tempfile");
    let pub_pem = NamedTempFile::new().expect("zenohd public-key tempfile");

    // `-traditional` forces the PKCS#1 `BEGIN RSA PRIVATE KEY` form: OpenSSL 3.0's
    // `genrsa` defaults to PKCS#8 (`BEGIN PRIVATE KEY`), which zenoh's
    // `from_pkcs1_pem` rejects ("unexpected PEM type label").
    let gen = Command::new("openssl")
        .arg("genrsa")
        .arg("-traditional")
        .arg("-out")
        .arg(priv_pem.path())
        .arg("2048")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run openssl genrsa (is openssl on PATH?)");
    assert!(gen.success(), "openssl genrsa failed");

    let pubgen = Command::new("openssl")
        .arg("rsa")
        .arg("-in")
        .arg(priv_pem.path())
        .arg("-RSAPublicKey_out")
        .arg("-out")
        .arg(pub_pem.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run openssl rsa -RSAPublicKey_out");
    assert!(pubgen.success(), "openssl public-key extraction failed");

    (priv_pem, pub_pem)
}

/// Spawn a zenohd whose transport REQUIRES pubkey auth: a PKCS#1 keypair is
/// passed via `--cfg transport/auth/pubkey/{public,private}_key_file`. Per zenoh
/// `from_config`, BOTH a public and a private key are required to enable pubkey
/// (one alone bails). Blocks until the TCP listener accepts. Returns the process
/// guard plus the two key tempfiles (kept alive for zenohd's lifetime).
fn spawn_pubkey_zenohd(port: u16) -> (ChildGuard, NamedTempFile, NamedTempFile, std::fs::File) {
    let (priv_pem, pub_pem) = generate_zenohd_pkcs1_keypair();

    // Capture zenohd's log (it writes tracing to stdout/stderr; both routed to
    // one tempfile). RUST_LOG=zenoh=trace surfaces the auth FSM's per-stage log,
    // and zenohd flushes its buffered log on graceful (SIGTERM) shutdown -- the
    // read happens after `graceful_terminate`.
    let log = tempfile::tempfile().expect("zenohd log tempfile");
    let out_writer = log.try_clone().expect("dup zenohd stdout");
    let err_writer = log.try_clone().expect("dup zenohd stderr");
    let mut command = Command::new(zenohd_binary());
    command
        .arg("-l")
        .arg(format!("tcp/127.0.0.1:{port}"))
        .arg("--no-multicast-scouting")
        .arg("--rest-http-port")
        .arg("none")
        .arg("--cfg")
        .arg(format!(
            "transport/auth/pubkey/public_key_file:\"{}\"",
            pub_pem.path().display()
        ))
        .arg("--cfg")
        .arg(format!(
            "transport/auth/pubkey/private_key_file:\"{}\"",
            priv_pem.path().display()
        ))
        .env("RUST_LOG", "zenoh=trace")
        .stdout(Stdio::from(out_writer))
        .stderr(Stdio::from(err_writer));
    let mut guard = ChildGuard::wrap(
        "zenohd (pubkey auth)",
        command.spawn().expect("spawn zenohd with pubkey auth"),
    );
    if let Err(e) = wait_for_tcp_accept_alive(guard.child_mut(), port, ZENOHD_TCP_ACCEPT_BUDGET) {
        panic!("zenohd (pubkey): {e}");
    }
    (guard, priv_pem, pub_pem, log)
}

/// The last `n` lines of a captured log, for a panic message.
fn log_tail(log: &str, n: usize) -> String {
    let lines: Vec<&str> = log.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// One in-process dial to zenohd with a fresh ephemeral RSA keypair.
async fn dial_with_pubkey(port: u16) -> Result<OpenedSession, OpenError> {
    let locator = parse_any_locator(&format!("tcp/127.0.0.1:{port}")).expect("parse locator");
    let key = generate_keypair(WZ_KEY_BITS).expect("wz initiator keypair");
    connect_and_open_session_with_auth(
        locator,
        zenohd_interop_session_init_params(),
        AuthDispatch::new(vec![Box::new(PubKeyMethod::initiator(key)) as _]),
        &DialConfig::default(),
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
}

/// wz's pubkey InitSyn is DECODED by a real zenohd 1.5.0 (byte-level wire
/// interop), and the handshake is blocked SOLELY by a zenoh upstream limitation
/// — not a wz defect. Stock zenohd cannot admit ANY pubkey client: `from_config`
/// builds `AuthPubKey::new` whose `lookup` is `Some(empty)` (which rejects every
/// key, `pubkey.rs:566-570`), `known_keys_file` is an unimplemented `@TODO`, and
/// `disable_lookup()` (the only accept-any path) is `pub(crate)` — unreachable
/// from config. So a success-path (Established) cross-impl is impossible with
/// stock zenohd; the achievable proof is that the canonical router DECODES wz's
/// exact pubkey wire and rejects only at the lookup.
///
/// The witness is zenohd's own trace log: it logs `PubKey extension - Recv
/// InitSyn. Unauthorized PubKey.` (the reject is AFTER a successful ZPublicKey
/// decode) and NOT a `Decoding error` (which a malformed wire would produce). If
/// a future zenoh implements `known_keys_file`, this test should be promoted to
/// assert Established (the wire already interoperates).
// wz-proves: access-extauth-pubkey wz->zenohd partial
// wz-proves: session-extauth wz->zenohd partial
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd router + openssl); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn wz_pubkey_wire_decodes_on_zenohd_blocked_only_by_known_keys_todo() {
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let (mut zenohd, _priv, _pub, mut zenohd_log) = spawn_pubkey_zenohd(port);
    drop(port_res);

    // Dial a few times: stock zenohd rejects every pubkey client, so each dial
    // MUST fail; the repeats clear the cold-start window so at least one dial
    // reaches zenohd's auth FSM (the buffered log is read after SIGTERM, not
    // mid-run). Each dial draws a fresh ephemeral key.
    for _ in 1..=5 {
        assert!(
            dial_with_pubkey(port).await.is_err(),
            "stock zenohd cannot admit a pubkey client (known_keys TODO), so the \
             dial must NOT reach Established"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // SIGTERM so zenohd flushes its buffered log, then read it.
    graceful_terminate(zenohd.child_mut(), Duration::from_secs(2));
    std::thread::sleep(Duration::from_millis(300));
    let log = read_captured(&mut zenohd_log);

    // The interop proof: zenohd logs `Unauthorized PubKey` ONLY after it has
    // DECODED wz's InitSyn ZPublicKey (the bail at pubkey.rs:569 is past the
    // decode at :561) — so this single positive witness proves wz's pubkey wire
    // is canonical-router decodable. A malformed wire would instead log a pubkey
    // `Decoding error` and never reach the lookup.
    assert!(
        log.contains("Unauthorized PubKey"),
        "expected zenohd to decode wz's pubkey InitSyn and reject at its lookup \
         ('Unauthorized PubKey'); none seen — did the handshake reach zenohd's \
         auth FSM?\n--- zenohd log tail ---\n{}",
        log_tail(&log, 25)
    );
}
