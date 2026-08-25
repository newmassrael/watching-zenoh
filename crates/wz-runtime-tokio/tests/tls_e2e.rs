// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-link-tls", feature = "transport-unicast"))]

//! R311oa — wz<->wz session end to end over a real loopback TLS link.
//!
//! The TLS analogue of `serial_pty_e2e` and the secured-stream sibling of the
//! TCP session tests: two nodes complete the rustls handshake, bring a zenoh
//! session up to Established over the encrypted byte stream, and a `Put`
//! published on one node is delivered byte-exact to a subscriber on the other
//! — proving the data plane rides the TLS stream through the SAME
//! StreamEnvelope framing TCP uses (`tls_pipeline` reuses `link_pipeline`'s
//! `writer_task` + `poll_framed`, differing only in the stream type).
//!
//! ## Cert plumbing
//!
//! A self-signed cert for `localhost` is generated at test time (`rcgen`).
//! The acceptor's rustls `ServerConfig` presents it; the dialer's
//! `ClientConfig` trusts exactly it (added to a fresh root store) and verifies
//! the server name `localhost`. Both configs pin the `ring` crypto provider
//! explicitly (`builder_with_provider`) so the test does not depend on a
//! process-default provider being installed. This mirrors how a production
//! caller supplies its own configs to `dial_tls`/`accept_tls` — the cert
//! POLICY lives at the call site, not in the `tls/...` locator.
//!
//! ## Non-flakiness
//!
//! Loopback TCP under TLS: the handshake + a single small Put are a handful of
//! in-order, loss-free segments on 127.0.0.1. Both sides drive continuously
//! (`None`) until the delivery is observed; the `select!` tears the drives
//! down once it fires, bounded by a ~3s probe budget so a regression fails
//! fast instead of hanging.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
// `DialConfig` is used only by the negative `dial_locator_*` test below; the
// open-path session_open imports moved to `tls_harness`.
use wz_runtime_tokio::session_open::DialConfig;
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::loopback_tls_configs;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

// The wz<->wz TLS open-both-to-Established drive is shared with
// `tls_pem_mtls_e2e` via the per-binary `tests/tls_harness/` module (R311oi
// SSOT — see its docs for why this is a subdir module, not the test-support
// crate).
mod tls_harness;

const KEYEXPR: &str = "demo/tls";

/// Two wz nodes handshake over TLS, reach Established, and a `Put` published on
/// the initiator is delivered byte-exact to a subscriber on the acceptor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wz_to_wz_over_tls_reaches_established_and_delivers_put() {
    let payload = b"tls-secured-hello".to_vec();
    let (server_config, client_config) = loopback_tls_configs();

    // Open BOTH ends over TLS to Established via the shared harness: the
    // acceptor runs the rustls server handshake over the accepted TcpStream, the
    // initiator dials a `tls/...` locator through the R311oc config-threaded seam
    // (proving the SEAM, pico `session_cfg` parity). See `tls_harness` for the
    // drive shared with `tls_pem_mtls_e2e`.
    let (mut opened_acc, mut opened_init) =
        tls_harness::open_both_to_established(server_config, client_config).await;

    // Both ends reached Established over the encrypted stream.
    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established over tls"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established over tls"
    );

    // ── Subscriber on the acceptor's observer; asserts the delivered payload
    //    byte-for-byte (proving data rides the TLS stream, not just handshake).
    let fired = Arc::new(AtomicUsize::new(0));
    let mut observer = ApplicationLayerObserver::new();
    {
        let fired = fired.clone();
        let expect = payload.clone();
        observer.subscribers.register(KEYEXPR, move |sample| {
            assert_eq!(sample.keyexpr(), KEYEXPR);
            assert_eq!(
                sample.payload(),
                &expect[..],
                "the payload delivered over tls matches the Put byte-for-byte"
            );
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

    // ── Publisher on the initiator side (fresh observer — no local
    //    subscriber, so the proof is the remote delivery over the TLS link).
    let publisher = TokioSession::new(
        opened_init.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened_init.clock),
    );

    let timeouts = SessionTimeouts::spec_defaults();
    let drive_acc = drive_session_until_terminal(
        &mut opened_acc.inbound,
        &opened_acc.actions,
        &mut opened_acc.engine,
        None,
        &opened_acc.clock,
        &timeouts,
        |event| observer.dispatch_event(event),
    );
    let drive_init = drive_session_until_terminal(
        &mut opened_init.inbound,
        &opened_init.actions,
        &mut opened_init.engine,
        None,
        &opened_init.clock,
        &timeouts,
        |_| {},
    );

    let fired_probe = fired.clone();
    let scenario = async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let delivered = publisher
            .publish(KEYEXPR, &payload, PublishOptions::put())
            .expect("tls publish builds and routes through the send seam");
        assert_eq!(delivered, 0, "no local subscriber on the publisher side");
        for _ in 0..100 {
            if fired_probe.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("subscriber did not fire within the ~3s budget");
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_init => panic!("initiator drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "exactly one delivery from the Put over the tls link"
    );
}

/// R311oc contract (negative): a `tls/...` locator with NO TLS config dials to
/// a typed `Unsupported` error — a TLS dial is opt-in via `DialConfig.tls`
/// (the seam cannot verify a peer with no certs). The positive direction
/// (config present -> dials -> Established) is the main test above.
#[tokio::test]
async fn dial_locator_tls_without_config_is_unsupported() {
    use wz_runtime_tokio::session_open::dial_locator;
    let locator = parse_any_locator("tls/127.0.0.1:9").expect("parse tls locator");
    // `DialedLink` is not `Debug`, so destructure rather than `expect_err`.
    let Err(err) = dial_locator(locator, &DialConfig::default()).await else {
        panic!("tls dial without config must error, got Ok");
    };
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::Unsupported,
        "tls dial without DialConfig.tls is Unsupported"
    );
}

/// R311y601 — a `tls/NAME:port` locator dials, and the name in the LOCATOR is
/// the name the certificate is verified against.
///
/// That rule is zenoh's: `get_tls_server_name` is
/// `ServerName::try_from(get_tls_host(address))`
/// (`io/zenoh-links/zenoh-link-tls/src/utils.rs:605`) — the locator host IS the
/// SNI, there is no separate configured name to disagree with it. wz's numeric
/// arm reads `DialConfig.tls.server_name` because a numeric locator names
/// nobody, and that decoupling is a deliberate superset (it is what lets one
/// `localhost` cert be dialed at `tls/127.0.0.1:port` with no IP SAN). This
/// test pins the seam between the two.
///
/// The discriminator is the deliberately WRONG configured name. The cert is for
/// `localhost`; the config says `wrong.example`. So:
///
/// - `tls/localhost:<port>` must SUCCEED — proving the arm took the SNI from
///   the locator. Had it used the configured name the handshake would die on a
///   SAN mismatch.
/// - `tls/127.0.0.1:<port>` must FAIL with that same config — proving the
///   numeric arm still honours the configured name, i.e. the named arm changed
///   one path and not both.
///
/// Neither half alone is enough: the first would also pass if `server_name`
/// were being ignored everywhere, and the second would also pass if the whole
/// scheme were broken. Together they pin which name each arm reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_named_tls_locator_verifies_against_the_locator_name_not_the_configured_one() {
    use tokio_rustls::rustls::pki_types::ServerName;
    use wz_runtime_tokio::session_open::{
        bind_locator, dial_locator, AcceptConfig, DialedLink, TlsAcceptConfig, TlsDialConfig,
    };

    let (server_config, client_config) = loopback_tls_configs();
    let accept_cfg = AcceptConfig::default().with_tls(TlsAcceptConfig { server_config });
    // The cert is for `localhost`; this config deliberately says otherwise.
    let dial_cfg = DialConfig::default().with_tls(TlsDialConfig {
        client_config,
        server_name: ServerName::try_from("wrong.example".to_string())
            .expect("a syntactically valid but WRONG server name"),
    });

    let mut listener = bind_locator(
        parse_any_locator("tls/127.0.0.1:0").expect("parse tls listen locator"),
        &accept_cfg,
    )
    .await
    .expect("bind tls/127.0.0.1:0");
    let port = listener.local_addr().expect("local_addr").port();

    // ── Half 1: the NAMED dial succeeds, so the SNI came from the locator.
    let acc = async move {
        let (accepted, _peer) = listener.accept_raw().await.expect("accept a tls peer");
        accepted
            .handshake()
            .await
            .expect("rustls server handshake with the localhost cert")
    };
    let dial = async {
        let locator =
            parse_any_locator(&format!("tls/localhost:{port}")).expect("parse tls name locator");
        dial_locator(locator, &dial_cfg).await
    };
    let (accepted, dialed) = tokio::join!(acc, dial);
    let dialed = dialed.expect(
        "tls/localhost dial must verify against `localhost` (the LOCATOR name), not the \
         configured `wrong.example`",
    );
    assert!(
        matches!(dialed, DialedLink::Tls(_)),
        "the named dial produced a TLS link"
    );
    assert!(
        matches!(accepted, DialedLink::Tls(_)),
        "the acceptor completed its side of the same handshake"
    );

    // ── Half 2: the NUMERIC dial with the same config must fail, so the
    //    configured name is still what a nameless locator verifies against.
    let mut listener = bind_locator(
        parse_any_locator("tls/127.0.0.1:0").expect("parse tls listen locator"),
        &accept_cfg,
    )
    .await
    .expect("re-bind tls/127.0.0.1:0 for the numeric half");
    let port = listener.local_addr().expect("local_addr").port();
    let acc = async move {
        // The server side sees the client abort on its SAN check; either
        // outcome is fine here — the assertion under test is the DIALER's.
        let _ = listener.accept_raw().await;
    };
    let dial = async {
        let locator =
            parse_any_locator(&format!("tls/127.0.0.1:{port}")).expect("parse numeric tls locator");
        dial_locator(locator, &dial_cfg).await
    };
    let (_, numeric) = tokio::join!(acc, dial);
    let Err(err) = numeric else {
        panic!(
            "a NUMERIC tls locator must still verify against DialConfig.tls.server_name, so a \
             `wrong.example` config against a `localhost` cert has to fail — it succeeded, which \
             means the configured name is no longer being read"
        );
    };
    // A SAN mismatch surfaces as a rustls alert through the stream, never as
    // the seam refusing the scheme.
    assert_ne!(
        err.kind(),
        std::io::ErrorKind::Unsupported,
        "the numeric arm is wired; its failure must be the certificate check (got {err:?})"
    );
}
