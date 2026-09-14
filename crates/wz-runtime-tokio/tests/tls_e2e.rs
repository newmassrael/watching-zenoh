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
        matches!(dialed, DialedLink::Tls(..)),
        "the named dial produced a TLS link"
    );
    assert!(
        matches!(accepted, DialedLink::Tls(..)),
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

/// R2355 — a tls link is TCP_NODELAY on BOTH halves, matching zenoh.
///
/// The SIBLING of `ws_e2e.rs`'s `a_ws_link_disables_nagle_on_both_the_dial_and_the_accept_half`,
/// and it is here because the defect was never ws-only. wz applied the TCP
/// tuning at each CALLER of the shared connect primitive; `dial_tcp` /
/// `dial_tcp_host` took that step and `dial_ws` / `dial_tls` did not, so the
/// population of broken dials was TWO and the atom that noticed was one. Upstream
/// has the line in all three families' shared dial+accept constructor
/// (`io/zenoh-links/zenoh-link-tls/src/unicast.rs`
/// @ `tcp_stream.set_nodelay(true)`).
///
/// Reading it back off a TLS link means reaching the TCP socket UNDER rustls:
/// `tokio_rustls::TlsStream::get_ref()` yields `(&IO, &CommonState)` and the
/// `IO` here is the `TcpStream` `connect_tcp_bound` returned — the same socket
/// whose tuning is under test, not a re-connected one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tls_link_disables_nagle_on_both_the_dial_and_the_accept_half() {
    use wz_runtime_tokio::session_open::{
        bind_locator, dial_locator, AcceptConfig, DialedLink, TlsAcceptConfig, TlsDialConfig,
    };

    let (server_config, client_config) = loopback_tls_configs();
    let accept_cfg = AcceptConfig::default().with_tls(TlsAcceptConfig { server_config });
    let dial_cfg = DialConfig::default().with_tls(TlsDialConfig {
        client_config,
        server_name: tokio_rustls::rustls::pki_types::ServerName::try_from("localhost".to_string())
            .expect("localhost is a valid server name"),
    });

    let mut listener = bind_locator(
        parse_any_locator("tls/127.0.0.1:0").expect("parse tls listen locator"),
        &accept_cfg,
    )
    .await
    .expect("bind tls/127.0.0.1:0");
    let port = listener.local_addr().expect("local_addr").port();

    let acc = async move {
        let (accepted, _peer) = listener.accept_raw().await.expect("accept a tls peer");
        accepted.handshake().await.expect("rustls server handshake")
    };
    let dial = async {
        let locator =
            parse_any_locator(&format!("tls/localhost:{port}")).expect("parse tls name locator");
        dial_locator(locator, &dial_cfg).await.expect("tls dial")
    };
    let (accepted, dialed) = tokio::join!(acc, dial);

    for (half, link) in [("dial", &dialed), ("accept", &accepted)] {
        let DialedLink::Tls(tls, _) = link else {
            panic!("{half}: expected a TLS link");
        };
        assert!(
            tls.get_ref().0.nodelay().expect("read TCP_NODELAY back"),
            "{half} half of a tls link left Nagle ON; zenoh sets TCP_NODELAY on \
             every TCP-backed link in its shared dial+accept constructor"
        );
    }
}

/// R2606 — a `tls/...` locator carrying its OWN certificate material reaches
/// Established with no ambient config at all, on both halves.
///
/// The atom this closes part of is `transport-link-tls`, whose reason recorded a
/// LIVE over-credit: R2599/R2600 declared the inline-PEM keys in the shared
/// locator parser, so the config-key gate counted them read, while the
/// `Proto::Tls` arms took their material from `DialConfig.tls` /
/// `AcceptConfig.tls` alone and DROPPED whatever the tail carried. Measured
/// before this round: every consumer of the parsed material was
/// `#[cfg(feature = "transport-link-quic")]`.
///
/// The refutation arm is what makes this a witness rather than a demonstration:
/// the same locator with the material stripped must NOT bind. Without it a
/// green would also be produced by an ambient config leaking in from somewhere,
/// or by the assertion never being reached at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tls_locator_carrying_its_own_material_handshakes_with_no_ambient_config() {
    use wz_runtime_tokio::runtime_impl::TokioTime;
    use wz_runtime_tokio::session_open::{
        accept_and_open_session, accept_bound_on, bind_locator, connect_and_open_session,
        AcceptConfig, DEFAULT_OPEN_TICK_MS,
    };
    use wz_runtime_tokio_test_support::fixture_session_init_params;

    const ITER_CAP: usize = 4096;

    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed localhost cert");
    let cert_pem = issued.cert.pem();
    let key_pem = issued.key_pair.serialize_pem();

    // Bind BEFORE the dial, to learn the OS-chosen port race-free.
    let listen = parse_any_locator(&format!(
        "tls/127.0.0.1:0#listen_certificate_raw={cert_pem};listen_private_key_raw={key_pem}"
    ))
    .expect("the listen locator parses");
    let mut listener = bind_locator(listen, &AcceptConfig::default())
        .await
        .expect("a locator's own listen material binds a tls acceptor with no AcceptConfig.tls");
    let addr: std::net::SocketAddr = listener
        .local_addr_display()
        .expect("the bound address is readable")
        .parse()
        .expect("a tls listener's address is numeric");

    // `localhost` on the DIAL side, so the SNI is the locator's own host and
    // matches the cert's SAN — the named-locator rule, unchanged by this round.
    let dial = parse_any_locator(&format!(
        "tls/localhost:{}#root_ca_certificate_raw={cert_pem}",
        addr.port()
    ))
    .expect("the dial locator parses");

    let acc_open = async {
        let link = accept_bound_on(&mut listener)
            .await
            .expect("accept the inbound tls peer");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        accept_and_open_session(
            link,
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established on locator-supplied material")
    };
    let init_open = async {
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        connect_and_open_session(
            dial,
            params,
            &DialConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established on locator-supplied material")
    };
    let (opened_acc, opened_init) = tokio::join!(acc_open, init_open);
    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established with its material taken from the tls locator alone"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established with its material taken from the tls locator alone"
    );

    // ── The refutation arm: the same listen locator, stripped of its material.
    let bare_listen = parse_any_locator("tls/127.0.0.1:0").expect("the bare listen locator parses");
    let Err(err) = bind_locator(bare_listen, &AcceptConfig::default()).await else {
        panic!("a tls listen with no material anywhere must not bind");
    };
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::Unsupported,
        "with neither a locator tail nor AcceptConfig.tls the acceptor is still Unsupported"
    );
}

/// R2608 — `close_link_on_expiration=true` on a `tls/...` DIAL tail tears the
/// link down when the peer's certificate chain expires, and a tail without the
/// key leaves it alone.
///
/// This witnesses the whole production path, which the unit arms on the signal
/// itself cannot: locator parse, the flag reaching `DialedLink::Tls`, the chain
/// read from the rustls connection BEFORE `wire_tls_stream` splits the stream,
/// the watcher, and the read half reporting `LostCause::CertificateExpired`.
///
/// NUMERIC locator on purpose. A named one would resolve, and on a host whose
/// resolver answers `::1` first the walk would spend R2607's per-candidate
/// bound before reaching the listener — deterministic, but slower for no gain
/// here. The certificate is minted for the IP so the numeric SNI matches.
///
/// The SECOND arm is what makes this a witness: upstream defaults the key to
/// `false`, so a build that armed unconditionally would pass the first
/// assertion and silently tear down every link whose peer certificate ever
/// expires.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expiring_peer_chain_closes_only_the_tls_link_that_asked_for_it() {
    use wz_runtime_tokio::session_open::{bind_locator, dial_locator, AcceptConfig, DialedLink};
    use wz_runtime_tokio::tls_pipeline::wire_tls_stream;
    use wz_runtime_tokio::LinkDriver;
    use wz_session_core::link::{LinkEvent, LostCause};

    let lifetime = 3i64;
    let deadline = time::OffsetDateTime::now_utc() + time::Duration::seconds(lifetime);
    let key_pair = rcgen::KeyPair::generate().expect("generate key pair");
    let mut params =
        rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("cert params");
    params.not_after = deadline;
    let issued = params
        .self_signed(&key_pair)
        .expect("self-signed loopback cert");
    let cert_pem = issued.pem();
    let key_pem = key_pair.serialize_pem();

    let listen = parse_any_locator(&format!(
        "tls/127.0.0.1:0#listen_certificate_raw={cert_pem};listen_private_key_raw={key_pem}"
    ))
    .expect("the listen locator parses");
    let mut listener = bind_locator(listen, &AcceptConfig::default())
        .await
        .expect("the listen material binds a tls acceptor");
    let addr: std::net::SocketAddr = listener
        .local_addr_display()
        .expect("the bound address is readable")
        .parse()
        .expect("a tls listener's address is numeric");

    let dial_at = |armed: bool| {
        let tail = if armed {
            ";close_link_on_expiration=true"
        } else {
            ""
        };
        parse_any_locator(&format!(
            "tls/127.0.0.1:{}#root_ca_certificate_raw={cert_pem}{tail}",
            addr.port()
        ))
        .expect("the dial locator parses")
    };

    // Both dials happen while the chain is still valid, so both handshake.
    let accepting = tokio::spawn(async move {
        let a = wz_runtime_tokio::session_open::accept_bound_on(&mut listener).await;
        let b = wz_runtime_tokio::session_open::accept_bound_on(&mut listener).await;
        (a, b)
    });
    let armed = match dial_locator(dial_at(true), &DialConfig::default()).await {
        Ok(DialedLink::Tls(stream, closes)) => {
            assert!(closes, "the armed tail must reach DialedLink::Tls");
            wire_tls_stream(*stream, closes).0
        }
        Ok(_) => panic!("expected a tls link"),
        Err(e) => panic!("the armed dial must handshake inside the window: {e}"),
    };
    let unarmed = match dial_locator(dial_at(false), &DialConfig::default()).await {
        Ok(DialedLink::Tls(stream, closes)) => {
            assert!(!closes, "a tail without the key must not arm");
            wire_tls_stream(*stream, closes).0
        }
        Ok(_) => panic!("expected a tls link"),
        Err(e) => panic!("the unarmed dial must handshake inside the window: {e}"),
    };
    // HELD, not dropped. `let _ = ..` drops the accepted links at once, the
    // peer closes, and both dials are Lost for the ORDINARY reason before any
    // certificate expires — which is exactly how this witness first failed: in
    // 0.38s, well inside a 3s window, with `OsError`. A named binding keeps the
    // far ends alive so the only thing that can end these links is the clock.
    let _accepted = accepting.await;

    let mut armed = armed;
    let event = tokio::time::timeout(Duration::from_secs(30), armed.poll_event())
        .await
        .expect("the armed link must be torn down once its chain expires");
    match event {
        LinkEvent::Lost { cause } => assert_eq!(
            cause,
            LostCause::CertificateExpired,
            "the cause must name the certificate, not a generic OS error"
        ),
        other => panic!("the armed link must be Lost; got {other:?}"),
    }

    // ── The refutation arm: the same expiry, a tail that did not ask.
    let mut unarmed = unarmed;
    assert!(
        tokio::time::timeout(Duration::from_secs(2), unarmed.poll_event())
            .await
            .is_err(),
        "a link whose tail omitted the key must survive its peer's expiry"
    );
}

/// R2609 — `tls_handshake_timeout_ms` on a LISTEN tail drops a peer that
/// connects and never finishes the TLS handshake, and a peer that handshakes
/// normally is untouched.
///
/// The witness is a raw `TcpStream` that connects and sends NOTHING: the TCP
/// accept succeeds, the rustls server handshake then waits for a ClientHello
/// that never comes, and the bound is the only thing that can end it. Before
/// this key was honoured that accept waited forever.
///
/// The SECOND arm is the control. Without it the first would also pass if
/// `accept_tls` had been made to fail unconditionally — which is the shape a
/// mis-wired timeout actually takes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listen_tail_bounds_a_handshake_that_never_arrives() {
    use wz_runtime_tokio::session_open::{accept_bound_on, bind_locator, AcceptConfig};

    let issued = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
        .expect("generate self-signed loopback cert");
    let cert_pem = issued.cert.pem();
    let key_pem = issued.key_pair.serialize_pem();

    // 300ms: far below the 10s default, so the assertion cannot pass by the
    // default alone -- the tail's own value has to be the one in force.
    let listen = parse_any_locator(&format!(
        "tls/127.0.0.1:0#listen_certificate_raw={cert_pem};listen_private_key_raw={key_pem};\
         tls_handshake_timeout_ms=300"
    ))
    .expect("the listen locator parses");
    let mut listener = bind_locator(listen, &AcceptConfig::default())
        .await
        .expect("the listen material binds a tls acceptor");
    let addr: std::net::SocketAddr = listener
        .local_addr_display()
        .expect("the bound address is readable")
        .parse()
        .expect("a tls listener's address is numeric");

    // Connect and say nothing. `_silent` is HELD: dropping it would close the
    // socket and end the handshake for the ordinary reason, which is the same
    // trap that made R2608's expiry witness pass for the wrong cause.
    let _silent = tokio::net::TcpStream::connect(addr)
        .await
        .expect("the raw peer connects");

    let started = std::time::Instant::now();
    let outcome =
        tokio::time::timeout(Duration::from_secs(5), accept_bound_on(&mut listener)).await;
    let elapsed = started.elapsed();
    match outcome {
        Ok(Err(e)) => assert_eq!(
            e.kind(),
            std::io::ErrorKind::TimedOut,
            "the bound must surface as TimedOut, not some other failure: {e}"
        ),
        Ok(Ok(_)) => panic!("a peer that sent no ClientHello must not yield a link"),
        Err(_) => panic!("the accept was never bounded; the tail's timeout did not apply"),
    }
    assert!(
        elapsed < Duration::from_secs(5),
        "the accept must end on the tail's 300ms bound, not the test's own ceiling"
    );

    // ── The control: an ordinary dial against the SAME listener still works,
    // so the bound rejects a silent peer rather than every peer.
    let mut listener2 = bind_locator(
        parse_any_locator(&format!(
            "tls/127.0.0.1:0#listen_certificate_raw={cert_pem};listen_private_key_raw={key_pem};\
             tls_handshake_timeout_ms=300"
        ))
        .expect("the second listen locator parses"),
        &AcceptConfig::default(),
    )
    .await
    .expect("the second acceptor binds");
    let addr2: std::net::SocketAddr = listener2
        .local_addr_display()
        .expect("readable")
        .parse()
        .expect("numeric");
    let dial = parse_any_locator(&format!(
        "tls/127.0.0.1:{}#root_ca_certificate_raw={cert_pem}",
        addr2.port()
    ))
    .expect("the dial locator parses");
    let accepting = tokio::spawn(async move { accept_bound_on(&mut listener2).await });
    let dialed = wz_runtime_tokio::session_open::dial_locator(dial, &DialConfig::default()).await;
    assert!(
        dialed.is_ok(),
        "a peer that DOES handshake must be accepted under the same bound"
    );
    let _accepted = accepting.await.expect("the accept task joins");
}
