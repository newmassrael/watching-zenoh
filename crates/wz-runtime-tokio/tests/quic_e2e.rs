// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-link-quic", feature = "transport-unicast"))]

//! R311xk — wz<->wz session end to end over a real loopback QUIC link.
//!
//! The QUIC sibling of `tls_e2e`: a self-signed `localhost` cert (`rcgen`) is
//! loaded through the PRODUCTION `quic_config` builders (TLS-1.3 + ALPN
//! `hq-29`), the acceptor binds a QUIC server `Endpoint` and accepts the single
//! bidirectional stream, and the initiator dials a `quic/...` LOCATOR through
//! the R311oc config-threaded seam (`connect_and_open_session` -> `dial_locator`
//! -> `dial_quic`) with `DialConfig.quic`. Both nodes reach Established and a
//! `Put` published on the initiator is delivered byte-exact to a subscriber on
//! the acceptor — proving the data plane rides the StreamEnvelope-framed QUIC
//! bidirectional stream exactly as it does over TCP/TLS.
//!
//! ## Fully runnable (NO `#[ignore]`)
//!
//! Unlike `vsock_e2e`, QUIC loopback needs no special kernel support — it rides
//! ordinary UDP on 127.0.0.1, and the self-signed cert is generated in-process.
//! So this is the fully-verified link round: the live (cid-free) QUIC dial /
//! accept / handshake / data path all execute here.
//!
//! ## Non-flakiness
//!
//! Loopback UDP under QUIC: the TLS-1.3 handshake + a single small Put are a
//! handful of in-order, loss-free datagrams on 127.0.0.1 (QUIC retransmits any
//! that are not). Both sides drive continuously (`None`) until the delivery is
//! observed; the `select!` tears the drives down once it fires, bounded by a
//! ~3s probe budget.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wz_runtime_tokio::link_socket::LinkSocket;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::quic_config::{quic_client_config_from_pem, quic_server_config_from_pem};
use wz_runtime_tokio::quic_pipeline::{accept_quic_on, bind_quic};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, accept_bound_on, bind_locator, connect_and_open_session, dial_locator,
    AcceptConfig, DialConfig, DialedLink, QuicDialConfig, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/quic";

/// Two wz nodes handshake over a loopback QUIC link (the initiator via a
/// `quic/<host>:<port>` locator + `DialConfig.quic`), reach Established, and a
/// `Put` published on the initiator is delivered byte-exact to a subscriber on
/// the acceptor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wz_to_wz_over_quic_reaches_established_and_delivers_put() {
    let payload = b"quic-framed-hello".to_vec();

    // Self-signed `localhost` cert via rcgen, loaded through the production
    // quic_config builders. The self-signed leaf is its own trust anchor (the
    // loopback_tls_configs pattern): the client roots = the same cert.
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed localhost cert");
    let cert_pem = issued.cert.pem();
    let key_pem = issued.key_pair.serialize_pem();
    let server_config = quic_server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), None)
        .expect("build quic server config");
    let client_config =
        quic_client_config_from_pem(cert_pem.as_bytes(), None).expect("build quic client config");

    // Bind the QUIC server endpoint BEFORE the initiator dials (learn the
    // OS-chosen port race-free, the bind/accept split pattern). The test owns
    // the endpoint so it outlives both sessions.
    let endpoint = bind_quic(
        "127.0.0.1:0".parse().expect("loopback addr"),
        server_config,
        &LinkSocket::NONE,
    )
    .await
    .expect("bind quic server endpoint");
    let addr = endpoint.local_addr().expect("endpoint local addr");

    // ── Open BOTH sessions concurrently: the acceptor accepts the inbound QUIC
    //    connection + its single bidi stream; the initiator dials the
    //    `quic/...` locator through the cert-threaded dial seam.
    let acc_open = async {
        let link = accept_quic_on(&endpoint).await.expect("accept quic peer");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4]; // distinct from the initiator
        accept_and_open_session(
            DialedLink::Quic(Box::new(link)),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established over quic")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("quic/{addr}")).expect("parse quic locator");
        // R311y253 — builder form, not a struct literal. Both `DialConfig`
        // fields are `#[cfg]`-gated, so an exhaustive literal only compiles for
        // the feature combo it was written against: this one omitted `tls` and
        // so failed E0063 the moment `transport-link-tls` was also on (which
        // `--all-features` does). `DialConfig` is now `#[non_exhaustive]`, so
        // the literal form is unrepresentable here and the builder is the only
        // way in — which also sidesteps the `needless_update` lint that the old
        // comment cited as the reason for omitting `..Default::default()`.
        let cfg = DialConfig::default().with_quic(QuicDialConfig {
            client_config,
            // SNI must match the cert SAN (`localhost`), independent of the
            // numeric dial address — exactly the tls model.
            server_name: "localhost".to_string(),
        });
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        connect_and_open_session(
            locator,
            params,
            &cfg,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established over quic via locator")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established over quic"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established over quic"
    );

    // ── Subscriber on the acceptor; asserts the delivered payload byte-exact.
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
                "the payload delivered over quic matches the Put byte-for-byte"
            );
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

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
            .expect("quic publish builds and routes through the send seam");
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
        "exactly one delivery from the Put over the quic link"
    );
}

/// R311y454 — the LISTEN-side `#iface=` bind decides whether a loopback dial can
/// reach the acceptor at all: pinned to `lo` the QUIC handshake completes, pinned to
/// a device loopback traffic never arrives on it cannot.
///
/// This is DELIVERY-based on purpose, and that is the whole point of it. The obvious
/// cheaper tests do not catch the likely bug. An implementation that builds a
/// socket, calls `SO_BINDTODEVICE` on it, DROPS it, and then still calls quinn's
/// convenience `Endpoint::server` would pass a "binding to `lo` works" test AND a
/// "binding to a nonexistent device returns ENODEV" test — the syscall ran, on a
/// socket quinn never used. Only asking whether a dial can actually connect
/// distinguishes a socket that was device-bound from one that was device-bound and
/// then thrown away.
///
/// The cross-impl sibling of this A/B is
/// `wz-integration-tests/tests/wz_quic_acceptor_iface_zenohd_interop.rs`, where the
/// dialer is a real zenohd; this one keeps the same discriminator inside the crate
/// that owns the code, so a regression reds without a foreign binary present.
#[cfg(feature = "locator-iface")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listen_iface_bind_decides_whether_a_loopback_quic_dial_connects() {
    use wz_runtime_tokio::quic_pipeline::{accept_quic_on, dial_quic};

    // Arm B needs a device that merely EXISTS — not one that works. A DOWN device is
    // a fine answer: `SO_BINDTODEVICE` accepts it and loopback traffic still never
    // arrives on it. Sorted for reproducibility; a `lo`-only host panics rather than
    // skipping, because a skipped arm is a green test that proved nothing.
    let mut names: Vec<String> = std::fs::read_dir("/sys/class/net")
        .expect("read /sys/class/net (Linux host with sysfs)")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "lo")
        .collect();
    names.sort();
    let other = names
        .into_iter()
        .next()
        .expect("a non-loopback interface name; this A/B cannot run on a lo-only host");

    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed localhost cert");
    let cert_pem = issued.cert.pem();
    let key_pem = issued.key_pair.serialize_pem();

    /// One arm: bind a quic acceptor pinned to `iface`, run one accept, and report
    /// whether an UNPINNED loopback dial completed its handshake inside `budget`.
    async fn dial_reaches(
        iface: &str,
        cert_pem: &str,
        key_pem: &str,
        budget: Duration,
    ) -> std::io::Result<bool> {
        use wz_runtime_tokio::link_socket::LinkSide;
        use wz_session_core::locator::{LinkSocketOptions, Proto};
        let server_config =
            quic_server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), None)
                .expect("build quic server config");
        let client_config =
            quic_client_config_from_pem(cert_pem.as_bytes(), None).expect("build quic client");
        let options = LinkSocketOptions {
            iface: Some(iface.to_string()),
            ..LinkSocketOptions::NONE
        };
        let endpoint = bind_quic(
            "127.0.0.1:0".parse().expect("loopback addr"),
            server_config,
            &LinkSocket::resolve(
                &options,
                &LinkSocketOptions::NONE,
                Proto::Quic,
                LinkSide::Listen,
            )
            .await?,
        )
        .await?;
        // The bind must SUCCEED in both arms — `bind(127.0.0.1)` with a foreign
        // device bound does not fail — so a difference in outcome is a difference in
        // DELIVERY, which is the property under test.
        let addr = endpoint.local_addr()?;
        // quinn completes the server half of the handshake only once the `Incoming`
        // is accepted, so the acceptor has to be live for arm A to connect.
        let acceptor = tokio::spawn(async move { accept_quic_on(&endpoint).await.map(|_| ()) });
        let dialed = tokio::time::timeout(
            budget,
            dial_quic(addr, client_config, "localhost", &LinkSocket::NONE),
        )
        .await;
        acceptor.abort();
        Ok(matches!(dialed, Ok(Ok(_))))
    }

    let reached_via_lo = dial_reaches("lo", &cert_pem, &key_pem, Duration::from_secs(5))
        .await
        .expect("binding a quic acceptor to `lo` must succeed");
    let reached_via_other = dial_reaches(&other, &cert_pem, &key_pem, Duration::from_secs(5))
        .await
        .unwrap_or_else(|e| panic!("binding a quic acceptor to `{other}` must succeed: {e}"));

    assert!(
        reached_via_lo,
        "a quic acceptor pinned to `lo` did not accept a loopback dial within 5s — \
         loopback traffic DOES arrive on `lo`, so the pin is over-restrictive and the \
         negative arm below would prove nothing"
    );
    assert!(
        !reached_via_other,
        "a quic acceptor pinned to `{other}` STILL accepted a dial to 127.0.0.1. That \
         datagram arrives on `lo`, so the listen socket cannot have been bound to \
         `{other}` — either the iface parameter is a no-op, or the device-bound socket \
         was built and then not handed to quinn"
    );
}

/// R311y601 — a `quic/NAME:port` locator dials and binds, and (as for `tls`)
/// the name in the LOCATOR is the SNI the certificate is verified against.
///
/// zenoh does the same: `get_quic_addr` resolves the locator with `lookup_host`
/// and `get_quic_host` feeds the SNI, both off the same address
/// (`io/zenoh-link-commons/src/quic/utils.rs` @ `pub async fn get_quic_addr`;
/// 1.10.0 moved it out of `zenoh-links/`). Before this round wz
/// answered `Unsupported` for `quic/NAME` on the dial half, and the bind half
/// had no `Proto::Quic` NAME arm at all.
///
/// Same two-sided discriminator as the TLS test: the cert is for `localhost`
/// while `QuicDialConfig.server_name` deliberately says `wrong.example`, so the
/// NAMED dial can only succeed by reading the locator, and the NUMERIC dial can
/// only fail by still reading the config.
///
/// Both halves go through the full session open rather than stopping at
/// `dial_locator`, and that is not gratuitous: quinn's `open_bi` puts nothing on
/// the wire until the stream is written, so a server-side `accept_bi` waits
/// forever on a dialer that connects and then goes quiet. The InitSyn is the
/// write that unblocks it — which is why the first draft of this test timed out
/// at the acceptor and why the sibling TLS/WS tests can stop at the link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_named_quic_locator_verifies_against_the_locator_name_not_the_configured_one() {
    use wz_runtime_tokio::session_open::{
        bind_locator, dial_locator, AcceptConfig, QuicAcceptConfig,
    };

    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed localhost cert");
    let cert_pem = issued.cert.pem();
    let key_pem = issued.key_pair.serialize_pem();
    let server_config = quic_server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), None)
        .expect("build quic server config");
    let client_config =
        quic_client_config_from_pem(cert_pem.as_bytes(), None).expect("build quic client config");

    let accept_cfg = AcceptConfig::default().with_quic(QuicAcceptConfig { server_config });
    let dial_cfg = DialConfig::default().with_quic(QuicDialConfig {
        client_config,
        // Syntactically fine, and NOT what the cert says.
        server_name: "wrong.example".to_string(),
    });

    // ── Half 1: bind by NAME, dial by NAME, both reach Established.
    let mut listener = bind_locator(
        parse_any_locator("quic/localhost:0").expect("parse quic listen locator"),
        &accept_cfg,
    )
    .await
    .expect("bind quic/localhost:0 — the NAME acceptor arm");
    let port = listener.local_addr().expect("local_addr").port();

    let acc_open = async move {
        let (accepted, _peer) = listener.accept_raw().await.expect("accept a quic peer");
        let link = accepted
            .handshake()
            .await
            .expect("quic server-side accept completes");
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
        .expect("acceptor reaches Established over the named quic link")
    };
    let init_open = async {
        let locator =
            parse_any_locator(&format!("quic/localhost:{port}")).expect("parse quic name locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        connect_and_open_session(
            locator,
            params,
            &dial_cfg,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect(
            "quic/localhost must verify against `localhost` (the LOCATOR name), not the \
             configured `wrong.example`",
        )
    };
    let (opened_acc, opened_init) = tokio::join!(acc_open, init_open);
    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established over the NAMED quic locator"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established on the NAMED quic bind"
    );

    // ── Half 2: the NUMERIC dial with the same config must fail on the SNI, so
    //    the configured name is demonstrably still what a nameless locator uses.
    //    The acceptor is driven only far enough to present its cert; whatever it
    //    then reports is not the assertion under test.
    let mut listener = bind_locator(
        parse_any_locator("quic/127.0.0.1:0").expect("parse numeric quic listen locator"),
        &accept_cfg,
    )
    .await
    .expect("re-bind for the numeric half");
    let port = listener.local_addr().expect("local_addr").port();
    let acc = async move {
        if let Ok((accepted, _peer)) = listener.accept_raw().await {
            let _ = accepted.handshake().await;
        }
    };
    let dial = async {
        let locator = parse_any_locator(&format!("quic/127.0.0.1:{port}"))
            .expect("parse numeric quic locator");
        dial_locator(locator, &dial_cfg).await
    };
    let (_, numeric) = tokio::join!(acc, dial);
    let Err(err) = numeric else {
        panic!(
            "a NUMERIC quic locator must still verify against DialConfig.quic.server_name, so a \
             `wrong.example` config against a `localhost` cert has to fail — it succeeded, which \
             means the configured name is no longer being read"
        );
    };
    assert_ne!(
        err.kind(),
        std::io::ErrorKind::Unsupported,
        "the numeric arm is wired; its failure must be the certificate check (got {err:?})"
    );
}

/// R2599 — a QUIC handshake whose certificate material comes ENTIRELY from the
/// two locators' own `#`-config tails. Neither side is given an
/// `AcceptConfig.quic` or a `DialConfig.quic`: both are `::default()`.
///
/// THE ABSENCE OF THOSE CONFIGS IS THE ASSERTION. Before R2599 wz read no TLS
/// material off a locator at all, so this pair bound and dialed cert-absent and
/// both halves returned a typed `Unsupported`. The keys the tails spell have no
/// other surface in either implementation — zenoh's config file carries the path
/// and `_base64` forms and no `_raw` field
/// (`commons/zenoh-config/src/lib.rs` @ `root_ca_certificate_base64: Option<SecretValue>,`) —
/// so a locator is the only place an operator can write inline PEM.
///
/// The SECOND half is the refutation arm, and it is permanent rather than a
/// control run once: the SAME pair of locators with the material stripped out
/// must still be refused. Without it a build that ignored the tails and quietly
/// fell back to some ambient default would pass the first half.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_locator_carrying_its_own_material_handshakes_with_no_ambient_config() {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed localhost cert");
    let cert_pem = issued.cert.pem();
    let key_pem = issued.key_pair.serialize_pem();

    // Bind BEFORE the dial, to learn the OS-chosen port race-free — the
    // bind/accept split the sibling tests use.
    let listen = parse_any_locator(&format!(
        "quic/127.0.0.1:0#listen_certificate_raw={cert_pem};listen_private_key_raw={key_pem}"
    ))
    .expect("the listen locator parses");
    let mut listener = bind_locator(listen, &AcceptConfig::default())
        .await
        .expect("a locator's own listen material binds a quic acceptor with no AcceptConfig.quic");
    let addr: std::net::SocketAddr = listener
        .local_addr_display()
        .expect("the bound address is readable")
        .parse()
        .expect("a quic listener's address is numeric");

    // `localhost` on the DIAL side, so the SNI is the locator's own host and
    // matches the cert's SAN — the named-locator rule, unchanged by R2599.
    let dial = parse_any_locator(&format!(
        "quic/localhost:{}#root_ca_certificate_raw={cert_pem}",
        addr.port()
    ))
    .expect("the dial locator parses");

    let acc_open = async {
        let link = accept_bound_on(&mut listener)
            .await
            .expect("accept the inbound quic peer");
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
        "initiator established with its material taken from the locator alone"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established with its material taken from the locator alone"
    );

    // ── The refutation arm: the same two locators, stripped of the material.
    let bare_listen = parse_any_locator("quic/127.0.0.1:0").expect("the bare listen parses");
    // `expect_err` is unavailable here: neither `BoundListener` nor
    // `DialedLink` is `Debug`, by design.
    let listen_err = match bind_locator(bare_listen, &AcceptConfig::default()).await {
        Ok(_) => panic!("a bare listen locator carries no material and no AcceptConfig.quic"),
        Err(err) => err,
    };
    assert_eq!(
        listen_err.kind(),
        std::io::ErrorKind::Unsupported,
        "the bind refusal must be the cert-absence one (got {listen_err:?})"
    );
    let bare_dial = parse_any_locator(&format!("quic/localhost:{}", addr.port()))
        .expect("the bare dial parses");
    let dial_err = match dial_locator(bare_dial, &DialConfig::default()).await {
        Ok(_) => panic!("a bare dial locator carries no material and no DialConfig.quic"),
        Err(err) => err,
    };
    assert_eq!(
        dial_err.kind(),
        std::io::ErrorKind::Unsupported,
        "the dial refusal must be the cert-absence one (got {dial_err:?})"
    );
}

/// R2600 — `close_link_on_expiration` on a DIAL tail tears the link down when
/// the PEER's certificate chain expires, and leaves it alone when the key is
/// absent.
///
/// The dialer watches the SERVER's chain, so this proves the whole mechanism —
/// chain read, earliest-`not_after` fold, timer, close — without the listen
/// half being armed. Upstream's default is `false`, so the second arm is not
/// decoration: a build that armed unconditionally would pass the first
/// assertion and silently tear down every link whose peer cert ever expires.
///
/// Wall-clock bounded on purpose: the certificate is issued valid-now and
/// expiring in `LIFETIME`, which is the only way to observe a real expiry —
/// an already-expired chain is refused by rustls at handshake, so the link
/// under test would never exist to be closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expiring_peer_chain_closes_only_the_link_that_asked_for_it() {
    use std::time::Duration as StdDuration;

    const LIFETIME: i64 = 3;

    // A `localhost` cert valid now and expiring shortly. `not_after` needs
    // second granularity, which rcgen's day-granular `date_time_ymd` cannot
    // express — hence the `time` dev-dep.
    let key_pair = rcgen::KeyPair::generate().expect("generate key pair");
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::seconds(LIFETIME);
    let issued = params
        .self_signed(&key_pair)
        .expect("self-signed localhost cert");
    let cert_pem = issued.pem();
    let key_pem = key_pair.serialize_pem();

    let server_config = quic_server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), None)
        .expect("build quic server config");
    let endpoint = bind_quic(
        "127.0.0.1:0".parse().expect("loopback addr"),
        server_config,
        &LinkSocket::NONE,
    )
    .await
    .expect("bind quic server endpoint");
    let addr = endpoint.local_addr().expect("endpoint local addr");

    // One dial ARMS the watcher, one does not. Both run before expiry, so both
    // handshake against a chain rustls still accepts; only the armed one should
    // be torn down when that chain goes stale.
    let dial_at = |armed: bool| {
        let tail = if armed {
            ";close_link_on_expiration=true"
        } else {
            ""
        };
        parse_any_locator(&format!(
            "quic/localhost:{}#root_ca_certificate_raw={cert_pem}{tail}",
            addr.port()
        ))
        .expect("dial locator parses")
    };

    let server = endpoint.clone();
    let accepting = tokio::spawn(async move {
        let a = accept_quic_on(&server).await;
        let b = accept_quic_on(&server).await;
        (a, b)
    });

    let armed = match dial_locator(dial_at(true), &DialConfig::default())
        .await
        .expect("armed dial reaches Established")
    {
        DialedLink::Quic(link) => link,
        _ => panic!("expected a quic link"),
    };
    let bare = match dial_locator(dial_at(false), &DialConfig::default())
        .await
        .expect("unarmed dial reaches Established")
    {
        DialedLink::Quic(link) => link,
        _ => panic!("expected a quic link"),
    };

    // The armed link must die once the chain expires.
    let closed = tokio::time::timeout(
        StdDuration::from_secs((LIFETIME as u64) + 12),
        armed.connection.closed(),
    )
    .await;
    assert!(
        closed.is_ok(),
        "an armed link must be closed once the peer's chain expires"
    );

    // ...and the unarmed one must still be alive at that same moment, which is
    // already PAST the expiry the armed link just died of.
    assert!(
        bare.connection.close_reason().is_none(),
        "an unarmed link must survive its peer's chain expiring (got {:?})",
        bare.connection.close_reason()
    );

    drop(accepting);
}

/// R2600 — the ACCEPT half: a listener arming `close_link_on_expiration` tears
/// its link down when the CLIENT's chain expires.
///
/// This is a SEPARATE witness from the dial one on purpose. The dial test proves
/// a dialer watches the server's chain; it says nothing about a listener
/// watching a client's, and the two arm through different code — `dial_locator`
/// versus `BoundListener` -> `AcceptedLink` -> `handshake`. Asserting the accept
/// path works because the dial path does is the unchecked-join error this round
/// has already made more than once.
///
/// It necessarily runs under mTLS: without client auth a QUIC server is given no
/// peer chain at all, so there is nothing to expire. That makes this test also
/// the behavioural cover open-debt item 728 asks for on `enable_mtls` — the
/// listener demands a client certificate, and the dialer presents one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expiring_client_chain_closes_the_listener_that_asked_for_it() {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use std::time::Duration as StdDuration;

    const LIFETIME: i64 = 3;

    // One CA signs both ends; only the CLIENT leaf is short-lived, so the
    // listener's own certificate is never what expires.
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca_params.self_signed(&ca_key).expect("self-signed ca");
    let ca_pem = ca.pem();

    let server_key = KeyPair::generate().expect("server key");
    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server = server_params
        .signed_by(&server_key, &ca, &ca_key)
        .expect("ca-signed server cert");

    // A FRESH client cert per iteration. One shared short-lived cert cannot
    // serve both arms: the armed arm spends the whole lifetime waiting for the
    // close, so the second handshake would be refused by rustls for a cert that
    // has already expired — which is a fact about the fixture, not the feature.
    let issue_client = || {
        let key = KeyPair::generate().expect("client key");
        let mut params =
            CertificateParams::new(vec!["wz-client".to_string()]).expect("client params");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::seconds(LIFETIME);
        let cert = params
            .signed_by(&key, &ca, &ca_key)
            .expect("ca-signed client cert");
        (cert.pem(), key.serialize_pem())
    };

    let listen_at = |armed: bool| {
        let tail = if armed {
            ";close_link_on_expiration=true"
        } else {
            ""
        };
        parse_any_locator(&format!(
            "quic/127.0.0.1:0#listen_certificate_raw={};listen_private_key_raw={};\
             root_ca_certificate_raw={ca_pem};enable_mtls=true{tail}",
            server.pem(),
            server_key.serialize_pem(),
        ))
        .expect("listen locator parses")
    };

    // The armed listener, and an unarmed twin as the permanent refutation arm.
    for armed in [true, false] {
        let mut listener = bind_locator(listen_at(armed), &AcceptConfig::default())
            .await
            .expect("mTLS listen material binds a quic acceptor");
        let addr: std::net::SocketAddr = listener
            .local_addr_display()
            .expect("bound address")
            .parse()
            .expect("numeric listener address");

        let (client_pem, client_key_pem) = issue_client();
        let dial = parse_any_locator(&format!(
            "quic/localhost:{}#root_ca_certificate_raw={ca_pem};enable_mtls=true;\
             connect_certificate_raw={client_pem};connect_private_key_raw={client_key_pem}",
            addr.port(),
        ))
        .expect("dial locator parses");

        let dial_cfg = DialConfig::default();
        // The dialer must WRITE, not merely connect. quinn's `open_bi` puts
        // nothing on the wire until the stream is written, so a server-side
        // `accept_bi` waits forever on a dialer that connects and goes quiet —
        // the trap this atom's own reason records from R311y601, and the reason
        // the sibling witnesses drive a full session open rather than stopping
        // at `dial_locator`.
        let (accepted, dialed) = tokio::join!(accept_bound_on(&mut listener), async {
            let mut d = dial_locator(dial, &dial_cfg).await?;
            if let DialedLink::Quic(ref mut link) = d {
                use tokio::io::AsyncWriteExt;
                link.send.write_all(b"wz").await?;
                link.send.flush().await?;
            }
            Ok::<_, std::io::Error>(d)
        });
        let dial_err = dialed.as_ref().err().map(|e| format!("{e:?}"));
        let accepted = accepted
            .unwrap_or_else(|e| panic!("listener accept failed: {e:?}; dial side: {dial_err:?}"));
        let _dialed = dialed.expect("the client's cert is accepted by the listener");
        let acc_link = match accepted {
            DialedLink::Quic(link) => link,
            _ => panic!("expected a quic link"),
        };

        if armed {
            let closed = tokio::time::timeout(
                StdDuration::from_secs((LIFETIME as u64) + 12),
                acc_link.connection.closed(),
            )
            .await;
            assert!(
                closed.is_ok(),
                "an armed LISTENER must close the link once the client's chain expires"
            );
        } else {
            tokio::time::sleep(StdDuration::from_secs((LIFETIME as u64) + 2)).await;
            assert!(
                acc_link.connection.close_reason().is_none(),
                "an unarmed listener must survive the client's chain expiring (got {:?})",
                acc_link.connection.close_reason()
            );
        }
    }
}
