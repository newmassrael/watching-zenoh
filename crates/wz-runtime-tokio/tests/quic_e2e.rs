// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::quic_config::{quic_client_config_from_pem, quic_server_config_from_pem};
use wz_runtime_tokio::quic_pipeline::{accept_quic_on, bind_quic};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, QuicDialConfig,
    DEFAULT_OPEN_TICK_MS,
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
        None,
    )
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
        let server_config =
            quic_server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), None)
                .expect("build quic server config");
        let client_config =
            quic_client_config_from_pem(cert_pem.as_bytes(), None).expect("build quic client");
        let endpoint = bind_quic(
            "127.0.0.1:0".parse().expect("loopback addr"),
            server_config,
            Some(iface),
        )?;
        // The bind must SUCCEED in both arms — `bind(127.0.0.1)` with a foreign
        // device bound does not fail — so a difference in outcome is a difference in
        // DELIVERY, which is the property under test.
        let addr = endpoint.local_addr()?;
        // quinn completes the server half of the handshake only once the `Incoming`
        // is accepted, so the acceptor has to be live for arm A to connect.
        let acceptor = tokio::spawn(async move { accept_quic_on(&endpoint).await.map(|_| ()) });
        let dialed =
            tokio::time::timeout(budget, dial_quic(addr, client_config, "localhost", None)).await;
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
