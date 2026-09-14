// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-link-quic-datagram",
    feature = "transport-unicast"
))]

//! R311y8 — wz<->wz session end to end over a real loopback QUIC DATAGRAM link.
//!
//! The DATAGRAM sibling of `quic_e2e`: the SAME self-signed `localhost` cert
//! (`rcgen`) loaded through the SAME production `quic_config` builders (TLS-1.3 +
//! ALPN `hq-29`), but the acceptor binds a QUIC server `Endpoint` that forbids
//! BOTH stream kinds (`bind_quic_datagram`) and the data plane rides QUIC
//! UNRELIABLE DATAGRAMS (`send_datagram`/`read_datagram`, RFC9221) — one datagram
//! per zenoh batch, no bidi stream, no StreamEnvelope. The initiator dials a
//! `quic-datagram/...` LOCATOR through the cert-threaded seam
//! (`connect_and_open_session` -> `dial_locator` -> `dial_quic_datagram`) with
//! `DialConfig.quic` (the SAME field as the stream backend — quic-datagram
//! implies transport-link-quic). Both nodes reach Established and a `Put`
//! published on the initiator is delivered byte-exact to a subscriber on the
//! acceptor — proving the data plane rides the datagram path exactly as the UDP
//! link does.
//!
//! ## Fully runnable (NO `#[ignore]`)
//!
//! Like `quic_e2e`, this needs no special kernel support — ordinary UDP on
//! 127.0.0.1 with an in-process self-signed cert.
//!
//! ## Non-flakiness
//!
//! The TLS-1.3 handshake rides QUIC crypto frames (reliable, retransmitted). The
//! wz handshake (InitSyn/InitAck/OpenSyn/OpenAck) + a single small Put are a
//! handful of small datagrams, each well under one datagram's MTU; quinn buffers
//! received datagrams (`datagram_receive_buffer_size`) until `read_datagram`
//! pops them, so a datagram arriving before the read loop is ready is queued, not
//! dropped — and on loopback there is no loss. Both sides drive continuously
//! (`None`) until the delivery is observed; the `select!` tears the drives down
//! once it fires, bounded by a ~3s probe budget.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wz_runtime_tokio::link_socket::LinkSocket;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::quic_config::{quic_client_config_from_pem, quic_server_config_from_pem};
use wz_runtime_tokio::quic_datagram_pipeline::{accept_quic_datagram_on, bind_quic_datagram};
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
const KEYEXPR: &str = "demo/quic-datagram";

/// Two wz nodes handshake over a loopback QUIC DATAGRAM link (the initiator via
/// a `quic-datagram/<host>:<port>` locator + `DialConfig.quic`), reach
/// Established, and a `Put` published on the initiator is delivered byte-exact to
/// a subscriber on the acceptor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wz_to_wz_over_quic_datagram_reaches_established_and_delivers_put() {
    let payload = b"quic-datagram-hello".to_vec();

    // Self-signed `localhost` cert via rcgen, loaded through the production
    // quic_config builders — the self-signed leaf is its own trust anchor (the
    // quic_e2e pattern): the client roots = the same cert.
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed localhost cert");
    let cert_pem = issued.cert.pem();
    let key_pem = issued.key_pair.serialize_pem();
    let server_config = quic_server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), None)
        .expect("build quic server config");
    let client_config = quic_client_config_from_pem(Some(cert_pem.as_bytes()), None)
        .expect("build quic client config");

    // Bind the QUIC datagram server endpoint BEFORE the initiator dials (learn
    // the OS-chosen port race-free, the bind/accept split). The test owns the
    // endpoint so it outlives both sessions.
    let endpoint = bind_quic_datagram(
        "127.0.0.1:0".parse().expect("loopback addr"),
        server_config,
        &LinkSocket::NONE,
    )
    .await
    .expect("bind quic datagram server endpoint");
    let addr = endpoint.local_addr().expect("endpoint local addr");

    // ── Open BOTH sessions concurrently: the acceptor accepts the inbound QUIC
    //    datagram connection (no stream); the initiator dials the
    //    `quic-datagram/...` locator through the cert-threaded dial seam.
    let acc_open = async {
        let link = accept_quic_datagram_on(&endpoint)
            .await
            .expect("accept quic datagram peer");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4]; // distinct from the initiator
        accept_and_open_session(
            DialedLink::QuicDatagram(Box::new(link)),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established over quic datagram")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("quic-datagram/{addr}"))
            .expect("parse quic-datagram locator");
        // R311y253 — builder form (`DialConfig` is `#[non_exhaustive]`; both its
        // fields are cfg-gated, so an exhaustive literal broke under any feature
        // combo it was not written against).
        let cfg = DialConfig::default().with_quic(QuicDialConfig {
            client_config,
            // SNI must match the cert SAN (`localhost`), independent of the
            // numeric dial address — the tls/quic model.
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
        .expect("initiator reaches Established over quic datagram via locator")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established over quic datagram"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established over quic datagram"
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
                "the payload delivered over quic datagram matches the Put byte-for-byte"
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
            .expect("quic-datagram publish builds and routes through the send seam");
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
        "exactly one delivery from the Put over the quic datagram link"
    );
}

/// R311y601 — the quic-datagram twin of the `quic` named-locator test: a
/// `quic-datagram/NAME:port` locator dials and binds, with the LOCATOR's name as
/// the verified SNI.
///
/// Worth its own test rather than trusting the `quic` one, because the two
/// share the cert config (`DialConfig.quic`) but NOT the dispatch: they are
/// separate `Proto` variants routed to separate arms over separate
/// `BoundListener` / `DialedLink` variants, and R311y408 is the record of an arm
/// that compiled only under a feature combination nobody built. The whole point
/// of adding both arms was that neither can stand in for the other.
///
/// Cert says `localhost`, config deliberately says `wrong.example`: the NAMED
/// dial can only succeed by reading the locator, the NUMERIC one can only fail
/// by still reading the config.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_named_quic_datagram_locator_verifies_against_the_locator_name() {
    use wz_runtime_tokio::session_open::{
        bind_locator, dial_locator, AcceptConfig, QuicAcceptConfig,
    };

    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed localhost cert");
    let cert_pem = issued.cert.pem();
    let key_pem = issued.key_pair.serialize_pem();
    let server_config = quic_server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), None)
        .expect("build quic server config");
    let client_config = quic_client_config_from_pem(Some(cert_pem.as_bytes()), None)
        .expect("build quic client config");

    let accept_cfg = AcceptConfig::default().with_quic(QuicAcceptConfig { server_config });
    let dial_cfg = DialConfig::default().with_quic(QuicDialConfig {
        client_config,
        server_name: "wrong.example".to_string(),
    });

    // ── Half 1: bind by NAME, dial by NAME, both reach Established.
    let mut listener = bind_locator(
        parse_any_locator("quic-datagram/localhost:0").expect("parse listen locator"),
        &accept_cfg,
    )
    .await
    .expect("bind quic-datagram/localhost:0 — the NAME acceptor arm");
    let port = listener.local_addr().expect("local_addr").port();

    let acc_open = async move {
        let (accepted, _peer) = listener.accept_raw().await.expect("accept a peer");
        let link = accepted
            .handshake()
            .await
            .expect("quic-datagram server-side accept completes");
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
        .expect("acceptor reaches Established over the named quic-datagram link")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("quic-datagram/localhost:{port}"))
            .expect("parse name locator");
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
            "quic-datagram/localhost must verify against `localhost` (the LOCATOR name), not \
             the configured `wrong.example`",
        )
    };
    let (opened_acc, opened_init) = tokio::join!(acc_open, init_open);
    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established over the NAMED quic-datagram locator"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established on the NAMED quic-datagram bind"
    );

    // ── Half 2: the NUMERIC dial with the same config must fail on the SNI.
    let mut listener = bind_locator(
        parse_any_locator("quic-datagram/127.0.0.1:0").expect("parse numeric listen locator"),
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
        let locator = parse_any_locator(&format!("quic-datagram/127.0.0.1:{port}"))
            .expect("parse numeric locator");
        dial_locator(locator, &dial_cfg).await
    };
    let (_, numeric) = tokio::join!(acc, dial);
    let Err(err) = numeric else {
        panic!(
            "a NUMERIC quic-datagram locator must still verify against \
             DialConfig.quic.server_name — it succeeded, which means the configured name is no \
             longer being read"
        );
    };
    assert_ne!(
        err.kind(),
        std::io::ErrorKind::Unsupported,
        "the numeric arm is wired; its failure must be the certificate check (got {err:?})"
    );
}

/// R2598 — `#initial_mtu=<n>` reaches quinn's `TransportConfig` and moves the
/// link MTU wz publishes, on EACH SIDE INDEPENDENTLY.
///
/// The observable is `link_mtu()`, the `max_datagram_size` `wire_quic_datagram`
/// samples once at wire time. That single sample is NOT deterministic on its
/// own, which cost two red runs to learn: quinn's MTU discovery races the
/// sample, so an unkeyed link read 1162 once and 1288 the next time, following
/// whichever side the scheduler left open longer. An earlier draft of this test
/// probed at 1400 — under discovery's 1452 bound — reasoning that discovery
/// could then not erase the difference. That was the wrong way round. The
/// assertions below instead put the keyed value ABOVE the bound, where
/// discovery cannot follow, so they compare against a CEILING rather than
/// against a drifting baseline.
///
/// THE THIRD ARM IS THE POINT. Measured on loopback before this test existed, a
/// build applying the key on the DIAL side alone still moves the dialer's own
/// `max_datagram_size` by the full amount, because each endpoint's `initial_mtu`
/// governs what THAT endpoint may send. A witness reading one side would
/// therefore pass a build that never configured the acceptor — the exact
/// half-build a shared `quic_server_endpoint` / `connect_quic_client` seam makes
/// easy to write. So the asymmetric arm asserts the acceptor stays at its
/// default while the dialer rises.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_mtu_on_the_locator_moves_each_sides_link_mtu_independently() {
    use wz_runtime_tokio::link_socket::LinkSide;
    use wz_runtime_tokio::quic_datagram_pipeline::{dial_quic_datagram, wire_quic_datagram};
    use wz_session_core::link::BoxedLinkDriver;
    use wz_session_core::locator::{LinkSocketOptions, Proto};

    fn opts(mtu: Option<u16>) -> LinkSocketOptions {
        LinkSocketOptions {
            initial_mtu: mtu,
            ..LinkSocketOptions::NONE
        }
    }

    /// One loopback quic-datagram link; returns (acceptor mtu, dialer mtu).
    async fn link_mtus(listen_mtu: Option<u16>, dial_mtu: Option<u16>) -> (usize, usize) {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate self-signed localhost cert");
        let cert_pem = issued.cert.pem();
        let key_pem = issued.key_pair.serialize_pem();
        let server_config =
            quic_server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), None)
                .expect("build quic server config");
        let client_config = quic_client_config_from_pem(Some(cert_pem.as_bytes()), None)
            .expect("build quic client");

        let listen_opts = opts(listen_mtu);
        let listen_sock = LinkSocket::resolve(
            &listen_opts,
            &LinkSocketOptions::NONE,
            Proto::QuicDatagram,
            LinkSide::Listen,
        )
        .await
        .expect("resolve listen socket");
        let endpoint = bind_quic_datagram(
            "127.0.0.1:0".parse().expect("loopback addr"),
            server_config,
            &listen_sock,
        )
        .await
        .expect("bind quic datagram endpoint");
        let addr = endpoint.local_addr().expect("endpoint local addr");

        // Each side wires its OWN link the instant it has one, which is what
        // production does (`dial_locator` hands straight to
        // `wire_quic_datagram`). Sampling after a `join!` instead leaves the
        // first-completed connection open while quinn's MTU discovery runs, and
        // the sample then reads a DISCOVERED mtu rather than the configured
        // one: measured, that alone lifted the dialer's baseline from 1162 to
        // 1288 and made the figure depend on scheduling. A standalone quinn
        // probe reads 1162 on BOTH sides at the default, so the asymmetry was
        // this harness, never QUIC.
        let acc = async {
            let link = accept_quic_datagram_on(&endpoint)
                .await
                .expect("accept quic datagram peer");
            let (_r, w, _h) = wire_quic_datagram(link);
            w.link_mtu()
        };
        let dial = async {
            let dial_opts = opts(dial_mtu);
            let dial_sock = LinkSocket::resolve(
                &dial_opts,
                &LinkSocketOptions::NONE,
                Proto::QuicDatagram,
                LinkSide::Dial,
            )
            .await
            .expect("resolve dial socket");
            let link = dial_quic_datagram(addr, client_config, "localhost", &dial_sock)
                .await
                .expect("dial quic datagram");
            let (_r, w, _h) = wire_quic_datagram(link);
            w.link_mtu()
        };
        tokio::join!(acc, dial)
    }

    // THE PROBE VALUE IS ABOVE quinn's discovery ceiling, and that is the whole
    // design of this test. `MtuDiscoveryConfig::default()` searches up to an
    // `upper_bound` of 1452, so an UNKEYED link's sampled mtu can be anywhere in
    // a range whose top is 1452 minus per-packet overhead — wherever discovery
    // happened to get to before `wire_quic_datagram` took its one sample.
    // Measured: the same unkeyed link read 1162 on one run and 1288 on the next,
    // and the drift followed whichever side was scheduled later, so NO absolute
    // unkeyed value is stable and no delta between the two sides is either. A
    // keyed value ABOVE the ceiling is reachable only by the key, which makes
    // the assertion independent of discovery timing instead of racing it.
    const PROBE_MTU: u16 = 1500;
    /// The most an unkeyed link can ever sample: quinn's `upper_bound` less the
    /// 38 bytes of 1-RTT overhead + datagram frame bound measured on this stack
    /// (1200 configured reads back as 1162).
    const DISCOVERY_CEILING: usize = 1452 - 38;

    let (base_acc, base_dial) = link_mtus(None, None).await;
    let (both_acc, both_dial) = link_mtus(Some(PROBE_MTU), Some(PROBE_MTU)).await;
    let (dial_only_acc, dial_only_dial) = link_mtus(None, Some(PROBE_MTU)).await;

    for (side, base) in [("acceptor", base_acc), ("dialer", base_dial)] {
        assert!(
            base <= DISCOVERY_CEILING,
            "an UNKEYED {side} cannot exceed quinn's discovery ceiling \
             {DISCOVERY_CEILING}; got {base}. If this fires the ceiling is wrong \
             and every assertion below rests on it"
        );
    }
    assert!(
        both_dial > DISCOVERY_CEILING,
        "the dialer's `initial_mtu` must carry it past anything discovery alone \
         could reach (ceiling {DISCOVERY_CEILING}, keyed {both_dial}, base {base_dial})"
    );
    assert!(
        both_acc > DISCOVERY_CEILING,
        "the acceptor's `initial_mtu` must carry it past anything discovery alone \
         could reach (ceiling {DISCOVERY_CEILING}, keyed {both_acc}, base {base_acc})"
    );

    // The asymmetric arm: the dialer's key governs the DIALER only.
    assert!(
        dial_only_dial > DISCOVERY_CEILING,
        "the dialer's own key governs its own mtu whatever the acceptor was \
         given (got {dial_only_dial})"
    );
    assert!(
        dial_only_acc <= DISCOVERY_CEILING,
        "the acceptor was given NO key, so it must stay within discovery's reach \
         ({DISCOVERY_CEILING}); got {dial_only_acc}. If this exceeds the ceiling \
         the acceptor is somehow reading the dialer's key, and this test can no \
         longer detect a missing listen-side apply"
    );
}
