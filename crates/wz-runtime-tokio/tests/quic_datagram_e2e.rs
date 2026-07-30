// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
    let client_config =
        quic_client_config_from_pem(cert_pem.as_bytes(), None).expect("build quic client config");

    // Bind the QUIC datagram server endpoint BEFORE the initiator dials (learn
    // the OS-chosen port race-free, the bind/accept split). The test owns the
    // endpoint so it outlives both sessions.
    let endpoint = bind_quic_datagram(
        "127.0.0.1:0".parse().expect("loopback addr"),
        server_config,
        None,
    )
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
