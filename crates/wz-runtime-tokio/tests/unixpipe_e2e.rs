// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-link-unixpipe",
    target_os = "linux",
    feature = "transport-unicast"
))]

//! R311y10 — wz<->wz session end to end over a real loopback unix named-pipe
//! (FIFO-pair) link.
//!
//! The FIFO sibling of `unixsock_e2e`: the acceptor `bind_unixpipe`s the
//! multi-client request channel + acceptor task and awaits the next accepted link
//! (`recv_new_link`); the initiator dials a `unixpipe/<path>` LOCATOR through the
//! dial seam (`connect_and_open_session` -> `dial_locator` -> `dial_unixpipe`),
//! which runs the zenoh-compatible invitation handshake. Both nodes reach Established
//! over the FIFO byte stream (the SAME StreamEnvelope framing as TCP/unixsock,
//! reused unchanged via tokio's native `pipe::Sender`/`Receiver`) and a `Put`
//! published on the initiator is delivered byte-exact to a subscriber on the
//! acceptor.
//!
//! ## Fully runnable (NO `#[ignore]`)
//!
//! A FIFO pair under the temp dir needs no special privilege; the kernel pipe
//! buffer makes the open order race-free (a frame written before the peer opens
//! its receiver is buffered, not dropped). Linux-only (the backend's
//! `target_os = "linux"` gate; the tokio `read_write` open-rendezvous knob).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, bind_endpoint, connect_and_open_session, DialConfig, DialedLink,
    DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio::unixpipe_pipeline::bind_unixpipe;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/unixpipe";

/// Two wz nodes handshake over a loopback unixpipe link (the initiator via a
/// `unixpipe/<path>` locator), reach Established, and a `Put` published on the
/// initiator is delivered byte-exact to a subscriber on the acceptor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wz_to_wz_over_unixpipe_reaches_established_and_delivers_put() {
    let payload = b"unixpipe-framed-hello".to_vec();

    // A unique FIFO-pair base path under the temp dir (pid-unique for parallel
    // test binaries); the locator is `unixpipe/<base>` (double-slash for the
    // absolute path).
    let base = std::env::temp_dir()
        .join(format!("wz-unixpipe-e2e-{}", std::process::id()))
        .to_string_lossy()
        .into_owned();

    // Bind the multi-client acceptor (creates the request channel + spawns the
    // acceptor task). The initiator's dial drives the invitation handshake; the
    // task yields the accepted listener-side link.
    let mut acc = bind_unixpipe(&base, None)
        .await
        .expect("bind the unixpipe acceptor");

    let acc_open = async {
        let link = acc.recv_new_link().await.expect("accept a unixpipe client");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4]; // distinct from the initiator
        accept_and_open_session(
            DialedLink::Unixpipe(link),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established over unixpipe")
    };
    let init_open = async {
        let locator =
            parse_any_locator(&format!("unixpipe/{base}")).expect("parse unixpipe locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        let cfg = DialConfig::default();
        connect_and_open_session(
            locator,
            params,
            &cfg,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established over unixpipe via locator")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established over unixpipe"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established over unixpipe"
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
                "the payload delivered over unixpipe matches the Put byte-for-byte"
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
            .expect("unixpipe publish builds and routes through the send seam");
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
        "exactly one delivery from the Put over the unixpipe link"
    );

    // The acceptor's Drop unlinks the base request node; dedicated per-connection
    // nodes auto-unlink via their read-end Drop. Best-effort base cleanup for a
    // crashed prior run.
    drop(acc);
    let _ = std::fs::remove_file(format!("{base}_uplink"));
}

/// A unique FIFO-pair base path for the accept-seam test (a distinct suffix from
/// the delivery test's base so the two never share FIFOs within one process).
fn unique_seam_pipe_base() -> String {
    std::env::temp_dir()
        .join(format!("wz-unixpipe-seam-{}", std::process::id()))
        .to_string_lossy()
        .into_owned()
}

/// R311y380 (accept-symmetry Stage 4, third arm) — wz ACCEPTS a session over
/// unixpipe through the SCHEME-KEYED accept seam (`bind_endpoint("unixpipe/..")`
/// -> `BoundListener::accept_raw` -> `AcceptedLink::handshake`), the acceptor
/// twin of the already-wired dial seam and the sibling of the unixsock (y378) /
/// vsock (y379) seam tests.
///
/// This is the DISCRIMINATOR the delivery test
/// [`wz_to_wz_over_unixpipe_reaches_established_and_delivers_put`] cannot be:
/// that test drives the RAW pipeline API (`bind_unixpipe` / `recv_new_link` +
/// a hand-wrapped `DialedLink::Unixpipe`), so it stays GREEN even while the
/// scheme-keyed `bind_locator` returns `Unsupported` for `AnyLocator::Unixpipe`.
/// THIS test binds through `bind_endpoint` — the seam a `--listen unixpipe/..`
/// router/acceptor uses — so before the Stage 4 arm lands it FAILS at
/// `bind_endpoint` (the seam was tcp/ws/tls/unixsock/vsock-only), and after it
/// reaches Established + delivers a `Put`. Unlike the vsock seam test, NO
/// `#[ignore]`: a FIFO pair under the temp dir needs no privilege, so this runs
/// in CI (the whole file is `transport-link-unixpipe` + Linux gated).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wz_accepts_a_session_over_unixpipe_via_the_bind_endpoint_seam() {
    let payload = b"unixpipe-seam-hello".to_vec();
    let base = unique_seam_pipe_base();

    // ── The Stage 4 gap: the scheme-keyed listen seam. Before the arm lands this
    //    is `Unsupported` (bind_locator wired only for tcp/ws/tls/unixsock/vsock);
    //    after, it `mkfifo`s the pair and yields a `BoundListener::Unixpipe`.
    let mut bound = bind_endpoint(&format!("unixpipe/{base}"))
        .await
        .expect("bind_endpoint accepts a unixpipe/ listen (Stage 4 accept seam)");
    assert_eq!(
        bound.transport_name(),
        "unixpipe",
        "the scheme-keyed bind yields a unixpipe listener"
    );

    let acc_open = async {
        // The pub accept seam: accept one peer (R311y392 — `accept_raw` awaits the
        // acceptor task's next completed invitation handshake, cancel-safe), then
        // run the (no-op for unixpipe) post-accept handshake into the SAME
        // DialedLink the dial side produces, exactly what one-shot `accept_bound`
        // drives internally.
        let (accepted, _peer) = bound
            .accept_raw()
            .await
            .expect("accept_raw yields a unixpipe peer");
        let link = accepted
            .handshake()
            .await
            .expect("unixpipe post-accept handshake (a direct wrap)");
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
        .expect("acceptor reaches Established over the unixpipe seam")
    };
    let init_open = async {
        let locator =
            parse_any_locator(&format!("unixpipe/{base}")).expect("parse unixpipe locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        connect_and_open_session(
            locator,
            params,
            &DialConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established over unixpipe")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established over the unixpipe seam"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established over the unixpipe seam"
    );

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
                "the payload delivered over the unixpipe seam matches the Put byte-for-byte"
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
            .expect("unixpipe seam publish builds and routes through the send seam");
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
        "exactly one delivery from the Put over the unixpipe seam"
    );

    // Best-effort cleanup of the two FIFO nodes `bind_endpoint` mkfifo'd (the
    // `_uplink` / `_downlink` suffixes the unixpipe backend documents). A stale
    // node is harmless — the next bind unlinks it — so this is `let _`.
    let _ = std::fs::remove_file(format!("{base}_uplink"));
    let _ = std::fs::remove_file(format!("{base}_downlink"));
}
