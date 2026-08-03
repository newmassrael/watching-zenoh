// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A4b (session-reconnect) — end-to-end reconnect over a real loopback TCP
//! link: a client session opened via `open_session_with_reconnect` declares
//! a subscriber, the acceptor observes it and then drops the connection
//! abruptly (no Close frame — the link-loss shape, zenoh-pico
//! `_zp_unicast_failed_result` trigger class), the supervisor re-dials and
//! re-handshakes against the re-accepting listener, and the SECOND accepted
//! connection observes the SAME Declare replayed from the declaration cache
//! (pico `_z_client_reopen_task_fn` cache-walk parity).
//!
//! Engines are driven on the current task (the `tokio::join!` pattern of
//! `accept_and_open_session.rs`); iteration caps bound every loop so a
//! regression fails fast instead of hanging.
//!
//! The subscriber scenario is the canonical shape (declared via
//! `send_declare_subscriber`); `queryable_declares_replay_after_link_loss_and_reconnect`
//! is the queryable sibling (A1) proving the same cache-walk replays the
//! `Declare(DeclQueryable)` kind. The transport variants (TLS / WS submodules,
//! GaveUp-resume) stay subscriber-only because the replay loop is
//! declaration-kind-agnostic.

#![cfg(feature = "session-reconnect")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::net::TcpListener;

use wz_runtime_tokio::reconnect::{
    open_session_with_reconnect, ReconnectDriveOutcome, ReconnectLocator, ReconnectPolicy,
};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::{drive_session_until_terminal, DriverOutcome};
use wz_runtime_tokio::session_open::{
    accept_and_open_session, DialConfig, DialedLink, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
use wz_session_core::locator::{parse_any_locator, parse_locator};
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;

/// Drive an already-Established acceptor session in single-iteration chunks
/// until at least one inbound `Declare` network message is observed; return
/// the Debug rendering of each (the replay assertion compares these across
/// connections, pinning the full decoded declaration — kind, id, keyexpr —
/// without depending on wire SNs). Shared by the TCP and TLS accept helpers:
/// the collect loop is transport-agnostic (it drives the `OpenedSession`, not
/// the link), so only the accept half (Tcp vs Tls handshake) differs (R311of).
async fn collect_first_declare(opened: &mut OpenedSession) -> Vec<String> {
    let mut declares = Vec::new();
    // Drive in single-iteration chunks so the helper returns as soon as the
    // Declare lands (a larger chunk would idle out its remaining iterations
    // on the steady loop's tick cadence before this loop can re-check).
    while declares.is_empty() {
        let outcome = drive_session_until_terminal(
            &mut opened.inbound,
            &opened.actions,
            &mut opened.engine,
            Some(1),
            &opened.clock,
            &SessionTimeouts::spec_defaults(),
            |event| {
                if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) =
                    event
                {
                    for message in messages {
                        if matches!(message, NetworkMessage::Declare(_)) {
                            declares.push(format!("{message:?}"));
                        }
                    }
                }
            },
        )
        .await;
        assert!(
            !matches!(outcome, DriverOutcome::Terminated),
            "peer terminated before its Declare arrived"
        );
    }
    declares
}

/// Accept one connection, complete the accept-side handshake, then collect its
/// first inbound `Declare` ([`collect_first_declare`]). Returns the live
/// acceptor session (dropping it severs the link abruptly) plus the observed
/// Declare renderings.
async fn accept_and_collect_declares(listener: &TcpListener) -> (OpenedSession, Vec<String>) {
    let (stream, _peer) = listener.accept().await.expect("accept");
    let mut params = fixture_session_init_params();
    params.zid = vec![0x02; 4]; // distinct zid from the initiator
    let mut opened = accept_and_open_session(
        DialedLink::Tcp(stream),
        params,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .expect("acceptor reaches Established");

    let declares = collect_first_declare(&mut opened).await;
    (opened, declares)
}

/// R311pg — the declaration kind a reconnect-replay scenario declares; drives
/// both the `send_declare_*` call and the Debug-marker assertion.
#[derive(Clone, Copy)]
enum ReplayDeclareKind {
    Subscriber,
    Queryable,
}

impl ReplayDeclareKind {
    /// The `DeclareOwnedVariant` Debug marker the replayed `Declare` must carry
    /// (`CodecZenohDeclSubscriber` / `CodecZenohDeclQueryable`).
    fn marker(self) -> &'static str {
        match self {
            ReplayDeclareKind::Subscriber => "DeclSubscriber",
            ReplayDeclareKind::Queryable => "DeclQueryable",
        }
    }
}

/// R311pg — the shared TCP reconnect-replay driver behind the subscriber and
/// queryable replay tests. A reconnect-supervised client opens, declares ONE
/// entity of `kind`, the acceptor observes the Declare, the link is severed, the
/// supervisor re-dials and replays the declaration cache, and connection #2 must
/// observe the SAME Declare verbatim.
///
/// Parameterizing over `kind` (rather than cloning the ~80-line driver) is the
/// honest application of this file's own kind-agnostic argument: the replay
/// cache-walk is declaration-kind-agnostic (one loop, a per-variant `replay_one`
/// arm — session_actions.rs), so only the `send_declare_*` call and the cached
/// variant differ. The `marker` assertion positively pins the kind so neither
/// case can pass green on a mis-wired emit of the other kind (the A1 false-green
/// hole this closes).
///
/// R311pw — `listener` + `locator` are supplied by the caller (the same
/// parameterize-don't-clone discipline): the IP legs bind `127.0.0.1:0` and
/// pass a numeric [`ReconnectLocator::Ip`], while the Named leg binds a
/// localhost listener and passes a [`ReconnectLocator::Named`] hostname — the
/// re-dial path (and the cache-replay it gates) is locator-shape-agnostic, so
/// only the dial target differs.
async fn assert_declare_replays_after_link_loss(
    listener: TcpListener,
    locator: ReconnectLocator,
    keyexpr: &str,
    kind: ReplayDeclareKind,
) {
    let mut params = fixture_session_init_params();
    params.zid = vec![0x01; 4];

    // ── Connection #1: client opens (reconnect-supervised wiring), declares
    //    one entity of `kind`; the acceptor handshakes and observes the Declare.
    let policy = ReconnectPolicy {
        retry_delay_ms: 50, // test cadence; production default is pico's 1s
        max_attempts: Some(100),
    };
    let (mut client, (server_conn1, declares_conn1)) = tokio::join!(
        async {
            let session = open_session_with_reconnect(
                locator,
                params,
                DialConfig::default(),
                TokioTime::new(),
                policy,
                Some(ITER_CAP),
                DEFAULT_OPEN_TICK_MS,
            )
            .await
            .expect("client reaches Established");
            match kind {
                ReplayDeclareKind::Subscriber => session
                    .actions()
                    .send_declare_subscriber(10, 0, Some(keyexpr))
                    .expect("declare subscriber"),
                ReplayDeclareKind::Queryable => session
                    .actions()
                    .send_declare_queryable(10, 0, Some(keyexpr), /*complete=*/ false)
                    .expect("declare queryable"),
            };
            session
        },
        accept_and_collect_declares(&listener),
    );
    assert_eq!(
        declares_conn1.len(),
        1,
        "connection #1 observes exactly the one declared entity"
    );
    // A1/R311pg — positively pin the KIND: the captured Declare's Debug must
    // carry this kind's `DeclareOwnedVariant` marker, so neither case can pass
    // green on a mis-wired emit of the other kind.
    assert!(
        declares_conn1[0].contains(kind.marker()),
        "connection #1's Declare must carry the {} marker; got {}",
        kind.marker(),
        declares_conn1[0],
    );

    // ── Sever the first link abruptly: dropping the acceptor session closes
    //    the socket without a Close frame — the client sees a link loss, not
    //    a peer-initiated close.
    drop(server_conn1);

    // ── Drive the client under the reconnect supervisor while the listener
    //    re-accepts. The supervisor re-dials, re-handshakes, and replays the
    //    declaration cache; connection #2 must observe the SAME Declare.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_server = stop.clone();
    let timeouts = SessionTimeouts::spec_defaults();
    let (drive_outcome, declares_conn2) = tokio::join!(
        client.drive(&timeouts, &stop, Some(ITER_CAP), |_| {}),
        async {
            let (server_conn2, declares) = accept_and_collect_declares(&listener).await;
            // Replay observed — release the client: raise the stop flag
            // FIRST, then sever the link so the supervisor's next loop
            // boundary sees Terminated + stop and returns Stopped instead
            // of reconnecting again.
            stop_for_server.store(true, Ordering::Release);
            drop(server_conn2);
            declares
        },
    );

    assert!(
        matches!(drive_outcome, ReconnectDriveOutcome::Stopped),
        "supervisor must observe the stop flag after the second link drop, \
         got {drive_outcome:?}"
    );
    assert_eq!(
        declares_conn2, declares_conn1,
        "the reconnected link must replay the cached Declare verbatim \
         (kind, id, keyexpr all preserved)"
    );
    // F6 — `drive` borrows, so the supervisor outlives termination: the
    // reconnect count survives for post-mortem observability.
    assert_eq!(
        client.reconnects(),
        1,
        "exactly one survived link loss across the run"
    );
}

/// R311y525 — THE DIAL-PATH DELIVERY GATE for the link-loss liveliness flush.
///
/// R311y521 built that flush and R311y523 corrected it, but neither shipped an
/// end-to-end test: R311y521's unit tests drive `LivelinessSubscriberRegistry`
/// directly with a plain sink, so they never cross the DEFERRED-FIRE seam that
/// turned out to be the whole defect. This is the missing evidence, and it is
/// written to fail on either half.
///
/// The shape: a reconnect-supervised client declares a liveliness subscriber,
/// the acceptor declares a token so the client's registry learns it, and then
/// the acceptor VANISHES. No `UndeclToken` can arrive — the link that would
/// carry one is what died — so the only thing that can tell the application is
/// the supervisor's own flush.
///
/// The PUT is asserted first. Without it the Delete leg could pass on a run
/// where the token never reached the client at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dying_link_delivers_remote_liveliness_deletes_to_the_dialer() {
    use std::sync::Mutex as StdMutex;
    use wz_runtime_tokio::declare::LivelinessSampleKind;
    use wz_runtime_tokio::observer::ApplicationLayerObserver;
    use wz_runtime_tokio::session::{LivelinessSubscriberOptions, TokioSession};
    use wz_runtime_tokio::sync::Mutex as WzMutex;

    const KEYEXPR: &str = "wz/live/dialgate";

    let (listener, locator) = ip_loopback().await;
    let mut params = fixture_session_init_params();
    params.zid = vec![0x07; 4];

    let policy = ReconnectPolicy {
        retry_delay_ms: 50,
        max_attempts: Some(100),
    };

    // Connection #1: the client opens under the supervisor; the acceptor
    // handshakes and declares ONE liveliness token.
    let (client, server) = tokio::join!(
        async {
            open_session_with_reconnect(
                locator,
                params,
                DialConfig::default(),
                TokioTime::new(),
                policy,
                Some(ITER_CAP),
                DEFAULT_OPEN_TICK_MS,
            )
            .await
            .expect("client reaches Established")
        },
        async {
            let (stream, _peer) = listener.accept().await.expect("accept");
            accept_and_open_session(
                DialedLink::Tcp(stream),
                fixture_session_init_params(),
                TokioTime::new(),
                Some(ITER_CAP),
                DEFAULT_OPEN_TICK_MS,
            )
            .await
            .expect("acceptor reaches Established")
        },
    );
    let mut client = client;

    // The application: a liveliness subscriber over the supervised session,
    // capturing every sample kind + keyexpr it is handed.
    let captured: Arc<StdMutex<Vec<(LivelinessSampleKind, String)>>> =
        Arc::new(StdMutex::new(Vec::new()));
    let sink = captured.clone();
    let observer = Arc::new(WzMutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(
        client.actions().clone(),
        observer,
        Arc::new(TokioTime::new()),
    );
    let _sub = session
        .declare_liveliness_subscriber(
            "wz/live/**".to_owned(),
            LivelinessSubscriberOptions::default(),
            move |s| {
                sink.lock().unwrap().push((s.kind, s.keyexpr.to_owned()));
            },
        )
        .expect("declare the liveliness subscriber");
    client.set_liveliness_flush(session.clone());

    // The acceptor announces a token, then the client drives until it lands.
    server
        .actions
        .send_declare_token(21, 0, Some(KEYEXPR))
        .expect("acceptor declares a liveliness token");
    let dispatch_session = session.clone();
    let mut dispatch = |e: IterationEvent<'_>| dispatch_session.dispatch_iteration_event(e);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_killer = stop.clone();
    let captured_for_killer = captured.clone();

    let timeouts = timeouts_for_gate();
    let (drive_outcome, _) = tokio::join!(
        client.drive(&timeouts, &stop, Some(ITER_CAP), &mut dispatch),
        async {
            // Wait for the PUT, then VANISH. Raising `stop` first makes the
            // supervisor return Stopped at its next loop boundary instead of
            // reconnecting, so the flush is the last thing it does.
            for _ in 0..400 {
                if captured_for_killer
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(k, ke)| *k == LivelinessSampleKind::Put && ke == KEYEXPR)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            stop_for_killer.store(true, Ordering::Release);
            drop(server);
        },
    );

    let seen = captured.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|(k, ke)| *k == LivelinessSampleKind::Put && ke == KEYEXPR),
        "the acceptor's token never reached the dialer as a PUT, so the Delete \
         leg below would be testing nothing. seen: {seen:?} (outcome {drive_outcome:?})"
    );
    assert!(
        seen.iter()
            .any(|(k, ke)| *k == LivelinessSampleKind::Delete && ke == KEYEXPR),
        "the peer holding {KEYEXPR} vanished and the application was never told: \
         no DELETE was delivered. No UndeclToken can arrive either — the link \
         that would carry one is what died. This fails if the supervisor skips \
         the flush (R311y521) OR stages it without draining the deferred-fire \
         queue (R311y523). seen: {seen:?} (outcome {drive_outcome:?})"
    );
}

/// The timeouts every gate in this file shares.
fn timeouts_for_gate() -> SessionTimeouts {
    SessionTimeouts::spec_defaults()
}

/// Bind a numeric loopback listener and the matching numeric
/// [`ReconnectLocator::Ip`] — the IP-leg setup shared by the subscriber and
/// queryable reconnect-replay tests (R311pw lifted it out of the driver so the
/// Named leg can supply its own listener + locator).
async fn ip_loopback() -> (TcpListener, ReconnectLocator) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let locator = ReconnectLocator::Ip(
        parse_locator(&format!("tcp/{addr}")).expect("parse loopback locator"),
    );
    (listener, locator)
}

/// Subscriber reconnect-replay — the canonical scenario. See
/// [`assert_declare_replays_after_link_loss`].
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declares_replay_after_link_loss_and_reconnect() {
    let (listener, locator) = ip_loopback().await;
    assert_declare_replays_after_link_loss(
        listener,
        locator,
        "home/reconnect",
        ReplayDeclareKind::Subscriber,
    )
    .await;
}

/// A1 — queryable sibling of [`declares_replay_after_link_loss_and_reconnect`],
/// closing the `send_declare_queryable` e2e-coverage parity gap and guarding the
/// `replay_one` `CachedDeclaration::Queryable` arm end-to-end (pico
/// `_z_client_reopen_task_fn` cache-replay parity). TLS/WS/GaveUp queryable
/// variants are intentionally omitted: the replay cache-walk is
/// declaration-kind-agnostic, so they would re-run the identical loop with a
/// different `build_declare_*` and add no distinct invariant — the transport
/// re-handshake those variants exercise is already covered by the subscriber
/// legs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queryable_declares_replay_after_link_loss_and_reconnect() {
    let (listener, locator) = ip_loopback().await;
    assert_declare_replays_after_link_loss(
        listener,
        locator,
        "home/qry-reconnect",
        ReplayDeclareKind::Queryable,
    )
    .await;
}

/// R311pw — debt B: a DNS-NAMED `--connect` endpoint reconnects. The supervisor
/// previously held only a numeric [`parse_locator`] result, so a hostname —
/// which the dial seam classifies to `AnyLocator::Named` (R311ps) — could be
/// dialed once yet never reconnect-supervised. Here the client opens with a
/// [`ReconnectLocator::Named`] host ("localhost", RE-RESOLVED on every re-dial),
/// survives an abrupt link loss, and replays its declaration cache onto
/// connection #2 — the same proof the IP leg gives, over the Named arm that
/// closes the dial/reconnect asymmetry.
///
/// The listener binds `localhost:0`, so it sits on one of localhost's resolved
/// addresses; the Named dial `localhost:{port}` resolves through the std
/// resolver and connects to it (each resolved address tried in order), making
/// the scenario deterministic without depending on v4-vs-v6 resolution order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn named_locator_reconnects_after_link_loss() {
    let listener = TcpListener::bind("localhost:0")
        .await
        .expect("bind localhost");
    let port = listener.local_addr().expect("local_addr").port();
    let locator = ReconnectLocator::try_from(
        parse_any_locator(&format!("tcp/localhost:{port}")).expect("parse named locator"),
    )
    .expect("a tcp hostname is reconnectable");
    // Positively pin the classification: the fix is the Named arm, so a
    // regression that re-narrowed to Ip (or rejected the name) fails here.
    assert!(
        matches!(locator, ReconnectLocator::Named { .. }),
        "a hostname must classify as ReconnectLocator::Named, got {locator:?}"
    );
    assert_declare_replays_after_link_loss(
        listener,
        locator,
        "home/named-reconnect",
        ReplayDeclareKind::Subscriber,
    )
    .await;
}

/// F6/R311ka — pin the documented GaveUp-resume contract: after `drive`
/// returns `GaveUp` (peer endpoint gone, attempt cap exhausted), the
/// borrowed supervisor can be driven AGAIN once the endpoint returns —
/// the dead connection's engine is already terminal, so the second
/// `drive` drops straight into the reopen loop, re-handshakes, and
/// replays the declaration cache (caller-paced retry beyond the policy
/// cap). Also pins the F2 contract inside the abandoned window: a send
/// over the surviving bundle rejects typed instead of silently vanishing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gave_up_supervisor_resumes_on_re_drive() {
    use wz_session_core::send_declare_error::SendDeclareError;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let locator = ReconnectLocator::Ip(
        parse_locator(&format!("tcp/{addr}")).expect("parse loopback locator"),
    );
    let mut params = fixture_session_init_params();
    params.zid = vec![0x01; 4];

    // Connection #1: open + declare, acceptor observes it.
    let policy = ReconnectPolicy {
        retry_delay_ms: 10, // test cadence
        max_attempts: Some(2),
    };
    let (mut client, (server_conn1, declares_conn1)) = tokio::join!(
        async {
            let session = open_session_with_reconnect(
                locator,
                params,
                DialConfig::default(),
                TokioTime::new(),
                policy,
                Some(ITER_CAP),
                DEFAULT_OPEN_TICK_MS,
            )
            .await
            .expect("client reaches Established");
            session
                .actions()
                .send_declare_subscriber(10, 0, Some("home/resume"))
                .expect("declare subscriber");
            session
        },
        accept_and_collect_declares(&listener),
    );

    // Kill the endpoint entirely: drop the live connection AND the
    // listener, so every reopen attempt dials a dead address.
    drop(server_conn1);
    drop(listener);

    let stop = AtomicBool::new(false);
    let timeouts = SessionTimeouts::spec_defaults();
    let outcome = client.drive(&timeouts, &stop, Some(ITER_CAP), |_| {}).await;
    assert!(
        matches!(outcome, ReconnectDriveOutcome::GaveUp { attempts: 2, .. }),
        "dial-refused attempts exhaust the cap, got {outcome:?}"
    );
    assert_eq!(client.reconnects(), 0, "no reconnect survived yet");
    // F2 — the abandoned window: handles over the surviving bundle are
    // inert-typed, not silently lossy.
    assert_eq!(
        client.actions().send_declare_keyexpr(8, "home/while-dead"),
        Err(SendDeclareError::TransportUnavailable),
        "post-GaveUp send must reject typed"
    );

    // The endpoint returns on the SAME address; re-driving the surviving
    // supervisor resumes the reopen loop and replays the cache.
    let listener = TcpListener::bind(addr).await.expect("rebind same addr");
    let stop_for_server = stop;
    let (drive_outcome, declares_conn2) = tokio::join!(
        client.drive(&timeouts, &stop_for_server, Some(ITER_CAP), |_| {}),
        async {
            let (server_conn2, declares) = accept_and_collect_declares(&listener).await;
            stop_for_server.store(true, Ordering::Release);
            drop(server_conn2);
            declares
        },
    );
    assert!(
        matches!(drive_outcome, ReconnectDriveOutcome::Stopped),
        "resumed supervisor must run to the stop flag, got {drive_outcome:?}"
    );
    assert_eq!(
        declares_conn2, declares_conn1,
        "the resumed reconnect must replay the cached Declare verbatim"
    );
    assert_eq!(client.reconnects(), 1, "the resumed re-drive survived once");
}

/// R311oe — reconnect over a real loopback **TLS** link: the TLS analogue of
/// `declares_replay_after_link_loss_and_reconnect`. A `tls/...` session opened
/// via `open_session_with_reconnect` (with a `DialConfig` carrying the rustls
/// client config) declares a subscriber; the link is severed; the supervisor
/// re-dials the SAME `tls/...` locator with the RETAINED DialConfig and
/// re-handshakes the rustls layer against the re-accepting listener, and
/// connection #2 observes the replayed Declare. This is the proof that the
/// dial config survives a reconnect: with the pre-R311oe default config the
/// re-dial would hit `dial_locator`'s tls arm with no certs and fail
/// `Unsupported` — so `reconnects() == 1` could not happen.
///
/// Gated additionally on `transport-link-tls` (=> `transport-link-tcp`) +
/// `transport-unicast`; the TLS imports + cert fixture live in this submodule
/// so the default `session-reconnect` build (TLS off) stays warning-clean. The
/// Layer C1u lane builds + runs it by adding `--test session_reconnect_e2e`
/// under `--features transport-link-tls` (its default+tls set already carries
/// session-reconnect + transport-unicast); without that the module is empty
/// and the retained-config re-dial is unexercised (gate-skew).
#[cfg(all(feature = "transport-link-tls", feature = "transport-unicast"))]
mod tls_reconnect {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use tokio::net::TcpListener;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::ServerConfig;

    use wz_runtime_tokio::reconnect::{
        open_session_with_reconnect, ReconnectDriveOutcome, ReconnectLocator, ReconnectPolicy,
    };
    use wz_runtime_tokio::runtime_impl::TokioTime;
    use wz_runtime_tokio::session_open::{
        accept_and_open_session, DialConfig, DialedLink, OpenedSession, TlsDialConfig,
        DEFAULT_OPEN_TICK_MS,
    };
    use wz_runtime_tokio::tls_pipeline::accept_tls;
    use wz_runtime_tokio_test_support::{fixture_session_init_params, loopback_tls_configs};
    use wz_session_core::locator::parse_locator;
    use wz_session_core::session_timeouts::SessionTimeouts;

    const ITER_CAP: usize = 4096;

    /// Accept one connection, run the rustls SERVER handshake, complete the
    /// accept-side session handshake, then drive until at least one inbound
    /// `Declare` lands. TLS analogue of the parent's
    /// `accept_and_collect_declares`; `server_config` is shared across both
    /// accepts (conn #1 and the reconnect's conn #2).
    async fn accept_tls_and_collect_declares(
        listener: &TcpListener,
        server_config: Arc<ServerConfig>,
    ) -> (OpenedSession, Vec<String>) {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let tls = accept_tls(stream, server_config)
            .await
            .expect("server tls handshake");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4]; // distinct zid from the initiator
        let mut opened = accept_and_open_session(
            DialedLink::Tls(Box::new(tls)),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established over tls");

        let declares = super::collect_first_declare(&mut opened).await;
        (opened, declares)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn declares_replay_after_tls_link_loss_and_reconnect() {
        let (server_config, client_config) = loopback_tls_configs();

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let locator =
            ReconnectLocator::Ip(parse_locator(&format!("tls/{addr}")).expect("parse tls locator"));
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];

        let policy = ReconnectPolicy {
            retry_delay_ms: 50, // test cadence; production default is pico's 1s
            max_attempts: Some(100),
        };
        // The retained dial config: a `tls/...` re-dial reads this on EVERY
        // reconnect, so the supervisor must own it (R311oe).
        let server_name = ServerName::try_from("localhost").expect("server name");
        // R311y253 — builder form (`DialConfig` is `#[non_exhaustive]`; both its
        // fields are cfg-gated, so an exhaustive literal broke under any feature
        // combo it was not written against — this one omitted `quic`).
        let dial_config = DialConfig::default().with_tls(TlsDialConfig {
            client_config,
            server_name,
        });

        // ── Connection #1: client opens (reconnect-supervised) over TLS,
        //    declares a subscriber; the acceptor handshakes and observes it.
        let (mut client, (server_conn1, declares_conn1)) = tokio::join!(
            async {
                let session = open_session_with_reconnect(
                    locator,
                    params,
                    dial_config,
                    TokioTime::new(),
                    policy,
                    Some(ITER_CAP),
                    DEFAULT_OPEN_TICK_MS,
                )
                .await
                .expect("client reaches Established over tls");
                session
                    .actions()
                    .send_declare_subscriber(10, 0, Some("home/tls-reconnect"))
                    .expect("declare subscriber");
                session
            },
            accept_tls_and_collect_declares(&listener, server_config.clone()),
        );
        assert_eq!(
            declares_conn1.len(),
            1,
            "connection #1 observes exactly the one declared subscriber"
        );

        // ── Sever the first TLS link abruptly (drop the acceptor session).
        drop(server_conn1);

        // ── Drive the client under the supervisor while the listener
        //    re-accepts over TLS. The re-dial uses the RETAINED DialConfig —
        //    the whole point of R311oe — so the rustls handshake completes on
        //    connection #2 and the cached Declare replays.
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_server = stop.clone();
        let timeouts = SessionTimeouts::spec_defaults();
        let (drive_outcome, declares_conn2) = tokio::join!(
            client.drive(&timeouts, &stop, Some(ITER_CAP), |_| {}),
            async {
                let (server_conn2, declares) =
                    accept_tls_and_collect_declares(&listener, server_config).await;
                stop_for_server.store(true, Ordering::Release);
                drop(server_conn2);
                declares
            },
        );

        assert!(
            matches!(drive_outcome, ReconnectDriveOutcome::Stopped),
            "supervisor must stop after the second tls link drop, got {drive_outcome:?}"
        );
        assert_eq!(
            declares_conn2, declares_conn1,
            "the reconnected TLS link must replay the cached Declare verbatim"
        );
        assert_eq!(
            client.reconnects(),
            1,
            "exactly one survived TLS link loss — the retained DialConfig re-dialed tls/"
        );
    }
}

/// WebSocket reconnect — the WS analogue of `tls_reconnect` (R311oj). On link
/// loss the supervisor re-dials the `ws/...` locator, which RE-RUNS the RFC6455
/// upgrade handshake and replays the cached `Declare`. The reconnect value under
/// test is WS-specific: TCP has no handshake to re-run and TLS re-reads a
/// retained cert config, but WS must complete a fresh RFC6455 upgrade on the
/// second connection with no config at all (`DialConfig::default()`).
///
/// Gated on `transport-link-ws` + `transport-unicast`; the WS imports live in
/// this submodule so the default `session-reconnect` build (WS off) stays
/// warning-clean. The Layer C1v lane builds + runs it by adding
/// `--test session_reconnect_e2e` under `--features transport-link-ws` (its
/// default+ws set already carries session-reconnect + transport-unicast);
/// without that the module is empty and the WS reconnect path is unexercised
/// (gate-skew, the same reasoning C1u uses for `tls_reconnect`).
#[cfg(all(feature = "transport-link-ws", feature = "transport-unicast"))]
mod ws_reconnect {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use tokio::net::TcpListener;

    use wz_runtime_tokio::reconnect::{
        open_session_with_reconnect, ReconnectDriveOutcome, ReconnectLocator, ReconnectPolicy,
    };
    use wz_runtime_tokio::runtime_impl::TokioTime;
    use wz_runtime_tokio::session_open::{
        accept_and_open_session, DialConfig, DialedLink, OpenedSession, DEFAULT_OPEN_TICK_MS,
    };
    use wz_runtime_tokio::ws_pipeline::accept_ws;
    use wz_runtime_tokio_test_support::fixture_session_init_params;
    use wz_session_core::locator::parse_locator;
    use wz_session_core::session_timeouts::SessionTimeouts;

    const ITER_CAP: usize = 4096;

    /// Accept one connection, run the RFC6455 SERVER handshake, complete the
    /// accept-side session handshake, then drive until at least one inbound
    /// `Declare` lands. WS analogue of `tls_reconnect`'s
    /// `accept_tls_and_collect_declares`, but WS needs no server config, so it
    /// takes only the listener (shared across conn #1 and the reconnect's #2).
    async fn accept_ws_and_collect_declares(
        listener: &TcpListener,
    ) -> (OpenedSession, Vec<String>) {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let ws = accept_ws(stream).await.expect("server ws handshake");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4]; // distinct zid from the initiator
        let mut opened = accept_and_open_session(
            DialedLink::Ws(Box::new(ws)),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established over ws");

        let declares = super::collect_first_declare(&mut opened).await;
        (opened, declares)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn declares_replay_after_ws_link_loss_and_reconnect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let locator =
            ReconnectLocator::Ip(parse_locator(&format!("ws/{addr}")).expect("parse ws locator"));
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];

        let policy = ReconnectPolicy {
            retry_delay_ms: 50, // test cadence; production default is pico's 1s
            max_attempts: Some(100),
        };
        // WS carries no cert material, so the retained dial config is the
        // default; the reconnect value under test is the RFC6455 re-handshake,
        // not a surviving config (contrast tls_reconnect's retained TlsDialConfig).
        let dial_config = DialConfig::default();

        // ── Connection #1: client opens (reconnect-supervised) over WS,
        //    declares a subscriber; the acceptor handshakes and observes it.
        let (mut client, (server_conn1, declares_conn1)) = tokio::join!(
            async {
                let session = open_session_with_reconnect(
                    locator,
                    params,
                    dial_config,
                    TokioTime::new(),
                    policy,
                    Some(ITER_CAP),
                    DEFAULT_OPEN_TICK_MS,
                )
                .await
                .expect("client reaches Established over ws");
                session
                    .actions()
                    .send_declare_subscriber(10, 0, Some("home/ws-reconnect"))
                    .expect("declare subscriber");
                session
            },
            accept_ws_and_collect_declares(&listener),
        );
        assert_eq!(
            declares_conn1.len(),
            1,
            "connection #1 observes exactly the one declared subscriber"
        );

        // ── Sever the first WS link abruptly (drop the acceptor session).
        drop(server_conn1);

        // ── Drive the client under the supervisor while the listener
        //    re-accepts over WS. The re-dial re-runs the RFC6455 upgrade on
        //    connection #2 and the cached Declare replays.
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_server = stop.clone();
        let timeouts = SessionTimeouts::spec_defaults();
        let (drive_outcome, declares_conn2) = tokio::join!(
            client.drive(&timeouts, &stop, Some(ITER_CAP), |_| {}),
            async {
                let (server_conn2, declares) = accept_ws_and_collect_declares(&listener).await;
                stop_for_server.store(true, Ordering::Release);
                drop(server_conn2);
                declares
            },
        );

        assert!(
            matches!(drive_outcome, ReconnectDriveOutcome::Stopped),
            "supervisor must stop after the second ws link drop, got {drive_outcome:?}"
        );
        assert_eq!(
            declares_conn2, declares_conn1,
            "the reconnected WS link must replay the cached Declare verbatim"
        );
        assert_eq!(
            client.reconnects(),
            1,
            "exactly one survived WS link loss — the supervisor re-dialed ws/"
        );
    }
}
