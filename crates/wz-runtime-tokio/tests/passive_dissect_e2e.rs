// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-unicast",
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-frame"
))]

//! R311y578 (G2) — the passive tracker reads a session it never joined.
//!
//! The bytes are NOT synthesised. Two real wz nodes handshake over loopback
//! TCP through a recording proxy that copies each direction verbatim; the
//! recording is then replayed into [`PassiveSession`], which has no access to
//! either node, no configuration, and no knowledge of the exchange beyond the
//! bytes.
//!
//! That distinction is the whole test. A fixture built from wz's own encoders
//! proves a round trip — the same code on both ends — and would stay green if
//! the framing rule the observer applies were wrong in a way the encoder
//! shared. A tapped stream proves the observer can frame and decode what the
//! LINK LAYER actually put on the wire.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::inbound::InboundFrame;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::passive::{Direction, PassiveSession, SessionPhase, PREFIX_WIDTH_UNIVERSAL};

const ITER_CAP: usize = 64;

/// A byte stream recorded off one direction of a live link.
type Tap = Arc<Mutex<Vec<u8>>>;

/// Copy `src` into `dst`, recording every byte into `tap` BEFORE forwarding
/// it. Recording first is what makes the test deterministic: anything a peer
/// could possibly have acted on is already in the tap by the time it arrives.
async fn pump<R, W>(mut src: R, mut dst: W, tap: Tap)
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = [0u8; 4096];
    loop {
        match src.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                tap.lock()
                    .expect("tap poisoned")
                    .extend_from_slice(&buf[..n]);
                if dst.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// Drain both directions in lockstep, the way a capture-ordered reader would.
/// Returns every frame in the order the observer produced it.
fn drain(session: &mut PassiveSession) -> Vec<wz_session_core::passive::PassiveFrame> {
    let mut out = Vec::new();
    loop {
        let mut progressed = false;
        for dir in [Direction::A, Direction::B] {
            while let Ok(frame) = session.next_frame(dir) {
                out.push(frame);
                progressed = true;
            }
        }
        if !progressed {
            return out;
        }
    }
}

/// The whole G2 claim, end to end: an observer handed only the two recorded
/// byte streams reconstructs the framing, decodes every handshake message, and
/// infers the negotiated context — patch level included — without ever
/// touching either node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tapped_handshake_replays_through_the_passive_tracker() {
    // The acceptor's real listener.
    let acceptor_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind acceptor");
    let acceptor_addr = acceptor_listener.local_addr().expect("acceptor addr");

    // The proxy the initiator dials instead.
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_addr = proxy_listener.local_addr().expect("proxy addr");

    // A = initiator -> acceptor, B = acceptor -> initiator.
    let tap_a: Tap = Arc::new(Mutex::new(Vec::new()));
    let tap_b: Tap = Arc::new(Mutex::new(Vec::new()));
    let (pump_a, pump_b) = (Arc::clone(&tap_a), Arc::clone(&tap_b));

    let proxy = tokio::spawn(async move {
        let (client, _) = proxy_listener.accept().await.expect("proxy accept");
        let server = TcpStream::connect(acceptor_addr)
            .await
            .expect("proxy dials the acceptor");
        let (client_rd, client_wr) = client.into_split();
        let (server_rd, server_wr) = server.into_split();
        tokio::join!(
            pump(client_rd, server_wr, pump_a),
            pump(server_rd, client_wr, pump_b),
        );
    });

    let acc = tokio::spawn(async move {
        let (stream, _peer) = acceptor_listener.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        accept_and_open_session(
            DialedLink::Tcp(stream),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established")
    });

    let locator = parse_any_locator(&format!("tcp/{proxy_addr}")).expect("parse proxy locator");
    let mut params = fixture_session_init_params();
    params.zid = vec![0x01; 4];
    let opened_init = connect_and_open_session(
        locator,
        params,
        &DialConfig::default(),
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .expect("initiator reaches Established");
    let opened_acc = acc.await.expect("acceptor task");

    // Both peers are Established, so every handshake byte has crossed the
    // proxy and been recorded. Tear the sessions down before reading the taps
    // so the pumps see EOF and cannot append mid-read.
    opened_init.drain_to_close().await;
    opened_acc.drain_to_close().await;
    let _ = proxy.await;

    let a_bytes = tap_a.lock().expect("tap a").clone();
    let b_bytes = tap_b.lock().expect("tap b").clone();
    assert!(
        !a_bytes.is_empty() && !b_bytes.is_empty(),
        "the tap recorded traffic"
    );

    // ── Replay. Nothing below can see either node. ──
    let mut observer = PassiveSession::new();
    assert_eq!(observer.context().phase, SessionPhase::Unseen);
    assert_eq!(
        observer.context().patch,
        None,
        "no Init seen yet is DISTINCT from a peer that announced patch 0"
    );

    observer.push(Direction::A, &a_bytes);
    observer.push(Direction::B, &b_bytes);
    let frames = drain(&mut observer);

    // CALIBRATION FIRST: an empty frame list would satisfy every `all(..)`
    // below vacuously. A 2-round handshake is at least InitSyn / InitAck /
    // OpenSyn / OpenAck, so four is the floor.
    assert!(
        frames.len() >= 4,
        "the replay produced {} frame(s); a handshake is at least 4",
        frames.len()
    );

    // Every framed message decoded. A single mis-framed prefix would
    // desynchronise the rest of that direction, so this is also the framing
    // assertion.
    assert!(
        frames.iter().all(|f| f.frame.is_ok()),
        "every framed message decodes: {:?}",
        frames
            .iter()
            .filter(|f| f.frame.is_err())
            .map(|f| (f.direction, f.stream_offset))
            .collect::<Vec<_>>()
    );
    assert!(
        frames
            .iter()
            .all(|f| f.prefix_width == PREFIX_WIDTH_UNIVERSAL),
        "a session that did not negotiate lowlatency keeps the 2-byte prefix throughout"
    );

    // The handshake is legible as a handshake: an Init and an Open in EACH
    // direction, in that order.
    for dir in [Direction::A, Direction::B] {
        let kinds: Vec<&str> = frames
            .iter()
            .filter(|f| f.direction == dir)
            .filter_map(|f| match f.frame {
                Ok(InboundFrame::Init { .. }) => Some("init"),
                Ok(InboundFrame::Open { .. }) => Some("open"),
                _ => None,
            })
            .collect();
        assert_eq!(
            kinds.first().copied(),
            Some("init"),
            "{dir:?} opens with an Init"
        );
        assert!(
            kinds.contains(&"open"),
            "{dir:?} carries an Open: {kinds:?}"
        );
    }

    // The inferred context. This is what a participant would have been
    // CONFIGURED with and the observer had to derive.
    let ctx = observer.context();
    assert!(
        matches!(ctx.phase, SessionPhase::Established | SessionPhase::Closed),
        "the observer followed the session to Established, got {:?}",
        ctx.phase
    );
    assert!(ctx.negotiated(), "both Inits were folded");
    assert_eq!(
        ctx.patch,
        Some(wz_session_core::extpatch::CURRENT_PATCH),
        "min(1, 1) off two wz peers"
    );
    assert!(
        ctx.fragmentation_markers(),
        "patch 1 arms the Fragment chain-boundary rules for anything reading this flow"
    );
    assert!(
        !ctx.lowlatency_active(),
        "neither fixture offers lowlatency, so the stream never reframes"
    );
    assert!(!ctx.compression_active());
}

/// The observer's context is a READING, not a default. Fed the SAME recorded
/// stream with the second direction withheld — a one-sided capture, the
/// commonest real defect in a tap — it must report the capabilities as NOT
/// negotiated rather than as the identity element of the `&=` fold.
///
/// Without this arm, `negotiated()` returning true above could be a constant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_one_sided_capture_does_not_claim_a_negotiation() {
    let acceptor_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind acceptor");
    let acceptor_addr = acceptor_listener.local_addr().expect("acceptor addr");
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_addr = proxy_listener.local_addr().expect("proxy addr");

    let tap_a: Tap = Arc::new(Mutex::new(Vec::new()));
    let tap_b: Tap = Arc::new(Mutex::new(Vec::new()));
    let (pump_a, pump_b) = (Arc::clone(&tap_a), Arc::clone(&tap_b));
    let proxy = tokio::spawn(async move {
        let (client, _) = proxy_listener.accept().await.expect("proxy accept");
        let server = TcpStream::connect(acceptor_addr).await.expect("proxy dial");
        let (client_rd, client_wr) = client.into_split();
        let (server_rd, server_wr) = server.into_split();
        tokio::join!(
            pump(client_rd, server_wr, pump_a),
            pump(server_rd, client_wr, pump_b),
        );
    });
    let acc = tokio::spawn(async move {
        let (stream, _peer) = acceptor_listener.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        accept_and_open_session(
            DialedLink::Tcp(stream),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established")
    });
    let locator = parse_any_locator(&format!("tcp/{proxy_addr}")).expect("parse proxy locator");
    let mut params = fixture_session_init_params();
    params.zid = vec![0x01; 4];
    let opened_init = connect_and_open_session(
        locator,
        params,
        &DialConfig::default(),
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .expect("initiator reaches Established");
    let opened_acc = acc.await.expect("acceptor task");
    opened_init.drain_to_close().await;
    opened_acc.drain_to_close().await;
    let _ = proxy.await;

    let a_bytes = tap_a.lock().expect("tap a").clone();

    let mut observer = PassiveSession::new();
    observer.push(Direction::A, &a_bytes);
    let frames = drain(&mut observer);

    assert!(
        frames
            .iter()
            .any(|f| matches!(f.frame, Ok(InboundFrame::Init { .. }))),
        "the one direction that WAS captured still decodes"
    );
    let ctx = observer.context();
    assert_eq!(
        ctx.phase,
        SessionPhase::HalfInit,
        "one Init is a half-fold, not a negotiation"
    );
    assert!(
        !ctx.negotiated(),
        "the capabilities must not read as negotiated off one side"
    );
    assert!(
        !ctx.lowlatency_active() && !ctx.compression_active(),
        "an un-negotiated capability is never IN FORCE, whatever the fold holds"
    );
    // The patch level IS readable from one side — it is an announcement, and
    // min(announced) over one announcement is that announcement. Distinguished
    // from the capabilities on purpose.
    assert_eq!(ctx.patch, Some(wz_session_core::extpatch::CURRENT_PATCH));
}
