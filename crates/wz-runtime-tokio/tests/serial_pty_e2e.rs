// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(feature = "transport-link-serial")]

//! R311nv — wz<->wz SERIAL link end-to-end over a PTY pair.
//!
//! The proof that the R311nt 2-layer SERIAL split composes into a working
//! transport: the transport-agnostic framing/handshake/locator LOGIC
//! (`wz_session_core::serial_link`) driven by the host tty BACKEND
//! (`wz_runtime_tokio::serial_pipeline`) carries a full wz<->wz session
//! over a real `openpty` serial pair, with NO network socket involved.
//!
//! Two phases, mirroring zenoh-pico's serial link:
//!
//! 1. **Serial-link handshake** — each PTY end drives
//!    `drive_serial_handshake` to Connected (Initiator sends INIT, Responder
//!    replies INIT|ACK). This is the link-level handshake that runs BEFORE
//!    the zenoh transport (`_z_connect_serial`), absent on TCP/UDP.
//! 2. **Zenoh transport + data** — the handshaked ends wrap as
//!    `DialedLink::Serial` and run the SAME `initiate_and_open_session` /
//!    `accept_and_open_session` path as TCP to Established, then a Push from
//!    the initiator is delivered byte-exact to a subscriber on the acceptor.
//!    The only serial-specific machinery is the COBS framing inside the
//!    drivers; the session FSM is transport-uniform.
//!
//! Non-flaky by construction: a PTY pair is `cfmakeraw` (serialport
//! `TTYPort::pair`, so no line-discipline byte mangling) and both ends are
//! immediately readable/writable, so the handshake never hits the RESET
//! throttle/retry path — there is no retry timing to race. The handshake is
//! bounded by a `timeout` and the transport open by an iteration cap so any
//! regression fails fast instead of hanging.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio_serial::SerialStream;

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::serial_pipeline::drive_serial_handshake;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, initiate_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::serial_link::SerialRole;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/serial";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wz_to_wz_over_serial_pty_handshakes_and_delivers_push() {
    let payload: Vec<u8> = b"serial-push-byte-exact".to_vec();

    // ── A connected async serial pair (two ends of one openpty link).
    let (mut end_init, mut end_acc) = SerialStream::pair().expect("openpty serial pair");

    // ── Phase 1: the serial-LINK handshake on both ends, over the whole
    //    stream, BEFORE the zenoh transport. Initiator sends INIT, Responder
    //    replies INIT|ACK; both must reach Connected. Bounded so a handshake
    //    regression fails fast.
    let (hs_init, hs_acc) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            drive_serial_handshake(&mut end_init, SerialRole::Initiator),
            drive_serial_handshake(&mut end_acc, SerialRole::Responder),
        )
    })
    .await
    .expect("serial link handshake completes within 5s");
    hs_init.expect("initiator link handshake reaches Connected");
    hs_acc.expect("responder link handshake reaches Connected");

    // ── Phase 2: the zenoh transport open over the handshaked serial links,
    //    driven concurrently (the 4-way handshake needs both sides
    //    progressing). Uniform with TCP — the serial framing lives entirely
    //    inside the wired drivers.
    let acc_open = async {
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4]; // distinct from the initiator
        accept_and_open_session(
            DialedLink::Serial(end_acc),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established over serial")
    };
    let init_open = async {
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        initiate_and_open_session(
            DialedLink::Serial(end_init),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established over serial")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    // ── Subscriber on the acceptor's observer; asserts the delivered payload
    //    byte-for-byte.
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
                "the serial-delivered Push payload matches byte-for-byte"
            );
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

    // ── Publisher on the initiator side (fresh observer — no local
    //    subscriber, so the proof is the remote serial delivery).
    let publisher = TokioSession::new(
        opened_init.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened_init.clock),
    );

    let timeouts = SessionTimeouts::spec_defaults();
    // Both sides driven continuously so steady state persists across the
    // publish + delivery; select! drops the drives once the scenario observes
    // the delivery.
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
        // Let both drives reach steady state, then publish once.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let delivered = publisher
            .publish(KEYEXPR, &payload, PublishOptions::put())
            .expect("serial publish builds and routes through the send seam");
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
        "exactly one Push delivered over the serial link"
    );
}

/// R311nw — an oversize Put (> `SERIAL_MTU`) published over the wz<->wz
/// serial link FRAGMENTS at the transport layer to chunks the serial frame
/// can carry, and the peer REASSEMBLES them into exactly one byte-exact
/// Sample. The serial complement of `layer3_reassembly_tx`'s TCP oversize
/// test.
///
/// The fragmentation precondition here is LINK-driven, not
/// batch-negotiated: both ends advertise the default (65535) batch, so
/// WITHOUT the `link_mtu` cap the negotiated TX budget would be 65535 and
/// the ~4 KB Put would emit as ONE frame that
/// `SerialWriteDriver::send_blocking` can only DROP (> SERIAL_MTU). The
/// test asserts `negotiated_batch_mtu() == SERIAL_MTU` up front — the cap
/// active, the false-positive guard — so a regression that dropped the
/// link bound fails the assert rather than silently losing the delivery.
///
/// Both sides are driven continuously (`None`) so the RX reassembly pool
/// persists across the fragment chain's arrivals; `select!` drops the
/// drives once the scenario observes the delivery. Requires
/// `transport-fragmentation` (the session-layer split + the reassembly
/// pool); the file's `transport-link-serial` gate provides the serial tty
/// backend.
#[cfg(feature = "transport-fragmentation")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wz_to_wz_over_serial_pty_fragments_and_reassembles_oversize_put() {
    use wz_session_core::serial_link::SERIAL_MTU;

    // A payload several serial frames long (4 KB > the 1500 SERIAL_MTU),
    // deterministic so the byte-exact reassembly check is reproducible.
    let payload: Vec<u8> = (0..4096u32).map(|i| i.wrapping_mul(31) as u8).collect();
    assert!(
        payload.len() > SERIAL_MTU,
        "payload must exceed one serial frame to force fragmentation"
    );

    let (mut end_init, mut end_acc) = SerialStream::pair().expect("openpty serial pair");

    // ── Phase 1: serial-LINK handshake on both ends.
    let (hs_init, hs_acc) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            drive_serial_handshake(&mut end_init, SerialRole::Initiator),
            drive_serial_handshake(&mut end_acc, SerialRole::Responder),
        )
    })
    .await
    .expect("serial link handshake completes within 5s");
    hs_init.expect("initiator link handshake reaches Connected");
    hs_acc.expect("responder link handshake reaches Connected");

    // ── Phase 2: the zenoh transport open over the handshaked serial links.
    let acc_open = async {
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        accept_and_open_session(
            DialedLink::Serial(end_acc),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established over serial")
    };
    let init_open = async {
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        initiate_and_open_session(
            DialedLink::Serial(end_init),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established over serial")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    // ── Fragmentation precondition, asserted BY CONSTRUCTION (R311nw): the
    //    serial link MTU caps the negotiated TX budget to SERIAL_MTU even
    //    though both peers advertised the 65535 default. The publisher side
    //    is the load-bearing one (it decides the split); the acceptor is
    //    asserted for negotiation symmetry. Without the link cap this would
    //    be 65535 and the ~4 KB Put would emit as one dropped frame — a
    //    false positive this assert forecloses.
    assert_eq!(
        opened_init.actions.negotiated_batch_mtu(),
        SERIAL_MTU,
        "publisher TX budget must cap to the serial link MTU so the oversize Put fragments"
    );
    assert_eq!(
        opened_acc.actions.negotiated_batch_mtu(),
        SERIAL_MTU,
        "acceptor TX budget caps to the same serial link MTU (symmetry)"
    );

    // ── Subscriber on the acceptor's observer; asserts the reassembled
    //    payload byte-for-byte.
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
                "the reassembled serial payload matches the oversize Put byte-for-byte"
            );
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

    // ── Publisher on the initiator side (fresh observer — no local
    //    subscriber, so the proof is the remote fragment chain over serial).
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
            .expect("oversize serial publish builds and routes through the send seam");
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
        "exactly one reassembled delivery from the oversize fragmented serial Put"
    );
}
