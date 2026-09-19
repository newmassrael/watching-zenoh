// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_serial::SerialStream;

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::serial_pipeline::{drive_serial_handshake, wire_serial_stream, SerialPort};
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, accept_endpoint, bind_locator, initiate_and_open_session,
    AcceptConfig, AcceptedLink, AcceptedPeer, BoundListener, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::{
    parse_any_locator, AnyLocator, SerialEndpoint, SerialOptions, SerialTarget,
};
use wz_session_core::serial_link::SerialRole;

/// The endpoint a PTY-pair test stands in for — `SerialStream::pair()` exposes no
/// device name, so the address is supplied the way the real dial path supplies the
/// one it parsed out of the locator.
fn pty_endpoint() -> SerialEndpoint {
    SerialEndpoint {
        target: SerialTarget::Device("/dev/wz-test-pty".to_string()),
        baudrate: 115_200,
        options: SerialOptions::default(),
    }
}
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
            DialedLink::Serial {
                stream: SerialPort::dialled(end_acc),
                endpoint: pty_endpoint(),
            },
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
            DialedLink::Serial {
                stream: SerialPort::dialled(end_init),
                endpoint: pty_endpoint(),
            },
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
            DialedLink::Serial {
                stream: SerialPort::dialled(end_acc),
                endpoint: pty_endpoint(),
            },
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
            DialedLink::Serial {
                stream: SerialPort::dialled(end_init),
                endpoint: pty_endpoint(),
            },
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

// ─────────────────────────────────────────────────────────────────────────────
// R311y805 — the ACCEPT SEAM slice. Everything above hand-composes
// `DialedLink::Serial` from a `SerialStream::pair()`, which proves the serial
// TRANSPORT and says nothing about whether a `serial/...` LISTEN STRING reaches
// it. Until this round it did not: `bind_locator`'s `AnyLocator::Serial` arm was
// a typed `Unsupported`, so `accept_serial` had no production caller and the
// only way to a serial acceptor was to build the link by hand — which is exactly
// what the tests above, and the pico interop witness, did.
//
// These four bind through the SHIPPED seam (`bind_locator` / `accept_endpoint`),
// so each one fails if the arm is removed.
// ─────────────────────────────────────────────────────────────────────────────

/// One PTY pair reduced to what an accept test needs: the master (the PEER's
/// end of the wire) and the slave's device PATH (what goes into the locator).
///
/// The slave handle is RETAINED and never read. Retained because a master read
/// fails `EIO` the moment the pty's last slave fd closes, and the seam opens its
/// own slave fd only later; never read because two fds on one pts share an input
/// queue, so a keepalive that read would steal the seam's bytes. Same shape as
/// `wz-integration-tests`' pico serial witness, which learned it first.
struct PtyEnd {
    master: SerialStream,
    path: String,
    _slave_keepalive: SerialStream,
}

fn pty_end() -> PtyEnd {
    let (master, slave) = SerialStream::pair().expect("openpty serial pair");
    let path = tokio_serial::SerialPort::name(&slave).expect("pty slave has a device path");
    PtyEnd {
        master,
        path,
        _slave_keepalive: slave,
    }
}

/// A `serial/...` LISTEN binds without touching the device, and addresses by tty.
///
/// THE DISCRIMINATOR is the device that does not exist: binding it must still
/// succeed. That is what separates "the bind records an endpoint" (upstream's
/// shape — zenoh's `new_listener` creates no `ZSerial` either; its accept task
/// does, `io/zenoh-links/zenoh-link-serial/src/unicast.rs` @ `async fn new_listener(&self, endpoint: EndPoint) -> ZResult<Locator> {`)
/// from "the bind opens the
/// tty", which would `NotFound` here. It is also why the accept, not the bind, is
/// where a serial listen can fail.
///
/// The rest pins the accessors the new variant had to answer, each of which had a
/// wrong-but-plausible alternative: `local_addr` could have returned the `Ok` the
/// IP families do, `supports_mesh_multi_peer` the `true` every other variant now
/// returns, and `advertised_locator` the log word `"serial"` instead of a
/// dialable string. The last is checked by PARSING IT BACK, the R311y470 lesson:
/// an advertised locator is flooded to peers, so it has to survive wz's own
/// parser rather than merely look right.
#[tokio::test]
async fn serial_listen_binds_without_opening_the_device_and_addresses_by_tty() {
    let absent = "/dev/wz-no-such-tty-r311y805";
    let locator = format!("serial/{absent}#baudrate=115200");
    let parsed = parse_any_locator(&locator).expect("wz parses its own serial locator");
    let endpoint = match parsed {
        AnyLocator::Serial(ep) => ep,
        other => panic!("`serial/...` must classify as AnyLocator::Serial, got {other:?}"),
    };

    let listener = bind_locator(
        AnyLocator::Serial(endpoint.clone()),
        &AcceptConfig::default(),
    )
    .await
    .expect("a serial bind records the endpoint; it must not open the device");
    assert!(
        matches!(listener, BoundListener::Serial(_)),
        "a serial locator binds to the serial variant"
    );
    assert_eq!(listener.transport_name(), "serial");
    assert_eq!(
        listener
            .local_addr_display()
            .expect("serial address renders"),
        format!("{absent}#baudrate=115200"),
        "a serial listener addresses by DEVICE plus the `#baudrate=` tail that \
         makes the string parse back"
    );
    assert_eq!(
        listener
            .local_addr()
            .expect_err("a tty has no IP address")
            .kind(),
        io::ErrorKind::Unsupported,
        "the IP accessor is a typed Unsupported, as for the other non-IP families"
    );
    // R2723 — still `false`, and that is a STATEMENT now rather than a refusal.
    // One tty carries one peer AT A TIME, so a mesh caller holds a single face
    // off it and accepts the next once that peer has gone; the bind sites REPORT
    // the cadence instead of rejecting the listen, and the accept loop no longer
    // has an admission test at all. The value must stay `false` for exactly the
    // reason it always did — a widened predicate would answer `true` for every
    // variant and say nothing.
    assert!(
        !listener.supports_mesh_multi_peer(),
        "one tty carries one peer at a time: a serial listener is NOT mesh-capable, \
         and a mesh caller is told so rather than refused"
    );

    // The advertised string must survive wz's OWN parser and land back on the
    // SAME endpoint — an advertised locator is flooded to peers, so "looks like a
    // locator" is not the bar.
    let advertised = listener.advertised_locator(
        &listener
            .local_addr_display()
            .expect("serial address renders"),
    );
    assert_eq!(advertised, format!("serial/{absent}#baudrate=115200"));
    match parse_any_locator(&advertised).expect("the advertised serial locator re-parses") {
        AnyLocator::Serial(back) => assert_eq!(
            back, endpoint,
            "the advertised locator round-trips to the endpoint it was bound from"
        ),
        other => panic!("the advertised serial locator must classify back, got {other:?}"),
    }
}

/// The accept RETURNS before the peer has said anything — the deferral clause.
///
/// THE DISCRIMINATOR is the silent peer. `accept_serial` (open + Responder
/// handshake in one call) is the obvious way to wire this arm, and it would HANG
/// here: the Responder half blocks until it reads `INIT`. So the assertion is not
/// "the accept works" but "the accept completes with a peer that has written
/// nothing", which only the split — tty open in `accept_raw`, handshake deferred
/// to `AcceptedLink::handshake` — can satisfy. That split is what keeps a serial
/// accept off the same cliff the tls/quic crypto is kept off.
///
/// It then pins the second half: the SAME accepted link, handed the handshake
/// once the peer does speak, completes into `DialedLink::Serial`. Without that
/// leg the test would pass on an accept that returned something unusable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serial_accept_returns_before_the_peer_speaks_and_defers_the_link_handshake() {
    let mut end = pty_end();
    let locator = format!("serial/{}#baudrate=115200", end.path);
    let endpoint = match parse_any_locator(&locator).expect("locator parses") {
        AnyLocator::Serial(ep) => ep,
        other => panic!("expected AnyLocator::Serial, got {other:?}"),
    };
    let mut listener = bind_locator(AnyLocator::Serial(endpoint), &AcceptConfig::default())
        .await
        .expect("serial bind");

    // The peer is SILENT. A handshake-inline accept cannot return here.
    let (accepted, peer) = tokio::time::timeout(Duration::from_secs(5), listener.accept_raw())
        .await
        .expect("the accept must not wait on the peer: the link handshake is deferred")
        .expect("opening the pty slave succeeds");
    assert_eq!(
        peer,
        AcceptedPeer::NonIp("serial"),
        "a tty open names no peer"
    );
    // R2723 — the accepted-side mesh predicate is GONE, and this assertion went
    // with it rather than being reworded: the loop no longer asks an accepted
    // link whether its acceptor is multi-peer, because a one-at-a-time acceptor
    // now feeds it like any other. The cadence is declared ONCE, at bind, and
    // `serial_listen_binds_without_opening_the_device_and_addresses_by_tty` is
    // where it is pinned.

    // Now let the peer speak, and run the DEFERRED half on that same link.
    let peer_side = async {
        drive_serial_handshake(&mut end.master, SerialRole::Initiator)
            .await
            .expect("peer initiator reaches Connected");
    };
    let wz_side = async {
        accepted
            .handshake()
            .await
            .expect("the deferred Responder handshake completes")
    };
    let (_, dialed) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(peer_side, wz_side)
    })
    .await
    .expect("the deferred handshake completes within 5s");
    assert!(
        matches!(dialed, DialedLink::Serial { .. }),
        "the accepted serial link completes into the same DialedLink the dial side produces"
    );
}

/// A bound tty yields one link AT A TIME: while that link is LIVE the accept
/// parks.
///
/// THE DISCRIMINATOR is the second accept's TIMEOUT. Three implementations are
/// distinguishable here and only one is right: re-opening the device returns
/// `Ok` (and would put a second reader on a live tty, splitting the byte
/// stream); returning `Err` re-arms the accept loop's `Step::Accepted(Err)`
/// throttle, which is the R311y382 F2 spin; parking does neither. So the
/// assertion is that the second accept neither succeeds nor fails — it does not
/// complete at all.
///
/// This is the half of the old `..._yields_one_link_then_parks` that stays true.
/// The half that did NOT is its sibling below: parking while the link is live is
/// upstream's behaviour, parking after it has gone was wz having no way to tell
/// the two apart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serial_listener_parks_while_its_link_is_live() {
    let end = pty_end();
    let locator = format!("serial/{}#baudrate=115200", end.path);
    let endpoint = match parse_any_locator(&locator).expect("locator parses") {
        AnyLocator::Serial(ep) => ep,
        other => panic!("expected AnyLocator::Serial, got {other:?}"),
    };
    let mut listener = bind_locator(AnyLocator::Serial(endpoint), &AcceptConfig::default())
        .await
        .expect("serial bind");

    // HELD, deliberately: the link stays alive across the second accept, which
    // is the whole condition under test.
    let _first = tokio::time::timeout(Duration::from_secs(5), listener.accept_raw())
        .await
        .expect("the first accept completes")
        .expect("the first accept opens the device");

    let second = tokio::time::timeout(Duration::from_millis(400), listener.accept_raw()).await;
    assert!(
        second.is_err(),
        "the second accept must PARK while the first link is live: an Ok would mean \
         a second fd on the same tty, an Err would re-arm the accept loop's throttle"
    );
}

/// Bind a `serial/...` listen STRING through the shipped seam, asserting only
/// that it classified and bound.
async fn bind_serial_listen(locator: &str) -> BoundListener {
    let endpoint = match parse_any_locator(locator).expect("locator parses") {
        AnyLocator::Serial(ep) => ep,
        other => panic!("expected AnyLocator::Serial, got {other:?}"),
    };
    bind_locator(AnyLocator::Serial(endpoint), &AcceptConfig::default())
        .await
        .expect("a serial listen binds")
}

/// Whether the listener is holding an OPEN device past the link that used it.
///
/// Reached through the VARIANT rather than the concrete listener type: no other
/// `BoundListener` arm can answer this, because no other scheme's accept is a
/// local open.
fn retains_device(listener: &BoundListener) -> bool {
    match listener {
        BoundListener::Serial(l) => l.retains_device(),
        _ => panic!("a serial locator must bind to BoundListener::Serial"),
    }
}

/// Accept one link off `listener` and complete its DEFERRED handshake against
/// `peer` driven as the Initiator, yielding the parts a session would wire.
async fn accept_and_handshake(
    listener: &mut BoundListener,
    peer: &mut SerialStream,
) -> (SerialPort, SerialEndpoint) {
    let (accepted, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept_raw())
        .await
        .expect("the accept completes")
        .expect("the accept yields a device");
    let (_, dialed) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            async {
                drive_serial_handshake(peer, SerialRole::Initiator)
                    .await
                    .expect("peer initiator reaches Connected");
            },
            async {
                accepted
                    .handshake()
                    .await
                    .expect("the deferred Responder handshake completes")
            },
        )
    })
    .await
    .expect("the deferred handshake completes within 5s");
    match dialed {
        DialedLink::Serial { stream, endpoint } => (stream, endpoint),
        _ => panic!("a serial accept completes into DialedLink::Serial"),
    }
}

/// Tear a serial link down the way a CLEAN session teardown does: wire it, drop
/// the read driver, release the last sender, and drain the writer task to
/// completion.
///
/// ⛔ THE WIRING IS NOT INCIDENTAL. An `AcceptedLink` that is merely dropped
/// never reaches [`wire_serial_stream`], so the stream is never split and neither
/// half has anywhere to come back FROM — a retain witness built on that path
/// would be green for a listener that retains nothing. The three retention arms
/// below therefore all tear down through here.
async fn wire_and_tear_down(port: SerialPort, endpoint: &SerialEndpoint) {
    let (inbound, outbound, handle) = wire_serial_stream(port, endpoint);
    drop(inbound); // the read half goes home; the guard frees the device
    drop(outbound); // the last sender goes, which seals the outbound queue
    handle.drain().await; // the writer task ends, and its half goes home
}

/// `release_on_close=false` is HONOURED — the listener keeps the OPEN device past
/// the link that used it — where R2722 refused the key at bind.
///
/// THE DISCRIMINATOR is `retains_device()` across the teardown, and it has to be
/// a property of the LISTENER rather than of the accept's return value: an accept
/// that quietly re-opened the tty would hand back an indistinguishable link, and
/// "accepted the string and re-opened anyway" is precisely what R2722 declined to
/// ship as honouring the key. Upstream is the same read the other way round —
/// it re-creates the port only `if release_on_close`
/// (`io/zenoh-links/zenoh-link-serial/src/unicast.rs` @ `if release_on_close {`)
/// and drops it on close only `if self.release_on_close`
/// (@ `if self.release_on_close {`) — so the CONDITIONAL half is the re-open.
///
/// ANTI-VACUITY: a retained fd that no longer worked would satisfy the flag and
/// nothing else, so the second half carries a SECOND link over the retained
/// device and completes its handshake on it. Its sibling below is the control.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn serial_listen_honours_release_on_close_false_by_retaining_the_device() {
    let mut end = pty_end();
    let retained = format!("serial/{}#baudrate=115200;release_on_close=false", end.path);
    assert!(
        !match parse_any_locator(&retained).expect("locator parses") {
            AnyLocator::Serial(ep) => ep,
            other => panic!("expected AnyLocator::Serial, got {other:?}"),
        }
        .options
        .release_on_close,
        "the fixture locator must actually carry the non-default, or this arm is vacuous"
    );
    let mut listener = bind_serial_listen(&retained).await;
    assert!(
        !retains_device(&listener),
        "nothing is retained before a link has lived on the device"
    );

    let (port, endpoint) = accept_and_handshake(&mut listener, &mut end.master).await;
    wire_and_tear_down(port, &endpoint).await;
    assert!(
        retains_device(&listener),
        "release_on_close=false must keep the OPEN device past its link: that is \
         the key's entire observable effect"
    );

    // The retained device still carries a link, and the accept TAKES it rather
    // than leaving a copy behind for a second reader to appear on.
    let (port, endpoint) = accept_and_handshake(&mut listener, &mut end.master).await;
    assert!(
        !retains_device(&listener),
        "the accept must CONSUME the retained device"
    );
    wire_and_tear_down(port, &endpoint).await;
}

/// THE CONTROL for its sibling above: under the DEFAULT `release_on_close=true`
/// the same teardown retains NOTHING.
///
/// Without this arm a listener that retained UNCONDITIONALLY would pass the
/// sibling, and unconditional retention is the wrong behaviour rather than a
/// harmless surplus — upstream drops the port on close in exactly this case
/// (`io/zenoh-links/zenoh-link-serial/src/unicast.rs` @ `if self.release_on_close {`,
/// guarding `self.unset_port();`), and a device held by a listener nobody is
/// using is a tty no other process can open.
///
/// It then accepts AGAIN, because releasing the device must leave the listener
/// able to re-open it: that is the R2722 property this round must not have
/// broken, and a release that merely lost the port would fail here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn serial_listen_releases_the_device_on_close_by_default() {
    let mut end = pty_end();
    let default = format!("serial/{}#baudrate=115200", end.path);
    assert!(
        match parse_any_locator(&default).expect("locator parses") {
            AnyLocator::Serial(ep) => ep,
            other => panic!("expected AnyLocator::Serial, got {other:?}"),
        }
        .options
        .release_on_close,
        "release_on_close defaults to true on both sides"
    );
    let mut listener = bind_serial_listen(&default).await;

    let (port, endpoint) = accept_and_handshake(&mut listener, &mut end.master).await;
    wire_and_tear_down(port, &endpoint).await;
    assert!(
        !retains_device(&listener),
        "the default key RELEASES the device on close; retaining it unconditionally \
         would hold a tty nothing is using"
    );

    let (port, endpoint) = accept_and_handshake(&mut listener, &mut end.master).await;
    wire_and_tear_down(port, &endpoint).await;
}

/// A serial accept CLEARS whatever the previous peer left on the wire.
///
/// THE DISCRIMINATOR is a read that must TIME OUT. The stale bytes are asserted
/// absent BY VALUE rather than by "the next handshake still worked", because
/// `SerialReadDriver`'s framer logs and resyncs past noise — a
/// handshake-completes assertion would be green whether or not anything was
/// cleared, which is the vacuity this file keeps catching in its own arms.
///
/// It runs under `release_on_close=false` on purpose: retention is the case where
/// those bytes can survive at all, because the fd is the same one. Under the
/// default the device is re-opened and the question does not arise — which is why
/// wz needed no clear before this round and needs one now. Upstream clears at the
/// same seam and unconditionally (`z-serial-0.3.1` @ `pub async fn accept(&mut self)`,
/// whose first act past the status check is `// Clear all buffers` / `self.clear()?`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_serial_re_accept_clears_what_the_previous_peer_left_on_the_wire() {
    let mut end = pty_end();
    let retained = format!("serial/{}#baudrate=115200;release_on_close=false", end.path);
    let mut listener = bind_serial_listen(&retained).await;

    let (port, endpoint) = accept_and_handshake(&mut listener, &mut end.master).await;
    wire_and_tear_down(port, &endpoint).await;
    assert!(
        retains_device(&listener),
        "the clear is only a question on a RETAINED fd, so this arm is vacuous \
         unless the device was kept"
    );

    // The previous peer's tail: bytes on the wire after its link died, which the
    // next handshake would otherwise read as its own first bytes.
    const STALE: &[u8] = b"\x11\x22\x33-left-behind";
    end.master
        .write_all(STALE)
        .await
        .expect("the departed peer writes its tail");
    end.master.flush().await.expect("the tail reaches the wire");
    // A settling margin, not a race this test depends on winning: a pty pair is
    // immediate, and the assertion below would fail OPEN (timeout = cleared) if
    // the bytes had not arrived at all, so the margin is generous.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let (accepted, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept_raw())
        .await
        .expect("the re-accept completes")
        .expect("the re-accept yields the retained device");
    let mut port = match accepted {
        AcceptedLink::Serial { stream, .. } => stream,
        _ => panic!("a serial accept yields AcceptedLink::Serial"),
    };
    let mut buf = [0u8; 64];
    match tokio::time::timeout(Duration::from_millis(300), port.stream_mut().read(&mut buf)).await {
        Err(_elapsed) => {} // nothing readable: the accept cleared the queue
        Ok(Ok(n)) => panic!(
            "the accept must clear the wire, but it delivered {n} stale byte(s): {:?}",
            &buf[..n]
        ),
        Ok(Err(e)) => panic!("reading the re-accepted device failed: {e}"),
    }
}

/// ⛔ THE LISTENER SURVIVES ITS PEER. Once the accepted link is DROPPED, the same
/// listener accepts again.
///
/// This is the structure wz did not have: upstream's serial listener spins on an
/// `is_connected` flag its LINK clears on close
/// (`io/zenoh-links/zenoh-link-serial/src/unicast.rs` @ `while is_connected.load(Ordering::Acquire) {`,
/// cleared at `self.is_connected.store(false, Ordering::Release);` in the link's
/// `close`), so a tty listener serves peer after peer, one at a time. wz's
/// listener had a one-shot `armed` flag and NO feedback from the link at all, so
/// it could not distinguish "my peer is still here" from "my peer is gone" and
/// parked on both — which is also why `release_on_close` had nothing to express:
/// the key's entire observable effect is on the re-accept this test performs.
///
/// RED-FIRST: this arm fails before the liveness seam exists (the second accept
/// times out exactly as its sibling above asserts), and that failure is what says
/// the sibling was pinning a defect rather than a decision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serial_listener_accepts_again_once_its_link_is_dropped() {
    let end = pty_end();
    let locator = format!("serial/{}#baudrate=115200", end.path);
    let endpoint = match parse_any_locator(&locator).expect("locator parses") {
        AnyLocator::Serial(ep) => ep,
        other => panic!("expected AnyLocator::Serial, got {other:?}"),
    };
    let mut listener = bind_locator(AnyLocator::Serial(endpoint), &AcceptConfig::default())
        .await
        .expect("serial bind");

    let first = tokio::time::timeout(Duration::from_secs(5), listener.accept_raw())
        .await
        .expect("the first accept completes")
        .expect("the first accept opens the device");
    drop(first);

    let second = tokio::time::timeout(Duration::from_secs(5), listener.accept_raw())
        .await
        .expect("the second accept completes once the first link has dropped")
        .expect("the second accept yields a link");
    drop(second);
}

/// The whole capability, through the shipped `--listen` seam: a wz Acceptor
/// named by a `serial/...` STRING carries a session to Established and delivers a
/// Push byte-exact.
///
/// This is the round's headline claim and it is deliberately end-to-end rather
/// than seam-shaped: `accept_endpoint` is the entry point the demo's Acceptor
/// role and pico's `z_open(listen=..)` both use, so passing it a serial locator
/// is the thing a deployment does. Every hand-composed `DialedLink::Serial` in
/// this file passes with the seam arm removed; this one cannot.
///
/// The peer half is the pty MASTER driven as the serial-link Initiator, which is
/// the role pico is forced into (it implements only `_z_connect_serial` and never
/// emits `ACK`), so the direction under test is the one a foreign client
/// produces.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wz_acceptor_binds_a_serial_listen_string_and_delivers_a_push() {
    let payload: Vec<u8> = b"serial-listen-seam-byte-exact".to_vec();
    let mut end = pty_end();
    let listen = format!("serial/{}#baudrate=115200", end.path);

    // ── The wz Acceptor comes up from the LISTEN STRING alone, concurrently
    //    with the peer's Initiator handshake on the other end of the wire.
    let accept_cfg = AcceptConfig::default();
    let accept_side = accept_endpoint(&listen, &accept_cfg);
    let peer_side = async {
        drive_serial_handshake(&mut end.master, SerialRole::Initiator)
            .await
            .expect("peer initiator reaches Connected");
    };
    let (accepted, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(accept_side, peer_side)
    })
    .await
    .expect("listen + peer handshake complete within 10s");
    let accepted = accepted.expect("a serial listen string binds, accepts and handshakes");
    assert!(matches!(accepted, DialedLink::Serial { .. }));

    // ── Phase 2: the zenoh transport over the accepted link, the peer end
    //    wrapped the way the dial side would wrap it.
    let acc_open = async {
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        accept_and_open_session(
            accepted,
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established over the serial listen")
    };
    let init_open = async {
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        initiate_and_open_session(
            DialedLink::Serial {
                stream: SerialPort::dialled(end.master),
                endpoint: pty_endpoint(),
            },
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established over serial")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

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
                "the Push delivered over the LISTENED serial link matches byte-for-byte"
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
            .expect("publish builds and routes through the send seam");
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
        "exactly one Push delivered over the serial link the LISTEN STRING opened"
    );
}
