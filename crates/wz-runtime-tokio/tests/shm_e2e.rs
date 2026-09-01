// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "session-extshm",
    feature = "transport-unicast",
    feature = "transport-link-tcp"
))]

//! wz<->wz scoped shared-memory transport end to end — the negotiated zero-copy
//! data path (R3b finale).
//!
//! The wz mirror of zenoh's SHM payload transfer: both peers OFFER the 0x2 SHM
//! capability on Init, the `&=` merge agrees (`is_shm`), and an SHM-backed Put
//! then carries only the segment DESCRIPTOR (+ the 0x2 ext_shm body marker) over
//! the wire while the bytes stay in /dev/shm — the subscriber mmaps the segment
//! and reads them zero-copy off the shared page. SCOPED: a UNIT capability
//! AND-merge (NOT zenoh's challenge-response), one segment per payload, same-host;
//! cross-impl deferred.
//!
//!   1. `shm_negotiates_and_delivers_put_zero_copy_over_real_tcp` — the
//!      end-to-end proof. Both sides reach Established with `is_shm()` true; the
//!      publisher writes a payload into a /dev/shm segment and `publish_shm`s it;
//!      the descriptor rides the TCP link; the acceptor's `PosixShmResolver` maps
//!      the segment and the subscriber receives the bytes BYTE-EXACT. The wire
//!      carried a descriptor (proven deterministically by the push_build unit
//!      test `build_push_shm_literal_carries_descriptor_and_marker`); here the
//!      byte-exact delivery proves the resolve closes the loop. The publisher
//!      holds the `ShmBackedPayload` alive until delivery (the scoped lifecycle).
//!   2. `shm_negotiation_and_merge` — the deterministic `&=`: both offer -> both
//!      `is_shm()` true; a one-sided offer -> BOTH false (the peer never
//!      reflects), so the data path stays inert.
//!
//! ## Non-flakiness
//! Test 1 is a handful of in-order loopback TCP datagrams + a same-process
//! /dev/shm mmap; the publisher holds the segment until the subscriber's counter
//! increments, bounded by a ~3s probe budget. Test 2 touches no socket.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session_with_shm, connect_and_open_session_with_shm, DialConfig, DialedLink,
    DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::shm_provider::{PosixShmResolver, ShmBackedPayload};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::{establish_capability_pair, fixture_params_with_zid};
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/shm";

/// Test 1 — two wz nodes handshake over loopback TCP, BOTH offering SHM, reach
/// Established with the capability negotiated on, and a Put published from a
/// /dev/shm segment is delivered byte-exact to a subscriber on the acceptor that
/// mmaps the segment off the descriptor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shm_negotiates_and_delivers_put_zero_copy_over_real_tcp() {
    let data = b"payload-living-in-dev-shm".to_vec();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept tcp peer");
        accept_and_open_session_with_shm(
            DialedLink::Tcp(stream),
            fixture_params_with_zid(0x02),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established with SHM offered")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        let cfg = DialConfig::default();
        connect_and_open_session_with_shm(
            locator,
            fixture_params_with_zid(0x01),
            &cfg,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established with SHM offered")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);
    // R311y516 — a live handle for the drive closure's negotiated-SHM stamp
    // (`&opened_acc.actions` is borrowed by the driver itself).
    let acc_actions_for_stamp = opened_acc.actions.clone();

    assert!(opened_init.actions.is_shm(), "initiator negotiated SHM on");
    assert!(opened_acc.actions.is_shm(), "acceptor negotiated SHM on");

    // Subscriber on the acceptor + the SHM resolver installed on the SAME registry
    // the drive dispatches through.
    let fired = Arc::new(AtomicUsize::new(0));
    let mut observer = ApplicationLayerObserver::new();
    observer
        .subscribers
        .set_shm_resolver(Box::new(PosixShmResolver));
    {
        let fired = fired.clone();
        let expect = data.clone();
        observer.subscribers.register(KEYEXPR, move |sample| {
            assert_eq!(sample.keyexpr(), KEYEXPR);
            assert_eq!(
                sample.payload(),
                &expect[..],
                "the subscriber reads the publisher's bytes off the shared segment"
            );
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

    // The publisher writes the payload into a /dev/shm segment; it MUST outlive
    // the round-trip (the scoped lifecycle — Drop unlinks).
    let mut shm_payload = ShmBackedPayload::alloc(data.len()).expect("alloc /dev/shm segment");
    shm_payload.write(&data);

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
        |event| {
            // R311y516 — a custom drive closure owes the subscriber registry the
            // same LIVE negotiated-SHM stamp the production dispatch SSOT
            // (`Session::dispatch_iteration_event_with`) applies, because the RX
            // un-swap now ENFORCES it (zenoh's
            // `if self.config.shm.is_some() { map_zmsg_to_shmbuf(..) }`,
            // io/zenoh-transport/src/unicast/universal/rx.rs:50-51). Read off the
            // live actions rather than hard-coded `true`, so this stays a
            // measurement of the negotiation and not an assertion about itself.
            observer
                .subscribers
                .set_shm_negotiated(acc_actions_for_stamp.is_shm());
            observer.dispatch_event(event)
        },
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
        tokio::time::sleep(Duration::from_millis(200)).await;
        let delivered = publisher
            .publish_shm(KEYEXPR, &shm_payload, PublishOptions::put())
            .expect("publish_shm builds the descriptor + routes through the send seam");
        assert_eq!(delivered, 0, "no local subscriber on the publisher side");
        for _ in 0..100 {
            if fired_probe.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("subscriber did not fire within the ~3s budget");
        // shm_payload stays in scope here -> the segment lives across the probe.
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_init => panic!("initiator drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "exactly one zero-copy delivery from the SHM Put"
    );
}

/// Test 2 — the deterministic negotiation `&=`: both offer -> both on; a
/// one-sided offer leaves BOTH sides off (the peer never reflects), so the data
/// path stays inert. The handshake drive is the shared
/// `establish_capability_pair`; the SHM offer is the closure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shm_negotiation_and_merge() {
    let both = establish_capability_pair(true, true, |a| {
        a.set_shm_offer(true);
    })
    .await;
    assert!(both.init_actions.is_shm(), "initiator negotiated SHM on");
    assert!(both.resp_actions.is_shm(), "acceptor negotiated SHM on");

    let one = establish_capability_pair(true, false, |a| {
        a.set_shm_offer(true);
    })
    .await;
    assert!(
        !one.init_actions.is_shm(),
        "a one-sided offer leaves the initiator off (peer did not reflect)"
    );
    assert!(
        !one.resp_actions.is_shm(),
        "the responder never offered, so it stays off"
    );
}

/// R311y507 — the CHALLENGE-RESPONSE over a real driven handshake, not just the
/// dispatch in isolation: both sides publish a POSIX auth segment, and `is_shm`
/// survives only because each one mapped the other's memory and echoed the
/// challenge it found there.
///
/// The four messages all have to land for this to pass — the initiator's segment
/// id on InitSyn, the acceptor's echo plus its own id on InitAck, the
/// initiator's answer on OpenSyn, the acceptor's counter block on OpenAck
/// (1.10.0 replaced the literal `1` that used to sit there, R2240) — so a
/// break anywhere in the chain shows up here as `is_shm() == false` rather than
/// as a passing session that negotiated nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_challenge_response_negotiates_shm_over_a_driven_handshake() {
    let pair = establish_capability_pair(true, true, |a| {
        a.set_shm_offer(true);
        a.install_shm_auth(Box::new(
            wz_runtime_tokio::shm_auth_segment::PosixShmAuthenticator::new()
                .expect("publish an auth segment"),
        ));
    })
    .await;
    assert!(
        pair.init_actions.is_shm(),
        "the initiator's flag is set at OpenAck, so this is the whole exchange"
    );
    assert!(
        pair.resp_actions.is_shm(),
        "the acceptor's flag is set at OpenSyn, on the initiator's echo"
    );
}

/// The two mechanisms do NOT half-mix. When only one side has an authenticator
/// installed, that side emits zenoh's ZBuf challenge while the other emits (and
/// looks for) the pre-R311y507 UNIT marker — neither recognises the other, and
/// BOTH end up without SHM.
///
/// This is the arm that matters for safety: a session that ended with one side
/// believing SHM was on would put descriptors on a wire the peer reads as
/// payload bytes. It is also why the challenge REPLACES the UNIT ext at the
/// stage seam rather than riding alongside it.
///
/// Driven through `establish_capability_pair`'s `resp_offer = false` arm so the
/// asymmetry comes from the HARNESS, not from a counter inside the closure — a
/// first-call-only latch would make the result depend on which test ran first
/// in the shared binary.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_one_sided_authenticator_leaves_both_sides_without_shm() {
    let init_only = establish_capability_pair(true, false, |a| {
        a.set_shm_offer(true);
        a.install_shm_auth(Box::new(
            wz_runtime_tokio::shm_auth_segment::PosixShmAuthenticator::new()
                .expect("publish an auth segment"),
        ));
    })
    .await;
    assert!(
        !init_only.init_actions.is_shm(),
        "the initiator sent a challenge and got nothing back, which proves \
         nothing about mapping — it must not negotiate SHM"
    );
    assert!(
        !init_only.resp_actions.is_shm(),
        "the responder never offered at all, so it stays off"
    );
}

/// The acceptor's side of the same asymmetry: it offers SHM the OLD way (the
/// UNIT marker, no authenticator) while the initiator speaks the real protocol.
/// The acceptor sees a ZBuf where it looks for a UNIT and clears; the initiator
/// sees a UNIT where it looks for a ZBuf echo and clears. Neither half-completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_unit_only_acceptor_does_not_half_complete_the_challenge() {
    let pair = establish_capability_pair(true, true, |a| {
        a.set_shm_offer(true);
    })
    .await;
    // Baseline: with NEITHER side authenticated, the legacy UNIT path still
    // negotiates — so the clearing below is about the mechanism mismatch, not
    // about `set_shm_offer` having stopped working.
    assert!(pair.init_actions.is_shm() && pair.resp_actions.is_shm());

    let mixed = establish_capability_pair(true, false, |a| {
        a.set_shm_offer(true);
    })
    .await;
    assert!(!mixed.init_actions.is_shm());
    assert!(!mixed.resp_actions.is_shm());
}

/// R311y516 — the RX un-swap ENFORCES the negotiation, not just the 0x2 marker.
///
/// Before R311y516 the receive path consulted `body_has_shm_marker` alone, so a
/// peer that had never negotiated SHM could name a `/dev/shm` segment and this
/// node would map it and deliver its contents: the negotiation was decorative on
/// the receive side. zenoh gates the whole un-swap on the negotiated per-transport
/// capability — `if self.config.shm.is_some() { map_zmsg_to_shmbuf(..) }`
/// (`io/zenoh-transport/src/unicast/universal/rx.rs:50-51`, the same expression
/// as its `is_shm()` at `unicast/universal/transport.rs:349-350`) — and wz now
/// carries the counterpart guard.
///
/// The two arms differ in EXACTLY ONE bit — `set_shm_negotiated`. Everything the
/// resolve needs is real and identical in both: the same live `/dev/shm` segment
/// written with the same bytes, the same installed `PosixShmResolver`, the same
/// valid descriptor, the same registered subscriber, the same Push. So the
/// NOT-negotiated arm cannot pass for a boring reason (missing segment, missing
/// resolver, malformed descriptor) — the negotiated arm proves each of those
/// preconditions holds by delivering the bytes.
#[test]
fn an_unnegotiated_peer_cannot_make_this_node_map_its_segment() {
    let data = b"the-payload-a-stranger-must-not-reach".to_vec();
    let mut payload = ShmBackedPayload::alloc(data.len()).expect("alloc /dev/shm segment");
    payload.write(&data);
    let descriptor = payload.descriptor();

    let build_push = || {
        wz_session_core::push_build::build_push_shm_literal(
            "demo/shm/enforce",
            &descriptor,
            &wz_session_core::metadata::PushMetadata::default(),
        )
        .expect("build the SHM Put")
    };

    let mut observer = ApplicationLayerObserver::new();
    observer
        .subscribers
        .set_shm_resolver(Box::new(PosixShmResolver));
    let seen: Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let seen = seen.clone();
        observer
            .subscribers
            .register("demo/shm/enforce", move |sample| {
                seen.lock().unwrap().push(sample.payload().to_vec());
            });
    }

    // ── Arm A: SHM was NOT negotiated with this peer ──────────────────────
    // The registry default is false; nothing stamps it. The segment exists and
    // the resolver is installed, so the ONLY thing standing between the peer and
    // this node's memory is the gate.
    assert!(
        !observer.subscribers.shm_negotiated(),
        "precondition: this registry has not been stamped as negotiated"
    );
    observer.subscribers.dispatch(
        &wz_session_core::network_message::NetworkMessage::Push(Box::new(build_push())),
        wz_session_core::reliability::Reliability::Reliable,
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "an un-negotiated peer's SHM descriptor must deliver NOTHING"
    );
    assert_eq!(
        observer.subscribers.shm_unnegotiated_drops(),
        1,
        "and the refusal is COUNTED, so it is observable rather than a vanished sample"
    );
    assert_eq!(
        observer.subscribers.shm_unresolved_drops(),
        0,
        "the drop is attributed to the NEGOTIATION, not to an unresolvable segment — \
         the segment is live and the resolver is installed"
    );

    // ── Arm B: same everything, negotiation ON ────────────────────────────
    // Proves Arm A measured the gate and not a broken fixture.
    observer.subscribers.set_shm_negotiated(true);
    observer.subscribers.dispatch(
        &wz_session_core::network_message::NetworkMessage::Push(Box::new(build_push())),
        wz_session_core::reliability::Reliability::Reliable,
    );
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        std::slice::from_ref(&data),
        "with SHM negotiated the SAME descriptor resolves to the owner's bytes"
    );
    assert_eq!(
        observer.subscribers.shm_unnegotiated_drops(),
        1,
        "the negotiated delivery adds no refusal"
    );
    assert_eq!(
        observer.subscribers.shm_unresolved_drops(),
        0,
        "and no resolve failed in either arm"
    );
}
