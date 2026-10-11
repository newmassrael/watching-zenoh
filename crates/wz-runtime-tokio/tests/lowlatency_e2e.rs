// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-lowlatency",
    feature = "transport-unicast",
    feature = "transport-link-tcp"
))]

//! wz<->wz lowlatency transport end to end — the negotiated lean data path.
//!
//! The wz mirror of zenoh's lowlatency unicast transport
//! (`init.rs:162 zextunit!(0x5,false)`): both peers OFFER the Z_EXT_LOWLATENCY
//! unit ext on InitSyn / InitAck, the `&=` merge agrees, and the established
//! session drops the Frame(sn) wrapper + fragmentation, serializing the bare
//! NetworkMessage directly (zenoh `TransportMessageLowLatencyRef::Network`).
//!
//! Two complementary proofs:
//!
//!   1. `lowlatency_negotiates_and_delivers_put_over_real_tcp` — the end-to-end
//!      proof over a real TCP loopback. Both sides reach Established with
//!      `is_lowlatency()` true, and a `Put` is delivered byte-exact. Since the
//!      tx seam is `if is_lowlatency() { lean; return }`, a true flag FORCES the
//!      lean wire; and a lean Put (leading id 0x1D, not a Frame) would tear the
//!      peer down on the universal path — so a successful delivery with the flag
//!      asserted proves BOTH the lean tx AND the lean rx engaged.
//!   2. `lowlatency_put_rides_a_bare_network_message_not_a_frame` — the
//!      deterministic, socket-free distinguishing proof: drive the handshake
//!      over recording drivers, publish, and inspect the captured wire. With
//!      lowlatency the Put's leading id is `N_MID_PUSH` (0x1D, a bare network
//!      message); the no-offer CONTROL wraps it in `T_MID_FRAME` (0x05). Plus
//!      the negotiation `&=`: a one-sided offer leaves BOTH sides universal.
//!
//! ## Non-flakiness
//!
//! Test 1 is a handful of in-order, loss-free datagrams on 127.0.0.1 (TCP
//! retransmits); both sides drive continuously until the delivery is observed,
//! bounded by a ~3s probe budget. Test 2 touches no socket and no clock — it is
//! a deterministic feed of each side's captured bytes into the other.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use wz_codecs::wire_const;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::{drive_session_until_terminal, SessionLinkActions};
use wz_runtime_tokio::session_open::{
    accept_and_open_session_with_lowlatency, connect_and_open_session_with_lowlatency, DialConfig,
    DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::{
    establish_capability_pair, fixture_params_with_zid, LifecycleRecordingDriver,
};
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/lowlatency";

/// The most recent outbound frame the recording driver captured.
fn last_send(driver: &LifecycleRecordingDriver) -> Vec<u8> {
    driver
        .snapshot()
        .sends
        .last()
        .expect("a send was recorded")
        .0
        .clone()
}

/// Test 1 — two wz nodes handshake over a loopback TCP link, BOTH offering
/// lowlatency, reach Established with the capability negotiated on, and a `Put`
/// published on the initiator is delivered byte-exact to a subscriber on the
/// acceptor — over the lean (no-Frame) wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lowlatency_negotiates_and_delivers_put_over_real_tcp() {
    let payload = b"lean-no-frame-hello".to_vec();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // ── Open BOTH sessions concurrently, each offering lowlatency.
    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept tcp peer");
        accept_and_open_session_with_lowlatency(
            DialedLink::Tcp(stream),
            fixture_params_with_zid(0x02),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established with lowlatency offered")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        let cfg = DialConfig::default();
        connect_and_open_session_with_lowlatency(
            locator,
            fixture_params_with_zid(0x01),
            &cfg,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established with lowlatency offered")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    // The negotiation succeeded on BOTH sides (the `&=` of two true offers).
    assert!(
        opened_init.actions.is_lowlatency(),
        "initiator negotiated lowlatency on"
    );
    assert!(
        opened_acc.actions.is_lowlatency(),
        "acceptor negotiated lowlatency on"
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
                "the payload delivered over the lean wire matches the Put byte-for-byte"
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
        tokio::time::sleep(Duration::from_millis(200)).await;
        let delivered = publisher
            .publish(KEYEXPR, &payload, PublishOptions::put())
            .expect("lowlatency publish builds and routes through the lean send seam");
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
        "exactly one delivery from the Put over the lean lowlatency wire"
    );
}

/// Publish a Put on `actions` and return its captured outbound wire bytes.
fn publish_and_capture(
    actions: &Arc<SessionLinkActions>,
    driver: &LifecycleRecordingDriver,
) -> Vec<u8> {
    let session = TokioSession::new(
        actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(TokioTime::new()),
    );
    session
        .publish(KEYEXPR, b"payload", PublishOptions::put())
        .expect("publish on an established session");
    last_send(driver)
}

/// Test 2 — the distinguishing wire-form proof. With lowlatency negotiated, the
/// Put's leading message id is a BARE NetworkMessage (`N_MID_PUSH`); without the
/// offer, the same Put is wrapped in a `T_MID_FRAME`. Plus the negotiation `&=`:
/// a one-sided offer leaves BOTH sides universal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lowlatency_put_rides_a_bare_network_message_not_a_frame() {
    let offer = |a: &Arc<SessionLinkActions>| {
        a.set_lowlatency_offer(true);
    };

    // Both offer -> negotiated on -> lean Put (leading id N_MID_PUSH, no Frame).
    let both = establish_capability_pair(true, true, offer).await;
    assert!(
        both.init_actions.is_lowlatency(),
        "initiator negotiated lowlatency on"
    );
    assert!(
        both.resp_actions.is_lowlatency(),
        "acceptor negotiated lowlatency on"
    );
    let lean = publish_and_capture(&both.init_actions, &both.init_driver);
    assert_eq!(
        lean[0] & 0x1F,
        wire_const::N_MID_PUSH,
        "the lowlatency Put rides a bare NetworkMessage (N_MID_PUSH), NO Frame wrapper"
    );

    // CONTROL: neither offers -> universal -> the Put is Frame-wrapped.
    let none = establish_capability_pair(false, false, offer).await;
    assert!(
        !none.init_actions.is_lowlatency(),
        "initiator stays universal"
    );
    assert!(
        !none.resp_actions.is_lowlatency(),
        "acceptor stays universal"
    );
    let framed = publish_and_capture(&none.init_actions, &none.init_driver);
    assert_eq!(
        framed[0] & 0x1F,
        wire_const::T_MID_FRAME,
        "without lowlatency the Put is wrapped in a T_MID_FRAME (the universal path)"
    );

    // NEGOTIATION `&=`: only the initiator offers -> the responder never
    // reflects, so BOTH finalize universal (zenoh `is_lowlatency &= other`).
    let one = establish_capability_pair(true, false, offer).await;
    assert!(
        !one.init_actions.is_lowlatency(),
        "a one-sided offer leaves the initiator universal (peer did not reflect)"
    );
    assert!(
        !one.resp_actions.is_lowlatency(),
        "the responder never offered, so it stays universal"
    );
}

/// Counts the allocations made BY THE CURRENT THREAD, so the parallel tests of
/// this binary (each on its own runtime) cannot move each other's numbers.
struct CountingAllocator;

thread_local! {
    static ALLOCATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

// SAFETY: every call forwards to `System` unchanged; the only addition is a
// thread-local counter bump, which neither allocates nor unwinds.
unsafe impl std::alloc::GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { std::alloc::System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { std::alloc::System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn allocations_during<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let before = ALLOCATIONS.with(std::cell::Cell::get);
    let out = f();
    (out, ALLOCATIONS.with(std::cell::Cell::get) - before)
}

/// Test 3 — runtime-zero-copy B3: a lean lowlatency unit is read WHERE IT LIES
/// by the in-place receive path (`wz_session_core::drive::dispatch_datagram`,
/// the MCU loop's under `rx-in-place`), as a `Frame`'s payload is: a Push is
/// lent as an `IterationEvent::InPlace`, any other record arrives as a
/// `Poll(FramePayload)` of the one message, and nothing about the unit is
/// copied. Before, a lean unit took the copying path whole (copied onto the
/// heap, decoded into a list of owned messages).
///
/// Measured on the established acceptor of a lowlatency pair, under a counting
/// allocator, against the copying path's dispatch of the same bytes (the
/// control: it must SEE the copies). And byte for byte: each record handed over
/// in place is the record the copying decode reads out of the same unit. The
/// generic in-place path runs here over the AP runtime because no MCU crate
/// forwards `transport-lowlatency`; the function is the one the MCU pump calls.
///
/// The zero-heap claim is the claim of a build WITHOUT `transport-stats`: the
/// counters classify a record by reading its owned message, so a build that has
/// them hands every Put over owned (three allocations for one Put: its key
/// expression, its payload and the owned message itself) and the test then
/// asserts what that build promises instead, that nothing it read went
/// uncounted. The lowlatency lane builds without the counters and runs the
/// zero-heap arm; the lane that turns every feature on runs the counting arm.
#[tokio::test(flavor = "current_thread")]
async fn a_lean_unit_is_read_in_place_and_handed_over_as_the_copying_path_reads_it() {
    use wz_session_core::drive::{dispatch_datagram, dispatch_link_event, DatagramPath};
    use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
    use wz_session_core::link::{LinkEvent, RxFrame};
    use wz_session_core::network_message::NetworkMessage;

    let pair = establish_capability_pair(true, true, |a: &Arc<SessionLinkActions>| {
        a.set_lowlatency_offer(true);
    })
    .await;
    let actions = pair.resp_actions;
    assert!(actions.is_lowlatency() && actions.is_established());
    let mut engine = wz_runtime_tokio::session_glue::new_session_engine(&actions);
    let mut record: Vec<NetworkMessage> = Vec::with_capacity(1);

    let push = |payload: &[u8]| {
        wz_session_core::push_build::build_push_literal(KEYEXPR, payload)
            .expect("a literal Put")
            .try_as_borrowed()
            .expect("a borrowed view")
            .encode_to_vec()
    };
    let oam = wz_codecs::oam::Oam {
        id: 7,
        ..Default::default()
    }
    .encode_to_vec();
    let one_put = push(b"lean");
    let two_puts = [push(b"one"), push(b"two")].concat();
    let put_then_oam = [push(b"three"), oam.clone()].concat();

    for unit in [&one_put, &two_puts, &put_then_oam] {
        // What the copying lean path decodes out of the same unit.
        let copied = dispatch_link_event(
            LinkEvent::Rx(RxFrame::new(unit.clone())),
            &actions,
            &mut engine,
        );
        let DriverLoopOutcome::FramePayload { messages, .. } = &copied else {
            panic!("the copying lean path reads a batch: {copied:?}");
        };
        let expected: Vec<Vec<u8>> = messages.iter().map(record_bytes).collect();
        let puts = messages
            .iter()
            .filter(|message| matches!(message, NetworkMessage::Push(_)))
            .count();

        // In place, with an observer that keeps nothing: what the path costs.
        let mut handed = 0usize;
        let mut lent_puts = 0usize;
        #[cfg(feature = "transport-stats")]
        let counted_before = actions.stats.report().rx.n_msgs_total();
        let (path, in_place_cost) = allocations_during(|| {
            dispatch_datagram(
                unit,
                &actions,
                &mut engine,
                &mut record,
                &mut |event| match event {
                    IterationEvent::InPlace(_) => {
                        handed += 1;
                        lent_puts += 1;
                    }
                    IterationEvent::Poll(_) => handed += 1,
                    _ => {}
                },
            )
        });
        assert_eq!(path, DatagramPath::LowLatencyInPlace);
        assert_eq!(handed, expected.len(), "one event per record");

        // What this build does with a Put is the build's own rule, and the test
        // states it from both sides: a build without `transport-stats` lends
        // every Put where it lies and that costs the heap nothing; a build with
        // it keeps the owned form, because its counters classify the owned
        // message (`RECORD_FORM` in the session core's drive module), so it
        // lends none and must have counted every record it read.
        if cfg!(feature = "transport-stats") {
            assert_eq!(lent_puts, 0, "a counting build hands its Puts over owned");
            #[cfg(feature = "transport-stats")]
            assert_eq!(
                actions.stats.report().rx.n_msgs_total() - counted_before,
                expected.len(),
                "a counting build counts each record it reads in place"
            );
        } else {
            assert_eq!(lent_puts, puts, "every Put is lent where it lies");
            if puts == expected.len() {
                assert_eq!(
                    in_place_cost, 0,
                    "a lean unit of Puts read in place costs the heap nothing"
                );
            }
        }

        // The copying control sees what in place does not make.
        let (_, copied_cost) = allocations_during(|| {
            dispatch_link_event(
                LinkEvent::Rx(RxFrame::new(unit.clone())),
                &actions,
                &mut engine,
            )
        });
        assert!(copied_cost > 0, "the control sees the copying path's heap");
        if !cfg!(feature = "transport-stats") {
            assert!(
                copied_cost > in_place_cost,
                "copying {copied_cost} against in place {in_place_cost}"
            );
        }

        // Byte for byte, in wire order.
        let mut got: Vec<Vec<u8>> = Vec::new();
        dispatch_datagram(
            unit,
            &actions,
            &mut engine,
            &mut record,
            &mut |event| match event {
                IterationEvent::InPlace(lent) => got.push(
                    lent.push()
                        .expect("only Puts and an OAM were encoded")
                        .encode_to_vec(),
                ),
                IterationEvent::Poll(DriverLoopOutcome::FramePayload {
                    messages,
                    reliable,
                    sn,
                    has_ext,
                    ..
                }) => {
                    assert_eq!((*reliable, *sn, *has_ext), (true, 0, false));
                    got.extend(messages.iter().map(record_bytes));
                }
                other => panic!("only records are reported: {other:?}"),
            },
        );
        assert_eq!(got, expected, "the records the copying decode reads");
    }

    // A KeepAlive is not a lean batch: the copying path decodes it.
    let keep_alive = [wire_const::T_MID_KEEP_ALIVE];
    let path = dispatch_datagram(&keep_alive, &actions, &mut engine, &mut record, &mut |_| {});
    assert_eq!(
        path,
        DatagramPath::Copied(wz_session_core::drive::CopyReason::NotAFrame)
    );
}

/// A decoded record's wire bytes: what both paths are compared by.
fn record_bytes(message: &wz_session_core::network_message::NetworkMessage) -> Vec<u8> {
    use wz_session_core::network_message::NetworkMessage;
    match message {
        NetworkMessage::Push(push) => push
            .try_as_borrowed()
            .expect("a borrowed view")
            .encode_to_vec(),
        NetworkMessage::Oam(oam) => oam
            .try_as_borrowed()
            .expect("a borrowed view")
            .encode_to_vec(),
        other => panic!("only Puts and an OAM were encoded: {other:?}"),
    }
}
