// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(feature = "transport-fragmentation")]

//! R311ni — unicast TX FRAGMENTATION end-to-end over a real loopback TCP
//! link. The complement of `layer3_reassembly_rx.rs` (which feeds
//! hand-crafted `T_MID_FRAGMENT` bytes into the dispatcher): this exercises
//! the PRODUCTION send path — `Session::publish` -> `send_network_message`
//! seam -> `SessionLinkActions::dispatch_network_message` ->
//! `emit_frame_or_fragments` (`session_actions.rs:1325`) — so an oversize
//! Put leaves the publisher node as a fragment chain on the wire, and the
//! subscriber node's steady-state drive loop reassembles it
//! (`report_outcome_reassembling`) back into one delivered Sample.
//!
//! The gap this closes (session review, R311nf): the UNICAST TX split had no
//! end-to-end proof — only codec round-trip (`frame_encode`) plus the
//! RX-ingest half (`layer3_reassembly_rx`). Its multicast counterpart is
//! `multicast_pubsub_loopback::oversize_put_fragments_and_reassembles_across_nodes`
//! (which forces a small MTU by setting `MulticastParams.batch_size` directly
//! — no handshake negotiation). This is the missing oversize real-socket
//! UNICAST send, where the MTU is NEGOTIATED, so the fragmentation
//! precondition is asserted explicitly (see `negotiated_batch_mtu` below)
//! rather than merely trusted.
//!
//! "Oversize" = a frame past a SMALL negotiated batch budget: both peers
//! advertise `batch_size = 64` in their InitSyn/InitAck, the negotiated MTU
//! is `min(own, peer) = 64`, and a 200-byte Put's frame far exceeds it. The
//! test ASSERTS the negotiated MTU is 64 before publishing (R311nj) so the
//! split is guaranteed by construction — a regression that broke negotiation
//! would fail the assert, not silently pass with a single un-fragmented
//! frame. Both sessions are driven with `max_iters = None` (continuous) so
//! the RX reassembly pool persists across the fragment chain's arrivals — a
//! chunked drive would reset it between fragments.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishError, PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/frag";
// 64-byte negotiated MTU; a 200-byte payload's Put frame exceeds it and
// fragments into a multi-chunk T_MID_FRAGMENT chain.
const BATCH_SIZE: u16 = 64;
/// R2238 — the fragment credit arm 2 of
/// [`an_exhausted_fragment_budget_abandons_the_chain_and_says_so_on_the_wire`]
/// starts with. Its only requirement is `0 < n < chain_len`, which that test
/// asserts against the encoder's own walk rather than trusting this number.
const MID_CHAIN_BUDGET: usize = 2;

/// An oversize unicast `Session::publish` fragments on TX and the peer's
/// drive loop reassembles it into exactly one delivered Sample carrying the
/// full payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unicast_oversize_put_fragments_on_tx_and_reassembles_on_rx() {
    let payload: Vec<u8> = (0..200u32).map(|i| (i * 13) as u8).collect();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // ── Open BOTH sessions concurrently (the handshake needs both sides
    //    progressing). Each side advertises batch_size = 64 so the
    //    negotiated steady-state MTU is 64.
    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4]; // distinct from the initiator
        params.batch_size = BATCH_SIZE;
        accept_and_open_session(
            DialedLink::Tcp(stream),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        params.batch_size = BATCH_SIZE;
        connect_and_open_session(
            locator,
            params,
            &DialConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    // ── Fragmentation precondition, asserted BY CONSTRUCTION (R311nj). The
    //    TX split in `emit_frame_or_fragments` branches on `frame.len() >
    //    mtu`, where `mtu = negotiated_batch_mtu() = min(own, peer)`. Pin the
    //    negotiated MTU to the tiny budget here: with MTU == 64 and a 200-byte
    //    payload (a Put frame far past 64), the publisher's `Session::publish`
    //    is FORCED through the fragment branch — without this assert the test
    //    would still pass if negotiation silently regressed to the 65535
    //    default (the 200-byte payload fits one frame within the msg_put 256-
    //    byte codec bound and would deliver as a single un-fragmented Sample,
    //    a false positive). The publisher side is the load-bearing one (it
    //    decides the split); the acceptor is asserted too for negotiation
    //    symmetry. Read before the bundles are borrowed by the drive loops.
    assert_eq!(
        opened_init.actions.negotiated_batch_mtu(),
        BATCH_SIZE as usize,
        "publisher negotiated MTU must be the tiny budget so the 200-byte Put fragments"
    );
    assert_eq!(
        opened_acc.actions.negotiated_batch_mtu(),
        BATCH_SIZE as usize,
        "acceptor negotiated the same tiny budget (symmetry)"
    );

    // ── Subscriber on the acceptor's observer.
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
                "the reassembled payload matches the oversize Put byte-for-byte"
            );
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

    // ── Publisher session over the initiator's bundle (fresh observer — the
    //    publisher has no local subscribers, so the publish loopback leg
    //    delivers nothing and the proof is entirely the remote fragment
    //    chain).
    let publisher = TokioSession::new(
        opened_init.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened_init.clock),
    );

    let timeouts = SessionTimeouts::spec_defaults();

    // Both sides driven continuously (None) so the RX reassembly pool lives
    // across the whole fragment chain. select! drops the drives when the
    // scenario observes the delivery.
    // Count the RX-observed fragment chunks so the acceptor PROVES the
    // publisher's TX actually took the split branch — `negotiated_batch_mtu()
    // == 64` alone only proves the fragmentation INPUT, not that
    // `emit_frame_or_fragments` emitted a multi-chunk chain. This catches a
    // CODE regression that collapses the split (marker / SN / chunk logic)
    // while `transport-fragmentation` is ON — the count drops to 0 (a single
    // un-fragmented send arrives as a Frame, not a Fragment) and the assert
    // fires. It does NOT guard the feature being DISABLED (this whole file is
    // `#![cfg(feature = "transport-fragmentation")]`, so it compiles out then,
    // silently absent rather than failing). It is the host-lane logic backstop
    // for the binary-dep wz->pico e2e (`wz_fragment_tx_to_pico_zsub`, R311y206),
    // whose pico-as-receiver exposes no wz-side chunk count.
    let frag_chunks = Arc::new(AtomicUsize::new(0));
    let drive_acc = {
        let frag_chunks = frag_chunks.clone();
        drive_session_until_terminal(
            &mut opened_acc.inbound,
            &opened_acc.actions,
            &mut opened_acc.engine,
            None,
            &opened_acc.clock,
            &timeouts,
            move |event| {
                if let IterationEvent::Poll(DriverLoopOutcome::Fragment { .. }) = &event {
                    frag_chunks.fetch_add(1, Ordering::SeqCst);
                }
                observer.dispatch_event(event)
            },
        )
    };
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
        // Let both drives reach the steady state, then publish once.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let delivered = publisher
            .publish(KEYEXPR, &payload, PublishOptions::put())
            .expect("oversize publish builds and routes through the send seam");
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
        "exactly one reassembled delivery from the oversize fragmented Put"
    );
    assert!(
        frag_chunks.load(Ordering::SeqCst) >= 2,
        "the publisher's oversize Put must leave TX as a multi-chunk \
         T_MID_FRAGMENT chain at MTU 64 (acceptor RX saw {} fragment chunks)",
        frag_chunks.load(Ordering::SeqCst)
    );
}

/// R2238 (open-debt item 580) — a FINITE fragment TX budget makes "the sender
/// abandoned this chain" a REACHABLE state, and the abandon is announced on
/// the wire with the `0x3 Drop` marker.
///
/// ## What was missing, and why the budget is the fix rather than the marker
///
/// wz's encoder could spell the marker since R311y578
/// (`extfragment::encode_fragment_drop_ext`) and its receiver has honoured it
/// just as long (`reassembly_dispatch`, `AbortReason::SenderDropped`) — but
/// nothing ever EMITTED one, because there was no state to emit it from:
/// `frame_encode::fragment_body` built the whole chain before a byte left, and
/// every link writer takes an unbounded channel, so "some fragments went and
/// the rest cannot" could not occur. Adding a caller would have been adding a
/// caller to a branch that never runs. The finite budget is what creates the
/// state; this leg is what proves the state is reached.
///
/// ## Four arms on ONE session, and the chain length is DERIVED, not assumed
///
/// All four publish the SAME oversize payload through the SAME session and
/// differ only in the budget standing when they run:
///
///   A. budget 0 — exhausted BEFORE the first fragment. Upstream's equivalent
///      arm writes nothing at all (`common/pipeline.rs`, the
///      `ext_first.is_some()` branch), and so must this one: a chain that
///      never started cannot be abandoned, so announcing one would be a lie
///      about a peer state that does not exist;
///   B. budget unbounded — a CONTROL, and the barrier that closes arm A;
///   C. budget 2 — exhausted MID-chain. Two fragments go, then the stop
///      fragment, and the acceptor's reassembler aborts the chain;
///   D. budget unbounded — the second CONTROL, and the barrier that closes C.
///
/// ⚠ The two controls are what let arm A's SILENCE be derived rather than
/// asserted against a number. A first attempt at this leg computed the chain
/// length from `FragmentChain` over the PAYLOAD and compared the total
/// against it — and was wrong by exactly one fragment, because what
/// fragments is the Push's network-message body, envelope included, not the
/// payload. So no literal is trusted here: with `L` the (unknown) chain
/// length, arm B contributes `a + L` fragments where `a` is whatever arm A
/// emitted, and arms C+D contribute `(2 + 1) + L`. Asserting those two
/// counts differ by exactly `2 + 1` says `a == 0` WITHOUT either side
/// knowing `L`, and a regression that made arm A emit anything moves the
/// difference.
///
/// Each control's delivery is the barrier its counts are read behind: it can
/// only fire after the preceding arm has been fully processed by the same
/// single RX loop, so every total is read at a determined point rather than
/// after a sleep. That is also why the exhaustion is driven by BUDGET and not
/// by time — nothing here waits for a deadline to lapse, and the arm
/// boundaries are counts, not instants.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exhausted_fragment_budget_abandons_the_chain_and_says_so_on_the_wire() {
    let payload: Vec<u8> = (0..200u32).map(|i| (i * 13) as u8).collect();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        params.batch_size = BATCH_SIZE;
        accept_and_open_session(
            DialedLink::Tcp(stream),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        params.batch_size = BATCH_SIZE;
        connect_and_open_session(
            locator,
            params,
            &DialConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    // The same by-construction fragmentation precondition the leg above
    // asserts: at MTU 64 a 200-byte Put cannot travel as one frame.
    assert_eq!(
        opened_init.actions.negotiated_batch_mtu(),
        BATCH_SIZE as usize,
        "publisher negotiated MTU must be the tiny budget so the Put fragments"
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
                "the control arm's payload arrives byte-for-byte"
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

    // Two counters over the acceptor's RX: every fragment it sees, and the
    // subset carrying the abandon marker. `DriverLoopOutcome::Fragment`
    // carries the projected markers, so this reads what ARRIVED on the wire
    // rather than what the publisher believes it sent.
    let frag_chunks = Arc::new(AtomicUsize::new(0));
    let drop_marked = Arc::new(AtomicUsize::new(0));
    let drive_acc = {
        let frag_chunks = frag_chunks.clone();
        let drop_marked = drop_marked.clone();
        drive_session_until_terminal(
            &mut opened_acc.inbound,
            &opened_acc.actions,
            &mut opened_acc.engine,
            None,
            &opened_acc.clock,
            &timeouts,
            move |event| {
                if let IterationEvent::Poll(DriverLoopOutcome::Fragment { markers, .. }) = &event {
                    frag_chunks.fetch_add(1, Ordering::SeqCst);
                    if markers.dropped {
                        drop_marked.fetch_add(1, Ordering::SeqCst);
                    }
                }
                observer.dispatch_event(event)
            },
        )
    };
    let drive_init = drive_session_until_terminal(
        &mut opened_init.inbound,
        &opened_init.actions,
        &mut opened_init.engine,
        None,
        &opened_init.clock,
        &timeouts,
        |_| {},
    );

    // Fragments counted at each control's delivery barrier: `after_b` closes
    // arm A, `after_d` closes arm C.
    let after_b = Arc::new(AtomicUsize::new(0));
    let after_d = Arc::new(AtomicUsize::new(0));

    let fired_probe = fired.clone();
    let frag_seen = frag_chunks.clone();
    let after_b_w = after_b.clone();
    let after_d_w = after_d.clone();
    let actions = opened_init.actions.clone();
    let scenario = async move {
        // Wait for the subscriber to have fired `n` times, then report the
        // fragment count AT that point. The barrier is a delivery, not a
        // duration; the sleep only yields between polls.
        async fn barrier(
            fired: &Arc<AtomicUsize>,
            frags: &Arc<AtomicUsize>,
            n: usize,
            what: &str,
        ) -> usize {
            for _ in 0..200 {
                if fired.load(Ordering::SeqCst) >= n {
                    return frags.load(Ordering::SeqCst);
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
            panic!(
                "{what} never delivered ({} fragments seen)",
                frags.load(Ordering::SeqCst)
            );
        }

        tokio::time::sleep(Duration::from_millis(300)).await;

        // ── Arm A: budget 0, exhausted before the first fragment.
        actions.set_fragment_tx_budget(0);
        let arm_a = publisher.publish(KEYEXPR, &payload, PublishOptions::put());
        assert!(
            matches!(arm_a, Err(PublishError::FragmentChainAbandoned)),
            "a publish with no fragment credit is refused, and NOT as \
             ExceedsCapacity (which claims no wire bytes AND a permanent \
             condition); got {arm_a:?}"
        );
        assert_eq!(
            actions.fragment_tx_budget(),
            0,
            "a chain refused before its first fragment draws no credit"
        );

        // ── Arm B: control + barrier. Everything arm A emitted (if anything)
        //    has reached the acceptor once this delivers.
        actions.set_fragment_tx_budget(usize::MAX);
        let delivered = publisher
            .publish(KEYEXPR, &payload, PublishOptions::put())
            .expect("with credit available the same publish succeeds");
        assert_eq!(delivered, 0, "no local subscriber on the publisher side");
        after_b_w.store(
            barrier(&fired_probe, &frag_seen, 1, "control arm B").await,
            Ordering::SeqCst,
        );

        // ── Arm C: budget 2, exhausted mid-chain.
        actions.set_fragment_tx_budget(MID_CHAIN_BUDGET);
        let arm_c = publisher.publish(KEYEXPR, &payload, PublishOptions::put());
        assert!(
            matches!(arm_c, Err(PublishError::FragmentChainAbandoned)),
            "the chain outruns its budget and is abandoned; got {arm_c:?}"
        );
        assert_eq!(
            actions.fragment_tx_budget(),
            0,
            "the chain spent every credit it had — and the stop fragment spent \
             none, being the abandon notice rather than chain payload"
        );

        // ── Arm D: the second control + barrier.
        actions.set_fragment_tx_budget(usize::MAX);
        publisher
            .publish(KEYEXPR, &payload, PublishOptions::put())
            .expect("the budget refills and the same publish succeeds again");
        after_d_w.store(
            barrier(&fired_probe, &frag_seen, 2, "control arm D").await,
            Ordering::SeqCst,
        );
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_init => panic!("initiator drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    let b = after_b.load(Ordering::SeqCst);
    let d = after_d.load(Ordering::SeqCst);

    assert_eq!(
        fired.load(Ordering::SeqCst),
        2,
        "exactly TWO deliveries, both controls'. The two abandoned chains \
         must not deliver"
    );
    assert_eq!(
        drop_marked.load(Ordering::SeqCst),
        1,
        "exactly ONE stop fragment reached the peer — arm C's. Arm A abandoned \
         nothing (no chain had started) and the controls abandoned nothing \
         (they had credit), so a second marker would mean the marker is not \
         attributable to mid-chain exhaustion"
    );
    // `b == a + L` and `d - b == (MID + 1) + L`, so this equality holds iff
    // `a == 0` — arm A put NOTHING on the wire — and it never names `L`.
    assert_eq!(
        d - b,
        b + MID_CHAIN_BUDGET + 1,
        "arm A must emit NOTHING: control B carried {b} fragments and arms C+D \
         carried {} — the difference is arm A's silence plus arm C's \
         {MID_CHAIN_BUDGET} paid fragments and its one stop fragment",
        d - b
    );
    assert!(
        b > MID_CHAIN_BUDGET,
        "arm C's budget ({MID_CHAIN_BUDGET}) must stop the chain ({b} fragments) \
         PART-WAY — a budget at or past the chain length would exhaust after the \
         last fragment, where there is nothing left to abandon"
    );
}
