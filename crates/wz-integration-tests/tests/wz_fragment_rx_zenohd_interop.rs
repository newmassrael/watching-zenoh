// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y439 — FOREIGN-INTEROP unicast fragmentation in the RECEIVE direction: a
//! real `zenohd` splits a routed `Put` into a `T_MID_FRAGMENT` chain sized to a
//! tiny negotiated batch, and watching-zenoh reassembles it into one byte-exact
//! `Sample` delivered to a routed subscriber.
//!
//! ## The gap this closes
//!
//! R311y438 gave `transport-fragmentation` its first zenohd witness, in the
//! wz -> zenohd direction only, and said so in its own carry: "STILL OPEN: the
//! zenohd -> wz fragmentation direction. The tiny MTU binds BOTH ways, so
//! zenohd's own outbound to wz is fragmented and wz's RX reassembly is in fact
//! exercised by this leg — but nothing asserts it, so no claim is made."
//! This leg makes the claim and asserts it.
//!
//! What was already proven is the pico sender: `wz_reassembles_pico_fragment_tx`
//! has a zenoh-pico `z_put` fragmenting into a wz ACCEPTOR. Both senders split
//! at the NEGOTIATED batch — pico sizes its tx wbuf to
//! `min(link_mtu, negotiated_batch)`
//! (`vendor/zenoh-pico/src/transport/unicast/transport.c:47`), zenohd min-
//! negotiates the same way — so the difference is the IMPLEMENTATION and the
//! TOPOLOGY, not the trigger. pico's is a fixed-capacity C wbuf on a direct
//! peer link; zenohd's is the full Rust pipeline
//! (`io/zenoh-transport/src/common/pipeline.rs:383-433` at zenoh 1.5.0)
//! splitting a message it is ROUTING onward, for a link whose MTU is smaller
//! than the one the message came in on. The north star is the superset of both
//! senders, so both need a witness.
//!
//! ## Topology
//!
//! ```text
//!   pico z_pub ──tcp──> zenohd ──tcp──> [counting relay] ──tcp──> wz
//!                          (splits to MTU 64)   ^ counts             (reassembles,
//!                                               T_MID_FRAGMENT        delivers Sample)
//!                                               zenohd -> wz
//! ```
//!
//! wz is the DIALER (via the relay) and declares a ROUTED subscriber, so zenohd
//! forwards pico's matching Put back down the wz link — the reverse data plane
//! `wz_to_zenohd_router::wz_routed_subscribe_from_zenohd` proves at the default
//! batch. The delta here is the same one R311y438 introduced: wz advertises
//! `batch_size = 64`, zenohd's acceptor min-negotiates to it
//! (`io/zenoh-transport/src/unicast/establishment/accept.rs:220-224`), and the
//! routed Put no longer fits in one batch.
//!
//! ## Two independent halves, and why the pair is the proof
//!
//!   * the RELAY, which is OUTSIDE wz, says zenohd put >= 2 FRAGMENT-tagged
//!     batches on the wire. Note the authorship compared to R311y438: there the
//!     tag was produced by wz and merely recognised by wz's own `wire_const`,
//!     so the relay alone proved self-consistency. Here it is authored by
//!     zenohd — a foreign implementation that owes wz nothing — and wz's
//!     constant only recognises it. That is a stronger statement about the TAG;
//!     it is a weaker one about wz, because in this direction the chain is a
//!     PRECONDITION for the behaviour under test rather than the behaviour
//!     itself.
//!   * WZ's own driver loop reports `DriverLoopOutcome::Fragment` at least
//!     twice, and the subscriber receives the whole 200-byte payload
//!     byte-exact. The byte-exact delivery is the completion witness: it is the
//!     only assertion here that cannot hold unless reassembly actually
//!     finished and re-parsed.
//!
//! Neither half is the proof. Drop the first and a wz that received one
//! oversize frame and delivered it would pass what remains — nothing would
//! attribute the delivery to a chain. Drop the second and a wz that logged the
//! chain but mis-assembled it (truncated, reordered, or never completing)
//! would pass, because a relay sees bytes, not whether the receiver rebuilt a
//! message from them. R311y439 measured that dependency rather than arguing
//! it: suppressing the reassembly-completion dispatch in
//! `wz-session-core/src/drive.rs` leaves both fragment counts intact and takes
//! deliveries to zero, while the twin below stays green.
//!
//! ## The option-atom PAIR
//!
//! Both legs run the SAME helper against the SAME stock zenohd with the SAME
//! publisher, differing in ONE field — `SessionInitParams::batch_size`:
//!
//!   1. the PROOF (`batch_size = 64`). Negotiated MTU 64, so zenohd MUST split
//!      the routed Put. Asserts MTU == 64, relay count >= 2, wz RX fragment
//!      count >= 2 with a terminator, and byte-exact delivery.
//!   2. the TWIN (`batch_size` left at the interop default). The negotiated MTU
//!      lands far above the payload, the same Put crosses as one frame, BOTH
//!      counters read zero — and the Sample still arrives. This is what makes
//!      leg 1's delivery attributable to reassembly rather than to "wz can
//!      subscribe through zenohd at all", and it is simultaneously the
//!      calibration that forbids reading either count as a constant.
//!
//! ## The payload, and the foreign example's shape
//!
//! pico's `z_pub` publishes `sprintf(buf, "[%4d] %s", idx, value)` into a
//! `char buf[256]` (`vendor/zenoh-pico/examples/unix/c11/z_pub.c:95-98`), so
//! what arrives is a 7-byte counter prefix followed by the value verbatim. The
//! assertions are written to that shape: the delivered payload must END WITH
//! the whole 200-byte value (in order — the value is [`frag_payload`], whose
//! coprime stride means a chunk reorder, duplicate or drop could not survive
//! byte-equality), and its LENGTH must equal the prefix plus that value, which
//! `ends_with` alone would not catch if reassembly duplicated a leading chunk.
//! pico is VENDORED in-repo, so that format cannot drift under this test
//! without a deliberate vendor bump. The same buffer is the ceiling on any
//! future enlargement of `PAYLOAD_LEN`: with the 7-byte prefix and the NUL,
//! 248 bytes of value is the largest that still FITS `buf[256]`, and 249
//! overflows it.
//!
//! Opt-in (`#[ignore]`, run-ci Layer Z): zenohd + the pico z_pub CLI are
//! external binaries. The test NAME carries `zenohd` because Layer E's skip
//! filter is a name substring (`--skip zenohd`) — a zenohd leg whose name lacks
//! the token gets pulled into the default sweep alone and reddens there
//! (R311y437).

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

use wz_codecs::wire_const::T_MID_FRAGMENT;
use wz_integration_tests::common::{
    frag_payload, spawn_counting_relay, spawn_publishing_zpub, spawn_zenohd_on_ephemeral_tcp,
    zenoh_pico_cli_binary, RelayFault,
};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{SubscribeOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{initiate_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::zenohd_interop_session_init_params;
use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
/// What pico publishes on; matched by [`SUB_KEYEXPR`], the filter wz declares.
const PUBLISH_KEYEXPR: &str = "demo/frag-rx";
const SUB_KEYEXPR: &str = "demo/**";
/// The tiny advertised batch. zenohd min-negotiates to it, so the routed Put
/// must fragment on its way to wz.
const TINY_BATCH: u16 = 64;
/// 200 B > 64 B MTU, and 200 + [`PICO_ZPUB_PREFIX_LEN`] is comfortably inside
/// the foreign example's 256-byte stack buffer.
const PAYLOAD_LEN: usize = 200;
/// `"[%4d] "` — the counter pico's `z_pub` example prepends to every value
/// (`vendor/zenoh-pico/examples/unix/c11/z_pub.c:98`). Exactly 7 bytes while
/// the index is under 10000, which the publisher's `-n 30` guarantees.
const PICO_ZPUB_PREFIX_LEN: usize = 7;

/// What one arm of the pair observed.
struct ArmOutcome {
    negotiated_mtu: usize,
    /// `T_MID_FRAGMENT`-tagged batches the relay saw going zenohd -> wz.
    fragments_on_wire: usize,
    /// `DriverLoopOutcome::Fragment` events wz's own RX drive loop reported.
    rx_fragments: usize,
    /// Of those, the ones carrying `more == false`: a terminating fragment was
    /// decoded and SN-admitted, so zenohd sent a COMPLETE chain rather than
    /// trailing off. It does NOT witness that reassembly completed — the event
    /// is emitted before `ingest` runs (`wz-session-core/src/drive.rs:712` vs
    /// `:786`), so an ingest that then aborts on capacity, quota or pool
    /// exhaustion still increments this. Completion is witnessed by the
    /// byte-exact delivery, and only by it.
    rx_chain_finals: usize,
    /// `IterationEvent::ReassemblyDropped` events — an ingest that aborted or
    /// was refused. The negative witness for the step `rx_chain_finals` is
    /// emitted too early to see; must be zero.
    rx_reassembly_drops: usize,
    deliveries: usize,
    /// Every delivered Sample ended with the whole published value and carried
    /// exactly prefix + value bytes.
    byte_exact: bool,
    delivery: Result<(), String>,
}

/// Drive one arm of the pair: stock zenohd, a wz routed subscriber that dials
/// THROUGH the counting relay with `batch_size`, and a pico `z_pub` publishing
/// an oversize value into the router.
///
/// Shared by both legs so the ONLY difference between them is that one
/// argument — the twin is a twin by construction, not by parallel maintenance
/// of two copies.
async fn subscribe_through_zenohd_with_batch(batch_size: Option<u16>) -> ArmOutcome {
    let value = frag_payload(PAYLOAD_LEN);
    let z_pub = zenoh_pico_cli_binary("z_pub");

    let (mut zenohd, zenohd_port) = spawn_zenohd_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    let relay = spawn_counting_relay(zenohd_port, T_MID_FRAGMENT, RelayFault::None);

    // The zenohd-STRICT open shape (version 0x09 / real batch_size / res 2).
    // The wz<->wz `fixture_session_init_params` shape (version 0x05 /
    // batch_size 0) is rejected by a real zenohd at InitSyn — the same reason
    // `wz_zenohd_storage_replication.rs:232-234` records for its own dial.
    let mut params = zenohd_interop_session_init_params();
    if let Some(batch) = batch_size {
        params.batch_size = batch;
    }
    let stream = TcpStream::connect(("127.0.0.1", relay.port()))
        .await
        .expect("wz dials the fragment-counting relay");
    let opened = initiate_and_open_session(
        DialedLink::Tcp(stream),
        params,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await;

    let mut opened = match opened {
        Ok(opened) => opened,
        Err(e) => {
            let _ = zenohd.child_mut().kill();
            let _ = zenohd.child_mut().wait();
            panic!("wz did not reach Established against zenohd through the relay: {e:?}");
        }
    };
    let negotiated_mtu = opened.actions.negotiated_batch_mtu();

    let session = TokioSession::new(
        opened.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened.clock),
    );

    let deliveries = Arc::new(AtomicUsize::new(0));
    let byte_exact = Arc::new(AtomicBool::new(true));
    // Bound to a named `_subscriber` (NOT `_`) so the RAII handle stays alive
    // through the drive; a `_`-drop would emit `Declare(UndeclSubscriber)` and
    // withdraw the route from zenohd before pico publishes.
    let _subscriber = {
        let deliveries = Arc::clone(&deliveries);
        let byte_exact = Arc::clone(&byte_exact);
        let expected = value.clone().into_bytes();
        session
            .declare_subscriber(SUB_KEYEXPR, SubscribeOptions::default(), move |sample| {
                let payload = sample.payload();
                let whole_value_in_order = payload.ends_with(&expected[..]);
                let nothing_extra = payload.len() == PICO_ZPUB_PREFIX_LEN + expected.len();
                // The prefix bytes are checked too, or the leading
                // PICO_ZPUB_PREFIX_LEN bytes of every reassembled Sample would
                // go uninspected — damage confined to the first chunk would
                // pass the tail equality and the length pin together.
                let prefix_intact = payload.first() == Some(&b'[')
                    && payload.get(PICO_ZPUB_PREFIX_LEN - 1) == Some(&b' ');
                // The wildcard the subscriber declared has to resolve to the
                // key pico published on; a Sample routed under some other
                // keyexpr is not this leg's evidence.
                let keyexpr_ok = sample.keyexpr() == PUBLISH_KEYEXPR;
                if !(whole_value_in_order && nothing_extra && prefix_intact && keyexpr_ok) {
                    byte_exact.store(false, Ordering::SeqCst);
                }
                deliveries.fetch_add(1, Ordering::SeqCst);
            })
            .expect("wz declares the routed subscriber (emits Declare(DeclSubscriber))")
    };

    // RX-side observation on wz's OWN drive loop — the half the relay
    // structurally cannot make. Three separate signals, because the obvious one
    // is not the one that means completion:
    //   - rx_fragments: the reassembly branch was entered at all.
    //   - rx_chain_finals: a `more == false` fragment was decoded and
    //     SN-admitted, i.e. zenohd sent a COMPLETE chain. It is emitted before
    //     `ingest` runs (`drive.rs:712` vs `:786`), so it does NOT witness that
    //     wz finished reassembling.
    //   - rx_reassembly_drops: `IterationEvent::ReassemblyDropped`
    //     (`drive.rs:794`) — the abort/refusal surface an ingest takes when a
    //     chain is out of order, over capacity, or past a pool quota. THIS is
    //     the honest negative witness for the step the terminator count cannot
    //     see, and it must stay at zero.
    let rx_fragments = Arc::new(AtomicUsize::new(0));
    let rx_chain_finals = Arc::new(AtomicUsize::new(0));
    let rx_reassembly_drops = Arc::new(AtomicUsize::new(0));
    let timeouts = SessionTimeouts::spec_defaults();
    let drive = {
        let rx_fragments = Arc::clone(&rx_fragments);
        let rx_chain_finals = Arc::clone(&rx_chain_finals);
        let rx_reassembly_drops = Arc::clone(&rx_reassembly_drops);
        let session_drive = session.clone();
        drive_session_until_terminal(
            &mut opened.inbound,
            &opened.actions,
            &mut opened.engine,
            None,
            &opened.clock,
            &timeouts,
            move |event| {
                match &event {
                    IterationEvent::Poll(DriverLoopOutcome::Fragment { more, .. }) => {
                        rx_fragments.fetch_add(1, Ordering::SeqCst);
                        if !more {
                            rx_chain_finals.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    IterationEvent::ReassemblyDropped(_) => {
                        rx_reassembly_drops.fetch_add(1, Ordering::SeqCst);
                    }
                    _ => {}
                }
                session_drive.dispatch_iteration_event(event)
            },
        )
    };

    let endpoint = format!("tcp/127.0.0.1:{zenohd_port}");
    let scenario = async {
        // pico is spawned only AFTER wz's routed subscriber has been declared,
        // so zenohd installs the route first — the same ordering
        // `wz_to_zenohd_router::wz_routed_subscribe_from_zenohd` uses. The
        // spawn helper BLOCKS until the child prints "Putting Data", so it runs
        // on a blocking thread: holding the async executor there would stall
        // the drive loop above and let the session's lease expire.
        let z_pub_child = tokio::task::spawn_blocking(move || {
            spawn_publishing_zpub(&z_pub, PUBLISH_KEYEXPR, &value, &endpoint, "zenohd", || {
                tempfile::tempfile().expect("tempfile for z_pub stdout")
            })
        })
        .await
        .expect("z_pub spawn task");

        // pico publishes on a 1s cadence for `-n 30` iterations, every value
        // byte-identical, so one landing after the route settles suffices —
        // deterministic, not flaky-masking retry.
        let deadline = Instant::now() + Duration::from_secs(15);
        let outcome = loop {
            if deliveries.load(Ordering::SeqCst) >= 1 {
                break Ok(());
            }
            if Instant::now() >= deadline {
                break Err(format!(
                    "wz's routed subscriber received nothing within 15s \
                     (negotiated MTU {negotiated_mtu}, {} fragment batch(es) seen on the wire, \
                     {} RX Fragment event(s))",
                    relay.acceptor_to_dialer_count(),
                    rx_fragments.load(Ordering::SeqCst),
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        (outcome, z_pub_child)
    };

    let (delivery, z_pub_child) = tokio::select! {
        _ = drive => (
            Err("wz drive loop reached a terminal state before the routed Sample arrived"
                .to_string()),
            None,
        ),
        (r, child) = scenario => (r, Some(child)),
    };

    if let Some(mut child) = z_pub_child {
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
    }
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    ArmOutcome {
        negotiated_mtu,
        fragments_on_wire: relay.acceptor_to_dialer_count(),
        rx_fragments: rx_fragments.load(Ordering::SeqCst),
        rx_chain_finals: rx_chain_finals.load(Ordering::SeqCst),
        rx_reassembly_drops: rx_reassembly_drops.load(Ordering::SeqCst),
        deliveries: deliveries.load(Ordering::SeqCst),
        byte_exact: byte_exact.load(Ordering::SeqCst),
        delivery,
    }
}

// wz-proves: transport-fragmentation zenohd->wz
// wz-proves: pubsub-sample zenohd->wz
// wz-proves: declare-subscriber wz->zenohd
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd router + zenoh-pico z_pub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn zenohd_fragmented_route_to_wz_is_reassembled_into_a_byte_exact_sample() {
    let arm = subscribe_through_zenohd_with_batch(Some(TINY_BATCH)).await;

    // Precondition — the arm really is the small-MTU one. This is a WZ-LOCAL
    // self-check and nothing more: `negotiated_batch_mtu()` is
    // `min(own, peer, link)` over a locally-read `own`
    // (`wz-session-core/src/session_actions.rs:1552-1577`), so 64 dominates
    // whatever zenohd answers. It would still read 64 if wz's InitSyn dropped
    // `batch_size` outright or zenohd ignored it. What actually catches that is
    // Assertion 1, which is measured on the wire.
    assert_eq!(
        arm.negotiated_mtu, TINY_BATCH as usize,
        "this arm must run at the tiny batch; a change to TINY_BATCH or to the local \
         batch_size plumbing lands here"
    );

    // Assertion 1 — ZENOHD really fragmented, observed on the wire OUTSIDE wz.
    // The tag is authored by the foreign router and only recognised by wz's
    // constant, and the twin below reads 0 through the same counter.
    //
    // The bound is 4, not 2. A 207-byte Push at MTU 64 costs roughly 42 bytes
    // of payload per chunk once the length prefix, fragment header and SN are
    // paid, so the real chain is 5 (measured, R311y439) and 4 leaves margin for
    // a header-size change. A bound of 2 would also be satisfied by any two
    // oversize Declares zenohd happens to send on this link, which is not the
    // chain this leg claims.
    assert!(
        arm.fragments_on_wire >= 4,
        "expected zenohd to route the Put as a multi-chunk T_MID_FRAGMENT chain at MTU 64; \
         the relay counted {}",
        arm.fragments_on_wire
    );

    // Assertion 2 — wz's RX path really took the reassembly branch, zenohd sent
    // a chain that TERMINATED, and no ingest was aborted or refused along the
    // way. Note what this does NOT say: the terminator event is emitted before
    // `ingest` runs, so none of these three witnesses reassembly COMPLETING.
    // Assertion 3 is the only one that does.
    assert!(
        arm.rx_fragments >= 4,
        "wz's drive loop must report the whole multi-chunk chain on the RX side (saw {})",
        arm.rx_fragments
    );
    assert!(
        arm.rx_chain_finals >= 1,
        "zenohd must send a COMPLETE chain — a Fragment with more == false; \
         {} fragment(s) with no terminator means the chain trailed off",
        arm.rx_fragments
    );
    assert_eq!(
        arm.rx_reassembly_drops, 0,
        "no chain may be aborted or refused by the reassembly dispatcher \
         (out-of-order, capacity, or pool quota)"
    );

    // Assertion 3 — cross-impl REASSEMBLY: the rebuilt message re-parsed into a
    // Sample and carried the WHOLE value, so a truncating or reordering
    // reassembly bound fails here.
    if let Err(msg) = arm.delivery {
        panic!("zenohd->wz RX-fragmentation interop FAILED.\n{msg}");
    }
    assert!(
        arm.deliveries >= 1,
        "the routed subscriber fired at least once"
    );
    assert!(
        arm.byte_exact,
        "every delivered Sample must end with the whole {PAYLOAD_LEN}B value and carry exactly \
         {PICO_ZPUB_PREFIX_LEN} prefix bytes before it"
    );
}

// wz-proves: none -- the CALIBRATION twin of the leg above. It differs in ONE
// field (batch_size) and witnesses that the SAME routed Put over a large MTU
// crosses with NO fragments while still being delivered, which is what makes
// the sibling's two fragment counts discriminators rather than constants. A
// delivery that correctly does not fragment proves no atom's cross-impl
// behaviour.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd router + zenoh-pico z_pub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn the_same_route_at_the_default_batch_arrives_unfragmented_from_zenohd() {
    let arm = subscribe_through_zenohd_with_batch(None).await;

    // The bound is `>` the payload, deliberately NOT an equality on a pinned
    // number. The zenohd-interop params carry batch_size 65535, but the
    // negotiated MTU is min'd with ZENOHD's TCP link MTU, and zenoh derives that
    // from the SOCKET: `TCP_DEFAULT_MTU - header` rounded down to a multiple of
    // half the TCP MSS (`zenoh-link-tcp/src/unicast.rs:83-96` at zenoh 1.5.0).
    // It is therefore MACHINE-DEPENDENT — pinning a constant here would red on a
    // host with a different MSS while nothing regressed.
    assert!(
        arm.negotiated_mtu > PICO_ZPUB_PREFIX_LEN + PAYLOAD_LEN,
        "the default-batch arm must negotiate an MTU above the published payload so \
         fragmentation is impossible by construction; got {}",
        arm.negotiated_mtu
    );
    assert_eq!(
        arm.fragments_on_wire, 0,
        "no fragment may cross the wire at MTU {} for a {PAYLOAD_LEN}B routed value",
        arm.negotiated_mtu
    );
    assert_eq!(
        arm.rx_fragments, 0,
        "and wz's RX path must never enter reassembly at MTU {}",
        arm.negotiated_mtu
    );

    // And the route is not merely un-fragmented but WORKING, so the sibling's
    // delivery assertion has a baseline that is not "wz can subscribe at all".
    if let Err(msg) = arm.delivery {
        panic!(
            "the un-fragmented control failed to route, so the proof leg has no baseline.\n{msg}"
        );
    }
    assert!(
        arm.byte_exact,
        "the un-fragmented control must deliver the same bytes the proof leg expects"
    );
}
