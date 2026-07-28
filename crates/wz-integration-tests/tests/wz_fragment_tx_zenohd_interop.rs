// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y438 — FOREIGN-INTEROP unicast fragmentation against the CANONICAL
//! router: wz dials a real `zenohd` with a tiny negotiated batch, its
//! oversize `Put` leaves as a `T_MID_FRAGMENT` chain, zenohd reassembles it,
//! and a zenoh-pico `z_sub` on the far side of that router prints the payload
//! byte-exact.
//!
//! ## The gap this closes
//!
//! `transport-fragmentation` had witnesses in both PICO directions —
//! `wz_fragment_tx_to_pico_zsub.rs` (wz->pico, `partial`) and
//! `wz_reassembles_pico_fragment_tx.rs` (pico->wz) — and a wz<->wz TX/RX split
//! in `wz-runtime-tokio/tests/layer3_reassembly_tx.rs`. It had NO zenohd
//! witness in either direction. That mattered because pico and zenohd are not
//! interchangeable reassemblers: pico's defrag is a fixed
//! `Z_FRAG_MAX_SIZE` wbuf (`vendor/zenoh-pico/src/transport/unicast/rx.c:208`)
//! while zenohd's is the full Rust transport, and the north star is the
//! SUPERSET of both.
//!
//! It also corrects a claim this round found stale. R311y433/y434/y437 carried
//! an "unexplained large-payload ceiling" in the wz -> zenohd -> pico chain and
//! cited `transport-fragmentation` being in preset-ap-client as the reason it
//! was suspicious. That ceiling is NOT a wz defect and has nothing to do with
//! wz's fragmenter: see `wz_compression_zenohd_interop.rs`'s module docs for
//! the measurement. What the investigation actually exposed is the gap above —
//! wz negotiates `batch_size` 65535 with zenohd by default
//! (`wz-session-core/src/session_init_params.rs:98-102`), so a few-KB Put never
//! fragments on the hop wz is on, and no leg had ever made it.
//!
//! ## Why a counting relay, and why this leg is `full` where the pico one is `partial`
//!
//! `wz_fragment_tx_to_pico_zsub.rs` marks itself `partial` and says why: the
//! receiver is a foreign binary, so the test cannot observe that wz actually
//! emitted a multi-chunk chain — "wz fragmented" is true BY CONSTRUCTION (MTU
//! 64 < payload) and is separately guarded by the wz<->wz host lane, which
//! counts chunks on its own acceptor. A cross-impl leg with a foreign receiver
//! inherits that hole.
//!
//! This leg closes it instead of inheriting it. wz does not dial zenohd
//! directly; it dials an in-test TCP relay that forwards both directions
//! verbatim and, in the wz->zenohd direction ONLY, counts the streamed-link
//! batches whose first transport message carries `T_MID_FRAGMENT`. So the
//! proof has two independent halves that a single defect cannot fake:
//!
//!   * the RELAY says wz put >= 2 FRAGMENT-tagged messages on the wire, and
//!   * ZENOHD — which owes wz nothing — reassembled them into a Sample that a
//!     third implementation (pico) printed byte-exact.
//!
//! The relay reads the fragment MID from wz's own `wire_const`, so on its own
//! it proves only "wz tagged these as fragments"; zenohd's successful
//! reassembly is what makes the tag mean what it says. Neither half is the
//! proof; the pair is.
//!
//! ## The option-atom PAIR
//!
//! Both legs run the SAME helper against the SAME stock zenohd with the SAME
//! payload, differing in ONE field — `SessionInitParams::batch_size`:
//!
//!   1. the PROOF (`batch_size = 64`). zenohd's acceptor takes
//!      `min(own, init_syn.batch_size)`
//!      (`io/zenoh-transport/src/unicast/establishment/accept.rs:220-224` at
//!      zenoh 1.5.0), so the negotiated MTU is 64 and the 200-byte Put is
//!      FORCED through `emit_frame_or_fragments`' split branch
//!      (`wz-session-core/src/session_actions.rs:3102-3104`). Asserts MTU ==
//!      64, relay fragment count >= 2, and byte-exact delivery.
//!   2. the TWIN (`batch_size` left at the interop default, 65535). The
//!      negotiated MTU lands far above the payload, the same 200-byte Put
//!      cannot fragment, the relay counts ZERO fragments — and the payload
//!      still arrives. This is what makes leg
//!      1's delivery attributable to the fragment chain rather than to "wz can
//!      publish through zenohd at all", and it is simultaneously the
//!      calibration that forbids reading the relay's count as a constant: the
//!      same counter reads 2+ in one arm and 0 in the other.
//!
//! R311y439 — the relay itself now lives in
//! [`wz_integration_tests::common::spawn_counting_relay`], lifted on
//! its second consumer (the zenohd -> wz leg,
//! `wz_fragment_rx_zenohd_interop.rs`, which points the SAME relay at the
//! opposite direction). Its docs carry the exactness argument for what the
//! count is — in short, it counts BATCHES whose first transport message is
//! tagged, which for a wz sender is one-to-one with messages and elsewhere
//! UNDERCOUNTS, the safe direction for leg 1's `>= 2`. Leg 2's `== 0` does not
//! rest on the count alone: its MTU assertion makes fragmentation impossible by
//! construction.
//!
//! Opt-in (`#[ignore]`, run-ci Layer Z): zenohd + the pico z_sub CLI are
//! external binaries. The test NAME carries `zenohd` because Layer E's skip
//! filter is a name substring (`--skip zenohd`) — a zenohd leg whose name lacks
//! the token gets pulled into the default sweep alone and reddens there
//! (R311y437).

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

use wz_codecs::wire_const::T_MID_FRAGMENT;
use wz_integration_tests::common::{
    frag_payload, read_captured, spawn_counting_relay, spawn_subscribed_zsub,
    spawn_zenohd_on_ephemeral_tcp, zenoh_pico_cli_binary, RelayFault,
};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{initiate_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::zenohd_interop_session_init_params;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const PUBLISH_KEYEXPR: &str = "demo/frag-zenohd";
const SUB_KEYEXPR: &str = "demo/**";
/// The tiny advertised batch. zenohd min-negotiates to it, so a 200-byte Put
/// must fragment.
const TINY_BATCH: u16 = 64;
/// 200 B > 64 B MTU and within the alloc (AP) MsgPut owned-bytes bound.
const PAYLOAD_LEN: usize = 200;

/// What one arm of the pair observed.
struct ArmOutcome {
    negotiated_mtu: usize,
    /// `T_MID_FRAGMENT`-tagged batches the relay saw going wz -> zenohd.
    fragments_on_wire: usize,
    delivery: Result<(), String>,
}

/// Drive one arm of the pair: stock zenohd, a pico `z_sub` client of it, and a
/// wz publisher that dials THROUGH the counting relay with `batch_size`.
///
/// Shared by both legs so the ONLY difference between them is that one
/// argument — the twin is a twin by construction, not by parallel maintenance
/// of two copies.
async fn publish_through_zenohd_with_batch(batch_size: Option<u16>) -> ArmOutcome {
    let payload = frag_payload(PAYLOAD_LEN);
    let z_sub = zenoh_pico_cli_binary("z_sub");

    let (mut zenohd, zenohd_port) = spawn_zenohd_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    let relay = spawn_counting_relay(zenohd_port, T_MID_FRAGMENT, RelayFault::None);

    // pico subscribes to zenohd DIRECTLY (not through the relay): it is the
    // far-side witness, and routing it through the relay would count nothing
    // and only add a failure mode.
    let (mut z_sub_child, mut z_sub_stdout_reader) = spawn_subscribed_zsub(
        &z_sub,
        SUB_KEYEXPR,
        &format!("tcp/127.0.0.1:{zenohd_port}"),
        "zenohd",
        || tempfile::tempfile().expect("tempfile for z_sub stdout"),
    );

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
            let _ = z_sub_child.child_mut().kill();
            let _ = z_sub_child.child_mut().wait();
            let _ = zenohd.child_mut().kill();
            let _ = zenohd.child_mut().wait();
            panic!("wz did not reach Established against zenohd through the relay: {e:?}");
        }
    };
    let negotiated_mtu = opened.actions.negotiated_batch_mtu();

    let publisher = TokioSession::new(
        opened.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened.clock),
    );
    let timeouts = SessionTimeouts::spec_defaults();
    let mut observer = ApplicationLayerObserver::new();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        |event| observer.dispatch_event(event),
    );

    let received_witness = ">> [Subscriber] Received";
    let scenario = async {
        // pico's subscriber is already declared (spawn_subscribed_zsub waits
        // for it), but the route still has to propagate through zenohd, so the
        // Put is republished on a cadence. Every Put is byte-identical, so one
        // landing after the route installs suffices — deterministic, not
        // flaky-masking retry.
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            publisher
                .publish(PUBLISH_KEYEXPR, payload.as_bytes(), PublishOptions::put())
                .expect("oversize publish builds and routes through the send seam");
            tokio::time::sleep(Duration::from_millis(150)).await;
            let captured = read_captured(&mut z_sub_stdout_reader);
            if captured.contains(received_witness) && captured.contains(&payload) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico z_sub did not print the {PAYLOAD_LEN}B Put within 12s \
                     (negotiated MTU {negotiated_mtu}, {} fragment(s) seen on the wire).\n\
                     --- captured z_sub stdout ---\n{captured}",
                    relay.dialer_to_acceptor_count()
                ));
            }
        }
    };

    let delivery = tokio::select! {
        _ = drive => Err(
            "wz drive loop reached a terminal state before pico received the Put".to_string()
        ),
        r = scenario => r,
    };

    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    ArmOutcome {
        negotiated_mtu,
        fragments_on_wire: relay.dialer_to_acceptor_count(),
        delivery,
    }
}

// wz-proves: transport-fragmentation wz->zenohd
// wz-proves: pubsub-put wz->zenohd
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd router + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn wz_tx_fragmented_put_is_reassembled_by_zenohd_and_reaches_pico_zsub() {
    let arm = publish_through_zenohd_with_batch(Some(TINY_BATCH)).await;

    // Precondition — the split is FORCED. zenohd's acceptor min-negotiates to
    // wz's advertised 64, so a negotiation regression to the 65535 default
    // would trip here rather than silently deliver one un-fragmented frame.
    assert_eq!(
        arm.negotiated_mtu, TINY_BATCH as usize,
        "wz advertised batch=64 and zenohd min-negotiates to it, so the 200B Put must fragment"
    );

    // Assertion 1 — wz REALLY fragmented, observed on the wire rather than
    // inferred from the MTU. This is the half `wz_fragment_tx_to_pico_zsub.rs`
    // documents that it cannot make, and the twin below reads 0 through the
    // same counter, so it is not a constant.
    assert!(
        arm.fragments_on_wire >= 2,
        "expected wz to emit a multi-chunk T_MID_FRAGMENT chain at MTU 64; the relay counted {}. \
         A split-collapsing regression in emit_frame_or_fragments / build_fragment_wire lands here.",
        arm.fragments_on_wire
    );

    // Assertion 2 — cross-impl REASSEMBLY: zenohd rebuilt the chain into a
    // NetworkMessage and routed it, and pico printed the payload byte-exact
    // (the WHOLE value, so a truncating reassembly bound fails here).
    if let Err(msg) = arm.delivery {
        panic!("wz->zenohd TX-fragmentation interop FAILED.\n{msg}");
    }
}

// wz-proves: none -- the CALIBRATION twin of the leg above. It differs in ONE
// field (batch_size) and witnesses that the SAME publish over a large MTU emits
// NO fragments while still delivering, which is what makes the sibling's
// fragment count a discriminator rather than a constant. A delivery that
// correctly does not fragment proves no atom's cross-impl behaviour.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd router + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn the_same_publish_at_the_default_batch_emits_no_fragments_through_zenohd() {
    let arm = publish_through_zenohd_with_batch(None).await;

    // The bound is `>` the payload, deliberately NOT an equality on a pinned
    // number. The zenohd-interop params carry batch_size 65535
    // (`wz-runtime-tokio-test-support/src/lib.rs:84`), but the negotiated MTU
    // is min'd with ZENOHD's TCP link MTU, and zenoh derives that from the
    // SOCKET: `TCP_DEFAULT_MTU - header` rounded down to a multiple of half the
    // TCP MSS (`zenoh-link-tcp/src/unicast.rs:83-96` at zenoh 1.5.0). It is
    // therefore MACHINE-DEPENDENT — measured 49152 on this box's loopback
    // (MSS 32768), not the 65535 the config alone suggests. Pinning a constant
    // here would red on a host with a different MSS while nothing regressed.
    assert!(
        arm.negotiated_mtu > PAYLOAD_LEN,
        "the default-batch arm must negotiate an MTU above the payload so fragmentation is \
         impossible by construction; got {}",
        arm.negotiated_mtu
    );
    assert_eq!(
        arm.fragments_on_wire, 0,
        "no fragment may cross the wire at MTU {} for a {PAYLOAD_LEN}B Put",
        arm.negotiated_mtu
    );

    // And the session is not merely un-fragmented but WORKING, so the sibling's
    // delivery assertion has a baseline that is not "wz can publish at all".
    if let Err(msg) = arm.delivery {
        panic!(
            "the un-fragmented control failed to route, so the proof leg has no baseline.\n{msg}"
        );
    }
}
