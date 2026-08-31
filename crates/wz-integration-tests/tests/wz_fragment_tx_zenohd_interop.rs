// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
use wz_integration_tests::fragment_ext::{ext_marked_batches_from, EXT_ID_DROP, EXT_ID_FIRST};
use wz_integration_tests::wire_tap::Side;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishError, PublishOptions, TokioSession};
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

/// R2238 (open-debt item 580) — the fragment credit the abandon arm starts
/// with. Any `0 < n < chain_len` works; the arm asserts the chain really was
/// cut part-way through the relay's own count rather than trusting this.
const ABANDON_BUDGET: usize = 2;

/// What one arm of the pair observed.
struct ArmOutcome {
    negotiated_mtu: usize,
    /// `T_MID_FRAGMENT`-tagged batches the relay saw going wz -> zenohd.
    fragments_on_wire: usize,
    /// R2238 — batches on that SAME direction carrying the `0x3 Drop` abandon
    /// marker, walked out of the relay's recorded bytes.
    drop_marked: usize,
    /// R2238 — batches on that direction carrying `0x2 First`. The
    /// anti-vacuity companion to `drop_marked`: a walk that cannot reach ANY
    /// fragment ext returns the same zero as a wire that carries no `0x3`, so
    /// every arm asserts this is non-zero before reading the one above.
    first_marked: usize,
    delivery: Result<(), String>,
    /// R2238 — whether the ONE chain published after the abandon reached pico,
    /// or `None` on an arm that never abandoned anything. Single-shot on
    /// purpose; see the note at its publish site.
    after_abandon: Option<Result<(), String>>,
}

/// Drive one arm of the pair: stock zenohd, a pico `z_sub` client of it, and a
/// wz publisher that dials THROUGH the counting relay with `batch_size`.
///
/// Shared by both legs so the ONLY difference between them is that one
/// argument — the twin is a twin by construction, not by parallel maintenance
/// of two copies.
async fn publish_through_zenohd_with_batch(
    batch_size: Option<u16>,
    fragment_budget: Option<usize>,
) -> ArmOutcome {
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

    let actions = opened.actions.clone();
    let received_witness = ">> [Subscriber] Received";
    let scenario = async {
        // pico's subscriber is already declared (spawn_subscribed_zsub waits
        // for it), but the route still has to propagate through zenohd, so the
        // Put is republished on a cadence. Every Put is byte-identical, so one
        // landing after the route installs suffices — deterministic, not
        // flaky-masking retry.
        let deadline = Instant::now() + Duration::from_secs(12);
        let route_installed = loop {
            publisher
                .publish(PUBLISH_KEYEXPR, payload.as_bytes(), PublishOptions::put())
                .expect("oversize publish builds and routes through the send seam");
            tokio::time::sleep(Duration::from_millis(150)).await;
            let captured = read_captured(&mut z_sub_stdout_reader);
            if captured.contains(received_witness) && captured.contains(&payload) {
                break Ok(());
            }
            if Instant::now() >= deadline {
                break Err(format!(
                    "pico z_sub did not print the {PAYLOAD_LEN}B Put within 12s \
                     (negotiated MTU {negotiated_mtu}, {} fragment(s) seen on the wire).\n\
                     --- captured z_sub stdout ---\n{captured}",
                    relay.dialer_to_acceptor_count()
                ));
            }
        };
        if route_installed.is_err() || fragment_budget.is_none() {
            return (route_installed, None);
        }

        // ── R2238 — the ABANDON arm, run AFTER the route is proven installed
        //    so what follows needs no retry. That ordering is the whole point:
        //    the marker SPENDS an SN, and zenoh's receive-side `SeqNum::roll`
        //    (`io/zenoh-transport/src/common/seq_num.rs:145-155`) accepts a
        //    transport message only when its SN advances the window. A marker
        //    that failed to spend its SN would make the NEXT chain's first
        //    fragment repeat one already accepted, and zenohd would drop it —
        //    but a RETRY LOOP would paper straight over that, because the
        //    retry after it carries fresh SNs and lands. MEASURED, R2238: with
        //    the marker's SN reserve removed, the retrying form of this leg
        //    stayed green and only the single-shot form below reddens. So the
        //    post-abandon publish happens EXACTLY ONCE.
        let n = fragment_budget.expect("checked above");
        actions.set_fragment_tx_budget(n);
        let refused = publisher.publish(PUBLISH_KEYEXPR, payload.as_bytes(), PublishOptions::put());
        if !matches!(refused, Err(PublishError::FragmentChainAbandoned)) {
            return (
                route_installed,
                Some(Err(format!(
                    "the finite budget ({n}) must cut the chain part-way; got {refused:?}"
                ))),
            );
        }
        actions.set_fragment_tx_budget(usize::MAX);

        // A DISTINCT payload, so its arrival cannot be satisfied by the
        // pre-abandon deliveries already in the captured stdout.
        let after = frag_payload(PAYLOAD_LEN + 8);
        publisher
            .publish(PUBLISH_KEYEXPR, after.as_bytes(), PublishOptions::put())
            .expect("with the budget refilled the publish is accepted");
        let after_deadline = Instant::now() + Duration::from_secs(12);
        let after_abandon = loop {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let captured = read_captured(&mut z_sub_stdout_reader);
            if captured.contains(&after) {
                break Ok(());
            }
            if Instant::now() >= after_deadline {
                break Err(format!(
                    "after the 0x3 stop fragment, the NEXT chain never reached pico \
                     within 12s — zenohd rejected it, which is what an SN the marker \
                     did not spend (or spent twice) looks like downstream.\n\
                     --- captured z_sub stdout ---\n{captured}"
                ));
            }
        };
        (route_installed, Some(after_abandon))
    };

    let (delivery, after_abandon) = tokio::select! {
        _ = drive => (
            Err("wz drive loop reached a terminal state before pico received the Put".to_string()),
            None,
        ),
        r = scenario => r,
    };

    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    // R2238 — walk the bytes the relay recorded on wz's OWN direction. This is
    // what wz put on the wire, read by something that is neither wz's encoder
    // nor its peer.
    let recording = relay.recording();
    ArmOutcome {
        negotiated_mtu,
        fragments_on_wire: relay.dialer_to_acceptor_count(),
        drop_marked: ext_marked_batches_from(
            &recording,
            Side::FromDialer,
            T_MID_FRAGMENT,
            EXT_ID_DROP,
        ),
        first_marked: ext_marked_batches_from(
            &recording,
            Side::FromDialer,
            T_MID_FRAGMENT,
            EXT_ID_FIRST,
        ),
        delivery,
        after_abandon,
    }
}

// wz-proves: transport-fragmentation wz->zenohd
// wz-proves: pubsub-put wz->zenohd
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd router + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn wz_tx_fragmented_put_is_reassembled_by_zenohd_and_reaches_pico_zsub() {
    let arm = publish_through_zenohd_with_batch(Some(TINY_BATCH), None).await;

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

    // R2238 — assertion 3, and the CONTROL for the abandon leg below: a
    // fragmenting publish with credit available emits NO stop fragment. The
    // walk is live here (`first_marked >= 1` over the same bytes), so this
    // zero is a negative result and not a probe that cannot see.
    assert!(
        arm.first_marked >= 1,
        "the 0x2/0x3 walk must reach wz's own chain START before its zero on \
         0x3 means anything (saw {} first-marked batch(es))",
        arm.first_marked
    );
    assert_eq!(
        arm.drop_marked, 0,
        "a chain that never ran out of budget must not announce an abandon"
    );
}

// wz-proves: transport-fragmentation wz->zenohd
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd router + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
/// R2238 (open-debt item 580) — wz puts the `0x3 Drop` marker ON THE WIRE when
/// a chain outruns its fragment budget, and a REAL zenohd takes it.
///
/// ## Why this is the leg item 580 asked for
///
/// Item 575 measured that NO implementation emits this marker at the pinned
/// version (`wz_chain_drop_zenohd_interop.rs`): zenoh (Rust) reaches its emit
/// site and the encode fails against an emptied reader, zenoh-pico's one call
/// site passes `false`, and wz had an encoder with no production caller. Item
/// 580 is the wz half of that — build the sender-side state the marker
/// describes, then emit it for real. This leg is where "for real" is checked
/// against something that is neither wz's encoder nor wz's receiver.
///
/// ## Three independent halves, none of which is the proof alone
///
///   1. the RELAY — a third party to both ends — walks wz's own direction of
///      the recorded wire and finds a `T_MID_FRAGMENT` batch carrying ext
///      `0x3`. The sibling leg above reads 0 through the SAME walk, so the
///      count discriminates rather than being a constant;
///   2. the chain was cut PART-WAY, not refused whole: the relay counted more
///      fragments than `ABANDON_BUDGET`, so fragments preceded the marker —
///      which is the only state in which announcing an abandon is honest;
///   3. ZENOHD carried on. The marker spends an SN, and zenoh's receive-side
///      `SeqNum::roll` (`io/zenoh-transport/src/common/seq_num.rs:145-155`)
///      accepts a transport message only when its SN advances the window, so a
///      marker that skipped its SN or reused one would strand every later
///      chain. The retry's payload reaching a THIRD implementation (pico
///      `z_sub`) byte-exact, through zenohd's reassembler, is what says the
///      router accepted the marker as a message rather than tolerating it.
///
/// ## ⚠ What this leg does NOT claim, and the measurement behind that
///
/// Item 580's completion condition asked to observe zenohd CLEARING its
/// defragmentation buffer. R2238 measured that this is not observable from a
/// conforming sender, and the reason is in upstream's own receive path
/// (`io/zenoh-transport/src/unicast/universal/rx.rs:176-185`): `ext_first`
/// clears the buffer too, on the very next chain. So a peer that abandons a
/// chain and then starts a NEW one — which is every conforming sender, wz
/// included — leaves the two indistinguishable downstream: same delivery,
/// same SN state, same buffer. The difference is only WHEN the buffer is
/// released, and nothing upstream reports that. Telling them apart would
/// need a fragment that continues the abandoned chain WITHOUT `0x2`, i.e. wz
/// deliberately violating the contract the marker just stated. This leg
/// therefore proves the marker is emitted and accepted, and the clear is
/// upstream's documented consequence of accepting it rather than a second
/// thing to measure.
async fn wz_abandons_an_over_budget_chain_with_a_marker_a_real_zenohd_accepts() {
    let arm = publish_through_zenohd_with_batch(Some(TINY_BATCH), Some(ABANDON_BUDGET)).await;

    assert_eq!(
        arm.negotiated_mtu, TINY_BATCH as usize,
        "wz advertised batch=64 and zenohd min-negotiates to it, so the 200B Put must fragment"
    );

    // Half 1 — the marker is ON THE WIRE, read off wz's own direction.
    assert_eq!(
        arm.drop_marked, 1,
        "exactly one abandoned chain, so exactly one 0x3 stop fragment; the \
         retries after the refill all had credit ({} fragment batches seen)",
        arm.fragments_on_wire
    );

    // Half 2 — it was cut PART-WAY. The abandon arm alone put `ABANDON_BUDGET`
    // fragments plus its marker on the wire before the delivering retry added
    // its own chain, so anything at or below the budget would mean the chain
    // never started and the marker is describing a peer state that never
    // existed.
    assert!(
        arm.fragments_on_wire > ABANDON_BUDGET + 1,
        "the abandoned chain must have emitted fragments BEFORE its marker \
         (budget {ABANDON_BUDGET}, relay counted {})",
        arm.fragments_on_wire
    );
    assert!(
        arm.first_marked >= 1,
        "and a chain START must be on the wire too (saw {})",
        arm.first_marked
    );

    // Half 3 — zenohd took the marker and kept routing. The pre-abandon
    // delivery proves the route existed; the SINGLE post-abandon chain is what
    // proves the router accepted the marker AS A MESSAGE, SN and all.
    if let Err(msg) = arm.delivery {
        panic!("the route was never installed, so half 3 asserts nothing.\n{msg}");
    }
    match arm.after_abandon {
        Some(Ok(())) => {}
        Some(Err(msg)) => panic!(
            "zenohd did not carry on after wz's 0x3 stop fragment — the marker's \
             SN handling is the first thing to look at.\n{msg}"
        ),
        None => panic!(
            "this arm was asked to abandon a chain and reported no post-abandon \
             result at all — the abandon step did not run"
        ),
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
    let arm = publish_through_zenohd_with_batch(None, None).await;

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
