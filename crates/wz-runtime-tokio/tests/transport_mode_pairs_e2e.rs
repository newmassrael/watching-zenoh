// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-qos",
    feature = "transport-lowlatency",
    feature = "session-extcompression",
    feature = "transport-batching",
    feature = "transport-unicast",
    feature = "transport-link-tcp"
))]

//! R311y435 — the two transport-mode PAIRS that R311y434's carry named as never
//! having been read against zenoh's composed data path, and which no test
//! covered at all.
//!
//! R311y434 established the defect class: a composition test can certify a
//! DIVERGENCE, because each single-mode leg matching upstream says nothing about
//! the composed one. Its carry listed the pairs still unread — shm x lowlatency,
//! shm x compression, qos x compression, batching x lowlatency. R311y435 read
//! all four against upstream. The first two are covered by
//! `transport_compose_e2e`'s legs. These two had NO coverage, so their "they
//! compose" verdict rested on reading alone, which is exactly the unproven-claim
//! shape the project forbids. This file converts both to measurements.
//!
//! ## Pair A — qos x compression
//!
//! Upstream composes them at DIFFERENT layers and the layers do not interact:
//! `is_qos` splits the transmission pipeline into per-priority queues, and every
//! one of those queues is constructed with the SAME `BatchConfig` — the struct
//! that carries `is_compression`
//! (`io/zenoh-transport/src/common/pipeline.rs:719` and `:733`). So a
//! prioritized frame is compressed exactly like a DEFAULT one, and the
//! compression wrap is OUTSIDE the Frame that carries `ext_qos`. wz reaches the
//! same wire from the other direction: `emit_on_link` wraps whatever bytes it is
//! handed, priority-blind, so the ordering falls out rather than being arranged.
//! The pair pins that it stays that way.
//!
//! ## Pair B — batching x lowlatency
//!
//! Upstream's lean transport has no transmission pipeline AT ALL: `schedule`
//! hands the message straight to `send`
//! (`io/zenoh-transport/src/unicast/lowlatency/transport.rs`
//! @ `self.send(msg).map(|_| true)`; 1.10.0 folded the old
//! `lowlatency/tx.rs` @ REMOVED into the transport), which serializes it
//! behind a 4-byte length prefix and writes it (`lowlatency/link.rs:33-73`).
//! There is no `WBatch` to accumulate into, so batching is not "disabled" on a
//! lean link — it does not exist there. wz reproduces that by ORDERING: the lean
//! early-return in `dispatch_network_message` precedes the batching arm, so an
//! ACTIVE batching window on a lean session accumulates nothing and every message
//! leaves immediately. That ordering is one `return` away from being wrong and
//! nothing pinned it, which is why leg B1 exists.
//!
//! ## Why each is an option-atom PAIR
//!
//! A single leg asserting "the composed wire looks like X" is what R311y434
//! showed to be insufficient — it can pass while X is wz-only. Each pair here
//! differs in exactly ONE offer, so the delta is attributable to that offer
//! rather than to the other capability having silently stopped working. Both
//! REDs were measured; see the ledger entry.

use std::sync::Arc;

use wz_codecs::wire_const;
use wz_runtime_tokio::session_glue::SessionLinkActions;
use wz_runtime_tokio_test_support::{establish_capability_pair, LifecycleRecordingDriver};
use wz_session_core::compression::{decompress_batch, BATCH_HEADER_COMPRESSION};
use wz_session_core::qos::Priority;

const KEYEXPR: &str = "demo/mode-pairs";

fn send_count(driver: &LifecycleRecordingDriver) -> usize {
    driver.snapshot().sends.len()
}

fn last_send(driver: &LifecycleRecordingDriver) -> Vec<u8> {
    driver.snapshot().sends.last().expect("a send").0.clone()
}

/// Every send recorded after `from`, in wire order.
fn sends_since(driver: &LifecycleRecordingDriver, from: usize) -> Vec<Vec<u8>> {
    driver
        .snapshot()
        .sends
        .iter()
        .skip(from)
        .map(|s| s.0.clone())
        .collect()
}

/// Publish one Put at `priority` and return the bytes handed to the link driver
/// (pre link-layer length framing). Shared by both Pair-A legs so they differ
/// ONLY in which offers were staged.
fn publish_at_priority(
    actions: &Arc<SessionLinkActions>,
    driver: &LifecycleRecordingDriver,
    priority: Priority,
) -> Vec<u8> {
    actions
        .send_push_literal_qos(KEYEXPR, b"prioritized-payload", true, priority)
        .expect("send on an established session");
    last_send(driver)
}

// ─── Pair A — qos x compression ──────────────────────────────────────────────

/// A1: BOTH negotiated. The compression BatchHeader is the OUTERMOST layer and
/// the `ext_qos`-bearing Frame is INSIDE it — the upstream layering, where the
/// per-priority queue and the batch compression sit at different levels
/// (`common/pipeline.rs:719`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compression_wraps_the_prioritized_frame_when_qos_is_also_negotiated() {
    let pair = establish_capability_pair(true, true, |a| {
        a.set_qos_offer(true);
        a.set_compression_offer(true);
    })
    .await;

    for (who, actions) in [
        ("initiator", &pair.init_actions),
        ("acceptor", &pair.resp_actions),
    ] {
        assert!(actions.is_qos(), "{who} negotiated qos");
        assert!(actions.is_compression(), "{who} negotiated compression");
        // qos is NOT lowlatency, so the wrap is ACTIVE here — the conjunct
        // R311y434 added must not over-reach to any non-universal mode.
        assert!(
            actions.compresses_batches(),
            "{who}: qos does not suppress the lz4 wrap (only lowlatency does)"
        );
    }

    let wire = publish_at_priority(
        &pair.init_actions,
        &pair.init_driver,
        Priority::InteractiveHigh,
    );

    // OUTERMOST = the compression BatchHeader. The short payload is
    // incompressible so the bit is clear, but the header byte is present.
    assert!(
        wire[0] == 0x00 || wire[0] == BATCH_HEADER_COMPRESSION,
        "the outermost wire layer is the compression BatchHeader (got {:#04x})",
        wire[0]
    );

    // INSIDE the wrap: the Frame, and it still carries ext_qos. This is the half
    // that fails if compression were applied at the wrong layer — e.g. inside
    // the Frame, or in a way that ate the ext chain.
    let inner = decompress_batch(&wire, 65536).expect("the batch un-wraps");
    assert_eq!(
        inner[0] & 0x1F,
        wire_const::T_MID_FRAME,
        "inside the compression wrap is a Frame(sn)"
    );
    assert_ne!(
        inner[0] & wire_const::FLAG_T_Z,
        0,
        "the wrapped Frame still sets the ext-chain Z flag: the prioritized \
         conduit's ext_qos survives compression (it is INSIDE the wrap, as in \
         zenoh, where every per-priority queue shares one BatchConfig)"
    );
}

/// A2 — the option-atom TWIN: the SAME offers MINUS compression. The Frame and
/// its `ext_qos` are unchanged and now lead the wire directly, so A1's header
/// byte is attributable to compression rather than to qos having changed shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_prioritized_frame_leads_the_wire_when_compression_is_not_negotiated() {
    let pair = establish_capability_pair(true, true, |a| {
        a.set_qos_offer(true);
    })
    .await;

    for (who, actions) in [
        ("initiator", &pair.init_actions),
        ("acceptor", &pair.resp_actions),
    ] {
        assert!(actions.is_qos(), "{who} negotiated qos");
        assert!(
            !actions.is_compression(),
            "{who} did not negotiate compression"
        );
        assert!(
            !actions.compresses_batches(),
            "{who}: no wrap without the ext"
        );
    }

    let wire = publish_at_priority(
        &pair.init_actions,
        &pair.init_driver,
        Priority::InteractiveHigh,
    );

    assert_eq!(
        wire[0] & 0x1F,
        wire_const::T_MID_FRAME,
        "without compression the prioritized Frame leads the wire, with NO \
         BatchHeader in front of it (got {:#04x})",
        wire[0]
    );
    assert_ne!(
        inner_z_flag(&wire),
        0,
        "the same ext_qos rides: the pair differs in the compression offer alone"
    );
}

fn inner_z_flag(wire: &[u8]) -> u8 {
    wire[0] & wire_const::FLAG_T_Z
}

// ─── Pair B — batching x lowlatency ──────────────────────────────────────────

/// B1: an ACTIVE batching window on a lean session accumulates NOTHING — each
/// Put leaves immediately as its own bare lean Push, and the flush that would
/// drain a universal session's open frame has nothing to drain.
///
/// This is upstream's shape reproduced by ordering rather than by a flag: the
/// lean transport has no pipeline to batch into
/// (`unicast/lowlatency/tx.rs:30-51`), and wz's lean early-return in
/// `dispatch_network_message` precedes the batching arm. Move that return below
/// the batching arm and this leg reds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batching_window_accumulates_nothing_on_a_lean_session() {
    let pair = establish_capability_pair(true, true, |a| {
        a.set_lowlatency_offer(true);
    })
    .await;

    assert!(
        pair.init_actions.is_lowlatency(),
        "initiator negotiated lowlatency"
    );

    pair.init_actions
        .batch_start()
        .expect("transport-batching is compiled in");

    let before = send_count(&pair.init_driver);
    for i in 0..3u8 {
        pair.init_actions
            .send_push_literal(KEYEXPR, &[0xA0 | i], true)
            .expect("send on an established session");
    }
    let emitted = sends_since(&pair.init_driver, before);

    assert_eq!(
        emitted.len(),
        3,
        "an open batching window absorbs nothing on a lean link: each Put is its \
         own datagram, because the lean path returns before the batching arm"
    );
    for (i, wire) in emitted.iter().enumerate() {
        assert_eq!(
            wire[0] & 0x1F,
            wire_const::N_MID_PUSH,
            "lean datagram {i} is a BARE Push with no Frame(sn) envelope (got \
             {:#04x})",
            wire[0]
        );
    }

    // And the flush is a no-op, because there is no open frame to drain.
    let before_flush = send_count(&pair.init_driver);
    pair.init_actions.batch_flush().expect("flush");
    assert_eq!(
        send_count(&pair.init_driver),
        before_flush,
        "batch_flush on a lean session emits nothing: the window never opened a \
         frame, so there is no empty Frame(sn) to leak onto the wire"
    );
}

/// B2 — the option-atom TWIN: the SAME batching window MINUS the lowlatency
/// offer. Now the three Puts accumulate into ONE Frame that only the flush
/// releases, which is what makes B1's three-datagram count attributable to
/// lowlatency rather than to batching being broken outright.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_same_batching_window_accumulates_one_frame_without_lowlatency() {
    let pair = establish_capability_pair(true, true, |_a| {}).await;

    assert!(
        !pair.init_actions.is_lowlatency(),
        "no lowlatency offer was staged"
    );

    pair.init_actions
        .batch_start()
        .expect("transport-batching is compiled in");

    let before = send_count(&pair.init_driver);
    for i in 0..3u8 {
        pair.init_actions
            .send_push_literal(KEYEXPR, &[0xA0 | i], true)
            .expect("send on an established session");
    }
    assert_eq!(
        send_count(&pair.init_driver),
        before,
        "a universal session ABSORBS all three Puts into the open frame: nothing \
         reaches the wire until the flush"
    );

    pair.init_actions.batch_flush().expect("flush");
    let emitted = sends_since(&pair.init_driver, before);
    assert_eq!(
        emitted.len(),
        1,
        "the flush releases exactly ONE accumulated Frame carrying all three Puts"
    );
    assert_eq!(
        emitted[0][0] & 0x1F,
        wire_const::T_MID_FRAME,
        "the accumulated batch is a Frame(sn) envelope (got {:#04x})",
        emitted[0][0]
    );
}
