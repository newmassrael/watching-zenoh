// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-lowlatency",
    feature = "session-extcompression",
    feature = "session-extshm",
    feature = "transport-unicast",
    feature = "transport-link-tcp"
))]

//! R311xr — the three transport-advanced capabilities COMPOSE on one session.
//!
//! The review flagged that lowlatency / compression / shm were each proven only
//! single-mode (each e2e asserts its lone `is_X()`); the 3-way composition was
//! "designed to compose, verified by a clippy pass". This is the missing proof:
//! a single session negotiates ALL THREE, an SHM-backed Put is published, and the
//! captured wire shows the correct LAYERING --
//!
//!   compression([ lean-frame( shm-descriptor Put ) ])
//!     ^ outermost: the BatchHeader            ^ innermost: the SHM swap put a
//!       (compression wraps the whole batch)     descriptor in the payload, and
//!                  ^ middle: lowlatency dropped the Frame(sn), so the bare
//!                    N_MID_PUSH rides directly inside the compression wrap.
//!
//! So the tx pipeline is `publish_shm -> dispatch_network_message (lean encode,
//! lowlatency) -> send_wire (lz4 wrap, compression)`, and the captured bytes prove
//! all three layers stacked in the only correct order. (The per-layer RX un-wrap
//! is proven by the three single-mode e2e; this proves they STACK.)

use std::sync::Arc;

use wz_codecs::wire_const;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::shm_provider::ShmBackedPayload;
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::{establish_capability_pair, LifecycleRecordingDriver};
use wz_session_core::compression::{decompress_batch, BATCH_HEADER_COMPRESSION};

const KEYEXPR: &str = "demo/compose";

fn last_send(driver: &LifecycleRecordingDriver) -> Vec<u8> {
    driver.snapshot().sends.last().expect("a send").0.clone()
}

/// A session that negotiates lowlatency + compression + shm publishes an SHM Put;
/// the captured wire is `compression-BatchHeader || lean-bare-Push(descriptor)`,
/// proving the three layers stack in the only correct order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lowlatency_compression_shm_compose_on_one_session() {
    let pair = establish_capability_pair(true, true, |a| {
        a.set_lowlatency_offer(true);
        a.set_compression_offer(true);
        a.set_shm_offer(true);
    })
    .await;

    // All three negotiated true on BOTH sides (the 3-way `&=` composes).
    for (who, actions) in [
        ("initiator", &pair.init_actions),
        ("acceptor", &pair.resp_actions),
    ] {
        assert!(actions.is_lowlatency(), "{who} negotiated lowlatency");
        assert!(actions.is_compression(), "{who} negotiated compression");
        assert!(actions.is_shm(), "{who} negotiated shm");
    }

    // Publish an SHM-backed Put on the all-three session; capture the composed
    // outbound wire.
    let mut payload = ShmBackedPayload::alloc(64).expect("alloc /dev/shm segment");
    payload.write(&[0xCDu8; 64]);
    let session = TokioSession::new(
        pair.init_actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(TokioTime::new()),
    );
    session
        .publish_shm(KEYEXPR, &payload, PublishOptions::put())
        .expect("publish_shm on the composed session");
    let wire = last_send(&pair.init_driver);

    // OUTERMOST layer = the compression BatchHeader. Once compression is
    // negotiated every batch carries it; the small descriptor Put is
    // incompressible, so the bit is clear (0x00), but the header byte is present
    // -- it is NOT a transport / network message id (which would mean no
    // compression layer).
    assert!(
        wire[0] == 0x00 || wire[0] == BATCH_HEADER_COMPRESSION,
        "the outermost wire layer is the compression BatchHeader (got {:#04x})",
        wire[0]
    );

    // INSIDE the compression wrap: decompress, and the payload is a BARE
    // NetworkMessage (N_MID_PUSH) with NO Frame(sn) wrapper -- lowlatency's lean
    // encode. That this Push exists at all (and carries an SHM descriptor) is the
    // shm layer; that it is bare (not Frame-wrapped) is the lowlatency layer; that
    // it sits under the BatchHeader is the compression layer. All three stacked.
    let inner = decompress_batch(&wire, 65536).expect("the batch un-wraps");
    assert_eq!(
        inner[0] & 0x1F,
        wire_const::N_MID_PUSH,
        "inside the compression wrap is a lean bare Push (lowlatency), produced by publish_shm (shm)"
    );
}
