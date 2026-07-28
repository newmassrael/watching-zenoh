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
//! R311y434 — and the composition is NOT a simple stack, because zenoh's is not.
//!
//! The review that produced this file flagged that lowlatency / compression / shm
//! were each proven only single-mode; this is the composition proof. Until
//! R311y434 it asserted the stack
//!
//!   compression([ lean-frame( shm-descriptor Put ) ])
//!
//! with the BatchHeader outermost — and that wire is unreadable by any zenoh
//! peer. zenoh negotiates the 0x6 ext on a lowlatency link exactly as on a
//! universal one (`unicast/establishment/open.rs:701` is independent of `:689`,
//! so both flags land on the config), but its LEAN transport serializes straight
//! to the link behind a 4-byte length prefix and never touches `WBatch` or
//! `BatchHeader` (`unicast/lowlatency/link.rs:33-73`); its lean rx likewise never
//! decompresses. So upstream, compression on a lean link is NEGOTIATED AND INERT.
//! wz wrapped anyway, which was self-consistent wz<->wz and wire-incompatible
//! with the reference impl. `SessionLinkActions::compresses_batches` now carries
//! the correction, and this file pins the corrected semantics. WITH lowlatency the
//! wire is `lean-bare-Push(shm-descriptor)` and carries NO BatchHeader, while
//! `is_compression()` stays TRUE — the capability WAS negotiated, only the wrap is
//! suppressed. WITHOUT lowlatency it is `compression([ Frame(shm-descriptor Put)
//! ])`, BatchHeader present.
//!
//! The two legs are an option-atom PAIR: they differ in the lowlatency offer and
//! nothing else, so the missing header in leg 1 is attributable to lowlatency
//! rather than to compression having silently stopped working. Leg 2 is what
//! fails if `compresses_batches` over-suppresses.

use std::sync::Arc;

use wz_codecs::wire_const;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::SessionLinkActions;
use wz_runtime_tokio::shm_provider::ShmBackedPayload;
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::{establish_capability_pair, LifecycleRecordingDriver};
use wz_session_core::compression::{decompress_batch, BATCH_HEADER_COMPRESSION};

const KEYEXPR: &str = "demo/compose";

fn last_send(driver: &LifecycleRecordingDriver) -> Vec<u8> {
    driver.snapshot().sends.last().expect("a send").0.clone()
}

/// Publish one SHM-backed Put on `actions` and return the bytes handed to the
/// link driver (pre link-layer length framing). Shared by both legs so the pair
/// differs ONLY in which offers were staged.
fn publish_shm_and_capture(
    actions: &Arc<SessionLinkActions>,
    driver: &LifecycleRecordingDriver,
) -> Vec<u8> {
    let mut payload = ShmBackedPayload::alloc(64).expect("alloc /dev/shm segment");
    payload.write(&[0xCDu8; 64]);
    let session = TokioSession::new(
        actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(TokioTime::new()),
    );
    session
        .publish_shm(KEYEXPR, &payload, PublishOptions::put())
        .expect("publish_shm on the composed session");
    last_send(driver)
}

/// lowlatency + compression + shm on ONE session: all three negotiate, and the
/// wire is the LEAN bare Push with NO compression BatchHeader — the zenoh
/// semantics, where a negotiated 0x6 is inert on a lean link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lowlatency_suppresses_the_compression_wrap_on_a_composed_session() {
    let pair = establish_capability_pair(true, true, |a| {
        a.set_lowlatency_offer(true);
        a.set_compression_offer(true);
        a.set_shm_offer(true);
    })
    .await;

    // All three NEGOTIATED true on BOTH sides (the 3-way `&=` composes). This is
    // the half that must NOT change: wz's Init/Open stays byte-identical to
    // zenoh's for the same config, so the ext is exchanged either way.
    for (who, actions) in [
        ("initiator", &pair.init_actions),
        ("acceptor", &pair.resp_actions),
    ] {
        assert!(actions.is_lowlatency(), "{who} negotiated lowlatency");
        assert!(actions.is_compression(), "{who} negotiated compression");
        assert!(actions.is_shm(), "{who} negotiated shm");
        // …and the DATA PATH predicate is nonetheless false. This is the
        // invariant: negotiated capability != applied wrap.
        assert!(
            !actions.compresses_batches(),
            "{who}: the lz4 wrap must be suppressed on a lean link even though \
             the 0x6 ext negotiated"
        );
    }

    let wire = publish_shm_and_capture(&pair.init_actions, &pair.init_driver);

    // The wire LEADS with the lean bare Push — no BatchHeader byte in front of it.
    // A header would be 0x00 or COMPRESSION (0x01), neither of which can mask to
    // N_MID_PUSH, so this single assertion excludes the wrapped shape.
    assert_eq!(
        wire[0] & 0x1F,
        wire_const::N_MID_PUSH,
        "the outermost layer is the lean bare Push (lowlatency), NOT a compression \
         BatchHeader (got {:#04x})",
        wire[0]
    );
    assert!(
        wire[0] != 0x00 && wire[0] != BATCH_HEADER_COMPRESSION,
        "a BatchHeader is present on a lean link (got {:#04x}) — the wrap was not \
         suppressed and no zenoh peer can read this wire",
        wire[0]
    );
}

/// The option-atom TWIN: the SAME offers MINUS lowlatency. Compression is then
/// active, so the wire is `BatchHeader || Frame(shm-descriptor Put)`. This is what
/// catches an over-broad suppression that killed the wrap everywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compression_still_wraps_when_lowlatency_is_not_negotiated() {
    let pair = establish_capability_pair(true, true, |a| {
        a.set_compression_offer(true);
        a.set_shm_offer(true);
    })
    .await;

    for (who, actions) in [
        ("initiator", &pair.init_actions),
        ("acceptor", &pair.resp_actions),
    ] {
        assert!(
            !actions.is_lowlatency(),
            "{who} did not negotiate lowlatency"
        );
        assert!(actions.is_compression(), "{who} negotiated compression");
        assert!(
            actions.compresses_batches(),
            "{who}: the lz4 wrap is ACTIVE without lowlatency"
        );
    }

    let wire = publish_shm_and_capture(&pair.init_actions, &pair.init_driver);

    // OUTERMOST layer = the compression BatchHeader. The small descriptor Put is
    // incompressible, so the bit is clear, but the header byte is PRESENT.
    assert!(
        wire[0] == 0x00 || wire[0] == BATCH_HEADER_COMPRESSION,
        "the outermost wire layer is the compression BatchHeader (got {:#04x})",
        wire[0]
    );
    // INSIDE the wrap: a Frame(sn), because this session is universal — the
    // structural contrast with leg 1's bare Push.
    let inner = decompress_batch(&wire, 65536).expect("the batch un-wraps");
    assert_eq!(
        inner[0] & 0x1F,
        wire_const::T_MID_FRAME,
        "inside the compression wrap is a Frame(sn) (no lowlatency), carrying the \
         shm-descriptor Put"
    );
}
