// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-unicast", feature = "codec-init-body"))]

//! R311y838 — the PATCH level a wz ACCEPTOR puts on the InitAck WIRE.
//!
//! wz has negotiated `min(local, peer)` internally since R311y578 and has
//! validated the peer's announcement since R311y817, but the byte it ANSWERS
//! with was never derived from either: `init_ack_ext` is seeded once at
//! construction with [`default_init_patch_ext_entry`] and nothing lowers it
//! after the InitSyn is read. So a wz acceptor announced `CURRENT` to every
//! peer, including one that announced less.
//!
//! # Why that is a divergence and not a nicety
//!
//! zenoh's acceptor answers `min(PatchType::CURRENT, state.patch)` where
//! `state.patch` is whatever the InitSyn carried — stored unexamined by
//! `AcceptFsm::recv_init_syn`, and left at `PatchType::NONE` when the InitSyn
//! carries no patch extension at all
//! (`io/zenoh-transport/src/unicast/establishment/ext/patch.rs:167-186`,
//! `StateAccept::new` at :119-124). zenoh-pico caps with the same `min`
//! (`src/transport/unicast/transport.c:237-241`).
//!
//! Two things ride on the answer, and both are the peer's to act on:
//!
//! * The negotiated level is the SOLE gate on the Fragment `First` / `Drop`
//!   chain-boundary markers (`PatchType::has_fragmentation_markers`,
//!   `commons/zenoh-protocol/src/transport/mod.rs:333`, read at
//!   `unicast/universal/rx.rs:155`). An acceptor that answers 1 to a peer that
//!   asked for 0 has told that peer to expect markers on a link where they were
//!   never agreed.
//! * Both references REFUSE an InitAck whose level exceeds the InitSyn's —
//!   zenoh `bail!`s (`ext/patch.rs:78-85`) and pico returns `_Z_ERR_GENERIC`
//!   before it builds the OpenSyn (`transport.c:142-148`). wz enforces that
//!   same rule as an initiator (R311y817). So the answer wz was giving is one
//!   wz itself would refuse.
//!
//! # Reachability, measured rather than asserted
//!
//! This is a FAITHFULNESS defect and a latent trap, not a live session break —
//! the R311y457 shape, and stated that way rather than sold as an outage.
//!
//! It IS reachable by a stock upstream build. zenoh-pico compiled with
//! `Z_FEATURE_FRAGMENTATION=0` initialises `_patch` to `_Z_NO_PATCH`
//! (`src/protocol/definitions/transport.c:172,278`) and its encoder writes the
//! entry only `if (msg->_patch != _Z_NO_PATCH)`
//! (`src/protocol/codec/transport.c:207-210`), so such a peer's InitSyn carries
//! no `0x7` entry at all — the input of the second test below. A real zenohd
//! answers it 0; wz answered 1.
//!
//! It is NOT a break against either stock 1.5.0 peer, and the reason is worth
//! recording because it is what kept this latent: the two upstream initiators
//! that VALIDATE the answer are exactly the two that announce `CURRENT`
//! (zenoh's `send_init_syn` is unconditional; pico's check sits under the same
//! `#if Z_FEATURE_FRAGMENTATION` as its announcement), so neither can present
//! the low announcement that would catch wz out. The peer that CAN — a
//! fragmentation-disabled pico — is also the one that never reads the field.
//! A peer that both announces below `CURRENT` and validates would have had its
//! session refused, and nothing in either reference forbids one.
//!
//! # What these tests read
//!
//! The InitAck BYTES the acceptor emitted, parsed back through
//! [`parse_inbound`] and projected with [`peer_patch`] — the same reader a peer
//! uses on wz's announcement, rather than an accessor for the staged slot. The
//! staged slot is the thing under test; reading it would assert the fix against
//! itself.

use std::sync::Arc;

use wz_codecs::wire_const;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::SessionFsmUnicastEvent as E;
use wz_runtime_tokio::session_glue::{
    new_session_actions, new_session_engine, poll_and_dispatch_one, BoxedLinkDriver,
};
use wz_runtime_tokio::{LinkEvent, RxFrame};
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, LifecycleRecordingDriver, QueueDriver,
};
use wz_session_core::accept_cookie::decode_accept_cookie;
use wz_session_core::extpatch::{patch_of_entry, peer_patch};
use wz_session_core::inbound::{parse_inbound, InboundFrame};
use wz_session_wire_fixtures::{craft_initsyn_wire, craft_initsyn_wire_with_patch};

/// Drive an acceptor through ONE InitSyn and return `(the patch entry it wrote
/// on the InitAck wire, if any, the level it negotiated internally)`.
///
/// The two are returned together on purpose: the defect this file pins is
/// exactly the two disagreeing, so a test that read only one of them could not
/// see it. The entry is returned as written rather than as `peer_patch` folds
/// it, because upstream answers level 0 with NO entry
/// (`commons/zenoh-codec/src/transport/init.rs` @
/// `if *ext_patch != ext::PatchType::NONE {`), and an entry carrying 0 would
/// read as the same level while being other bytes.
async fn acceptor_answers(init_syn_wire: Vec<u8>) -> (Option<u8>, u8) {
    let driver = Arc::new(LifecycleRecordingDriver::default());
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = driver.clone();
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize().unwrap_or_else(|never| match never {});
    engine.process_event(E::InboundStart);

    let mut queue = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(init_syn_wire))]);
    poll_and_dispatch_one(&mut queue, &actions, &mut engine).await;

    let sent = driver.snapshot().sends;
    let init_ack = sent
        .last()
        .expect("the acceptor emits an InitAck for an admitted InitSyn")
        .0
        .clone();
    let (extensions, cookie) = match parse_inbound(&init_ack).expect("wz parses its own InitAck") {
        InboundFrame::Init {
            is_ack: true,
            extensions,
            body,
            ..
        } => (extensions, body.cookie.clone()),
        other => panic!("the acceptor's reply is not an InitAck: {other:?}"),
    };
    // R2774 — the internal level is read from the COOKIE this InitAck carries.
    // Between InitAck and OpenSyn the acceptor no longer holds what it
    // negotiated, so the slot would report nothing; the cookie is where that
    // level now lives until the OpenSyn rebuilds it.
    let cookie = cookie
        .expect("the acceptor mints a carrying cookie")
        .to_vec();
    let carried = decode_accept_cookie(&fixture_session_init_params().cookie_signing_key, &cookie)
        .expect("the acceptor's own cookie verifies");
    let negotiated = carried
        .negotiated
        .patch
        .0
        .expect("an admitted InitSyn always agrees a level");
    let entry = extensions.iter().find_map(patch_of_entry);
    assert_eq!(
        entry.unwrap_or(0),
        peer_patch(&extensions),
        "the entry written is the level a peer reads"
    );
    assert_eq!(
        init_ack[0] & wire_const::FLAG_T_Z != 0,
        !extensions.is_empty(),
        "the InitAck's Z flag says whether an extension follows it, also when the patch \
         entry was lowered away: a Z with nothing behind it is an InitAck the peer cannot \
         decode"
    );
    (entry, negotiated)
}

/// A downgraded InitAck (one that carries no patch entry because the peer announced none)
/// still sets Z exactly when another extension follows, whatever else the acceptor answers
/// with; the control answers CURRENT, carries the entry and so sets Z.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_downgraded_init_ack_sets_z_only_when_an_extension_follows() {
    for (init_syn, downgraded) in [
        (craft_initsyn_wire(), true),
        (craft_initsyn_wire_with_patch(0), true),
        (craft_initsyn_wire_with_patch(1), false),
    ] {
        let driver = Arc::new(LifecycleRecordingDriver::default());
        let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = driver.clone();
        let actions =
            new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
        let mut engine = new_session_engine(&actions);
        engine.initialize().unwrap_or_else(|never| match never {});
        engine.process_event(E::InboundStart);
        let mut queue = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(init_syn))]);
        poll_and_dispatch_one(&mut queue, &actions, &mut engine).await;
        let init_ack = driver
            .snapshot()
            .sends
            .last()
            .expect("the acceptor answers an admitted InitSyn")
            .0
            .clone();
        let InboundFrame::Init {
            is_ack: true,
            has_ext,
            extensions,
            ..
        } = parse_inbound(&init_ack).expect("wz parses its own InitAck")
        else {
            panic!("the acceptor's reply is not an InitAck");
        };
        let z = init_ack[0] & wire_const::FLAG_T_Z != 0;
        assert_eq!(z, has_ext, "the parser reads the header's own Z");
        assert_eq!(
            z,
            !extensions.is_empty(),
            "downgraded={downgraded}: Z is set exactly when an extension follows"
        );
        assert_eq!(
            extensions.iter().find_map(patch_of_entry).is_none(),
            downgraded,
            "downgraded={downgraded}: a lowered level writes no patch entry"
        );
    }
}

/// THE DEFECT, on the wire: a peer announcing PATCH 0 must be answered 0.
///
/// `min(CURRENT=1, 0) = 0`, which is what zenoh's `send_init_ack` returns and
/// what pico's cap leaves in `iam`. Before R311y838 wz answered 1 here while
/// its own `negotiated_patch()` already said 0 — the two halves of the same
/// negotiation disagreeing, one of them on the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_announcing_patch_zero_is_answered_zero() {
    let (on_wire, negotiated) = acceptor_answers(craft_initsyn_wire_with_patch(0)).await;
    assert_eq!(
        negotiated, 0,
        "precondition: the min() already took the peer's level"
    );
    assert_eq!(
        on_wire, None,
        "zenoh answers min(CURRENT, peer) = 0 (ext/patch.rs:180-186) and writes \
         level 0 as no entry; an acceptor that answers 1 has announced markers \
         the peer never agreed to, and named a level both references refuse"
    );
}

/// The same rule reached the OTHER way a peer can decline the extension:
/// by not sending it. zenoh's `StateAccept::new()` starts at `PatchType::NONE`
/// and `recv_init_syn` only overwrites it when the ext is present, so an
/// absent extension and an explicit 0 are the same input to the `min`.
///
/// This arm is not a duplicate of the one above: `peer_patch` distinguishes
/// "no `0x7` entry" from "a `0x7` entry carrying 0" at the READ, and only this
/// arm proves the acceptor's answer collapses them the way upstream does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_sends_no_patch_ext_at_all_is_answered_zero() {
    let (on_wire, negotiated) = acceptor_answers(craft_initsyn_wire()).await;
    assert_eq!(negotiated, 0, "an absent ext reads as NO_PATCH");
    assert_eq!(
        on_wire, None,
        "a pre-patch peer gets upstream's level-0 answer, no entry, not wz's \
         own CURRENT"
    );
}

/// THE CONTROL that keeps the two above from being satisfied by an acceptor
/// that answers 0 unconditionally: a peer announcing CURRENT still gets
/// CURRENT, and the markers are still armed on a wz<->wz link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_announcing_current_is_still_answered_current() {
    let (on_wire, negotiated) = acceptor_answers(craft_initsyn_wire_with_patch(1)).await;
    assert_eq!(negotiated, 1, "min(1, 1) = 1");
    assert_eq!(
        on_wire,
        Some(1),
        "the fix lowers the answer to the peer's level; it must not lower it \
         past wz's own"
    );
}

/// THE SECOND CONTROL: the answer is a `min`, not an ECHO. A peer announcing a
/// FUTURE level is negotiated DOWN to wz's own — neither reference refuses it
/// (zenoh stores it unexamined, pico caps), and neither adopts it.
///
/// Without this arm, "derive the InitAck level from the peer" would pass while
/// meaning "answer whatever the peer said", which would put a level wz cannot
/// speak on the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_announcing_a_future_level_is_answered_wz_own_current() {
    let (on_wire, negotiated) = acceptor_answers(craft_initsyn_wire_with_patch(9)).await;
    assert_eq!(negotiated, 1, "min(1, 9) = 1 — capped, not refused");
    assert_eq!(
        on_wire,
        Some(1),
        "the acceptor answers its own CURRENT, never the peer's claim"
    );
}
