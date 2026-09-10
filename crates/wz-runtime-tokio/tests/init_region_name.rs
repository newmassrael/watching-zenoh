// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-unicast", feature = "codec-init-body"))]

//! R2539 — the `0x8` REGION-NAME identity a wz node puts on the Init WIRE,
//! and the peer's it reads back off one.
//!
//! # The residual this closes
//!
//! `session-unicast-open`'s last named residual, opened by R2437's
//! re-derivation at the pin: the pin ADDED an establishment extension wz had
//! never heard of. `init::ext::RegionName = zextzbuf!(0x8, false)`
//! (`commons/zenoh-protocol/src/transport/init.rs`
//! @ `pub ext_region_name: Option<ext::RegionName>`), a node's region identity
//! carried on BOTH InitSyn and InitAck. wz neither
//! emitted nor surfaced it; `region_name` existed only as an unhonoured
//! config key.
//!
//! # ⛔ zenoh is the ONLY reference, and it is measured rather than assumed
//!
//! zenoh-pico has no region identity: the vendored submodule's `src/` and
//! `include/` carry the word only in prose about non-contiguous MEMORY
//! regions. This atom has taken the same discriminator twice before — GENERIC
//! over pico's silence for the establishment Close's reason byte (R311y823),
//! and a LINK scope for its session flag (R2389) — so the rule here is
//! zenoh's, unopposed rather than chosen between references.
//!
//! # What is read, and off what
//!
//! The level is read off the EMITTED BYTES, parsed back with the production
//! [`parse_inbound`] and projected with [`peer_region`] — the same reader a
//! peer would use. Reading the staged slot instead would assert the fix
//! against its own input, which is the trap R311y838 recorded on the
//! neighbouring `0x7` extension.

use std::sync::Arc;

use wz_codecs::wire_const::T_MID_CLOSE;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::SessionFsmUnicastEvent as E;
use wz_runtime_tokio::session_glue::CloseReason;
use wz_runtime_tokio::session_glue::{
    new_session_actions, new_session_engine, poll_and_dispatch_one, BoxedLinkDriver,
};
use wz_runtime_tokio::{LinkEvent, RxFrame};
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, LifecycleRecordingDriver, QueueDriver,
};
use wz_session_core::extregion::{peer_region, RegionName, MAX_REGION_NAME_LEN};
use wz_session_core::inbound::{parse_inbound, InboundFrame};
use wz_session_wire_fixtures::{craft_initsyn_wire, craft_initsyn_wire_with_region};

/// Drive an acceptor through ONE InitSyn and return `(the region name it wrote
/// on the InitAck wire, the peer identity it recorded)`.
///
/// Both are returned together on purpose: the emit and the read are the two
/// halves this file pins, and a test that saw only one could not tell a node
/// that announces its identity from one that merely stores the peer's.
async fn acceptor_answers(
    local: Option<&str>,
    init_syn_wire: Vec<u8>,
) -> (Option<RegionName>, Option<RegionName>, Option<u8>) {
    let driver = Arc::new(LifecycleRecordingDriver::default());
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = driver.clone();
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    if let Some(local) = local {
        actions.set_local_region(Some(RegionName::new(local).expect("a valid fixture name")));
    }
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    engine.process_event(E::InboundStart);

    let mut queue = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(init_syn_wire))]);
    poll_and_dispatch_one(&mut queue, &actions, &mut engine).await;

    // ⚠ A REFUSED InitSyn is not a silent one. The reject leaves through
    // `establishment.ext_rejected` into Closing, whose onentry puts a Close on
    // the wire (R311y823) — so the answer to "was it refused" is a Close
    // frame, not an absent send. The first draft of this harness assumed
    // silence and its three refusal arms failed on that assumption rather than
    // on the product, which is how the Close reason came to be graded here at
    // all.
    let sent = driver.snapshot().sends;
    let mut announced = None;
    let mut close_reason = None;
    for (bytes, ..) in &sent {
        if bytes.first().map(|h| h & 0x1f) == Some(T_MID_CLOSE) {
            assert_eq!(bytes.len(), 2, "Close is a header plus one reason byte");
            close_reason = Some(bytes[1]);
            continue;
        }
        if let Ok(InboundFrame::Init {
            is_ack: true,
            extensions,
            ..
        }) = parse_inbound(bytes)
        {
            announced = peer_region(&extensions).expect("wz's own emit is a valid region");
        }
    }
    (announced, actions.peer_region(), close_reason)
}

/// THE EMIT: a node with a region identity announces it on the InitAck.
///
/// zenoh's acceptor returns `self.region_name.clone().map(name_to_ext)` from
/// `send_init_ack`
/// (`io/zenoh-transport/src/unicast/establishment/ext/region_name.rs`
/// @ `fn send_init_ack`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_with_a_region_announces_it_on_the_init_ack() {
    let (announced, _peer, close) = acceptor_answers(Some("north"), craft_initsyn_wire()).await;
    assert_eq!(
        announced.as_ref().map(RegionName::as_str),
        Some("north"),
        "the identity must reach the WIRE, not merely the session",
    );
    assert_eq!(close, None, "a conforming InitSyn is not closed");
}

/// THE ABSENCE, which is a separate claim: a node WITHOUT a region emits no
/// entry at all. Upstream's `Option` is what says so — there is no empty
/// region name, and `RegionName::validate` refuses one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_without_a_region_announces_nothing() {
    let (announced, _peer, close) = acceptor_answers(None, craft_initsyn_wire()).await;
    assert_eq!(announced, None);
    assert_eq!(close, None, "announcing nothing is not a refusal");
}

/// THE READ: the peer's identity is taken off its InitSyn and surfaced.
///
/// zenoh's `AcceptFsm::recv_init_syn` stores it as `other_region_name`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_peers_region_is_read_off_its_init_syn() {
    let (_announced, peer, _close) =
        acceptor_answers(None, craft_initsyn_wire_with_region(b"south-2")).await;
    assert_eq!(
        peer.as_ref().map(RegionName::as_str),
        Some("south-2"),
        "the acceptor must surface the identity the peer announced",
    );
}

/// The two halves are INDEPENDENT: a node announces its OWN identity, it does
/// not echo the peer's. This is the arm that would catch a reflection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_answer_is_this_nodes_identity_and_not_the_peers() {
    let (announced, peer, _close) =
        acceptor_answers(Some("north"), craft_initsyn_wire_with_region(b"south-2")).await;
    assert_eq!(announced.as_ref().map(RegionName::as_str), Some("north"));
    assert_eq!(peer.as_ref().map(RegionName::as_str), Some("south-2"));
}

/// THE REFUSAL, and it is the half a reader gets backwards: an entry that is
/// PRESENT and malformed fails the handshake. Upstream's receive arms are
/// `ext.map(ext_to_name).transpose()?` on both roles, so an empty value
/// propagates an error out of the FSM rather than reading as "no region".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_region_value_is_refused_rather_than_read_as_absent() {
    let (announced, peer, close) =
        acceptor_answers(None, craft_initsyn_wire_with_region(b"")).await;
    assert_eq!(
        peer, None,
        "a refused Init must not leave its value in the session",
    );
    assert_eq!(
        announced, None,
        "a refused InitSyn is not answered with an InitAck",
    );
    assert_eq!(
        close,
        Some(CloseReason::Generic as u8),
        "an EXTENSION reject closes GENERIC, not the body's INVALID -- the \
         split this atom established at R311y823",
    );
}

/// The same refusal for a value over upstream's ceiling. Driven at
/// `MAX + 1` and paired with the acceptance at `MAX` below, because a
/// boundary graded from one side cannot tell "at the limit" from "over" it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_over_long_region_value_is_refused() {
    let over = vec![b'x'; MAX_REGION_NAME_LEN + 1];
    let (announced, peer, close) =
        acceptor_answers(None, craft_initsyn_wire_with_region(&over)).await;
    assert_eq!(peer, None);
    assert_eq!(announced, None);
    assert_eq!(close, Some(CloseReason::Generic as u8));
}

/// The other side of that boundary: exactly `MAX_LEN` is ACCEPTED, because
/// upstream's rule is `len() > MAX_LEN`. Without this arm the refusal above
/// would also pass an implementation that refused every region name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_region_value_at_the_ceiling_is_accepted() {
    let at = vec![b'x'; MAX_REGION_NAME_LEN];
    let (_announced, peer, _close) =
        acceptor_answers(None, craft_initsyn_wire_with_region(&at)).await;
    assert_eq!(
        peer.as_ref().map(RegionName::as_str),
        Some(core::str::from_utf8(&at).expect("ascii")),
        "the ceiling itself is a valid name",
    );
}

/// A non-UTF-8 value is the third arm of upstream's `ext_to_name`, reached
/// through `String::from_utf8`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_utf8_region_value_is_refused() {
    let (announced, peer, close) =
        acceptor_answers(None, craft_initsyn_wire_with_region(&[0xff, 0xfe])).await;
    assert_eq!(peer, None);
    assert_eq!(announced, None);
    assert_eq!(close, Some(CloseReason::Generic as u8));
}

/// THE NARROWING CONTROL: an InitSyn carrying NO region ext is admitted and
/// answered as usual. Without it every refusal above would also pass an
/// acceptor that refused every InitSyn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_init_syn_with_no_region_ext_is_admitted_normally() {
    let (announced, peer, close) = acceptor_answers(Some("north"), craft_initsyn_wire()).await;
    assert_eq!(peer, None, "the peer announced none");
    assert_eq!(close, None, "the narrowing control must NOT be refused");
    assert_eq!(
        announced.as_ref().map(RegionName::as_str),
        Some("north"),
        "and the handshake still completed far enough to emit an InitAck",
    );
}
