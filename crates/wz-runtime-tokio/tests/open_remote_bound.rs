// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-unicast",
    feature = "codec-init-body",
    feature = "codec-open-body"
))]

//! R2858 — the `0x7` REMOTE-BOUND a peer announces on its OpenSyn, read off
//! the WIRE by a real acceptor, and the `sessions[].region` it produces.
//!
//! # What is pinned
//!
//! `open::ext::RemoteBound = zextz64!(0x7, false)`
//! (`commons/zenoh-protocol/src/transport/open.rs`
//! @ `pub type RemoteBound = zextz64!(0x7, false);`) is the bound the sender
//! computed for us. Upstream's acceptor reads it while building its OpenSyn
//! output and `?`s an invalid one out with GENERIC
//! (`io/zenoh-transport/src/unicast/establishment/accept.rs`
//! @ `other_bound: match open_syn.ext_remote_bound {`), and `local_data`
//! renders the region `compute_region_of` derives from it.
//!
//! # Why the remote is a CLIENT
//!
//! The acceptor is a peer. For a peer holding a peer every arm answers
//! `north`, so the bound would be invisible. For a peer holding a client the
//! auto answer is `south:0:client`, and a client that calls us SOUTH moves
//! it to `north` — so the bound is visible in the answer, and a node that
//! ignored the extension would answer the auto region in both arms.
//!
//! # The send half (open-debt item 751)
//!
//! A node whose south is partitioned announces a bound for each peer on its own
//! Open: `compute_transient_bound_of` (`zenoh/src/net/runtime/region.rs`
//! @ `pub(crate) fn compute_transient_bound_of(`), run as the transport's bound
//! callback while it builds the OpenSyn or the OpenAck
//! (`io/zenoh-transport/src/unicast/establishment/open.rs`
//! @ `let ext_remote_bound = if let Some(callback) = self.ext_remote_bound.as_ref() {`).
//! Read here off the Open each role EMITS, parsed back with the production
//! reader, in both roles, with the auto preset as the control that announces
//! nothing and the one error the callback can raise refusing the handshake.

use std::sync::Arc;

use wz_codecs::wire_const::T_MID_CLOSE;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::CloseReason;
use wz_runtime_tokio::session_glue::{
    new_session_actions, new_session_engine, poll_and_dispatch_one, BoxedLinkDriver,
};
use wz_runtime_tokio::{LinkEvent, Reliability, RxFrame};
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, LifecycleRecordingDriver, QueueDriver,
};
use wz_session_core::extbound::{peer_remote_bound, Bound};
use wz_session_core::inbound::{parse_inbound, InboundFrame};
use wz_session_core::region_partition::{RegionFilter, SouthPartition, SouthSubregion};
use wz_session_core::WhatAmI;
use wz_session_wire_fixtures::{
    craft_initack_wire, craft_initsyn_wire_as_client, craft_opensyn_wire,
    craft_opensyn_wire_with_remote_bound, FIXTURE_LISTENER_ZID,
};

/// What the acceptor did with one OpenSyn: whether it reached Established,
/// the region it reports, and the Close reason if it refused.
struct Outcome {
    established: bool,
    region: String,
    close_reason: Option<u8>,
}

/// Drive a peer acceptor through a client's InitSyn and then the OpenSyn
/// `open_syn(cookie)` builds from the InitAck's cookie.
async fn acceptor_opens(open_syn: impl Fn(&[u8]) -> Vec<u8>) -> Outcome {
    let driver = Arc::new(LifecycleRecordingDriver::default());
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = driver.clone();
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    engine.process_event(E::InboundStart);

    let mut queue = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(
        craft_initsyn_wire_as_client(),
    ))]);
    poll_and_dispatch_one(&mut queue, &actions, &mut engine).await;
    let cookie = driver
        .snapshot()
        .sends
        .iter()
        .find_map(|(bytes, ..)| match parse_inbound(bytes) {
            Ok(InboundFrame::Init {
                is_ack: true, body, ..
            }) => body.cookie.map(|c| c.to_vec()),
            _ => None,
        })
        .expect("the acceptor answers a conforming InitSyn with a cookie");

    let mut queue = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(open_syn(&cookie)))]);
    poll_and_dispatch_one(&mut queue, &actions, &mut engine).await;

    let close_reason = driver.snapshot().sends.iter().find_map(|(bytes, ..)| {
        (bytes.first().map(|h| h & 0x1f) == Some(T_MID_CLOSE)).then(|| bytes[1])
    });
    Outcome {
        established: engine.get_current_state() == S::Established,
        region: actions.admin_region(),
        close_reason,
    }
}

/// No bound announced: the auto table, `south:0:client`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_no_bound_a_peer_places_a_client_in_its_south() {
    let out = acceptor_opens(craft_opensyn_wire).await;
    assert!(out.established, "a plain OpenSyn is admitted");
    assert_eq!(out.region, "south:0:client");
}

/// A client that calls us SOUTH is in our NORTH: this is the arm a node
/// ignoring the extension cannot pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_calls_us_south_is_in_our_north() {
    let out = acceptor_opens(|c| craft_opensyn_wire_with_remote_bound(c, 1)).await;
    assert!(out.established, "a valid bound is admitted");
    assert_eq!(out.region, "north");
}

/// Called north, the auto answer stands, because the auto preset also calls
/// a client our south's member with a north bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_calls_us_north_keeps_the_auto_region() {
    let out = acceptor_opens(|c| craft_opensyn_wire_with_remote_bound(c, 0)).await;
    assert!(out.established);
    assert_eq!(out.region, "south:0:client");
}

/// `ext.value as u8` truncates: 257 is read as 1, south, and admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_value_past_one_byte_is_truncated_as_upstream_truncates_it() {
    let out = acceptor_opens(|c| craft_opensyn_wire_with_remote_bound(c, 257)).await;
    assert!(out.established, "257 truncates to a valid bound");
    assert_eq!(out.region, "north");
}

/// Neither bound after truncation: the handshake is REFUSED with GENERIC,
/// not admitted with the value ignored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invalid_bound_refuses_the_handshake() {
    let out = acceptor_opens(|c| craft_opensyn_wire_with_remote_bound(c, 2)).await;
    assert!(
        !out.established,
        "an invalid bound must not reach Established"
    );
    assert_eq!(
        out.close_reason,
        Some(CloseReason::Generic as u8),
        "an extension reject closes GENERIC"
    );
}

// ── the send half (open-debt item 751) ──

/// The bound an Open in `sends` announces, read with the production reader:
/// `Some(None)` when the Open carries no entry, `None` when no Open of that
/// kind was sent.
fn announced_on_open(sends: &[(Vec<u8>, Reliability)], is_ack: bool) -> Option<Option<Bound>> {
    sends
        .iter()
        .find_map(|(bytes, ..)| match parse_inbound(bytes) {
            Ok(InboundFrame::Open {
                is_ack: ack,
                extensions,
                ..
            }) if ack == is_ack => {
                Some(peer_remote_bound(&extensions).expect("wz's own emit is a valid bound"))
            }
            _ => None,
        })
}

/// One subregion with no filters: it matches every remote.
fn one_open_subregion() -> SouthPartition {
    SouthPartition::Custom(vec![SouthSubregion { filters: None }])
}

/// One subregion holding exactly the remote whose wire zid is `zid`.
fn only_zid(zid: &[u8]) -> SouthPartition {
    SouthPartition::Custom(vec![SouthSubregion {
        filters: Some(vec![RegionFilter {
            zids: Some(vec![zid.to_vec()]),
            ..RegionFilter::default()
        }]),
    }])
}

/// What an initiator of role `whatami`, south partitioned as `partition`, did
/// with an InitAck from a remote of role `remote` (as the fixture's listener
/// zid): the bound its OpenSyn announced, the Close reason if it refused, and
/// the outcome the drive loop reported.
async fn initiator_answers(
    whatami: WhatAmI,
    partition: SouthPartition,
    remote: WhatAmI,
) -> (Option<Option<Bound>>, Option<u8>, String) {
    let driver = Arc::new(LifecycleRecordingDriver::default());
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = driver.clone();
    let mut params = fixture_session_init_params();
    params.whatami = whatami;
    let actions = new_session_actions(outbound, params, TokioTime::new());
    actions.set_south_partition(partition);
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);
    assert_eq!(engine.get_current_state(), S::SentInitSyn);

    // The fixture's InitAck is a peer's; its cbyte carries the role in the low
    // two bits (Router 0, Peer 1, Client 2) over the zid length.
    let mut init_ack = craft_initack_wire(&[0xC0, 0x01]);
    init_ack[2] = (init_ack[2] & !0x03) | remote.to_wire();
    let mut queue = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(init_ack))]);
    let outcome = poll_and_dispatch_one(&mut queue, &actions, &mut engine).await;

    let sends = driver.snapshot().sends;
    let close_reason = sends.iter().find_map(|(bytes, ..)| {
        (bytes.first().map(|h| h & 0x1f) == Some(T_MID_CLOSE)).then(|| bytes[1])
    });
    (
        announced_on_open(&sends, false),
        close_reason,
        format!("{outcome:?}"),
    )
}

/// What a peer acceptor, south partitioned as `partition`, announced on the
/// OpenAck it answered a client's handshake with, and whether it established.
async fn acceptor_announces(partition: SouthPartition) -> (Option<Option<Bound>>, bool) {
    let driver = Arc::new(LifecycleRecordingDriver::default());
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = driver.clone();
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    actions.set_south_partition(partition);
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    engine.process_event(E::InboundStart);

    let mut queue = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(
        craft_initsyn_wire_as_client(),
    ))]);
    poll_and_dispatch_one(&mut queue, &actions, &mut engine).await;
    let cookie = driver
        .snapshot()
        .sends
        .iter()
        .find_map(|(bytes, ..)| match parse_inbound(bytes) {
            Ok(InboundFrame::Init {
                is_ack: true, body, ..
            }) => body.cookie.map(|c| c.to_vec()),
            _ => None,
        })
        .expect("the acceptor answers a conforming InitSyn with a cookie");
    let mut queue = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_opensyn_wire(
        &cookie,
    )))]);
    poll_and_dispatch_one(&mut queue, &actions, &mut engine).await;
    (
        announced_on_open(&driver.snapshot().sends, true),
        engine.get_current_state() == S::Established,
    )
}

/// The control: a node on the `auto` preset announces nothing, in either role,
/// which is what every stock node does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_on_the_auto_preset_announces_no_bound() {
    let (announced, close, _) =
        initiator_answers(WhatAmI::Router, SouthPartition::Auto, WhatAmI::Router).await;
    assert_eq!(announced, Some(None), "an OpenSyn went out, with no bound");
    assert_eq!(close, None);
    let (announced, established) = acceptor_announces(SouthPartition::Auto).await;
    assert_eq!(announced, Some(None), "an OpenAck went out, with no bound");
    assert!(established);
}

/// An initiator router whose rule places the remote router in a subregion tells
/// it so: SOUTH, which the remote reads as "I am south of you".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_initiator_announces_south_for_a_remote_its_rule_places_south() {
    let (announced, close, _) =
        initiator_answers(WhatAmI::Router, one_open_subregion(), WhatAmI::Router).await;
    assert_eq!(announced, Some(Some(Bound::South)));
    assert_eq!(close, None);
}

/// A rule that matches no remote leaves it north, and the bound says so: an
/// entry valued NORTH, not an absent one, because the node has a rule.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_initiator_with_a_rule_that_matches_nobody_announces_north() {
    let (announced, close, _) = initiator_answers(
        WhatAmI::Router,
        SouthPartition::Custom(vec![]),
        WhatAmI::Router,
    )
    .await;
    assert_eq!(announced, Some(Some(Bound::North)));
    assert_eq!(close, None);
}

/// The rule reads the remote's zid as it arrived on the InitAck: the listener's
/// zid is placed south, any other zid is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_rule_reads_the_zid_the_remote_sent() {
    let (announced, _, _) = initiator_answers(
        WhatAmI::Router,
        only_zid(&FIXTURE_LISTENER_ZID),
        WhatAmI::Peer,
    )
    .await;
    assert_eq!(announced, Some(Some(Bound::South)), "the listener matches");
    let (announced, _, _) =
        initiator_answers(WhatAmI::Router, only_zid(&[0x55; 4]), WhatAmI::Peer).await;
    assert_eq!(announced, Some(Some(Bound::North)), "another zid does not");
}

/// The acceptor announces too, on its OpenAck, decided from the facts its
/// cookie brought back: a client placed in the one open subregion is SOUTH.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_acceptor_announces_its_bound_on_the_open_ack() {
    let (announced, established) = acceptor_announces(one_open_subregion()).await;
    assert_eq!(announced, Some(Some(Bound::South)));
    assert!(
        established,
        "announcing a bound does not refuse the session"
    );
}

/// The callback's one error: a router remote matched by a subregion of a node
/// that is not a router. Upstream fails the handshake GENERIC instead of
/// sending its Open, and so does wz.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_whose_rule_places_a_router_in_its_south_refuses_the_handshake() {
    let (announced, close, outcome) =
        initiator_answers(WhatAmI::Peer, one_open_subregion(), WhatAmI::Router).await;
    assert_eq!(announced, None, "no OpenSyn is sent");
    assert_eq!(close, Some(CloseReason::Generic as u8));
    assert!(
        outcome.starts_with("OpenLocalBoundUnplaceable(RouterSubregionOfNonRouter"),
        "{outcome}"
    );
    // The same peer with a remote PEER is placed and announces south: the
    // refusal is the router's, not the rule's.
    let (announced, close, _) =
        initiator_answers(WhatAmI::Peer, one_open_subregion(), WhatAmI::Peer).await;
    assert_eq!(announced, Some(Some(Bound::South)));
    assert_eq!(close, None);
}
