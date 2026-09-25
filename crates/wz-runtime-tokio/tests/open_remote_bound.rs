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
use wz_runtime_tokio::{LinkEvent, RxFrame};
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, LifecycleRecordingDriver, QueueDriver,
};
use wz_session_core::inbound::{parse_inbound, InboundFrame};
use wz_session_wire_fixtures::{
    craft_initsyn_wire_as_client, craft_opensyn_wire, craft_opensyn_wire_with_remote_bound,
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
