// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ep — Layer M: active-scouting multicast loopback e2e.
//!
//! Exercises the full scout-initiator path end-to-end over a real UDP
//! multicast socket: `UdpDriver::bind_multicast_v4` (join + loop) ->
//! `scout_emit` encode + multicast send -> `poll_event` recv -> Hello
//! decode in `record_hello_and_emit` -> discovered locator. A blind
//! "responder" socket models a peer replying with a Hello on the group.
//!
//! Opt-in only (`#[ignore]`, driven by `scripts/run-ci.sh --layer M` /
//! `WZ_RUN_LAYER_M=1`): multicast routing is environment-dependent (a
//! container without a multicast route on the default interface drops the
//! join), so this must not be a default-gate (no-flaky rule). The
//! deterministic FSM + encode/decode logic is covered without a socket by
//! the `scouting_glue` unit tests in the library crate.
//!
//! Gated on `scouting-active`: the whole file is empty under the default
//! feature set, so Layer C1's `cargo test --workspace` does not build it;
//! the Layer M lane builds it with `--features scouting-active`.
#![cfg(feature = "scouting-active")]

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::net::UdpSocket;
use wz_codecs::hello::HelloOwned;
use wz_codecs::locator::LocatorOwned;
use wz_codecs::wire_const;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::scouting_glue::{
    drive_scouting_until_resolved, new_scouting_engine, ScoutOutcome, ScoutingActions,
};
use wz_runtime_tokio::UdpDriver;
use wz_session_core::scout_params::ScoutParams;

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 224);
const PORT: u16 = 7446;
const PEER_LOCATOR: &str = "udp/127.0.0.1:7447";

/// Build a `[S_MID_HELLO|L][version][cbyte][zid][VLE 1][locator]` Hello
/// datagram carrying one locator (mirror of the layer3_hello wire shape).
fn craft_hello_datagram(locator: &str) -> Vec<u8> {
    let zid = vec![0x01, 0x02, 0x03];
    let cbyte = 0x01 | (((zid.len() as u8) - 1) << 4); // whatami=peer | zid_len_m1
    let body = HelloOwned {
        version: 0x09,
        cbyte,
        zid,
        num_locators: Some(1),
        locators: Some(vec![LocatorOwned {
            locator_len: locator.len() as u64,
            locator: locator.to_string(),
        }]),
    }
    .try_as_borrowed()
    .expect("borrowed projection of owned Hello")
    .encode_to_vec(1 /* L flag projected */);

    let mut dgram = Vec::with_capacity(1 + body.len());
    dgram.push(wire_const::S_MID_HELLO | wire_const::FLAG_S_HELLO_L);
    dgram.extend_from_slice(&body);
    dgram
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "multicast loopback e2e; Layer M runs via --layer M / WZ_RUN_LAYER_M=1 --ignored"]
async fn scout_discovers_peer_locator_over_multicast() {
    // Scout side: bind the group port, join the group, loopback on.
    let mut driver = UdpDriver::bind_multicast_v4(GROUP, PORT)
        .await
        .expect("bind multicast scouting link");
    let actions = ScoutingActions::new(ScoutParams {
        version: 0x09,
        what: 0x03, // ROUTER | PEER
        zid: vec![0xAA, 0xBB, 0xCC, 0xDD],
    });
    let mut engine = new_scouting_engine(&actions);

    // Responder: an ephemeral socket (no group-port bind, so no
    // SO_REUSEADDR contention) that sends a Hello to the group once the
    // scout is in AwaitingHello.
    let responder = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .expect("bind ephemeral responder");
    let hello = craft_hello_datagram(PEER_LOCATOR);
    let responder_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        responder
            .send_to(&hello, (GROUP, PORT))
            .await
            .expect("responder send Hello to group");
    });

    let clock = TokioTime::new();
    let outcome = drive_scouting_until_resolved(
        &mut driver,
        &actions,
        &mut engine,
        &clock,
        Some(10_000), // iteration guard so a missing Hello cannot hang CI
        50,           // scheduler-tick cadence (ms); window itself is SCXML-owned
    )
    .await;

    responder_task.await.expect("responder task");

    assert_eq!(
        outcome,
        ScoutOutcome::Discovered(PEER_LOCATOR.to_string()),
        "scout should resolve the peer locator from the Hello"
    );
    let trace = actions.trace_snapshot();
    assert_eq!(trace.scout_emit, 1, "exactly one Scout emitted");
    assert_eq!(trace.record_hello, 1, "exactly one Hello recorded");
    assert_eq!(trace.tx_failed, 0, "multicast send succeeded");
}
