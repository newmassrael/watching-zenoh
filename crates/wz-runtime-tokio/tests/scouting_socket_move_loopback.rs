// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2142 (open-debt item 225) — Layer M: a scouting socket MOVED BY CONFIG,
//! witnessed from BOTH ends, plus the reason the obvious probe for it is
//! vacuous.
//!
//! ## What was missing
//!
//! `scouting/multicast/address` moves the scouting socket. Three lanes already
//! touch that key and none of them witnesses it between two wz nodes:
//!
//! * the config reader's tests prove it PARSES and round-trips;
//! * the demo's tests prove it reaches `--scout-addr`;
//! * `scouting_multicast_loopback.rs` proves a wz SCOUTER joins the moved
//!   group — but the thing that answers it there is a hand-rolled
//!   `UdpSocket::send_to`, not a wz node.
//!
//! So the ANSWERING half on a moved socket was never driven, and the two-node
//! question an operator actually asks — *"I moved the group on both boxes; do
//! they still find each other?"* — had no lane at all. That is item 225.
//!
//! ## ⛔ Why a group-only probe cannot answer it (the second test here)
//!
//! The obvious probe is "move the group and see if the stranger goes quiet".
//! On Linux it does not, and a test built that way reports success for the very
//! defect it exists to catch. `IP_MULTICAST_ALL` (ip(7), default 1) delivers to
//! a WILDCARD-bound socket every group joined *globally on the host*, not the
//! groups that socket itself joined. wz binds `0.0.0.0:port`
//! (`lib.rs` `bind_multicast_v4`) and so does zenoh
//! (`io/zenoh-links/zenoh-link-udp/src/multicast.rs:308-312`), and NEITHER sets
//! `IP_MULTICAST_ALL` — so this is upstream-faithful behaviour, not a wz defect,
//! and the fix is emphatically NOT to diverge by clearing the option.
//!
//! ⚠ The precondition matters and the register entry omitted it: the leak needs
//! a CO-JOINER — some socket on the host holding the other group on that port.
//! Measured 2026-08-27 on this machine, all three arms:
//!
//! | arrangement                                   | delivered |
//! |-----------------------------------------------|-----------|
//! | same port, other group, NO co-joiner          | no        |
//! | same port, other group, co-joiner present     | **yes**   |
//! | same port, other group, co-joiner + ALL=0     | no        |
//!
//! A loopback two-node lane is exactly the co-joiner case — the node that moved
//! IS the socket holding the other group — which is why a group-only control
//! passes there while proving nothing. **The PORT is the axis that isolates.**
//! The second test below pins both halves of that so the vacuous probe cannot
//! be rebuilt: moving only the group leaves the responder reachable, moving the
//! port silences it.
//!
//! ## The third test — the `#join=` axis
//!
//! Paid here rather than filed, because it is the same seam: `extra_joins` is a
//! field of the same config struct, installed on the same socket. Its refusal
//! path had a unit test and its DELIVERY had none. Its control is only
//! meaningful BECAUSE of the measurement above -- with nothing else holding the
//! extra group, the responder's own join is the only thing that can deliver the
//! Scout, which is exactly what the control takes away.
//!
//! Opt-in (`#[ignore]`, run-ci Layer M / `WZ_RUN_LAYER_M=1`) like every
//! multicast e2e here: a container with no multicast route drops the join, and
//! that is the environment rather than this code.
//!
//! Each arm owns DISTINCT ports. The scouting port is inherently multi-listener
//! (`bind_multicast_v4` sets `SO_REUSEPORT`), so two arms sharing one would each
//! be asserting about the other's datagrams.
#![cfg(all(feature = "scouting-active", feature = "scouting-responder"))]

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use wz_codecs::scout::Scout;
use wz_codecs::whatami::WhatAmI;
use wz_codecs::wire_const;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::scouting_glue::{
    drive_scouting_until_resolved, new_scouting_engine, ScoutOutcome, ScoutingActions,
};
use wz_runtime_tokio::scouting_responder::{serve, ResponderStep, ScoutingResponder};
use wz_runtime_tokio::{McastSocketConfig, UdpDriver};
use wz_session_core::scout_params::ScoutParams;
use wz_session_core::scout_responder::ResponderIdentity;

/// zenoh's compiled-in scouting group — what a node that was NOT told to move
/// stays on (`Z_CONFIG_MULTICAST_LOCATOR_DEFAULT`).
const HOME_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 224);
/// Where an operator moves it to. Not `.225` / `.226` / `.99`, which the sibling
/// Layer M binaries already hold.
const MOVED_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 231);

/// NOT zenoh's 7446, for the reason the autoconnect lane states: a developer
/// running a zenohd on this host would otherwise answer the scout, and the
/// witness would credit a node it did not arrange. One port per arm, because the
/// arms run in one binary under cargo's default multi-thread.
const A_MOVED_PORT: u16 = 17476;
const A_HOME_PORT: u16 = 17477;
const B_SHARED_PORT: u16 = 17478;
const B_HOME_PORT: u16 = 17479;
const B_MOVED_PORT: u16 = 17480;
const C_JOINED_PORT: u16 = 17482;
const C_UNJOINED_PORT: u16 = 17483;

/// The `#join=` test's own group, and it must be one NOTHING ELSE HOLDS.
///
/// ⛔ Measured the hard way (R2142): this test first used `MOVED_GROUP`, and its
/// CONTROL failed inside the file's concurrent run while passing alone. A
/// multicast membership is per `(group, device)` and NOT per port, so the two
/// sibling tests above — which legitimately hold `MOVED_GROUP` while they run —
/// put that group on the host, and `IP_MULTICAST_ALL` then delivered the control
/// arm's Scout to a socket that had joined nothing. A distinct PORT does not
/// save it; only a distinct GROUP does.
///
/// Organization-local scope (239.0.0.0/8, RFC2365), which no other test, lane,
/// or zenoh default touches — the same remedy, and the same reasoning, as
/// `multicast_pubsub_loopback.rs`'s iface pin.
const C_EXTRA_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 225, 7);

/// The locator the answering node advertises. Nothing binds it — it is the
/// payload that makes a discovery ATTRIBUTABLE: the scouting node learns this
/// string by no other route, so `Discovered(_)` carrying it can only have come
/// from decoding this responder's Hello.
const WZ_LOCATOR: &str = "tcp/127.0.0.1:17481";
const WZ_ZID: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
const SCOUT_ZID: &[u8] = &[0xBB, 0xBB, 0xBB, 0xBB];

/// Roles, API form (`zenoh-codec` `scouting/scout.rs:48`).
const WHAT_ROUTER: u8 = 0b001;
const WHAT_PEER: u8 = 0b010;

/// The drive loop's bounded ITERATION budget — not a duration. What ends an arm
/// is `ScoutParams::timeout_ms` above; this is the test guard that stops a
/// wedged loop from spinning forever, and exhausting it yields
/// `ScoutOutcome::IterationLimit`, which is neither of the two verdicts asserted
/// below. Matches the sibling loopback lane's budget.
const SCOUT_ITER_CAP: usize = 10_000;

fn wz_identity() -> ResponderIdentity {
    ResponderIdentity::try_new(
        0x09,
        WhatAmI::Peer,
        WZ_ZID.to_vec(),
        vec![WZ_LOCATOR.to_string()],
    )
    .expect("the identity shape is well-formed")
}

/// A Scout datagram in the shape wz's `scout_emit` and zenoh's `Runtime::scout`
/// both put on the group.
fn scout_datagram(what: u8) -> Vec<u8> {
    let mut scout = Scout::new();
    scout.version = 0x09;
    scout.set_what(what);
    let body = scout.encode_to_vec();
    let mut wire = vec![wire_const::S_MID_SCOUT];
    wire.extend_from_slice(&body);
    wire
}

/// An ephemeral socket that never joins a group — a stranger asking.
async fn foreign_scouter() -> UdpSocket {
    UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .expect("bind an ephemeral foreign scouter")
}

/// Hold a membership in `group` on `port` without reading it.
///
/// This is the CO-JOINER the module doc names: the node on the other side of the
/// move. Its only job is to make the host hold that group, which is the
/// precondition `IP_MULTICAST_ALL` needs. The returned driver must stay ALIVE —
/// dropping it drops the membership and the leak disappears with it.
async fn co_joiner(group: Ipv4Addr, port: u16) -> UdpDriver {
    UdpDriver::bind_multicast_v4(group, port, McastSocketConfig::default())
        .await
        .expect("bind + join as the co-joiner")
}

/// ONE end-to-end run between TWO REAL wz NODES.
///
/// The answering node is a real `ScoutingResponder` on `resp`; the asking node
/// is a real scouting engine driving a real socket aimed at `scout`. Both halves
/// are wz — that is the whole point of item 225, and what every prior lane
/// substituted a hand-rolled socket for on one side.
///
/// The scouter sends from an EPHEMERAL port (`bind_multicast_tx_v4`, upstream's
/// `ucast_sock`). It must: the responder replies unicast to the datagram's
/// source, and if the scouter had bound the group port instead — which the
/// responder also binds, with `SO_REUSEPORT` — the kernel would hand that reply
/// to whichever of the two it chose, and the verdict would be a coin flip.
async fn discover(scout: (Ipv4Addr, u16), resp: (Ipv4Addr, u16)) -> ScoutOutcome {
    let responder = ScoutingResponder::new(co_joiner(resp.0, resp.1).await, wz_identity());
    let responding = async {
        serve(responder, |_step| {}).await;
        // PARKED: only the scouting arm may complete the `select!` below, or a
        // run could finish with no outcome to assert on.
        std::future::pending::<()>().await
    };

    let mut scout_driver =
        UdpDriver::bind_multicast_tx_v4(scout.0, scout.1, McastSocketConfig::default())
            .await
            .expect("bind the scouting sender");
    let actions = ScoutingActions::new(ScoutParams {
        version: 0x09,
        what: WHAT_ROUTER | WHAT_PEER,
        zid: SCOUT_ZID.to_vec(),
        timeout_ms: 500,
        exit_on_first: true,
    });
    let mut engine = new_scouting_engine(&actions);
    let clock = TokioTime::new();
    let scouting = drive_scouting_until_resolved(
        &mut scout_driver,
        &actions,
        &mut engine,
        &clock,
        Some(SCOUT_ITER_CAP),
        50,
    );

    tokio::select! {
        outcome = scouting => outcome,
        _ = responding => unreachable!("the responder arm parks after returning"),
    }
}

/// THE LANE ITEM 225 ASKS FOR: both nodes told to move, and the control that
/// makes it a measurement.
///
/// Both arms are in ONE test on purpose. A separately-`#[ignore]`d control is a
/// control that can be skipped alone, and the positive arm passes in the world
/// where wz ignores the configured address entirely.
///
///   POSITIVE — both nodes moved onto the same socket  -> discovered.
///   CONTROL  — only the asker moved, answerer left home -> nothing.
///
/// The control is what fails if wz stays on its compiled-in socket: a node that
/// ignored the config would sit on `HOME` alongside the answerer and discover it
/// in BOTH arms.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "multicast loopback e2e; Layer M runs via --layer M / WZ_RUN_LAYER_M=1 --ignored"]
async fn two_nodes_moved_onto_one_socket_find_each_other_and_a_lone_mover_finds_nothing() {
    // POSITIVE: both ends were told the same new address.
    assert_eq!(
        discover((MOVED_GROUP, A_MOVED_PORT), (MOVED_GROUP, A_MOVED_PORT)).await,
        ScoutOutcome::Discovered(WZ_LOCATOR.to_string()),
        "two wz nodes both configured onto {MOVED_GROUP}:{A_MOVED_PORT} did not find \
         each other, so the configured address never reached both sockets"
    );

    // CONTROL: only the asker moved. The answerer is still on zenoh's group, on
    // a port the asker never speaks to, so an honouring node hears nothing.
    assert_eq!(
        discover((MOVED_GROUP, A_MOVED_PORT), (HOME_GROUP, A_HOME_PORT)).await,
        ScoutOutcome::TimedOut,
        "a node moved to {MOVED_GROUP}:{A_MOVED_PORT} still discovered one left on \
         {HOME_GROUP}:{A_HOME_PORT}, so it never left its compiled-in socket and the \
         positive arm above proves nothing"
    );
}

/// ⛔ THE DAMAGED PROBE, MADE EXECUTABLE — item 225's core.
///
/// This is not a wz behaviour under test; it is a TEST-DESIGN fact pinned so the
/// vacuous probe cannot be written again. See the module doc for the mechanism
/// and the three-arm measurement behind it.
///
///   ARM 1 — group moved, port SHARED, co-joiner present -> still answers.
///           A control built on the group alone would pass here on a node that
///           honoured nothing, which is what makes it vacuous.
///   ARM 2 — group AND port moved                        -> silent.
///           The same arrangement one axis further, showing the witness CAN
///           produce a negative — without which ARM 1 would just be a test that
///           always sees an answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "multicast loopback e2e; Layer M runs via --layer M / WZ_RUN_LAYER_M=1 --ignored"]
async fn moving_only_the_group_leaves_a_responder_reachable_but_moving_the_port_does_not() {
    // ── ARM 1: the group differs, the port does not. ──
    // Held in a binding, not `_`: dropping it drops the membership, and the leak
    // it creates is the entire point of the arm.
    let _mover = co_joiner(MOVED_GROUP, B_SHARED_PORT).await;
    let mut stranger =
        ScoutingResponder::new(co_joiner(HOME_GROUP, B_SHARED_PORT).await, wz_identity());
    let asker = foreign_scouter().await;
    asker
        .send_to(
            &scout_datagram(WHAT_ROUTER | WHAT_PEER),
            (MOVED_GROUP, B_SHARED_PORT),
        )
        .await
        .expect("scout the MOVED group");

    let step = timeout(Duration::from_secs(5), stranger.answer_next()).await;
    assert!(
        matches!(step, Ok(ResponderStep::Answered { .. })),
        "a responder on {HOME_GROUP} did NOT answer a Scout sent to {MOVED_GROUP} on the \
         shared port {B_SHARED_PORT}, got {step:?}. If this ever fails, IP_MULTICAST_ALL \
         no longer holds here and a group-only control has BECOME meaningful — re-read \
         the module doc before trusting one."
    );

    // ── ARM 2: the port differs too. ──
    let _mover_b = co_joiner(MOVED_GROUP, B_MOVED_PORT).await;
    let mut stranger_b =
        ScoutingResponder::new(co_joiner(HOME_GROUP, B_HOME_PORT).await, wz_identity());
    let asker_b = foreign_scouter().await;
    asker_b
        .send_to(
            &scout_datagram(WHAT_ROUTER | WHAT_PEER),
            (MOVED_GROUP, B_MOVED_PORT),
        )
        .await
        .expect("scout the MOVED group on the moved port");

    let quiet = timeout(Duration::from_secs(2), stranger_b.answer_next()).await;
    assert!(
        quiet.is_err(),
        "a responder on {HOME_GROUP}:{B_HOME_PORT} answered a Scout sent to \
         {MOVED_GROUP}:{B_MOVED_PORT}, so the PORT did not isolate it either and this \
         file's control axis is gone: got {quiet:?}"
    );
    assert_eq!(
        stranger_b.answered(),
        0,
        "the port-isolated responder must have answered nothing at all"
    );
}

/// The `#join=` axis, both-ended — this round's same-seam residue, paid here
/// rather than filed as its own number.
///
/// `McastSocketConfig::extra_joins` installs memberships IN ADDITION to the
/// locator's own group, on the SAME socket (zenoh `multicast.rs:316-347`). The
/// refusal path had a unit test; DELIVERY had no witness, so "wz joins the extra
/// groups it was given" rested on the join call being present in the source.
///
/// ⚠ The discriminator rests on the module doc's measurement, and would be
/// VACUOUS without it. With no other socket on this host holding `MOVED_GROUP`,
/// a datagram addressed to it is refused by the host outright — so the
/// responder's own `#join=` is the only thing that can make it arrive, which is
/// precisely what the control removes. ⛔ That is why it asks on
/// [`C_EXTRA_GROUP`] and not on `MOVED_GROUP`: see that constant for the
/// measured failure: membership is per `(group, device)`, so a sibling test
/// holding the asked-for group anywhere on the host satisfies the control
/// through `IP_MULTICAST_ALL` instead of through the join, and a distinct port
/// does not help. The arms still take a port each so neither waits on the
/// other's membership being dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "multicast loopback e2e; Layer M runs via --layer M / WZ_RUN_LAYER_M=1 --ignored"]
async fn a_responder_answers_on_an_extra_joined_group_and_only_because_it_joined_it() {
    /// One run: a wz responder whose locator group is HOME, given `joins` as its
    /// `#join=` list, asked on `MOVED_GROUP`.
    async fn answered_with_joins(port: u16, joins: &[String]) -> bool {
        let driver = UdpDriver::bind_multicast_v4(
            HOME_GROUP,
            port,
            McastSocketConfig {
                extra_joins: joins,
                ..Default::default()
            },
        )
        .await
        .expect("bind + join the home group plus the extra ones");
        let mut responder = ScoutingResponder::new(driver, wz_identity());
        let asker = foreign_scouter().await;
        asker
            .send_to(
                &scout_datagram(WHAT_ROUTER | WHAT_PEER),
                (C_EXTRA_GROUP, port),
            )
            .await
            .expect("scout the extra group");
        matches!(
            timeout(Duration::from_secs(3), responder.answer_next()).await,
            Ok(ResponderStep::Answered { .. })
        )
    }

    // POSITIVE: told to join the extra group, so the Scout addressed to it lands.
    assert!(
        answered_with_joins(C_JOINED_PORT, &[C_EXTRA_GROUP.to_string()]).await,
        "a responder given `#join={C_EXTRA_GROUP}` did not answer a Scout sent to \
         that group, so the extra membership was never installed"
    );

    // CONTROL: identical in every respect except the list.
    assert!(
        !answered_with_joins(C_UNJOINED_PORT, &[]).await,
        "a responder given NO extra join still answered a Scout sent to \
         {C_EXTRA_GROUP}, so the positive arm above proves nothing about `#join=` — \
         something else on this host is holding that group, and the dedicated \
         239.0.0.0/8 address this test picked to prevent exactly that is no longer \
         private to it"
    );
}
