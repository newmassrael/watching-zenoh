// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2141 (open-debt item 223) — THE WITNESS: a wz node scouts a real multicast
//! group, another wz node answers, and the scouter OPENS A SESSION TO THE NODE
//! THAT ANSWERED.
//!
//! # The sentence this proves, and the sentence it corrects
//!
//! Item 223 records the gap as "a wz that ANSWERED a Scout never dials the node
//! that asked". Read against the pinned checkout, upstream does not do that
//! either: `Runtime::responder` answers and dials nothing, and `autoconnect_all`
//! is a separate task that SCOUTS and dials whoever answers ITS scout
//! (`zenoh/src/net/runtime/orchestrator.rs`). So the corrected sentence — the one
//! asserted below — is: **a wz node that scouts dials the node that answered it,
//! when and only when its `scouting/multicast/autoconnect` policy admits that
//! node's role and zid.**
//!
//! # Why this is not the `--scout` witness one level over
//!
//! `wz_scout_zenohd_interop` (R311y428) proves wz can resolve ONE locator by
//! scouting and open a one-shot session to it. That path exits on the first Hello
//! and has no policy: it dials whatever answers first. This one keeps scouting,
//! sees every responder in the window, and consults
//! [`AutoConnect`](wz_routing_graph::AutoConnect) per Hello — which is what the
//! two config keys mean, and what wz could not do.
//!
//! # The discriminator
//!
//! `AcceptLoopSummary::scout_dialed` (R2141) is incremented in exactly one place:
//! the accept loop's `Step::Dial` arm, for an intent tagged
//! `DialIntentOrigin::MulticastScout`. Nothing in the workspace produces that tag
//! except `scouting_autoconnect`'s gate, and that gate is reached only by a Hello
//! decoded off the scouting group. A build that parsed the policy and dialled
//! nothing, or that dialled without consulting it, moves `dialed` and not this.
//!
//! Both legs stand up the SAME fixture in the SAME process and differ ONLY in
//! the policy's matcher. An environment that cannot route multicast fails both,
//! so a green control cannot be mistaken for coverage.
//!
//! They take DIFFERENT group ports, and that is not tidiness either. The test
//! harness runs the two functions concurrently; a Scout is multicast, so on one
//! shared port each leg's responder would answer the OTHER leg's scout, and both
//! responders carry the same fixture zid — so which acceptor the positive leg
//! dialled would be a race, decided by which unicast Hello landed first. The
//! assertion would still hold (either address came out of a Hello), which is
//! precisely why it is worth removing: a witness whose subject is decided by
//! arrival order cannot say WHOSE Hello it proved.
//!
//! # Socket layout, which is upstream's
//!
//! The responder binds the GROUP PORT (upstream's `mcast_sock`); the scouting
//! side sends from an EPHEMERAL port (upstream's `ucast_sock`,
//! [`UdpDriver::bind_multicast_tx_v4`]). That is not tidiness: the Hello goes
//! back UNICAST to the scout's source address, and two sockets sharing the group
//! port under `SO_REUSEPORT` would make which of them receives it a coin toss.
//!
//! Opt-in only (`#[ignore]`), like every multicast e2e here: a container with no
//! multicast route on the default interface drops the join, and a gate that
//! depends on the environment is a flaky gate. The deterministic half — the
//! policy verdict for every kind of Hello — is unit-tested without a socket in
//! `wz_runtime_tokio::scouting_autoconnect`.
#![cfg(all(
    feature = "scouting-active",
    feature = "scouting-responder",
    feature = "routing-peer",
    feature = "transport-link-tcp",
))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::sync::watch;

use wz_codecs::whatami::{WhatAmI, WhatAmIMatcher};
use wz_routing_graph::{AutoConnect, AutoConnectStrategies, AutoConnectStrategy, Zid};
use wz_runtime_tokio::accept_loop::{
    accept_loop, peer_loop, AcceptEvent, AcceptLoopSummary, FaceSources, NoOpForwarder,
};
use wz_runtime_tokio::link_pipeline::bind_tcp;
use wz_runtime_tokio::retry_period::RetryPolicy;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::scouting_autoconnect::{serve_autoconnect, AutoconnectPlan, AutoconnectStep};
use wz_runtime_tokio::scouting_glue::{new_scouting_engine, ScoutingActions};
use wz_runtime_tokio::scouting_responder::{serve, ResponderIdentity, ScoutingResponder};
use wz_runtime_tokio::session_open::{BoundListener, SessionOffer, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio::{McastSocketConfig, UdpDriver};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::scout_params::ScoutParams;

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 224);
/// NOT zenoh's 7446. A developer running a zenohd on this host would otherwise
/// have it answer the scout, and the test would pass on a Hello it did not
/// arrange — the shape where a witness credits the wrong node.
///
/// One per leg, for the same reason one level in: the two legs run
/// concurrently, and a shared port makes each one's responder a candidate answer
/// to the other one's scout (see the module doc).
const PORT_ADMITTED: u16 = 17466;
const PORT_REFUSED: u16 = 17467;

/// The responder's role. `Router` is what a stock CLIENT's `autoconnect` default
/// (`["router"]`) looks for and what a PEER's default (`["router", "peer"]`)
/// includes, so it is a role the two legs' matchers genuinely differ about rather
/// than one picked to suit either.
const RESPONDER_ROLE: WhatAmI = WhatAmI::Router;
const RESPONDER_ZID: &[u8] = &[0xAA, 0xAA, 0xAA, 0xAA];
/// The scouting node's own zid. GREATER than the responder's, so a `greater-zid`
/// tie-break would ADMIT — which keeps the control leg's refusal attributable to
/// the matcher and to nothing else.
const SCOUT_ZID: &[u8] = &[0xBB, 0xBB, 0xBB, 0xBB];

/// How long a leg may run before it is cut. The positive leg ends as soon as the
/// dialed face is up; this is what ends the CONTROL leg, where no face ever comes
/// up — a negative result reached on purpose rather than by timing out the test.
const LEG_BUDGET_MS: u64 = 8_000;

async fn shutdown_on(mut rx: watch::Receiver<bool>) {
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

fn loopback_any() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

/// Run one leg: stand up a responder advertising a REAL TCP acceptor, scout the
/// group under `matcher`, and return the scouting node's accept-loop summary.
///
/// Everything is per-leg (fresh sockets, fresh zids-seen set, its own group
/// `port`); only `matcher` differs in what the leg MEANS.
async fn leg(port: u16, matcher: WhatAmIMatcher) -> AcceptLoopSummary {
    // ── The node that will be DISCOVERED: a TCP acceptor, plus a scout responder
    //    that advertises that acceptor's address. ──
    let acceptor_socket = bind_tcp(loopback_any(), None)
        .await
        .expect("bind the acceptor");
    let acc_addr = acceptor_socket.local_addr().expect("acceptor local_addr");

    let mut acceptor_params = fixture_session_init_params();
    acceptor_params.zid = RESPONDER_ZID.to_vec();
    // PARKED after it returns, like every background arm here: the `select!`
    // below must be endable by the peer loop and by nothing else, or a leg could
    // finish with no summary to assert on. (The loops are not `Send` — they hold
    // a `&dyn FaceForwarder` and boxed non-`Send` open futures — so they are
    // driven as concurrent arms of one task rather than spawned.)
    let acceptor = async {
        accept_loop(
            BoundListener::Tcp(acceptor_socket),
            acceptor_params,
            TokioTime::new(),
            DEFAULT_OPEN_TICK_MS,
            std::future::pending::<()>(),
            |_event: &AcceptEvent| {},
            &NoOpForwarder,
        )
        .await;
        std::future::pending::<()>().await
    };

    // The GROUP-PORT socket (upstream's `mcast_sock`): joins, and answers Scouts.
    let responder_driver = UdpDriver::bind_multicast_v4(GROUP, port, McastSocketConfig::default())
        .await
        .expect("bind + join the scouting group as the responder");
    let identity = ResponderIdentity::try_new(
        0x09,
        RESPONDER_ROLE,
        RESPONDER_ZID.to_vec(),
        // THE LINK BETWEEN THE TWO HALVES: the locator the Hello advertises is
        // the acceptor's KERNEL-CHOSEN port. The scouting node is never told this
        // address by any other route, so a face to it can only have come from
        // decoding this Hello.
        vec![format!("tcp/{acc_addr}")],
    )
    .expect("responder identity");
    let responder = async {
        serve(
            ScoutingResponder::new(responder_driver, identity),
            |_step| {},
        )
        .await;
        std::future::pending::<()>().await
    };

    // ── The SCOUTING node: an ephemeral-port sender (upstream's `ucast_sock`)
    //    plus the peer mesh loop that turns intents into dials. ──
    let mut scout_driver =
        UdpDriver::bind_multicast_tx_v4(GROUP, port, McastSocketConfig::default())
            .await
            .expect("bind the scouting sender");
    let actions = ScoutingActions::new(ScoutParams {
        version: 0x09,
        what: 0x03, // ROUTER | PEER — what this node is looking for.
        zid: SCOUT_ZID.to_vec(),
        timeout_ms: 300,
        // SURVEY mode: every responder in the window, not just the first. This is
        // the arm `autoconnect_all` runs in; `--scout` uses the other one.
        exit_on_first: false,
    });
    let mut engine = new_scouting_engine(&actions);

    let policy = AutoConnect::with_strategies(
        Zid::from_slice(SCOUT_ZID),
        matcher,
        AutoConnectStrategies::Unique(AutoConnectStrategy::Always),
    );

    let (dial_tx, dial_rx) = tokio::sync::mpsc::unbounded_channel();
    // A clone kept HERE so the channel never closes: the peer loop parks on its
    // intent arm, and a closed channel would be a second way for the loop to end
    // that the assertions could not tell from the first.
    let keepalive_tx = dial_tx.clone();
    let (go_tx, go_rx) = watch::channel(false);

    let peer_socket = bind_tcp(loopback_any(), None)
        .await
        .expect("bind the peer listener");
    let mut peer_params = fixture_session_init_params();
    peer_params.zid = SCOUT_ZID.to_vec();

    let scouting = async {
        serve_autoconnect(
            &mut scout_driver,
            &actions,
            &mut engine,
            &TokioTime::new(),
            AutoconnectPlan {
                policy: &policy,
                dial_tx: &dial_tx,
                // Bounded: enough cycles that a responder still joining the
                // group is not what decides the verdict, and few enough that the
                // control leg is over well inside the budget.
                max_cycles: Some(8),
                tick_interval_ms: 25,
            },
            |step: AutoconnectStep| eprintln!("autoconnect: {step:?}"),
        )
        .await;
        std::future::pending::<()>().await
    };

    let peer = peer_loop(
        FaceSources {
            listeners: vec![BoundListener::Tcp(peer_socket)],
            // NOTHING configured. Every dial this loop makes therefore comes from
            // an intent, which is what makes `dialed` attributable at all.
            dial_targets: vec![],
            dial_intents: Some(dial_rx),
            mcast_ingress: None,
            mcast_members: None,
            mcast_group_subs: None,
            reconcile: None,
            offer: SessionOffer::universal(),
            retry: RetryPolicy::constant(1000),
            #[cfg(feature = "transport-multilink")]
            max_links: 1,
        },
        peer_params,
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        async {
            // Whichever comes first: the dialed face came up (positive leg), or
            // the budget elapsed (control leg).
            tokio::select! {
                _ = shutdown_on(go_rx) => {}
                _ = tokio::time::sleep(Duration::from_millis(LEG_BUDGET_MS)) => {}
            }
        },
        move |event: &AcceptEvent| {
            if let AcceptEvent::FaceUp(_) = event {
                let _ = go_tx.send(true);
            }
        },
        &NoOpForwarder,
    );

    // The four arms run CONCURRENTLY; only the peer loop can complete, so the
    // summary is always the peer loop's. Dropping the others afterwards is what
    // shuts the acceptor and the responder down.
    let summary = tokio::select! {
        s = peer => s,
        _ = acceptor => unreachable!("the acceptor arm parks after returning"),
        _ = responder => unreachable!("the responder arm parks after returning"),
        _ = scouting => unreachable!("the scouting arm parks after returning"),
    };

    drop(keepalive_tx);
    summary
}

/// POSITIVE: the policy admits the responder's role, so the scouting node dials
/// the node that answered it and holds the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "multicast loopback e2e; Layer M runs via --layer M / WZ_RUN_LAYER_M=1 --ignored"]
async fn a_scouted_responder_the_policy_admits_is_dialed() {
    // The zenoh PEER default for `scouting/multicast/autoconnect`:
    // `["router", "peer"]` (DEFAULT_CONFIG.json5).
    let summary = leg(PORT_ADMITTED, WhatAmIMatcher::empty().router().peer()).await;

    assert_eq!(
        summary.scout_dialed, 1,
        "the node that ANSWERED the Scout must be dialed, and attributed to the \
         multicast plane: summary = {summary:?}"
    );
    assert_eq!(
        summary.gossip_dialed, 0,
        "no gossip flood exists in this test, so a gossip-attributed dial would \
         mean the origin tag is not being read: summary = {summary:?}"
    );
    assert_eq!(
        summary.dialed, 1,
        "exactly one dial, and it is the discovered one — no target was \
         configured: summary = {summary:?}"
    );
    assert_eq!(
        summary.established, 1,
        "the dialed face reached Established, so this is a SESSION with the \
         responder and not merely an intent: summary = {summary:?}"
    );
    assert_eq!(summary.accepted, 0, "nothing dialed in: {summary:?}");
}

/// CONTROL: the SAME responder, the SAME group, the SAME process — and a matcher
/// that does not admit its role. Nothing is dialed.
///
/// This is what makes the positive leg mean "the policy decided" rather than "wz
/// dials whatever answers". `client` is chosen because it is a role the responder
/// does not have, so the Hello still arrives and is still decoded: the refusal
/// happens at the gate and nowhere earlier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "multicast loopback e2e; Layer M runs via --layer M / WZ_RUN_LAYER_M=1 --ignored"]
async fn a_scouted_responder_the_policy_refuses_is_not_dialed() {
    let summary = leg(PORT_REFUSED, WhatAmIMatcher::empty().client()).await;

    assert_eq!(
        summary.scout_dialed, 0,
        "a role outside the matcher must not be dialed: summary = {summary:?}"
    );
    assert_eq!(
        summary.dialed, 0,
        "nothing at all should have been dialed: summary = {summary:?}"
    );
}
