// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y846 — Layer M: the scouting RESPONDER over a real UDP multicast socket.
//!
//! The mirror of `scouting_multicast_loopback.rs`, which drives wz as the node
//! that ASKS. Here a foreign scouter asks and wz answers, which is the direction
//! that decides whether an existing zenoh network can find a wz node at all.
//!
//! ## Why the reply arriving is itself the unicast proof
//!
//! The scouter socket here binds an ephemeral port and **never joins the
//! group**. So a Hello sent to `GROUP:PORT` — the shape a naive responder would
//! send, since that is where the question came from — is not delivered to it by
//! the kernel at all. The `recv_from` succeeding is therefore a load-bearing
//! assertion rather than a liveness check: it can only succeed if wz replied to
//! the datagram's SOURCE, which is what upstream does
//! (`socket.send_to(wbuf.as_slice(), peer)`, zenoh
//! `net/runtime/orchestrator.rs:1168`) and what a scouting node's own recv half
//! requires (it reads on the ephemeral sockets it sent from, `:879-885`).
//!
//! Opt-in (`#[ignore]`, run-ci Layer M / `WZ_RUN_LAYER_M=1`) for the same reason
//! the sibling loopback test is: multicast routing is environment-dependent, so
//! a container without a route on the default interface would drop the join and
//! red a lane that is not about this code. The gates themselves are covered
//! without a socket by the `scout_responder` unit tests in wz-session-core.
//!
//! Each test owns a DISTINCT group and port. The scouting port is inherently
//! multi-listener (`SO_REUSEPORT` is set by `bind_multicast_v4`), so two tests
//! sharing one would receive each other's traffic and each would be asserting
//! about a datagram the other sent.
#![cfg(feature = "scouting-responder")]

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use wz_codecs::scout::Scout;
use wz_codecs::whatami::WhatAmI;
use wz_codecs::wire_const;
use wz_runtime_tokio::scouting_responder::{
    bind_reply_sockets, ReplySource, ResponderStep, ScoutingResponder,
};
use wz_runtime_tokio::{McastSocketConfig, UdpDriver};
use wz_session_core::scout_responder::{ResponderIdentity, ScoutIgnored};
use wz_session_core::scouting_message::{parse_scouting, ScoutingFrame};

const WZ_ZID: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
const WZ_LOCATOR: &str = "tcp/127.0.0.1:7447";

/// Roles, API form — the bitmask a Scout's `what` carries
/// (`zenoh-codec` `scouting/scout.rs:48`).
const WHAT_ROUTER: u8 = 0b001;
const WHAT_PEER: u8 = 0b010;
const WHAT_CLIENT: u8 = 0b100;

/// A Scout datagram in the shape both wz's `scout_emit` and zenoh's
/// `Runtime::scout` put on the group: MID header, version, flags, optional zid.
fn scout_datagram(what: u8) -> Vec<u8> {
    let mut scout = Scout::new();
    scout.version = 0x09;
    scout.set_what(what);
    // No zid — this is zenoh's own shape (`orchestrator.rs:840` sends
    // `zid: None`), so the test's asker is indistinguishable from a stock one
    // and the self-echo gate is not what is under test here.
    let body = scout.encode_to_vec();
    let mut wire = vec![wire_const::S_MID_SCOUT];
    wire.extend_from_slice(&body);
    wire
}

fn wz_identity() -> ResponderIdentity {
    ResponderIdentity::try_new(
        0x09,
        WhatAmI::Peer,
        WZ_ZID.to_vec(),
        vec![WZ_LOCATOR.to_string()],
    )
    .expect("the demo's identity shape is well-formed")
}

async fn responder_on(group: Ipv4Addr, port: u16) -> ScoutingResponder {
    let driver = UdpDriver::bind_multicast_v4(group, port, McastSocketConfig::default())
        .await
        .expect("bind + join the scouting group");
    ScoutingResponder::new(driver, wz_identity())
}

/// An ephemeral socket that does NOT join the group. See the module doc: not
/// joining is what makes the reply's arrival a unicast proof.
async fn foreign_scouter() -> UdpSocket {
    UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .expect("bind an ephemeral foreign scouter")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "multicast responder e2e; Layer M runs via --layer M / WZ_RUN_LAYER_M=1 --ignored"]
async fn a_foreign_scout_is_answered_with_wzs_hello_unicast_to_the_asker() {
    const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 225);
    const PORT: u16 = 17446;

    let mut responder = responder_on(GROUP, PORT).await;
    let scouter = foreign_scouter().await;
    let scouter_port = scouter.local_addr().expect("scouter local addr").port();

    scouter
        .send_to(&scout_datagram(WHAT_ROUTER | WHAT_PEER), (GROUP, PORT))
        .await
        .expect("scout the group");

    let step = timeout(Duration::from_secs(5), responder.answer_next())
        .await
        .expect("the responder must see the Scout within the budget");
    match step {
        ResponderStep::Answered { to, from, bytes } => {
            assert_eq!(
                to.port(),
                scouter_port,
                "the Hello must go to the ASKER's port, not the group's"
            );
            assert_ne!(
                to.ip(),
                std::net::IpAddr::V4(GROUP),
                "a reply addressed to the group is not delivered where the asker listens"
            );
            assert_eq!(
                from,
                ReplySource::Group,
                "this responder was given no unicast socket, and that state is \
                 REPORTED rather than silent — the assertion below about the \
                 Hello's source port is only true of the group-socket arm"
            );
            assert!(bytes > 0);
        }
        other => panic!("a matching Scout must be answered, got {other:?}"),
    }
    assert_eq!(responder.answered(), 1);
    assert_eq!(responder.ignored(), 0);

    // The receive that could not happen over multicast, because this socket
    // never joined the group.
    let mut buf = vec![0u8; 2048];
    let (n, from) = timeout(Duration::from_secs(5), scouter.recv_from(&mut buf))
        .await
        .expect("the Hello must reach the ungrouped scouter — i.e. it was unicast")
        .expect("recv_from");
    assert_eq!(
        from.port(),
        PORT,
        "the Hello comes FROM the group socket wz answered on"
    );
    match parse_scouting(&buf[..n]).expect("the reply must decode in the scouting namespace") {
        ScoutingFrame::Hello { body, .. } => {
            assert_eq!(body.zid.to_vec(), WZ_ZID, "wz's own zid");
            assert_eq!(body.whatami(), WhatAmI::Peer.to_wire());
            let locators = body
                .locators
                .as_ref()
                .expect("wz advertises a locator, so L is set and the list is there");
            assert_eq!(locators.len(), 1);
            assert_eq!(
                locators[0].locator.as_str(),
                WZ_LOCATOR,
                "the dial hint is what wz advertises, which is what makes it findable"
            );
        }
        other => panic!("the reply is not a Hello: {other:?}"),
    }
}

/// R2219 — THE MULTI-HOMED ELECTION, over real sockets: two askers reach the
/// same responder over the same receiving socket, and the Hello leaves a
/// DIFFERENT interface for each, chosen by which one is nearest.
///
/// The two arms are the discriminator. A responder that answers from the socket
/// the Scout arrived on — every wz responder before this round — passes neither,
/// because both replies would then carry the receiving socket's address; a
/// responder that elected a constant would pass one arm and fail the other.
///
/// The addresses are loopback, and that is what makes this a real multi-homed
/// test on a single-NIC host: `127.0.0.1` and `127.0.0.2` are two local
/// addresses that differ in their LAST octet, so the election has to read three
/// octets before it can separate them. `#[ignore]` for an environment reason of
/// its own rather than the group one: `127.0.0.2` is bindable on Linux, where
/// the whole `127.0.0.0/8` is local, and is not on every host this may compile
/// for.
///
/// No multicast group is joined. The election reads the ASKER's address and
/// nothing about how the datagram arrived, so a unicast receiving socket
/// exercises exactly the same path with one fewer environmental precondition.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binds 127.0.0.2 (Linux loopback range); Layer M runs via --layer M / WZ_RUN_LAYER_M=1 --ignored"]
async fn the_hello_leaves_the_interface_nearest_the_asker() {
    const NEAR: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
    const FAR: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

    // The socket the Scout arrives on, standing in for the group socket: the
    // election is a function of the ASKER's address, so what this test needs of
    // it is only that it receives and attributes a source.
    let inbound = UdpDriver::bind_reply_unicast(NEAR.into())
        .await
        .expect("bind the receiving socket");
    let inbound_addr = inbound.local_addr().expect("its local address");

    let (reply_sockets, refused) = bind_reply_sockets(&[FAR.into(), NEAR.into()]).await;
    assert!(
        refused.is_empty(),
        "both loopback addresses must bind; got {refused:?}"
    );
    let mut responder =
        ScoutingResponder::with_reply_sockets(inbound, wz_identity(), reply_sockets);
    let sources = responder.reply_sources();
    assert_eq!(sources.len(), 2, "both reply sockets are held: {sources:?}");

    for (asker_addr, expected) in [(NEAR, NEAR), (FAR, FAR)] {
        let asker = UdpSocket::bind((asker_addr, 0))
            .await
            .unwrap_or_else(|e| panic!("bind an asker on {asker_addr}: {e}"));
        asker
            .send_to(&scout_datagram(WHAT_ROUTER | WHAT_PEER), inbound_addr)
            .await
            .expect("scout the responder");

        let step = timeout(Duration::from_secs(5), responder.answer_next())
            .await
            .expect("the responder must see the Scout within the budget");
        let ResponderStep::Answered { from, .. } = step else {
            panic!("a matching Scout must be answered, got {step:?}");
        };
        match from {
            ReplySource::Elected(local) => assert_eq!(
                local.ip(),
                std::net::IpAddr::V4(expected),
                "an asker on {asker_addr} must be answered from {expected}"
            ),
            ReplySource::Group => panic!(
                "the group socket answered an asker two unicast sockets could \
                 reach — the election did not run"
            ),
        }

        // And the WIRE agrees with the report. The reported source is this
        // process's view; `recv_from` is the asker's, and a responder that named
        // one socket and sent from another would differ only here.
        let mut buf = vec![0u8; 2048];
        let (n, seen) = timeout(Duration::from_secs(5), asker.recv_from(&mut buf))
            .await
            .expect("the Hello must arrive")
            .expect("recv_from");
        assert_eq!(
            seen.ip(),
            std::net::IpAddr::V4(expected),
            "the asker sees the Hello coming FROM the elected interface"
        );
        assert!(matches!(
            parse_scouting(&buf[..n]).expect("the reply decodes"),
            ScoutingFrame::Hello { .. }
        ));
    }
    assert_eq!(responder.answered(), 2);
    assert_eq!(responder.ignored(), 0);
}

/// THE CONTROL. Same sockets, same code path, one byte different in the Scout:
/// a `what` that does not include wz's role. Without this arm the test above
/// passes on a responder that answers every datagram it ever receives — which
/// would hand a client scouting for routers a peer's Hello and make it dial a
/// node that cannot serve it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "multicast responder e2e; Layer M runs via --layer M / WZ_RUN_LAYER_M=1 --ignored"]
async fn a_scout_for_a_role_wz_does_not_have_gets_no_hello() {
    const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 226);
    const PORT: u16 = 17447;

    let mut responder = responder_on(GROUP, PORT).await;
    let scouter = foreign_scouter().await;

    scouter
        .send_to(&scout_datagram(WHAT_CLIENT), (GROUP, PORT))
        .await
        .expect("scout the group for clients only");

    let step = timeout(Duration::from_secs(5), responder.answer_next())
        .await
        .expect("the responder must see the Scout within the budget");
    match step {
        ResponderStep::Ignored {
            why: ScoutIgnored::WhatMismatch { what },
            from,
        } => {
            assert_eq!(what, WHAT_CLIENT);
            assert!(
                from.is_some(),
                "the source is attributed even when the datagram is refused — an \
                 operator asking why nothing finds this node needs to know WHO asked"
            );
        }
        other => panic!("a client-only Scout must be refused on the what gate, got {other:?}"),
    }
    assert_eq!(responder.answered(), 0);
    assert_eq!(responder.ignored(), 1);

    // And nothing is on the wire. A short budget is honest here: the positive
    // test above measures how long an answer actually takes on this socket
    // (well under a second), so a second of silence is the absence of a reply
    // rather than a race with one.
    let mut buf = vec![0u8; 2048];
    let quiet = timeout(Duration::from_secs(1), scouter.recv_from(&mut buf)).await;
    assert!(
        quiet.is_err(),
        "no Hello may be sent for a role wz does not have; got {quiet:?}"
    );
}
