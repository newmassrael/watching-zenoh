// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2612 — the ask-side fan-out REACHES an interface the kernel's default route
//! does not, and the single socket it replaced does not.
//!
//! # What was missing, and why the other arms could not supply it
//!
//! R2611 built the fan-out and witnessed it two ways that hold on any host: the
//! set is one socket per offered address, and each socket's egress is the
//! address it was given, read back from `IP_MULTICAST_IF` rather than from the
//! call that set it. Neither says a DATAGRAM leaves by a second interface. That
//! needs a second interface, and a one-NIC runner has none — which is the whole
//! reason this leg lives behind a namespace rather than in the library lane.
//!
//! # Why a veth pair is enough, measured before this file was written
//!
//! `scripts/lib/netns-topology.sh` leaves the HOST end of the pair in this
//! namespace, so the root namespace gains a second `MULTICAST,UP` interface with
//! an address of its own — and it is not the default multicast route. Measured
//! on this tree with plain sockets: a datagram sent with egress pinned to the
//! veth address ARRIVES at a receiver joined for the group via that address, and
//! the identical datagram sent unpinned DOES NOT. So the discrimination this leg
//! needs is a property of the topology, not of anything wz does, and no peer
//! process inside the namespace is required.
//!
//! That is also why the CONTROL is the pre-R2611 behaviour rather than a damaged
//! build: a single group socket on the default route is exactly what wz had, and
//! it must fail to reach the receiver here.
//!
//! # The order of the arms
//!
//! The control runs FIRST. If it ran second, a positive arm that had already put
//! a datagram on the group could not be told from a control that leaked one, and
//! the silence being asserted would be silence after the fact.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use wz_integration_tests::common::NetnsPair;
use wz_runtime_tokio::scouting_fanout::{
    bind_scout_sockets, scout_interface_addresses, ScoutFanOut,
};
use wz_runtime_tokio::{LinkDriver, McastSocketConfig, UdpDriver};
use wz_session_core::link::{LinkEvent, TxFrame};
use wz_session_core::reliability::Reliability;

/// An organization-local group no other lane, test or zenoh default binds.
const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 73, 12);
/// A port no other multicast lane binds.
const PORT: u16 = 7475;
const HOST_CIDR: &str = "10.251.9.1/30";
const PEER_CIDR: &str = "10.251.9.2/30";
/// The host end's address, which is the interface the receiver joins on.
const HOST_ADDR: &str = "10.251.9.1";

/// What the control sends, and what the fan-out sends. Distinct so a receiver
/// cannot pass an arm on the other arm's datagram.
const CONTROL_BYTES: &[u8] = b"WZ-SCOUT-CONTROL-R2612";
const FANOUT_BYTES: &[u8] = b"WZ-SCOUT-FANOUT-R2612";

/// Long enough that a silent arm is silent for a reason, short enough that the
/// leg does not dominate its lane. The positive arm is on the same host over a
/// veth: it arrives in microseconds or not at all.
const SILENT_BUDGET: Duration = Duration::from_millis(800);
const DELIVERY_BUDGET: Duration = Duration::from_secs(2);

/// The next datagram to arrive at `rx` within `budget`, or `None`.
async fn arrives(rx: &mut UdpDriver, budget: Duration) -> Option<Vec<u8>> {
    match tokio::time::timeout(budget, rx.poll_event()).await {
        Ok(LinkEvent::Rx(frame)) => Some(frame.bytes),
        Ok(_) => None,
        Err(_) => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a network namespace; Layer M runs it after probing for one"]
async fn the_fan_out_reaches_an_interface_the_default_route_does_not() {
    let _ns = NetnsPair::up("scoutfan", HOST_CIDR, PEER_CIDR);

    // The receiver joins the group ONLY through the veth host address, so it
    // hears a datagram only if that datagram left by the veth.
    let mut rx = UdpDriver::bind_multicast(
        GROUP,
        PORT,
        McastSocketConfig {
            iface: Some(HOST_ADDR),
            ttl: None,
            extra_joins: &[],
        },
    )
    .await
    .expect("bind the receiver on the veth interface");

    // CONTROL, and it is the pre-R2611 product: one group socket, egress by the
    // kernel's default route.
    let mut single = UdpDriver::bind_multicast_tx(GROUP, PORT, McastSocketConfig::default())
        .await
        .expect("bind the single-socket control");
    single
        .send(
            &TxFrame {
                bytes: CONTROL_BYTES,
            },
            Reliability::BestEffort,
        )
        .await
        .expect("the control sends");
    assert!(
        arrives(&mut rx, SILENT_BUDGET).await.is_none(),
        "a Scout on the default route must NOT reach a peer that only the veth \
         can hear — if it does, this host's default multicast route IS the veth \
         and the leg cannot discriminate"
    );

    // POSITIVE: the production enumeration, which now includes the veth.
    let locals = scout_interface_addresses()
        .expect("this build enumerates and pins; the lane names both features");
    assert!(
        locals.contains(&IpAddr::V4(HOST_ADDR.parse().expect("host addr parses"))),
        "the veth must be IN the enumeration or this leg is not testing the \
         fan-out; got {locals:?}"
    );
    let (ask, refused) = bind_scout_sockets(IpAddr::V4(GROUP), PORT, &locals, None).await;
    let group_socket = UdpDriver::bind_multicast_tx(GROUP, PORT, McastSocketConfig::default())
        .await
        .expect("bind the fan-out's group member");
    let (mut fan, shape) = ScoutFanOut::over(group_socket, ask, refused);
    assert!(
        !shape.fell_back_to_group,
        "the fan-out must have real ask sockets here, not the fallback"
    );
    fan.send(
        &TxFrame {
            bytes: FANOUT_BYTES,
        },
        Reliability::BestEffort,
    )
    .await
    .expect("the fan-out sends");

    assert_eq!(
        arrives(&mut rx, DELIVERY_BUDGET).await.as_deref(),
        Some(FANOUT_BYTES),
        "the fan-out's Scout must reach the peer the default route cannot"
    );
}
