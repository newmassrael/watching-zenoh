// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 902 -- an interface that goes away takes its datagram link with
//! it, and the link says so, instead of leaving the session to its lease.
//!
//! # The premise, measured here rather than recited
//!
//! A datagram socket has no connection to lose. Remove the device a UDP link
//! runs over and the kernel gives the READ half nothing: `recvfrom` just does not
//! return. It is the WRITE half that fails, with `ENODEV` or `ENETUNREACH`. The
//! link's loss used to be reported only from the read half, so neither the
//! multicast group link nor a unicast UDP link ever reported an interface loss:
//! the group session kept its peers until their leases expired and a unicast
//! session ran on to its own lease, with the writer task logging a failure that
//! nothing listened to. Upstream ends the transport at the first failed write as
//! it does at the first failed read (`io/zenoh-transport/src/multicast/link.rs`
//! @ `tracing::debug!("TX task failed: {}", e);`).
//!
//! Each leg asserts the premise first, in the same run: after the device is
//! removed the read half stays silent. A leg that skipped that would pass for a
//! stack whose `recvfrom` DOES fail, which is not the case this repairs.
//!
//! # What this does not witness
//!
//! The re-join that follows a lost group link (`serve_group`, `GroupRejoin`) is
//! witnessed by its own paused-time tests; this leg ends where the link reports
//! `Lost`, which is the seam item 900's re-join loop was waiting on.

use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;
use std::time::Duration;

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::NetnsPair;
use wz_runtime_tokio::link_socket::LinkSocket;
use wz_runtime_tokio::udp_pipeline::{dial_udp, wire_udp_socket};
use wz_runtime_tokio::{LinkDriver, LinkEvent, LostCause, McastSocketConfig, UdpDriver};
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::reliability::Reliability;

/// An organization-local group no other lane, test or zenoh default binds.
const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 73, 41);
/// A port no other multicast lane binds.
const GROUP_PORT: u16 = 17492;

const GROUP_HOST_CIDR: &str = "10.251.14.1/30";
const GROUP_PEER_CIDR: &str = "10.251.14.2/30";
const GROUP_HOST_ADDR: &str = "10.251.14.1";

const DIAL_HOST_CIDR: &str = "10.251.15.1/30";
const DIAL_PEER_CIDR: &str = "10.251.15.2/30";
const DIAL_PEER_ADDR: Ipv4Addr = Ipv4Addr::new(10, 251, 15, 2);

/// How long a silent half is watched to be sure it is silent.
const SILENT_FOR: Duration = Duration::from_millis(600);
/// How long a link that has lost its interface is given to say so. The report
/// is immediate where it works; this bounds a test waiting for one that never
/// comes.
const LOST_WITHIN: Duration = Duration::from_secs(5);

/// Delete the host end of the pair, as a hot-unplugged or reconfigured
/// interface is deleted. The peer end goes with it.
fn remove_the_interface(ns: &NetnsPair) {
    let out = Command::new("sudo")
        .args(["-n", "ip", "link", "del", "dev", &ns.host_iface()])
        .output_bounded()
        .expect("run ip link del");
    assert!(
        out.status.success(),
        "ip link del {} failed: {}",
        ns.host_iface(),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a network namespace; Layer M runs it after probing for one"]
async fn a_group_link_whose_interface_is_removed_is_lost_at_its_next_write() {
    let ns = NetnsPair::up("grplost", GROUP_HOST_CIDR, GROUP_PEER_CIDR);
    let mut link = UdpDriver::bind_multicast_link(
        GROUP,
        GROUP_PORT,
        McastSocketConfig {
            iface: Some(GROUP_HOST_ADDR),
            ttl: None,
            extra_joins: &[],
            bind: None,
            dscp: None,
        },
    )
    .await
    .expect("join the group on the veth host end");
    let sender = link.group_sender().expect("the link's send half");

    // Up: a write works, and the datagram loops back to the member that sent it,
    // so the link demonstrably carries data before anything is removed.
    sender
        .send(b"before")
        .await
        .expect("a group write works while the interface exists");
    match tokio::time::timeout(LOST_WITHIN, link.poll_event()).await {
        Ok(LinkEvent::Rx(frame)) => assert_eq!(frame.bytes, b"before"),
        other => panic!("the link carries its own group datagram while up; got {other:?}"),
    }

    remove_the_interface(&ns);

    // The premise: the read half has nothing to say about a removed interface.
    let silent = tokio::time::timeout(SILENT_FOR, link.poll_event()).await;
    assert!(
        silent.is_err(),
        "removal must leave the read half silent (that is why the writer is the \
         source of this loss); got {silent:?}"
    );

    // The write fails, and that failure is the link's loss.
    sender
        .send(b"after")
        .await
        .expect_err("a group write must fail once its interface is gone");
    let event = tokio::time::timeout(LOST_WITHIN, link.poll_event()).await;
    assert!(
        matches!(
            event,
            Ok(LinkEvent::Lost {
                cause: LostCause::OsError
            })
        ),
        "a group link whose write failed must be lost; got {event:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a network namespace; Layer M runs it after probing for one"]
async fn a_dial_link_whose_route_is_removed_is_lost_at_its_next_write() {
    let ns = NetnsPair::up("diallost", DIAL_HOST_CIDR, DIAL_PEER_CIDR);
    let peer = SocketAddr::from((DIAL_PEER_ADDR, 9));
    let socket = dial_udp(peer, &LinkSocket::NONE)
        .await
        .expect("dial across the veth");
    let (mut read, write, _writer) = wire_udp_socket(socket, peer);

    // Nothing has been sent, so nothing has been refused: the link is quiet.
    let quiet = tokio::time::timeout(SILENT_FOR, read.poll_event()).await;
    assert!(
        quiet.is_err(),
        "a link nobody has written to is quiet; got {quiet:?}"
    );

    remove_the_interface(&ns);

    // The premise, again: the read half stays silent for the removal itself.
    let silent = tokio::time::timeout(SILENT_FOR, read.poll_event()).await;
    assert!(
        silent.is_err(),
        "removal must leave the read half silent; got {silent:?}"
    );

    // A queued write is refused by the kernel and that ends the link.
    let queued = write.send_blocking(b"after", Reliability::BestEffort);
    assert_eq!(
        queued,
        wz_session_core::link::LinkSendOutcome::Sent,
        "the datagram is accepted by the queue; the kernel refuses it at the writer"
    );
    let event = tokio::time::timeout(LOST_WITHIN, read.poll_event()).await;
    assert!(
        matches!(
            event,
            Ok(LinkEvent::Lost {
                cause: LostCause::OsError
            })
        ),
        "a dial link whose write failed must be lost; got {event:?}"
    );
}
