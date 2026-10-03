// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R3014 — the HOST facets of multicast, witnessed with wz's own two drivers and
//! nothing else: a datagram that `UdpDriver::bind_multicast_tx` sends to a group
//! reaches a `UdpDriver::bind_multicast` member on the same host.
//!
//! The fuller multicast tests (`scouting_multicast_loopback`,
//! `multicast_pubsub_loopback`) exercise wz's scouting and session logic over a
//! group and say nothing OS-specific that this does not; they also build raw
//! sockets of their own, so they cannot be pointed at another interface without
//! editing each one. This is the narrow witness of what DOES differ per host,
//! the part of the multicast plane that is a conversation with the kernel: the
//! bind with port reuse, the membership, the loopback, the egress pin, the send.
//!
//! Which interface carries it is the one thing that differs by host, and that is
//! a MEASUREMENT, not a preference. The hosted runners were asked, before wz
//! touched anything, what a plain socket does with a send to `224.0.0.224`:
//!
//!   * Linux: a send with no interface pinned works, and so does one pinned to
//!     the default route's address.
//!   * Windows: the same two work. A send pinned to `127.0.0.1` FAILS with
//!     `WinError 10051` (the loopback adapter does not carry multicast), so
//!     loopback is not an option there and the default interface is the witness.
//!   * macOS: a send with no interface pinned FAILS with `EHOSTUNREACH`, and so
//!     does one pinned to the default route's address, although the routing table
//!     holds a multicast route for exactly that interface. Only a send pinned to
//!     `127.0.0.1` works. A plain Python process failed the same way, so it is
//!     not wz: it is macOS's local-network privacy denying the real interface to a
//!     process the runner's daemon spawned. Upstream, which leaves the interface
//!     to the OS the same way, would be denied identically, and the pin that
//!     reaches the network is the one thing a hosted macOS runner cannot grant.
//!
//! So macOS uses `lo0` and the other hosts keep the default, and what this does
//! NOT prove on macOS is multicast over a real interface; no hosted runner can.
//!
//! Opt-in (`#[ignore]`), like every multicast e2e here: whether a host can join
//! and loop a group is an environment fact, and the lane that runs it says so.

#![cfg(all(
    feature = "transport-multicast",
    feature = "locator-iface",
    feature = "transport-link-udp"
))]

use std::net::Ipv4Addr;
use std::time::Duration;

use wz_runtime_tokio::{LinkDriver, LinkEvent, McastSocketConfig, Reliability, TxFrame, UdpDriver};

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 224);
// Distinct from the other multicast tests' group ports (7446, 7448, 7449) so an
// `--ignored` run never contends with them on a bind.
const PORT: u16 = 7453;
const PAYLOAD: &[u8] = b"wz-multicast-host-roundtrip";

/// The interface this host's witness uses; see the module doc for the measurement
/// behind each arm.
fn host_iface() -> Option<&'static str> {
    if cfg!(target_os = "macos") {
        Some("lo0")
    } else {
        None
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "multicast loopback e2e; opt-in like Layer M, run by the Platform lane"]
async fn a_datagram_sent_to_the_group_reaches_a_member_on_the_same_host() {
    let cfg = McastSocketConfig {
        iface: host_iface(),
        ..McastSocketConfig::default()
    };

    let mut member = UdpDriver::bind_multicast(GROUP, PORT, cfg)
        .await
        .expect("a group member binds and joins on this host");
    let mut sender = UdpDriver::bind_multicast_tx(GROUP, PORT, cfg)
        .await
        .expect("a send-only group socket binds on this host");

    // A pin is a setsockopt, and one that returned Ok is not yet evidence: the
    // value the kernel kept is. Read back what the sender leaves by.
    if host_iface().is_some() {
        assert_eq!(
            sender
                .multicast_egress_v4()
                .expect("the kernel reports the egress interface"),
            Ipv4Addr::LOCALHOST,
            "the sender must be pinned to the interface the host witness uses"
        );
    }

    sender
        .send(&TxFrame { bytes: PAYLOAD }, Reliability::BestEffort)
        .await
        .expect("a send to the group leaves this host's interface");

    // Another member of the group may speak first on a shared port, so read until
    // OUR datagram arrives or the budget ends; a datagram that is not ours is not
    // a failure, only not the answer.
    let arrived = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let LinkEvent::Rx(frame) = member.poll_event().await {
                if frame.bytes.as_slice() == PAYLOAD {
                    return;
                }
            }
        }
    })
    .await;
    assert!(
        arrived.is_ok(),
        "the datagram a member's own host sent to the group did not come back to it"
    );
}
