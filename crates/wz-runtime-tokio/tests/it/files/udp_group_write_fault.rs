// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 902 — a group link whose SEND fails is a lost link.
//!
//! A multicast session reads its group on one task and writes it from another
//! (`UdpDriver::group_sender`, as upstream's multicast link writes from a TX
//! task of its own). The read half turned a receive error into
//! `LinkEvent::Lost`; the write half returned its error to a transmit task that
//! counted the datagram as unwritten and carried on. A group whose interface
//! was removed behaves exactly so: `recvfrom` on the socket bound to it
//! just never returns, while every `send` fails with `ENODEV`. Nothing then
//! told the session its link was gone, and it ran on until its peers' leases
//! expired, where upstream deletes the transport on the first failed write
//! (`io/zenoh-transport/src/multicast/link.rs` @
//! `tracing::debug!("TX task failed: {}", e);`).
//!
//! No group, no interface and no privilege are needed to witness the wiring:
//! the driver is built over an ordinary socket, and a datagram one byte past
//! what UDP carries is refused by the kernel with `EMSGSIZE`, which is a failed
//! write like any other. The interface-removal case itself is witnessed in a
//! network namespace by the demo's group-session leg.

#![cfg(feature = "transport-link-udp")]

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;
use wz_runtime_tokio::{LinkDriver, LinkEvent, LostCause, UdpDriver};

/// Past this a datagram is refused by `sendto(2)` with `EMSGSIZE`.
const MAX_UDP_PAYLOAD: usize = 65_507;

/// How long a link that has failed to write is given to say so.
const LOST_WITHIN: Duration = Duration::from_secs(5);

/// How long a healthy link is watched for a loss that must not come.
const QUIET_FOR: Duration = Duration::from_millis(400);

async fn driver_over_an_ordinary_socket(peer: SocketAddr) -> UdpDriver {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    UdpDriver::from_socket(socket, peer)
}

#[tokio::test]
async fn a_group_send_that_fails_is_a_lost_link() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let mut driver = driver_over_an_ordinary_socket(peer.local_addr().expect("peer addr")).await;
    let sender = driver.group_sender().expect("a send half");

    sender
        .send(&vec![0u8; MAX_UDP_PAYLOAD + 1])
        .await
        .expect_err("the kernel refuses a datagram UDP cannot carry");

    let event = timeout(LOST_WITHIN, driver.poll_event()).await;
    assert!(
        matches!(
            event,
            Ok(LinkEvent::Lost {
                cause: LostCause::OsError
            })
        ),
        "a failed group send must end the link; got {event:?}"
    );
}

/// The negative half. A send that succeeds says nothing about the link, so a
/// latch that tripped on any send would end every group session at its first
/// JOIN. The sender is cloned first, as the transmit task takes it.
#[tokio::test]
async fn a_group_send_that_succeeds_leaves_the_link_up() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let mut driver = driver_over_an_ordinary_socket(peer.local_addr().expect("peer addr")).await;
    let sender = driver.group_sender().expect("a send half").clone();

    sender.send(b"a-datagram").await.expect("a send that works");

    let event = timeout(QUIET_FOR, driver.poll_event()).await;
    assert!(
        event.is_err(),
        "a link that wrote fine is not lost; got {event:?}"
    );
}
