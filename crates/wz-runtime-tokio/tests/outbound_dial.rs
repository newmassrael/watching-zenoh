// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311es integration test — the outbound dial half of the scouting
//! locator seam. `TcpDriver::connect` / `UdpDriver::connect` turn the
//! numeric endpoint a `ParsedLocator` carries into a connected link
//! driver, the Initiator-side counterpart to the acceptor-side
//! `from_stream` / `from_socket` constructors.
//!
//! Both tests dial a real loopback peer and confirm a frame written
//! through the dialed driver reaches that peer, proving the connect
//! path establishes a usable link (not just a constructed value).

use tokio::net::TcpListener;
#[cfg(feature = "transport-link-udp")]
use tokio::net::UdpSocket;
#[cfg(feature = "transport-link-udp")]
use wz_runtime_tokio::UdpDriver;
use wz_runtime_tokio::{LinkDriver, LinkEvent, Reliability, TcpDriver, TxFrame};

#[tokio::test]
async fn tcp_connect_dials_a_usable_loopback_link() {
    // Acceptor side: bind a loopback listener, accept into a
    // from_stream driver.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let accept_task = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.expect("accept");
        TcpDriver::from_stream(stream)
    });

    // Initiator side: dial via the new connect constructor.
    let mut client = TcpDriver::connect(addr).await.expect("connect");
    let mut acceptor = accept_task.await.expect("accept join");

    // A frame written through the dialed driver reaches the peer
    // verbatim across the streamed-link envelope.
    let payload = b"r311es-tcp-dial";
    client
        .send(&TxFrame { bytes: payload }, Reliability::Reliable)
        .await
        .expect("send");

    match acceptor.poll_event().await {
        LinkEvent::Rx(rx) => assert_eq!(rx.bytes, payload),
        other => panic!("expected Rx, got {other:?}"),
    }
}

#[cfg(feature = "transport-link-udp")]
#[tokio::test]
async fn udp_connect_dials_a_usable_loopback_peer() {
    // Receiver side: a plain bound socket whose address the dialer
    // targets.
    let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind receiver");
    let peer = receiver.local_addr().expect("local_addr");

    // Initiator side: dial via the new connect constructor (binds an
    // ephemeral local socket, targets `peer` for unicast send).
    let mut client = UdpDriver::connect(peer).await.expect("connect");

    let payload = b"r311es-udp-dial";
    client
        .send(&TxFrame { bytes: payload }, Reliability::BestEffort)
        .await
        .expect("send");

    let mut buf = [0u8; 64];
    let (n, _from) = receiver.recv_from(&mut buf).await.expect("recv");
    assert_eq!(&buf[..n], payload);
}
