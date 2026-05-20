// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R52 echo demo expansion — msg_del path + UDP datagram round-trip.
//!
//! Sibling to tests/echo_demo.rs (R51 msg_put + TCP). Two
//! additional integration tests:
//!
//!   - msg_del over TCP: validates the §6.1 DEL body path (R31
//!     codec) survives the same loopback round-trip the msg_put
//!     test validated. Same MID-vs-header byte assertion.
//!
//!   - msg_put over UDP: validates the UdpDriver impl. Same
//!     MsgPut payload, but UDP datagram preserves message
//!     boundaries — no 4-byte length prefix needed. Reliability
//!     hint sets BestEffort (the natural UDP semantic).

use sce_forge_runtime::codec::SceCursor;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use wz_codecs::msg_del::MsgDel;
use wz_codecs::msg_put::MsgPut;
use wz_runtime_tokio::{
    LinkDriver, LinkEvent, Reliability, TcpDriver, TxFrame, UdpDriver,
};

const MID_Z_PUT: u8 = 0x01;
const MID_Z_DEL: u8 = 0x02;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn echo_msg_del_tcp_round_trip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (addr_tx, addr_rx) = oneshot::channel::<u16>();
    addr_tx.send(port).expect("send port");

    let subscriber = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let mut driver = TcpDriver::from_stream(stream);
        driver.open().await.expect("subscriber open");
        let event = driver.poll_event().await;
        let frame_bytes = match event {
            LinkEvent::Rx(frame) => frame.bytes,
            other => panic!("expected Rx, got {other:?}"),
        };
        let mut cursor = SceCursor::new(&frame_bytes);
        let received = MsgDel::decode(&mut cursor).expect("decode");
        driver.close().await.expect("close");
        received
    });

    let publisher = tokio::spawn(async move {
        let port = addr_rx.await.expect("rx port");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let mut driver = TcpDriver::from_stream(stream);
        driver.open().await.expect("publisher open");
        let original = MsgDel {
            header: MID_Z_DEL,
            timestamp: None,
            extensions: None,
        };
        let bytes = original.encode_to_vec();
        driver
            .send(&TxFrame { bytes: &bytes }, Reliability::Reliable)
            .await
            .expect("send");
        driver.close().await.expect("close");
        original
    });

    let original = publisher.await.expect("publisher join");
    let received = subscriber.await.expect("subscriber join");
    assert_eq!(received.header, original.header);
    assert!(received.timestamp.is_none() && received.extensions.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn echo_msg_put_udp_round_trip() {
    // Bind subscriber socket first to capture port.
    let sub_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind sub");
    let sub_port = sub_socket.local_addr().expect("addr").port();
    let (port_tx, port_rx) = oneshot::channel::<u16>();
    port_tx.send(sub_port).expect("send port");

    let subscriber = tokio::spawn(async move {
        // UdpDriver needs a peer; for receive-only role we set
        // peer to a placeholder (loopback) since this side won't
        // call send(). poll_event() ignores peer.
        let placeholder_peer = "127.0.0.1:0".parse().expect("parse placeholder");
        let mut driver = UdpDriver::from_socket(sub_socket, placeholder_peer);
        driver.open().await.expect("subscriber open");
        let event = driver.poll_event().await;
        let frame_bytes = match event {
            LinkEvent::Rx(frame) => frame.bytes,
            other => panic!("expected Rx, got {other:?}"),
        };
        let mut cursor = SceCursor::new(&frame_bytes);
        let received = MsgPut::decode(&mut cursor).expect("decode");
        driver.close().await.expect("close");
        received
    });

    let publisher = tokio::spawn(async move {
        let port = port_rx.await.expect("rx port");
        let pub_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind pub");
        let peer = format!("127.0.0.1:{port}").parse().expect("parse peer");
        let mut driver = UdpDriver::from_socket(pub_socket, peer);
        driver.open().await.expect("publisher open");
        let original = MsgPut {
            header: MID_Z_PUT,
            timestamp: None,
            encoding: None,
            extensions: None,
            payload_len: 3,
            payload: vec![0x11, 0x22, 0x33],
        };
        let bytes = original.encode_to_vec();
        // Tiny grace so the subscriber's recv_from is ready; UDP
        // is connectionless, so a too-early send would be silently
        // dropped (no kernel buffer set up yet on the listener).
        tokio::time::sleep(Duration::from_millis(50)).await;
        driver
            .send(&TxFrame { bytes: &bytes }, Reliability::BestEffort)
            .await
            .expect("send");
        driver.close().await.expect("close");
        original
    });

    let original = publisher.await.expect("publisher join");
    let received = subscriber.await.expect("subscriber join");
    assert_eq!(received.header, original.header);
    assert_eq!(received.payload, original.payload);
    assert_eq!(received.payload_len, original.payload_len);
}
