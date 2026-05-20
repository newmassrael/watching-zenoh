// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Echo demo — FIRST OBSERVABLE COMMUNICATION milestone.
//!
//! Two tokio tasks on a single process exchange a real wz-encoded
//! MsgPut body over a tokio TCP loopback link:
//!
//!   publisher                       subscriber
//!   ─────────                       ──────────
//!   1. construct MsgPut             1. listen on 127.0.0.1:port
//!      with payload                 2. accept connection
//!   2. encode via wz-codecs         3. wrap TcpStream in TcpDriver
//!      → Vec<u8> wire bytes         4. poll_event → LinkEvent::Rx
//!   3. connect to subscriber        5. decode via wz-codecs
//!   4. wrap TcpStream in TcpDriver     → MsgPut struct
//!   5. send(TxFrame{bytes})         6. assert decoded == published
//!   6. close
//!
//! What this proves:
//!   - wz-codecs encode produces bytes that wz-codecs decode
//!     accepts round-trip across a network socket boundary
//!     (independent of in-memory test correctness).
//!   - The 4-method LinkDriver contract is operable (open / send /
//!     close / poll_event).
//!   - The Layer 3 wire-validated codec actually survives a real
//!     TCP transport — i.e., the bytes Layer 3 byte-compared
//!     against zenoh-pico are the SAME bytes that flow on the wire
//!     in production.
//!
//! What this does NOT yet prove:
//!   - Interop with an actual zenoh-pico endpoint (needs the
//!     session-FSM handshake — R54 wiring round).
//!   - Multi-message reliability / fragmentation / extensions.
//!   - Trust-class gating, io_uring path, pool-slot zero-copy
//!     borrows (all deferred per docs/runtime-crate-tokio.md).

use sce_forge_runtime::codec::SceCursor;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use wz_codecs::msg_put::MsgPut;
use wz_runtime_tokio::{LinkDriver, LinkEvent, Reliability, TcpDriver, TxFrame};

const MID_Z_PUT: u8 = 0x01;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn echo_demo_msg_put_round_trip() {
    // Bind a TCP listener on an OS-chosen port. The subscriber task
    // captures the bound address via a oneshot channel.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 127.0.0.1:0");
    let port = listener.local_addr().expect("local_addr").port();
    let (addr_tx, addr_rx) = oneshot::channel::<u16>();
    addr_tx.send(port).expect("send port");

    // ---- Subscriber task ----
    let subscriber = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let mut driver = TcpDriver::from_stream(stream);
        driver.open().await.expect("subscriber open");

        // Wait for the single frame the publisher sends.
        let event = driver.poll_event().await;
        let frame_bytes = match event {
            LinkEvent::Rx(frame) => frame.bytes,
            other => panic!("expected Rx, got {other:?}"),
        };

        // Decode via wz-codecs.
        let mut cursor = SceCursor::new(&frame_bytes);
        let received = MsgPut::decode(&mut cursor).expect("decode");
        driver.close().await.expect("subscriber close");
        received
    });

    // ---- Publisher task ----
    let publisher = tokio::spawn(async move {
        let port = addr_rx.await.expect("rx port");
        // Small delay to let the listener get fully ready; OS-level
        // bind+listen is usually instant but a 50ms grace prevents
        // ECONNREFUSED on slow CI runners.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let mut driver = TcpDriver::from_stream(stream);
        driver.open().await.expect("publisher open");

        // Construct + encode a known MsgPut.
        let original = MsgPut {
            header: MID_Z_PUT,
            timestamp: None,
            encoding: None,
            extensions: None,
            payload_len: 5,
            payload: vec![0xCA, 0xFE, 0xBA, 0xBE, 0x42],
        };
        let bytes = original.encode_to_vec();
        driver
            .send(&TxFrame { bytes: &bytes }, Reliability::Reliable)
            .await
            .expect("send");
        driver.close().await.expect("publisher close");
        original
    });

    // Both tasks complete; cross-check the round-trip.
    let original = publisher.await.expect("publisher join");
    let received = subscriber.await.expect("subscriber join");

    assert_eq!(received.header, original.header, "header round-trip");
    assert_eq!(received.payload_len, original.payload_len, "payload_len");
    assert_eq!(received.payload, original.payload, "payload bytes");
    assert!(
        received.timestamp.is_none() && received.encoding.is_none()
            && received.extensions.is_none(),
        "no flags decoded"
    );
}
