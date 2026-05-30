// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311et — the lifted split-link session-open pipeline round-trips frames
//! end to end against a unified `TcpDriver` peer, proving:
//!
//!   - `dial_tcp` + `wire_tcp_stream` produce a usable split link
//!     (outbound channel + writer task + inbound read driver).
//!   - the outbound `TcpWriteDriver` -> `writer_task` path frames bytes
//!     through the `StreamEnvelope` codec, so a `TcpDriver::from_stream`
//!     peer (which decodes via the same codec) reads the exact payload.
//!   - the inbound `TcpReadDriver` decodes a frame the peer sent, exercising
//!     the shared `poll_framed` framing state machine on the split read half.
//!
//! Cross-checking against `TcpDriver` (not a hand-rolled reader) is what
//! proves the wire shape is codec-consistent across both link models.

use tokio::net::TcpListener;
use wz_runtime_tokio::link_pipeline::{dial_tcp, wire_tcp_stream};
use wz_runtime_tokio::session_glue::BoxedLinkDriver;
use wz_runtime_tokio::{LinkDriver, LinkEvent, Reliability, TcpDriver, TxFrame};

#[tokio::test]
async fn pipeline_round_trips_both_directions_through_codec_envelope() {
    // Acceptor side: a unified TcpDriver decodes/encodes via StreamEnvelope.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let accept_task = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.expect("accept");
        TcpDriver::from_stream(stream)
    });

    // Initiator side: dial via the raw-dial primitive, then split into the
    // session-open pipeline triple.
    let stream = dial_tcp(addr).await.expect("dial");
    let (mut inbound, outbound, writer_handle) = wire_tcp_stream(stream);
    let mut peer = accept_task.await.expect("accept join");

    // Outbound: send_blocking enqueues; the writer task frames it via the
    // codec; the peer reads the verbatim payload back.
    let out_payload = b"r311et-pipeline-out";
    outbound.send_blocking(out_payload, Reliability::Reliable);
    match peer.poll_event().await {
        LinkEvent::Rx(rx) => assert_eq!(rx.bytes, out_payload),
        other => panic!("expected outbound Rx, got {other:?}"),
    }

    // Inbound: the peer sends; the split read driver decodes it.
    let in_payload = b"r311et-pipeline-in";
    peer.send(&TxFrame { bytes: in_payload }, Reliability::Reliable)
        .await
        .expect("peer send");
    match inbound.poll_event().await {
        LinkEvent::Rx(rx) => assert_eq!(rx.bytes, in_payload),
        other => panic!("expected inbound Rx, got {other:?}"),
    }

    // Dropping the outbound Arc closes the channel; the writer task drains
    // and shuts the write half, then the join completes.
    drop(outbound);
    writer_handle.await.expect("writer task join");
}
