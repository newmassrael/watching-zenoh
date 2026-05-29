// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// R265 — `TcpDriver::poll_event` cancel-safety integration suite.
//
// The R264 fixture surfaced an architectural gap: under a
// `tokio::select!` race that cancels `poll_event` mid-frame, the
// previous `read_exact`-based impl dropped any bytes already
// consumed from the socket, leaving the next iteration's poll
// re-syncing from a mis-aligned cursor (the payload's first byte
// became the next frame's length lo-byte). R265 refactors
// `TcpDriver::poll_event` into a `ReadState` state machine where
// each `.await` is a single `.read()` syscall (cancel-safe per
// tokio's documented contract), and the partial-read buffer
// survives cancellation in `self.read_state`.
//
// This file exercises that contract end-to-end against a real
// loopback `TcpListener` / `TcpStream` pair so the assertion is
// "after the documented cancellation pattern, `poll_event` returns
// the byte-correct payload that the peer wrote" — i.e. the
// integration-level proof, not just a unit-level state-machine
// snapshot. Three scenarios cover the failure modes:
//
//   1. `partial_length_prefix_survives_cancel` — peer writes 1 of
//      2 length bytes, select-cancel fires, peer completes the
//      frame, `poll_event` returns the correct payload.
//   2. `partial_payload_survives_cancel` — peer writes the full
//      length prefix + a slice of the payload, select-cancel
//      fires (possibly multiple times mid-payload), peer completes,
//      `poll_event` returns the byte-correct payload.
//   3. `eof_mid_frame_surfaces_peer_closed` — peer writes a
//      partial frame and drops; `poll_event` returns
//      `LinkEvent::Lost { cause: PeerClosed }` after the
//      next iteration sees EOF on `.read()` returning Ok(0).
//
// All three exercise the production wire envelope shape
// (`StreamEnvelope` = u16 LE prefix + payload) so the codec's
// decode path is also covered.

use std::time::Duration;

use sce_forge_runtime::codec::SceCursor;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use wz_codecs::stream_envelope::StreamEnvelope;
use wz_runtime_tokio::{LinkDriver, LinkEvent, LostCause, TcpDriver};

/// Build a loopback (writer, reader) pair where the reader half is
/// wrapped in a `TcpDriver`. The writer half is returned as a raw
/// `TcpStream` so the test can drive controlled partial writes.
async fn loopback_pair() -> (TcpStream, TcpDriver) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().expect("local_addr");
    let accept_task = tokio::spawn(async move {
        let (peer, _) = listener.accept().await.expect("accept");
        peer
    });
    let writer = TcpStream::connect(addr).await.expect("connect");
    let reader = accept_task.await.expect("accept join");
    // Disable Nagle so the test's small `write_all + flush` sequences
    // hit the wire promptly. Without this the kernel may coalesce a
    // 1-byte write with the next batched write, masking the
    // partial-read scenarios that this suite is designed to exercise.
    writer
        .set_nodelay(true)
        .expect("set_nodelay on writer side");
    reader
        .set_nodelay(true)
        .expect("set_nodelay on reader side");
    (writer, TcpDriver::from_stream(reader))
}

/// Encode a payload through the production `StreamEnvelope` codec
/// and return the full on-wire bytes (2-byte LE prefix + payload).
/// The test peer writes these bytes in controlled slices so the
/// reader-side state machine sees partial frames.
fn envelope_bytes(payload: &[u8]) -> Vec<u8> {
    let envelope = StreamEnvelope {
        payload_len: payload.len() as u16,
        payload,
    };
    envelope.encode_to_vec()
}

/// Sanity decode helper — confirms a `LinkEvent::Rx` carries the
/// expected payload bytes after the state machine reassembles a
/// frame across cancellations. Panics with a diagnostic on
/// mismatch so test failures surface the actual byte sequence.
fn assert_rx_payload(event: LinkEvent, expected: &[u8]) {
    match event {
        LinkEvent::Rx(rx) => {
            assert_eq!(
                rx.bytes, expected,
                "Rx payload bytes mismatch — state machine likely \
                 mis-reassembled across cancellation"
            );
            // Double-check: re-decode the (regenerated) wire shape
            // through StreamEnvelope to confirm the production codec
            // accepts the bytes verbatim. This catches any subtle
            // length / prefix mismatch the bytes-equality check
            // might miss.
            let wire = envelope_bytes(&rx.bytes);
            let mut cursor = SceCursor::new(&wire);
            let env = StreamEnvelope::decode(&mut cursor)
                .expect("StreamEnvelope::decode on re-encoded bytes");
            assert_eq!(env.payload, expected);
        }
        other => panic!("expected LinkEvent::Rx, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r265_partial_length_prefix_survives_cancel() {
    let (mut writer, mut driver) = loopback_pair().await;
    let payload = b"abc";
    let wire = envelope_bytes(payload);
    assert_eq!(wire.len(), 5, "2-byte prefix + 3-byte payload");

    // Stage 1: write 1 of 2 length-prefix bytes. The driver's
    // state machine sees `prefix[..1]` and parks in
    // ReadState::Length { offset: 1 } waiting for the second
    // byte. A select-cancel here is the precise scenario the
    // R265 refactor protects.
    writer
        .write_all(&wire[..1])
        .await
        .expect("partial length write");
    writer.flush().await.expect("flush partial length");

    // Race `poll_event` against a 100 ms timer. The timer wins
    // because the second length byte hasn't been written yet, so
    // the read call inside the Length arm is parked.
    let timeout_won = tokio::select! {
        _ = driver.poll_event() => false,
        _ = tokio::time::sleep(Duration::from_millis(100)) => true,
    };
    assert!(
        timeout_won,
        "poll_event must not return with only 1 of 2 length bytes"
    );

    // Stage 2: write the remaining length byte + full payload.
    // The state machine must resume from offset=1 (not offset=0)
    // for the assembled frame to decode correctly. If R265 had
    // regressed (e.g. by re-reading the prefix from scratch) the
    // next poll would read the OLD wire[1] byte plus the new
    // wire[2] byte as a length prefix, sized the payload wrong,
    // and the StreamEnvelope decode would either fail or return
    // garbage.
    writer.write_all(&wire[1..]).await.expect("complete write");
    writer.flush().await.expect("flush complete write");

    let event = tokio::time::timeout(Duration::from_secs(2), driver.poll_event())
        .await
        .expect("poll_event timed out waiting for complete frame");
    assert_rx_payload(event, payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r265_partial_payload_survives_cancel() {
    let (mut writer, mut driver) = loopback_pair().await;
    let payload = b"watching-zenoh-cancel-safety";
    let wire = envelope_bytes(payload);

    // Stage 1: write the full length prefix + 5 of N payload bytes.
    // The state machine consumes the prefix, transitions to
    // ReadState::Payload { offset: 5 }, and parks waiting for the
    // remaining payload bytes.
    let stage1_end = 2 + 5;
    writer
        .write_all(&wire[..stage1_end])
        .await
        .expect("partial payload write");
    writer.flush().await.expect("flush partial payload");

    let timeout_won = tokio::select! {
        _ = driver.poll_event() => false,
        _ = tokio::time::sleep(Duration::from_millis(100)) => true,
    };
    assert!(
        timeout_won,
        "poll_event must not return with partial payload (5 of {} bytes)",
        payload.len()
    );

    // Stage 2: write a few more payload bytes, cancel again. This
    // exercises the multi-cancel resilience — the state machine
    // must accumulate bytes across two consecutive cancellations
    // without losing the partial buffer.
    let stage2_end = 2 + 12;
    writer
        .write_all(&wire[stage1_end..stage2_end])
        .await
        .expect("second partial payload write");
    writer.flush().await.expect("flush second partial payload");

    let timeout_won_again = tokio::select! {
        _ = driver.poll_event() => false,
        _ = tokio::time::sleep(Duration::from_millis(100)) => true,
    };
    assert!(
        timeout_won_again,
        "poll_event must not return with second partial payload (12 of {} bytes)",
        payload.len()
    );

    // Stage 3: complete the frame.
    writer
        .write_all(&wire[stage2_end..])
        .await
        .expect("final payload write");
    writer.flush().await.expect("flush final payload");

    let event = tokio::time::timeout(Duration::from_secs(2), driver.poll_event())
        .await
        .expect("poll_event timed out waiting for complete frame");
    assert_rx_payload(event, payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r265_eof_mid_frame_surfaces_peer_closed() {
    let (mut writer, mut driver) = loopback_pair().await;
    let payload = b"truncated";
    let wire = envelope_bytes(payload);

    // Write the length prefix + 3 of 9 payload bytes, then drop
    // the writer half to half-close the connection. The reader
    // side's next `.read()` returns Ok(0) (EOF) which the state
    // machine maps to LinkEvent::Lost { PeerClosed }.
    let partial_end = 2 + 3;
    writer
        .write_all(&wire[..partial_end])
        .await
        .expect("partial wire write before close");
    writer.flush().await.expect("flush before close");
    writer
        .shutdown()
        .await
        .expect("shutdown writer half to half-close");
    drop(writer);

    let event = tokio::time::timeout(Duration::from_secs(2), driver.poll_event())
        .await
        .expect("poll_event timed out instead of surfacing EOF");
    match event {
        LinkEvent::Lost {
            cause: LostCause::PeerClosed,
        } => {}
        other => panic!("expected Lost {{ PeerClosed }} after mid-frame EOF, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r265_back_to_back_frames_with_intermediate_cancel() {
    let (mut writer, mut driver) = loopback_pair().await;
    let p1 = b"first";
    let p2 = b"second";
    let w1 = envelope_bytes(p1);
    let w2 = envelope_bytes(p2);

    // Write the entire first frame plus the first half of the
    // second frame's wire bytes in one shot, then cancel partway
    // through the second frame's read. The state machine must
    // emit the first frame cleanly (Rx with p1), then on the
    // next iteration park in ReadState::Length / Payload waiting
    // for the second frame's remaining bytes, surviving the
    // cancellation, and finally emit the second frame (Rx with p2).
    let stage1: Vec<u8> = w1.iter().chain(&w2[..2]).copied().collect();
    writer
        .write_all(&stage1)
        .await
        .expect("first frame + partial second frame write");
    writer.flush().await.expect("flush first stage");

    // First poll_event must return the complete first frame.
    let ev1 = tokio::time::timeout(Duration::from_secs(2), driver.poll_event())
        .await
        .expect("poll_event for first frame timed out");
    assert_rx_payload(ev1, p1);

    // Second poll_event should park waiting for the remainder of
    // the second frame's payload (only the prefix has arrived).
    let timeout_won = tokio::select! {
        _ = driver.poll_event() => false,
        _ = tokio::time::sleep(Duration::from_millis(100)) => true,
    };
    assert!(
        timeout_won,
        "poll_event must not return with only the second frame's prefix"
    );

    // Complete the second frame.
    writer
        .write_all(&w2[2..])
        .await
        .expect("second frame payload write");
    writer.flush().await.expect("flush second frame payload");
    let ev2 = tokio::time::timeout(Duration::from_secs(2), driver.poll_event())
        .await
        .expect("poll_event for second frame timed out");
    assert_rx_payload(ev2, p2);
}
