// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "pubsub-encoding",
    feature = "pubsub-attachment",
    feature = "pubsub-timestamp"
))]

//! R311y207 — host-lane WIRE proof that a `Put`'s body metadata (encoding +
//! attachment) propagates over a real loopback TCP link and surfaces on the
//! peer's delivered `Sample`. The complement of the loopback-only metadata
//! tests in `wz-runtime-tokio/src/session/tests.rs` (which exercise
//! `build_loopback_sample`, NOT the wire encode) and the host-lane backstop
//! for the binary-dep wz->pico encoding e2e
//! (`wz-integration-tests/tests/wz_encoding_to_pico_zsub.rs`, R311y207): pico
//! as receiver exposes no wz-side field readback, so THIS test — where the
//! receiver IS wz — pins that `Session::publish` routes a metadata-bearing
//! publish through `build_push_literal_with_meta` -> `build_msg_put_with_meta`
//! (encoding field) + `build_body_extensions` (attachment ext 0x43) and the
//! peer's `parse_inbound` recovers both. A code regression that drops either
//! field on the wire fails here on every CI run, no pico needed.
//!
//! Scope of the guarantee: this catches a CODE regression in the wire
//! metadata encode/decode while `pubsub-encoding` / `pubsub-attachment` /
//! `pubsub-timestamp` are ON (the file `#![cfg(all(...))]`-gates on all three,
//! since it asserts each dimension). It does NOT guard those features being
//! DISABLED (the file compiles out then). The wz->pico e2e's assertion is a
//! positive value (`with encoding: text/plain`), so it self-detects a
//! feature-drop there (a dropped encoding prints the default `zenoh/bytes`).

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::net::TcpListener;

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::sample::{EncodingHint, TimestampHint};
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/meta";
// text/plain = zenoh encoding id 4 -> wz packed_id 8 (id << 1, no schema).
const TEXT_PLAIN_PACKED_ID: u32 = 8;
const ATTACHMENT: &[u8] = b"wz-meta-blob";
// A distinctive ntp64 `time` word carried by the explicit timestamp.
const TS_TIME: u64 = 0x0102_0304_0506_0708;

/// The delivered sample's metadata, captured from the acceptor's subscriber
/// callback (a named struct keeps the shared cell off clippy's
/// `type_complexity` radar and folds the fire count in).
#[derive(Default)]
struct CapturedMeta {
    encoding: Option<EncodingHint>,
    attachment: Option<Vec<u8>>,
    timestamp: Option<TimestampHint>,
    fired: usize,
}

/// A metadata-bearing `Session::publish` (encoding text/plain + an attachment
/// blob + an explicit timestamp) reaches the peer over a real TCP link and all
/// three fields survive the wire encode/decode round-trip onto the delivered
/// `Sample`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unicast_put_metadata_propagates_over_the_wire() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // Open both sessions concurrently (default batch — no fragmentation; the
    // proof is the recovered metadata, not the framing).
    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        accept_and_open_session(
            DialedLink::Tcp(stream),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        connect_and_open_session(
            locator,
            params,
            &DialConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    // Subscriber on the acceptor captures the delivered sample's metadata.
    let captured = Arc::new(StdMutex::new(CapturedMeta::default()));
    let mut observer = ApplicationLayerObserver::new();
    {
        let captured = captured.clone();
        observer.subscribers.register(KEYEXPR, move |sample| {
            assert_eq!(sample.keyexpr(), KEYEXPR);
            let mut c = captured.lock().unwrap();
            c.encoding = sample.encoding().cloned();
            c.attachment = sample.attachment().map(<[u8]>::to_vec);
            c.timestamp = sample.timestamp().cloned();
            c.fired += 1;
        });
    }

    let publisher = TokioSession::new(
        opened_init.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened_init.clock),
    );

    let timeouts = SessionTimeouts::spec_defaults();
    let drive_acc = drive_session_until_terminal(
        &mut opened_acc.inbound,
        &opened_acc.actions,
        &mut opened_acc.engine,
        None,
        &opened_acc.clock,
        &timeouts,
        |event| observer.dispatch_event(event),
    );
    let drive_init = drive_session_until_terminal(
        &mut opened_init.inbound,
        &opened_init.actions,
        &mut opened_init.engine,
        None,
        &opened_init.clock,
        &timeouts,
        |_| {},
    );

    let captured_probe = captured.clone();
    let scenario = async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        publisher
            .publish(
                KEYEXPR,
                b"metadata-payload",
                PublishOptions::put()
                    .with_encoding(EncodingHint {
                        packed_id: TEXT_PLAIN_PACKED_ID,
                        schema: None,
                    })
                    .with_attachment(ATTACHMENT.to_vec())
                    .with_timestamp(TimestampHint {
                        time: TS_TIME,
                        zid: vec![0xAB],
                    }),
            )
            .expect("metadata publish builds and routes through the send seam");
        for _ in 0..100 {
            if captured_probe.lock().unwrap().fired > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("subscriber did not fire within the ~3s budget");
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_init => panic!("initiator drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    let c = captured.lock().unwrap();
    assert_eq!(c.fired, 1, "exactly one wire-delivered sample");
    let enc = c
        .encoding
        .as_ref()
        .expect("the text/plain encoding must survive the wire (a dropped field would be None)");
    assert_eq!(
        enc.packed_id, TEXT_PLAIN_PACKED_ID,
        "the recovered encoding id must be text/plain"
    );
    assert!(enc.schema.is_none(), "text/plain carries no schema");
    assert_eq!(
        c.attachment.as_deref(),
        Some(ATTACHMENT),
        "the attachment blob must survive the wire ext 0x43 encode/decode"
    );
    let ts = c
        .timestamp
        .as_ref()
        .expect("the explicit timestamp must survive the wire (T-flag 0x20 + MsgPut.timestamp)");
    assert_eq!(
        ts.time, TS_TIME,
        "the recovered ntp64 time word must match the published one"
    );
}
