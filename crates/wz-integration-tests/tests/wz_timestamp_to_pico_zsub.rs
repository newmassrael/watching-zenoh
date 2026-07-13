// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y208 — FOREIGN-INTEROP Put TIMESTAMP: a watching-zenoh publisher emits a
//! `Put` carrying an explicit body timestamp, and a real zenoh-pico
//! `z_sub_attachment` CLI decodes it and prints `with timestamp: <ntp64>`.
//!
//! ## The gap this closes
//!
//! wz's Put timestamp reaches the wire via `Session::publish` ->
//! `build_push_literal_with_meta` -> `build_msg_put_with_meta`, which sets the
//! `MsgPut.timestamp` field (`gated_timestamp_field`, gated `pubsub-timestamp`)
//! AND the header T-flag `0x20` (`push_build.rs`), so a patched peer decodes it
//! off `header & 0x20`. This test (and the wz<->wz `metadata_wire_e2e` backstop)
//! prove the timestamp propagates.
//!
//! R311y255 — this note used to say the `publish_common.rs` field-doc comment
//! ("current wire branch DROPS this field") was STALE. That comment has since
//! been corrected (the `PublishOptions::timestamp` doc now cites this very test),
//! so the note pointed at a quote that no longer exists — a stale claim ABOUT a
//! stale claim. Dropped; the propagation fact it was guarding is stated directly
//! above.
//!
//! ## Witness
//!
//! `z_sub_attachment` prints `with timestamp: <ntp64-u64>` ONLY when the
//! delivered sample carries a timestamp
//! (`vendor/zenoh-pico/examples/unix/c11/z_sub_attachment.c`:
//! `if (ts != NULL) printf(... z_timestamp_ntp64_time(ts))`). So the assertion
//! is a positive discriminator: a dropped timestamp prints no line and the
//! test fails loudly (no false-positive, self-detects a feature-drop).
//! `z_timestamp_ntp64_time` returns the raw ntp64 `time` word, which is exactly
//! wz's `TimestampHint.time`, so pico prints its decimal verbatim.
//!
//! ## Harness shape
//!
//! Mirrors `wz_encoding_to_pico_zsub.rs` (in-test wz acceptor + `Session::publish`
//! over the accepted session, accept-retry + readiness gate + 150ms republish);
//! the only deltas are the `with_timestamp` publish and the `with timestamp:`
//! assertion.

use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;

use wz_integration_tests::common::{read_captured, zenoh_pico_cli_binary, ChildGuard};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{accept_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::sample::TimestampHint;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const PUBLISH_KEYEXPR: &str = "demo/ts";
const SUB_KEYEXPR: &str = "demo/**";
const PAYLOAD: &str = "timestamped-hello-from-wz";
// A distinctive ntp64 `time` word; pico prints it verbatim in decimal.
const TS_TIME: u64 = 0x0102_0304_0506_0708;

// wz-proves: pubsub-timestamp wz->pico
// wz-proves: pubsub-put wz->pico
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_sub_attachment); Layer E runs via --ignored"]
async fn wz_put_timestamp_decoded_by_pico_zsub_attachment() {
    let z_sub = zenoh_pico_cli_binary("z_sub_attachment");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz acceptor");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("tcp/{addr}");

    // Accept + handshake WITH RETRY (pico one-shot open transient -> retry).
    const OPEN_ATTEMPTS: usize = 6;
    let established = {
        let mut acc = None;
        for attempt in 1..=OPEN_ATTEMPTS {
            let z_sub_stdout = tempfile::tempfile().expect("tempfile for z_sub stdout");
            let z_sub_stdout_writer = z_sub_stdout.try_clone().expect("dup z_sub stdout handle");
            let z_sub_stdout_reader = z_sub_stdout;
            let mut z_sub_child = ChildGuard::wrap(
                "z_sub_attachment client (zenoh-pico)",
                Command::new("stdbuf")
                    .args(["-oL", "-eL"])
                    .arg(&z_sub)
                    .args(["-k", SUB_KEYEXPR, "-e", &endpoint, "-m", "client"])
                    .stdout(Stdio::from(z_sub_stdout_writer))
                    .stderr(Stdio::inherit())
                    .spawn()
                    .expect("spawn z_sub_attachment via stdbuf"),
            );
            let accepted = tokio::time::timeout(Duration::from_secs(8), listener.accept()).await;
            let stream = match accepted {
                Ok(Ok((stream, _peer))) => stream,
                _ => {
                    let _ = z_sub_child.child_mut().kill();
                    let _ = z_sub_child.child_mut().wait();
                    eprintln!(
                        "attempt {attempt}/{OPEN_ATTEMPTS}: pico did not connect within 8s; retrying"
                    );
                    continue;
                }
            };
            let params = fixture_session_init_params();
            match accept_and_open_session(
                DialedLink::Tcp(stream),
                params,
                TokioTime::new(),
                Some(ITER_CAP),
                DEFAULT_OPEN_TICK_MS,
            )
            .await
            {
                Ok(opened) => {
                    acc = Some((opened, z_sub_child, z_sub_stdout_reader));
                    break;
                }
                Err(e) => {
                    let _ = z_sub_child.child_mut().kill();
                    let _ = z_sub_child.child_mut().wait();
                    eprintln!(
                        "attempt {attempt}/{OPEN_ATTEMPTS}: wz<->pico handshake failed ({e:?}); retrying"
                    );
                    continue;
                }
            }
        }
        acc.expect(
            "wz acceptor reached Established against a pico z_sub_attachment client within OPEN_ATTEMPTS",
        )
    };
    let (mut opened, mut z_sub_child, mut z_sub_stdout_reader) = established;

    let publisher = TokioSession::new(
        opened.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened.clock),
    );

    let timeouts = SessionTimeouts::spec_defaults();
    let mut observer = ApplicationLayerObserver::new();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        |event| observer.dispatch_event(event),
    );

    let received_witness = ">> [Subscriber] Received";
    let timestamp_witness = format!("with timestamp: {TS_TIME}");
    let subscribed_witness = "Declaring Subscriber on";
    let scenario = async {
        let ready_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let captured = read_captured(&mut z_sub_stdout_reader);
            if captured.contains(subscribed_witness) {
                break;
            }
            if Instant::now() >= ready_deadline {
                return Err(format!(
                    "pico z_sub_attachment did not declare its subscriber within 10s.\n\
                     --- captured stdout ---\n{captured}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            publisher
                .publish(
                    PUBLISH_KEYEXPR,
                    PAYLOAD.as_bytes(),
                    PublishOptions::put().with_timestamp(TimestampHint {
                        time: TS_TIME,
                        zid: vec![0xAB],
                    }),
                )
                .expect("timestamped publish builds and routes through the send seam");
            tokio::time::sleep(Duration::from_millis(150)).await;
            let captured = read_captured(&mut z_sub_stdout_reader);
            if captured.contains(received_witness)
                && captured.contains(PAYLOAD)
                && captured.contains(&timestamp_witness)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico z_sub_attachment did not decode wz's timestamped Put within 12s.\n\
                     Expected '{received_witness}' + payload '{PAYLOAD}' + '{timestamp_witness}' \
                     (a dropped timestamp prints no timestamp line).\n\
                     --- captured stdout ---\n{captured}"
                ));
            }
        }
    };

    let result = tokio::select! {
        _ = drive => panic!(
            "wz drive loop reached a terminal state before pico decoded the timestamped Put"
        ),
        r = scenario => r,
    };

    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();

    if let Err(msg) = result {
        panic!("wz->pico Put-timestamp interop FAILED.\n{msg}");
    }
}
