// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y209 — FOREIGN-INTEROP Put ATTACHMENT: a watching-zenoh publisher emits
//! a `Put` whose attachment carries a `ze_serializer` kv-pair sequence, and a
//! real zenoh-pico `z_sub_attachment` CLI deserializes + prints it as
//! `with attachment:` followed by one `i: <key>, <value>` line per pair.
//!
//! ## The gap this closes
//!
//! wz's attachment WIRE ext (PUSH body ext `0x43`) was proven to carry an
//! OPAQUE blob end-to-end wz<->wz (`metadata_wire_e2e.rs`, R311y207) — but the
//! blob's INTERNAL structure had never been decoded by a foreign peer. pico's
//! `z_sub_attachment` does not treat the attachment as opaque: it runs
//! `ze_deserializer_deserialize_sequence_length` then a per-element
//! `ze_deserializer_deserialize_string` key/value loop
//! (`vendor/zenoh-pico/examples/unix/c11/z_sub_attachment.c:70-83`). A bare
//! opaque blob (`b"wz-meta-blob"`) mis-decodes there — pico reads the first
//! byte as a pair count. This test proves wz can emit the STRUCTURED payload
//! pico expects, via `wz_session_core::attachment::serialize_kv_attachment`
//! (the `VLE(count)` + per-string `VLE(len) bytes` form, byte-identical to
//! pico's `ze_serializer`), so pico decodes and prints the real key/value pairs.
//!
//! ## Why z_sub_attachment and this witness
//!
//! `z_sub_attachment` is the only stock pico CLI that reads + prints the
//! attachment (the plain `z_sub` ignores it). Its `print_attachment`
//! (z_sub_attachment.c:35-41) emits `     %zu: %.*s, %.*s` per pair, so a
//! two-pair blob surfaces as `0: alpha, uno` and `1: beta, dos`. Asserting
//! BOTH lines proves the sequence-length decode (count == 2) AND the
//! per-element string decode — a dropped or mis-serialized count would print
//! zero pairs (or garbage), not these exact lines.
//!
//! ## Harness shape
//!
//! Mirrors `wz_encoding_to_pico_zsub.rs` (in-test wz acceptor +
//! `Session::publish` over the accepted session, `select!` drive-vs-scenario,
//! pico CLI dial-in with accept-retry + a subscriber-declared readiness gate +
//! a 150 ms republish cadence). The only deltas: the `with_attachment`
//! kv-pair publish and the `with attachment:` + per-pair witnesses. The
//! wz<->wz host-lane proof that the attachment ext survives a real TCP round
//! trip is `wz-runtime-tokio/tests/metadata_wire_e2e.rs`; the exact kv-pair
//! wire bytes are locked by the `serialize_kv_attachment_*` unit tests in
//! `wz-session-core/src/attachment.rs`. This e2e is the foreign-decoder proof
//! the two host-lane gates cannot give (pico exposes no wz-side field readback).

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
use wz_session_core::attachment::serialize_kv_attachment;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const PUBLISH_KEYEXPR: &str = "demo/att";
const SUB_KEYEXPR: &str = "demo/**";
const PAYLOAD: &str = "attach-hello-from-wz";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_sub_attachment); Layer E runs via --ignored"]
async fn wz_put_attachment_decoded_by_pico_zsub_attachment() {
    let z_sub = zenoh_pico_cli_binary("z_sub_attachment");

    // wz acceptor binds first so pico's client dial lands in the listen
    // backlog and `accept()` resolves it.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz acceptor");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("tcp/{addr}");

    // Accept + handshake WITH RETRY (same rationale as wz_encoding_to_pico_zsub):
    // pico's one-shot open transient must be a retry, not a red build. The
    // common case succeeds on attempt 1.
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
            // Default (non-fragmenting) batch: a small Put stays one frame; the
            // proof is the decoded attachment, not fragmentation.
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

    // Publisher over the accepted session's actions (Arc-shared); the drive
    // loop below borrows `&opened.actions`, the publisher holds an independent
    // Arc clone.
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

    // The two kv-pairs wz serializes into the attachment; pico prints them as
    // `i: key, value`. Distinctive strings keep the substring witnesses
    // unambiguous.
    let attachment = serialize_kv_attachment(&[
        (b"alpha".as_slice(), b"uno".as_slice()),
        (b"beta".as_slice(), b"dos".as_slice()),
    ]);

    let received_witness = ">> [Subscriber] Received";
    let attachment_header_witness = "with attachment:";
    let pair0_witness = "0: alpha, uno";
    let pair1_witness = "1: beta, dos";
    let subscribed_witness = "Declaring Subscriber on";
    let scenario = async {
        // Gate the delivery budget on pico's subscriber-declared witness
        // before publishing (no-flaky; pico open latency does not eat the
        // delivery deadline). The drive loop keeps the session alive.
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
        // Republish the kv-attachment Put on a 150 ms cadence until pico prints
        // the payload AND both decoded pairs (idempotent, byte-identical — one
        // landing after the subscription is installed suffices; not
        // flaky-masking retry).
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            publisher
                .publish(
                    PUBLISH_KEYEXPR,
                    PAYLOAD.as_bytes(),
                    PublishOptions::put().with_attachment(attachment.clone()),
                )
                .expect("attachment publish builds and routes through the send seam");
            tokio::time::sleep(Duration::from_millis(150)).await;
            let captured = read_captured(&mut z_sub_stdout_reader);
            if captured.contains(received_witness)
                && captured.contains(PAYLOAD)
                && captured.contains(attachment_header_witness)
                && captured.contains(pair0_witness)
                && captured.contains(pair1_witness)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico z_sub_attachment did not decode wz's kv-attachment Put within 12s.\n\
                     Expected '{received_witness}' + payload '{PAYLOAD}' + '{attachment_header_witness}' \
                     + '{pair0_witness}' + '{pair1_witness}' (a mis-serialized kv-sequence would \
                     print zero pairs or garbage).\n\
                     --- captured stdout ---\n{captured}"
                ));
            }
        }
    };

    let result = tokio::select! {
        _ = drive => panic!(
            "wz drive loop reached a terminal state before pico decoded the attachment Put"
        ),
        r = scenario => r,
    };

    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();

    if let Err(msg) = result {
        panic!("wz->pico Put-attachment interop FAILED.\n{msg}");
    }
}
