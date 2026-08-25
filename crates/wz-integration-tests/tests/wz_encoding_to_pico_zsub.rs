// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y207 — FOREIGN-INTEROP Put ENCODING: a watching-zenoh publisher emits a
//! `Put` carrying a non-default body encoding (`text/plain`), and a real
//! zenoh-pico `z_sub_attachment` CLI decodes + prints it as
//! `with encoding: text/plain`.
//!
//! ## The gap this closes
//!
//! wz's Put-metadata wire propagation (encoding / attachment / qos) is built —
//! `Session::publish` routes a metadata-bearing publish through
//! `build_push_literal_with_meta` -> `build_msg_put_with_meta` (encoding
//! field) and `build_body_extensions` (attachment ext) — but it had NEVER been
//! exercised against a non-wz decoder. Every existing wz->pico Put test sends a
//! bare value with the default encoding, so pico only ever decoded
//! `zenoh/bytes`. This test proves wz's `encoding` wire form (zenoh
//! `Encoding` = `VLE(id << 1 | schema_bit)` then optional schema) is decodable
//! by zenoh-pico's `_z_encoding_decode`.
//!
//! ## Why `text/plain` (packed_id 8) and z_sub_attachment
//!
//! wz's `EncodingHint.packed_id` IS the zenoh wire value `id << 1 | schema_bit`
//! (session/tests.rs: "text/plain = zenoh encoding id 4 -> wz packed_id 8").
//! `8 = 4 << 1`, no schema. zenoh-pico maps id 4 -> `"text/plain"`
//! (`vendor/zenoh-pico/src/api/encoding.c:39,94`,
//! `Z_FEATURE_ENCODING_VALUES = 1`). The stock `z_sub` prints only key+value;
//! `z_sub_attachment` additionally prints `with encoding: <mime>` for EVERY
//! sample (`vendor/zenoh-pico/examples/unix/c11/z_sub_attachment.c:61`), so it
//! is the witness. The assertion distinguishes "encoding propagated"
//! (`text/plain`) from "encoding dropped on the wire" (pico would print the
//! default `zenoh/bytes`).
//!
//! ## Harness shape
//!
//! Mirrors `wz_fragment_tx_to_pico_zsub.rs` (in-test wz acceptor +
//! `Session::publish` over the accepted session, `select!` drive-vs-scenario,
//! pico CLI dial-in with accept-retry + a readiness gate + a 150 ms republish
//! cadence). The only deltas: the default (non-fragmenting) batch, the
//! `with_encoding` publish, the `z_sub_attachment` witness, and the
//! `with encoding: text/plain` assertion. `pubsub-encoding` is ON in this
//! crate's `wz-runtime-tokio` dev-dep (its default set), so the wire encode
//! carries the field. The wz<->wz host-lane proof of the same WIRE propagation
//! is `wz-runtime-tokio/tests/metadata_wire_e2e.rs` (R311y207) — it asserts
//! encoding + attachment survive a real TCP round-trip onto the peer's Sample
//! (the loopback tests in `session/tests.rs` cover only the field threading,
//! NOT the wire encode). A dropped encoding here surfaces as the default
//! `zenoh/bytes` in pico's output, so this e2e also self-detects a feature-drop.

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
use wz_session_core::sample::EncodingHint;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const PUBLISH_KEYEXPR: &str = "demo/enc";
const SUB_KEYEXPR: &str = "demo/**";
const PAYLOAD: &str = "encoded-hello-from-wz";
// zenoh Encoding wire value: id (4 = text/plain) << 1, no schema bit.
const TEXT_PLAIN_PACKED_ID: u32 = 8;

// wz-proves: pubsub-encoding wz->pico partial
// wz-proves: pubsub-put wz->pico
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_sub_attachment); Layer E runs via --ignored"]
async fn wz_put_encoding_decoded_by_pico_zsub_attachment() {
    let z_sub = zenoh_pico_cli_binary("z_sub_attachment");

    // wz acceptor binds first so pico's client dial lands in the listen
    // backlog and `accept()` resolves it.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz acceptor");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("tcp/{addr}");

    // Accept + handshake WITH RETRY (same rationale as wz_fragment_tx_to_pico_zsub):
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
            // proof is the decoded encoding, not fragmentation.
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

    let received_witness = ">> [Subscriber] Received";
    let encoding_witness = "with encoding: text/plain";
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
        // Republish the text/plain-encoded Put on a 150 ms cadence until pico
        // prints BOTH the payload AND `with encoding: text/plain` (idempotent,
        // byte-identical — one landing after the subscription is installed
        // suffices; not flaky-masking retry).
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            publisher
                .publish(
                    PUBLISH_KEYEXPR,
                    PAYLOAD.as_bytes(),
                    PublishOptions::put().with_encoding(EncodingHint {
                        packed_id: TEXT_PLAIN_PACKED_ID,
                        schema: None,
                    }),
                )
                .expect("encoded publish builds and routes through the send seam");
            tokio::time::sleep(Duration::from_millis(150)).await;
            let captured = read_captured(&mut z_sub_stdout_reader);
            if captured.contains(received_witness)
                && captured.contains(PAYLOAD)
                && captured.contains(encoding_witness)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico z_sub_attachment did not decode wz's text/plain Put within 12s.\n\
                     Expected '{received_witness}' + payload '{PAYLOAD}' + '{encoding_witness}' \
                     (a dropped encoding would print the default 'zenoh/bytes').\n\
                     --- captured stdout ---\n{captured}"
                ));
            }
        }
    };

    let result = tokio::select! {
        _ = drive => panic!(
            "wz drive loop reached a terminal state before pico decoded the encoded Put"
        ),
        r = scenario => r,
    };

    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();

    if let Err(msg) = result {
        panic!("wz->pico Put-encoding interop FAILED.\n{msg}");
    }
}
