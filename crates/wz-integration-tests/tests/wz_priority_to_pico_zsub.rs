// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y240 — FOREIGN-INTEROP Put PRIORITY: a watching-zenoh publisher emits a
//! `Put` carrying a non-default qos priority (`RealTime` = 1), and a real
//! zenoh-pico `z_sub_attachment` CLI decodes it and prints `with priority: 1`.
//!
//! ## The gap this closes
//!
//! wz's Put-metadata WIRE propagation for the outer Push QoS ext (priority /
//! congestion-control / express, packed one byte) is built — `Session::publish`
//! routes a metadata-bearing publish through `push_metadata()` ->
//! `build_push_literal_with_meta` -> `build_push_outer_extensions`, which emits
//! the `_Z_MSG_EXT_ENC_ZINT | 0x01` QoS ext when the packed byte differs from
//! `QosLevel::DEFAULT` — and it is wz<->wz proven (session/tests.rs field
//! threading + the outer-ext unit tests in push_build.rs). But the byte had
//! NEVER been decoded by a foreign peer: encoding (y207), timestamp (y208) and
//! attachment (y209) each gained a wz->pico witness, while the qos byte had
//! none. This test closes the PRIORITY SUB-FIELD wz->pico gap.
//!
//! ## Scope — priority sub-field ONLY
//!
//! The QoS ext byte packs priority (low 3 bits) + congestion (bit 3) + express
//! (bit 4). `z_sample_priority` witnesses ONLY the priority sub-field. This
//! test does NOT prove congestion-control or express foreign-decode — those
//! ride the same byte and are witnessed separately by
//! `wz_qos_congestion_express_to_pico_zsub` (R311y242) via pico's public
//! `z_sample_congestion_control` / `z_sample_express` getters (both DO exist
//! and read the same `sample->qos` byte — do not repeat the earlier "no
//! congestion getter" mis-read). Do not read this single test as a full "qos
//! cross-impl proven" claim.
//!
//! ## Why `RealTime` (1) and not the default
//!
//! pico's default sample priority is `Z_PRIORITY_DATA` = 5
//! (`constants.h`, `_Z_N_QOS_DEFAULT._val = 5`). If wz DROPPED the priority on
//! the wire, pico would decode the default and print `with priority: 5`. A
//! `Data`(5) publish is doubly wrong: wz's `build_push_outer_extensions`
//! SUPPRESSES the ext when the byte equals `QosLevel::DEFAULT` (0x05), so pico
//! would print 5 whether or not propagation works — a tautology. `RealTime`(1)
//! is maximally distinct: wz's `Priority::wire_byte()` is 1:1 with pico's
//! `z_priority_t` (`RealTime = 1` on both), the emitted qos byte is 0x01, and
//! pico decodes `0x01 & 0x07 = 1`. So `with priority: 1` genuinely
//! discriminates "priority propagated" from "priority dropped" (which prints
//! the default 5), the same discriminating shape as the y207 encoding witness
//! (`text/plain` vs the fallback `zenoh/bytes`).
//!
//! ## The witness
//!
//! The stock `z_sub_attachment` does NOT print priority; `scripts/
//! build-zenoh-pico-cli.sh` build-time-patches it to add a
//! `printf("    with priority: %d\n", (int)z_sample_priority(sample))` line
//! (the 2nd wz-side in-place pico-example patch, alongside the z_put.c
//! BLOCK-congestion patch; documented in THIRD_PARTY.md, reverted on exit by
//! the shared trap). `pubsub-priority` is ON in this crate's wz-runtime-tokio
//! dev-dep default set, so the send-side encodes the byte.
//!
//! ## Harness shape
//!
//! Mirrors `wz_encoding_to_pico_zsub.rs` (in-test wz acceptor +
//! `Session::publish` over the accepted session, `select!` drive-vs-scenario,
//! pico CLI dial-in with accept-retry + a subscriber-declared readiness gate +
//! a 150 ms republish cadence). The only deltas: the `with_priority` publish
//! and the `with priority: 1` assertion.

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
use wz_session_core::qos::Priority;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const PUBLISH_KEYEXPR: &str = "demo/prio";
const SUB_KEYEXPR: &str = "demo/**";
const PAYLOAD: &str = "prioritized-hello-from-wz";

// R311y312 — was `pubsub-priority`, which R311y307 demoted to an elidable cargo
// alias of `pubsub-qos` with zero cfg sites of its own; a proof must bind to the
// atom's own gated code, and the code this test drives is gated on `pubsub-qos`.
// `partial` is the honest strength: this test witnesses the priority bits (0-2)
// of the qos byte, not the nodrop (3) or express (4) bits. The FULL claim on the
// whole byte is wz_qos_congestion_express_to_pico_zsub, which asserts all three.
// wz-proves: pubsub-qos wz->pico partial
// wz-proves: pubsub-put wz->pico
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_sub_attachment); Layer E runs via --ignored"]
async fn wz_put_priority_decoded_by_pico_zsub_attachment() {
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
            // proof is the decoded priority, not fragmentation.
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
    // `RealTime` = 1; a dropped priority would print the default `5`, so the
    // exact `with priority: 1` line discriminates propagated from dropped.
    let priority_witness = "with priority: 1";
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
        // Republish the RealTime-priority Put on a 150 ms cadence until pico
        // prints BOTH the payload AND `with priority: 1` (idempotent,
        // byte-identical — one landing after the subscription is installed
        // suffices; not flaky-masking retry).
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            publisher
                .publish(
                    PUBLISH_KEYEXPR,
                    PAYLOAD.as_bytes(),
                    PublishOptions::put().with_priority(Priority::RealTime),
                )
                .expect("prioritized publish builds and routes through the send seam");
            tokio::time::sleep(Duration::from_millis(150)).await;
            let captured = read_captured(&mut z_sub_stdout_reader);
            if captured.contains(received_witness)
                && captured.contains(PAYLOAD)
                && captured.contains(priority_witness)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico z_sub_attachment did not decode wz's RealTime-priority Put within 12s.\n\
                     Expected '{received_witness}' + payload '{PAYLOAD}' + '{priority_witness}' \
                     (a dropped priority would print the default 'with priority: 5').\n\
                     --- captured stdout ---\n{captured}"
                ));
            }
        }
    };

    let result = tokio::select! {
        _ = drive => panic!(
            "wz drive loop reached a terminal state before pico decoded the prioritized Put"
        ),
        r = scenario => r,
    };

    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();

    if let Err(msg) = result {
        panic!("wz->pico Put-priority interop FAILED.\n{msg}");
    }
}
