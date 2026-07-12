// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y243 — FOREIGN-INTEROP Put SOURCE_INFO: a watching-zenoh publisher
//! emits a `Put` carrying a non-default `source_info` (zid `[0xAB,0xCD]`,
//! eid 66, sn 153), and a real zenoh-pico `z_sub_attachment` CLI decodes it
//! and prints `with source_info eid: 66 sn: 153`.
//!
//! ## The gap this closes
//!
//! source_info was the last Put-body metadata slot with NO wz->pico witness:
//! encoding (y207), timestamp (y208), attachment (y209) and the QoS byte
//! (priority y240 / congestion+express y242) each gained a foreign witness,
//! while source_info's encode was pinned solely by the wz-internal unit test
//! `build_msg_put_with_meta_attaches_source_info_ext_and_sets_z_flag` — never
//! decoded by a foreign peer. This test closes it.
//!
//! ## Observation path (verified by direct read of vendor pin 3b3ab65)
//!
//! wz emits source_info as a body ext `ENC_ZBUF | 0x01`
//! (`source_info_ext.rs::encode_source_info_ext_entry`, header 0x41) whose
//! value bytes are `[(zid_len-1)<<4][zid][VLE eid][VLE sn]`. pico's
//! `_z_push_body_decode_extensions` decodes exactly that id at
//! `message.c:309-311` into `_body._put._commons._source_info`
//! (`_z_source_info_decode`, `message.c:196`: `(zidlen>>4)+1` then zid then
//! two `_z_zsize_decode`s — the byte-exact inverse of wz's encoder), the
//! subscription trigger copies it into the sample (`net/sample.c:31`
//! `dst->source_info = *source_info`), and `z_sample_source_info` returns it
//! (`api.c:1242`). That getter is gated on `Z_FEATURE_UNSTABLE_API`, which the
//! vendor build defaults OFF (`CMakeLists.txt:316`) — so
//! `scripts/build-zenoh-pico-cli.sh` now sets `-DZ_FEATURE_UNSTABLE_API=ON`
//! and prints the source_info line under `#ifdef Z_FEATURE_UNSTABLE_API`.
//!
//! ## Why these values discriminate
//!
//! `z_sample_source_info` returns NULL when the sender set no source_info
//! (`primitives.h:2239`), and the patched CLI prints the line only inside
//! `if (wz_si != NULL)`. So if wz DROPPED source_info the CLI would print NO
//! `with source_info` line at all and the test would time out — the exact
//! `eid: 66 sn: 153` line therefore discriminates "propagated" from "dropped",
//! and also proves the eid/sn VLE fields round-trip (a mis-encoded length or
//! swapped field would decode to different integers). eid 66 (0x42) + sn 153
//! (0x99) are arbitrary non-zero values distinct from any default.
//!
//! ## Harness shape
//!
//! Mirrors `wz_qos_congestion_express_to_pico_zsub.rs` (in-test wz acceptor +
//! `Session::publish` + `select!` drive-vs-scenario + pico CLI dial-in with
//! accept-retry + a subscriber-readiness gate + a 150 ms republish cadence).
//! The only deltas: the `with_source_info` publish and the source_info
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
use wz_session_core::sample::SourceInfo;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const PUBLISH_KEYEXPR: &str = "demo/srcinfo";
const SUB_KEYEXPR: &str = "demo/**";
const PAYLOAD: &str = "source-info-hello-from-wz";
const SRC_EID: u32 = 66;
const SRC_SN: u32 = 153;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_sub_attachment); Layer E runs via --ignored"]
async fn wz_put_source_info_decoded_by_pico_zsub_attachment() {
    let z_sub = zenoh_pico_cli_binary("z_sub_attachment");

    // wz acceptor binds first so pico's client dial lands in the listen
    // backlog and `accept()` resolves it.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz acceptor");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("tcp/{addr}");

    // Accept + handshake WITH RETRY (same rationale as the sibling qos
    // witnesses): pico's one-shot open transient must be a retry, not a red
    // build. The common case succeeds on attempt 1.
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
            // proof is the decoded source_info, not fragmentation.
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
    // eid 66 + sn 153; a dropped source_info would print NO `with source_info`
    // line (the CLI guards on `z_sample_source_info != NULL`), so the exact
    // line discriminates propagated from dropped AND proves the VLE fields.
    let source_info_witness = "with source_info eid: 66 sn: 153";
    let subscribed_witness = "Declaring Subscriber on";
    // zid [0xAB,0xCD] is arbitrary + distinct from the wz session zid (self-echo
    // dedup is a receive-side concern; pico is the subscriber here, so the send
    // path encodes source_info verbatim).
    let source_info = SourceInfo::new(&[0xAB, 0xCD], SRC_EID, SRC_SN);
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
        // Republish the source_info-bearing Put on a 150 ms cadence until pico
        // prints the payload AND the exact source_info line (idempotent,
        // byte-identical — one landing after the subscription is installed
        // suffices; not flaky-masking retry).
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            publisher
                .publish(
                    PUBLISH_KEYEXPR,
                    PAYLOAD.as_bytes(),
                    PublishOptions::put().with_source_info(source_info.clone()),
                )
                .expect("source_info publish builds and routes through the send seam");
            tokio::time::sleep(Duration::from_millis(150)).await;
            let captured = read_captured(&mut z_sub_stdout_reader);
            if captured.contains(received_witness)
                && captured.contains(PAYLOAD)
                && captured.contains(source_info_witness)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico z_sub_attachment did not decode wz's source_info Put within 12s.\n\
                     Expected '{received_witness}' + payload '{PAYLOAD}' + '{source_info_witness}' \
                     (a dropped source_info would print NO 'with source_info' line).\n\
                     --- captured stdout ---\n{captured}"
                ));
            }
        }
    };

    let result = tokio::select! {
        _ = drive => panic!(
            "wz drive loop reached a terminal state before pico decoded the source_info Put"
        ),
        r = scenario => r,
    };

    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();

    if let Err(msg) = result {
        panic!("wz->pico Put-source_info interop FAILED.\n{msg}");
    }
}
