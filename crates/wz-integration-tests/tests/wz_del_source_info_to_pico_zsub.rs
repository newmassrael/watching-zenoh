// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y246 — FOREIGN-INTEROP DELETE SOURCE_INFO: a watching-zenoh publisher
//! emits a `Delete` carrying a non-default `source_info` (zid `[0x11,0x22]`,
//! eid 44, sn 55), and a real zenoh-pico `z_sub_attachment` CLI decodes it and
//! prints `with kind: 1` (DELETE) + `with source_info eid: 44 sn: 55`.
//!
//! ## The gap this closes (the FOURTH source_info carrier — a whole-session catch)
//!
//! y243 proved source_info on the PUSH-PUT carrier, y244 on the QUERY body,
//! y245 on the REPLY-PUT body. The whole-session review of the y242→y245 batch
//! caught that the "source_info surface EXHAUSTED (Put/Query/Reply), only Err
//! remains" claim over-reached: the PUSH-DEL body is a fourth foreign-decodable
//! carrier those rounds missed. A Del is a genuinely distinct message type
//! (`_z_msg_del_t`, wire header `0x02`, NOT a Put), and it genuinely carries
//! source_info: wz's `build_msg_del_with_meta` emits the SAME
//! `encode_source_info_ext_entry` body ext (`ENC_ZBUF | 0x01`) on the Del, and
//! pico delivers the Delete as a delete-kind sample read back by the SAME
//! `z_sample_source_info` getter. This test closes the Push-Del carrier.
//!
//! ## What is (and is NOT) proven — do NOT read this as "exhausted"
//!
//! With y246, source_info is foreign-proven on FOUR carriers: Push-Put (y243),
//! Query (y244), Reply-Put (y245), Push-Del (y246). TWO source_info carriers
//! remain UNWITNESSED (per the y246 review — the "exhausted" instinct keeps
//! over-reaching by exactly one carrier, [[feedback-ledger-claims-conservative]]):
//!   - REPLY-DEL: a Delete-form reply. wz stamps it (`ResponseReplyBuilder`'s
//!     `CodecZenohMsgDel` arm, response_build.rs) and pico decodes it via the
//!     same `z_sample_source_info` on a delete-kind reply sample — but it is
//!     reachable only through the low-level builder (`ReplyOut::reply_del`
//!     takes no source_info), so no handler-level witness exists. By this
//!     test's own kind-matters rationale, reply-Del != reply-Put, so unproven.
//!   - ERR: wz CAN stamp Err source_info (`ResponseErrBuilder::source_info`)
//!     and pico DECODES it internally, but pico exposes NO per-sample getter
//!     for it (`primitives.h` has only `z_reply_err_payload` / `_encoding`), so
//!     it is foreign-NON-observable — nothing to witness, NOT "never stamped".
//!
//! ## Why the `with kind: 1` assertion (not just source_info)
//!
//! `z_sub_attachment` decodes source_info identically for a Put or a Delete
//! sample, so asserting only `with source_info eid: 44 sn: 55` would pass even
//! if wz's `PublishOptions::del()` had a bug that sent a PUT — it would NOT
//! prove the DEL carrier. The z_sub_attachment patch therefore also prints
//! `with kind:` (`z_sample_kind`, stable API: 0=PUT / 1=DELETE); this test
//! asserts `with kind: 1`, so a mis-sent Put (`kind: 0`) fails, genuinely
//! proving the DEL send path + pico's delete-sample source_info delivery.
//!
//! ## Why these values discriminate
//!
//! `z_sample_source_info` returns NULL when the sender set none; the patched
//! CLI prints the line only inside `if (wz_si != NULL)`. A dropped Del
//! source_info prints no source_info line -> timeout -> panic. eid 44 + sn 55
//! are distinct from the Put(66/153) / Query(77/88) / Reply(90/91) witnesses,
//! and eid 44 != sn 55 discriminates field ordering.
//!
//! ## Harness shape
//!
//! Mirrors `wz_source_info_to_pico_zsub.rs` (y243) exactly, except the publish
//! is `PublishOptions::del().with_source_info(..)` (the payload arg is ignored
//! for a Del) and the witness adds the `with kind: 1` conjunct. No new pico
//! patch: the shared z_sub_attachment already prints `with kind:` +
//! `with source_info` (the y246 kind line + the y243 source_info line).

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
const PUBLISH_KEYEXPR: &str = "demo/del";
const SUB_KEYEXPR: &str = "demo/**";
const SRC_EID: u32 = 44;
const SRC_SN: u32 = 55;

// wz-proves: pubsub-delete wz->pico
// wz-proves: pubsub-source-info wz->pico partial
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_sub_attachment); Layer E runs via --ignored"]
async fn wz_del_source_info_decoded_by_pico_zsub_attachment() {
    let z_sub = zenoh_pico_cli_binary("z_sub_attachment");

    // wz acceptor binds first so pico's client dial lands in the listen
    // backlog and `accept()` resolves it.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz acceptor");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("tcp/{addr}");

    // Accept + handshake WITH RETRY (same rationale as the sibling witnesses).
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
    // kind 1 = DELETE (0 = PUT); a mis-sent Put would print `with kind: 0`.
    let kind_witness = "with kind: 1";
    // eid 44 + sn 55; a dropped source_info prints NO `with source_info` line.
    let source_info_witness = "with source_info eid: 44 sn: 55";
    let subscribed_witness = "Declaring Subscriber on";
    // The Del ignores its payload arg (zenoh-pico `_z_n_msg_make_push_del`
    // carries no payload); source_info rides the Del body ext.
    let source_info = SourceInfo::new(&[0x11, 0x22], SRC_EID, SRC_SN);
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
        // Republish the source_info-bearing Delete on a 150 ms cadence until
        // pico prints the received line AND `with kind: 1` AND the exact
        // source_info line (idempotent; one landing after the subscription is
        // installed suffices).
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            publisher
                .publish(
                    PUBLISH_KEYEXPR,
                    &[],
                    PublishOptions::del().with_source_info(source_info.clone()),
                )
                .expect("source_info Delete builds and routes through the send seam");
            tokio::time::sleep(Duration::from_millis(150)).await;
            let captured = read_captured(&mut z_sub_stdout_reader);
            if captured.contains(received_witness)
                && captured.contains(kind_witness)
                && captured.contains(source_info_witness)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico z_sub_attachment did not decode wz's source_info Delete within 12s.\n\
                     Expected '{received_witness}' + '{kind_witness}' (DELETE) + \
                     '{source_info_witness}' (a dropped source_info would print NO \
                     'with source_info' line; a mis-sent Put would print 'with kind: 0').\n\
                     --- captured stdout ---\n{captured}"
                ));
            }
        }
    };

    let result = tokio::select! {
        _ = drive => panic!(
            "wz drive loop reached a terminal state before pico decoded the source_info Delete"
        ),
        r = scenario => r,
    };

    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();

    if let Err(msg) = result {
        panic!("wz->pico Delete-source_info interop FAILED.\n{msg}");
    }
}
