// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y260 — FOREIGN-INTEROP the WHOLE 53-entry ENCODING TABLE: a watching-zenoh
//! publisher emits one `Put` per predefined encoding id (0..=52), and a real
//! zenoh-pico `z_sub_attachment` CLI decodes each one and prints the MIME string
//! its OWN table maps that id to. Every id is checked against wz's table, so a
//! single-entry divergence between the two implementations fails the test.
//!
//! ## The gap this closes
//!
//! R311y207 (`wz_encoding_to_pico_zsub`) proved exactly ONE id — `text/plain`
//! (4) — which established that the `encoding` field crosses the wire at all.
//! It left the TABLE unproven: 52 other ids, each a separate opportunity for wz
//! and zenoh-pico to disagree about what a number means. A mismatch there is
//! silent and nasty — the payload arrives intact and is labelled as the wrong
//! media type, so a `application/cbor` sample decodes as, say, `application/cdr`
//! in the foreign consumer.
//!
//! wz's table is `wz_session_core::encoding::mime_for_id` (ids 0..=52, dense);
//! zenoh-pico's is the array in `vendor/zenoh-pico/src/api/encoding.c` behind
//! `Z_FEATURE_ENCODING_VALUES = 1`. This test makes the two tables meet on a
//! real socket. wz's own table is the expected-value SSOT here — the test never
//! restates it, so it cannot drift from the implementation it checks.
//!
//! ## Why the witness is per-id and not a set
//!
//! `z_sub_attachment` prints, for each sample, two CONSECUTIVE lines
//! (`vendor/zenoh-pico/examples/unix/c11/z_sub_attachment.c:59,61`):
//!
//! ```text
//! >> [Subscriber] Received ('demo/enc': 'enc-13')
//!     with encoding: application/protobuf
//! ```
//!
//! so tagging each Put's PAYLOAD with its id correlates the id to the MIME pico
//! resolved for it. Merely asserting that the SET of printed MIMEs equals the set
//! of wz's 53 would pass a table PERMUTATION (wz id 4 -> "text/plain" while pico
//! id 4 -> "application/json", with 5 swapped the other way). The pairing closes
//! that.
//!
//! ## What is (and is NOT) proven — do NOT read this as "encoding exhausted"
//!
//! - The 52 non-default ids are DISCRIMINATING witnesses: had wz dropped or
//!   mis-encoded the encoding field, pico would print the default `zenoh/bytes`
//!   instead of the expected MIME.
//! - Id 0 (`zenoh/bytes`, the `encoding-empty` atom) is NOT discriminating on its
//!   own: pico prints `zenoh/bytes` both when wz sends id 0 explicitly and when
//!   the encoding field is absent entirely. wz DOES put it on the wire (
//!   `push_build.rs::gated_encoding_field` special-cases nothing, so an explicit
//!   `EncodingHint { packed_id: 0 }` sets the field and the E flag), and the other
//!   52 ids in the same session prove the field is transmitted — but the id-0 line
//!   alone cannot tell the two apart. Hence `encoding-empty` is claimed `partial`.
//! - The SCHEMA sub-field (`id << 1 | 1`, then the schema bytes) is NOT exercised
//!   here in the wz->pico direction; it is proven only pico->wz, by
//!   `pico_pub_attachment_to_wz_sub`. That is why `pubsub-encoding wz->pico` stays
//!   `partial` rather than being promoted by this test.
//! - `encoding-mime` is likewise `partial`, NOT full. That atom is the whole MIME
//!   subsystem — `mime_for_id` AND `id_for_mime` AND `encoding_from_mime` /
//!   `encoding_to_mime` (the `"mime;schema"` parse) AND the `ID_CUSTOM` (0xFFFF)
//!   fallback for an unknown MIME. This test witnesses exactly one of those, in one
//!   direction: the id -> MIME half of the table. The same absence of the schema path
//!   that keeps `pubsub-encoding` partial keeps this one partial too.
//! - The five per-family atoms (`encoding-utf8` / `-json` / `-cbor` / `-protobuf` /
//!   `-bytes`) ARE full, but only because the sweep publishes their NAMED CONSTANTS
//!   (`NAMED_ENCODINGS`) and not a hand-built `id << 1`. Each atom's inventory entry
//!   defines it as its `EncodingHint::<NAME>` const; a sweep that never touched those
//!   consts would keep passing if one of them were re-pointed at the wrong id, while
//!   every caller silently mislabelled its payload. The claim has to bind to the code
//!   the atom IS.
//!
//! ## Harness shape
//!
//! Mirrors `wz_encoding_to_pico_zsub.rs` verbatim (in-test wz acceptor +
//! `Session::publish` over the accepted session, `select!` drive-vs-scenario, pico
//! CLI dial-in with accept-retry, a readiness gate on pico's subscriber-declared
//! line, and a republish cadence). The delta is the sweep: every cycle republishes
//! all 53 ids AND the 6 named constants, and the scenario completes when every
//! (payload, MIME) pair has been observed with none disagreeing.

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
use wz_session_core::encoding::mime_for_id;
use wz_session_core::sample::EncodingHint;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 8192;
const PUBLISH_KEYEXPR: &str = "demo/enc";
const SUB_KEYEXPR: &str = "demo/**";
/// The predefined-id range of the zenoh encoding table. wz's `mime_for_id` is the
/// SSOT for the mapping; this is only its extent.
const LAST_PREDEFINED_ID: u16 = 52;

/// The NAMED encoding constants, each paired with the MIME string it promises.
///
/// This table is what binds the per-family claims (`encoding-json`, `encoding-cbor`,
/// ...) to the code those atoms are actually DEFINED as: each atom's inventory entry
/// names its `EncodingHint::<NAME>` const, not a bare number. Publishing `id << 1` by
/// hand would prove the table while leaving the constants unwitnessed -- flip
/// `ID_APPLICATION_JSON` from 5 to 6 and a hand-built sweep still passes, while every
/// caller of `EncodingHint::APPLICATION_JSON` silently mislabels its payload as
/// `text/json`. So the constants themselves go on the wire, and the MIME each one is
/// expected to mean is spelled out here rather than looked up from the same table the
/// other half of this test is checking.
const NAMED_ENCODINGS: &[(EncodingHint, &str)] = &[
    (EncodingHint::ZENOH_BYTES, "zenoh/bytes"), // encoding-empty
    (
        EncodingHint::APPLICATION_OCTET_STREAM,
        "application/octet-stream",
    ), // encoding-bytes
    (EncodingHint::TEXT_PLAIN, "text/plain"),   // encoding-utf8
    (EncodingHint::APPLICATION_JSON, "application/json"), // encoding-json
    (EncodingHint::APPLICATION_CBOR, "application/cbor"), // encoding-cbor
    (EncodingHint::APPLICATION_PROTOBUF, "application/protobuf"), // encoding-protobuf
];

/// Payload that tags a sample with the encoding id it was published under, so
/// pico's `Received (...)` line and its following `with encoding:` line can be
/// paired back to the id under test.
fn payload_for(id: u16) -> String {
    format!("enc-{id}")
}

/// Payload tag for the named-constant sweep, kept disjoint from `payload_for`.
fn named_payload_for(index: usize) -> String {
    format!("named-{index}")
}

/// Pair pico's two-line-per-sample output back into (payload, mime).
///
/// `z_sub_attachment` prints `>> [Subscriber] Received ('<key>': '<value>')` and
/// then `    with encoding: <mime>` for the SAME sample, so the mime belongs to
/// the payload on the line immediately above it.
fn observed_pairs(captured: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut last_payload: Option<String> = None;
    // pico is still appending while we read, so the final line may be a TORN fragment
    // (`    with encoding: application/js`). Parsing it would yield a truncated MIME and
    // trip the mismatch branch -- surfacing a transient short read as the alarming
    // "wz and zenoh-pico DISAGREE on the encoding table". Only whole lines are evidence.
    let whole = match captured.rfind('\n') {
        Some(i) => &captured[..=i],
        None => "",
    };
    for line in whole.lines() {
        if let Some(rest) = line.split_once("Received ('") {
            last_payload = rest
                .1
                .split_once("': '")
                .and_then(|(_, v)| v.split_once("')"))
                .map(|(v, _)| v.to_string());
            continue;
        }
        if let Some((_, mime)) = line.split_once("with encoding: ") {
            if let Some(p) = last_payload.take() {
                out.push((p, mime.trim().to_string()));
            }
        }
    }
    out
}

// wz-proves: encoding-mime wz->pico partial
// wz-proves: encoding-utf8 wz->pico
// wz-proves: encoding-json wz->pico
// wz-proves: encoding-cbor wz->pico
// wz-proves: encoding-protobuf wz->pico
// wz-proves: encoding-bytes wz->pico
// wz-proves: encoding-empty wz->pico partial
// wz-proves: pubsub-encoding wz->pico partial
// wz-proves: pubsub-put wz->pico
// wz-proves: codec-push wz->pico
// wz-proves: codec-frame wz->pico
// wz-proves: keyexpr-literal wz->pico
// wz-proves: session-unicast-accept wz->pico
// wz-proves: transport-link-tcp wz->pico
// wz-proves: transport-unicast wz->pico
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_sub_attachment); Layer E runs via --ignored"]
async fn wz_full_encoding_table_decoded_by_pico_zsub_attachment() {
    let z_sub = zenoh_pico_cli_binary("z_sub_attachment");

    // wz acceptor binds first so pico's client dial lands in the listen backlog
    // and `accept()` resolves it.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz acceptor");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("tcp/{addr}");

    // Accept + handshake WITH RETRY (same rationale as wz_encoding_to_pico_zsub):
    // pico's one-shot open transient must be a retry, not a red build.
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

    let subscribed_witness = "Declaring Subscriber on";
    let scenario = async {
        // Gate the delivery budget on pico's subscriber-declared witness before
        // publishing (no-flaky; pico's open latency must not eat the deadline).
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

        // Expected (payload, mime) across BOTH sweeps:
        //   - the whole table:      id           -> mime_for_id(id)   (the 53-entry table)
        //   - the named constants:  EncodingHint -> the MIME it promises (the atoms' code)
        let mut expected: Vec<(String, &'static str)> = (0..=LAST_PREDEFINED_ID)
            .map(|id| {
                (
                    payload_for(id),
                    mime_for_id(id).expect("wz table is dense over 0..=52"),
                )
            })
            .collect();
        expected.extend(
            NAMED_ENCODINGS
                .iter()
                .enumerate()
                .map(|(i, (_, mime))| (named_payload_for(i), *mime)),
        );

        let check = |captured: &str| {
            let pairs = observed_pairs(captured);
            let mut missing = Vec::new();
            let mut mismatched = Vec::new();
            for (want_payload, want_mime) in &expected {
                match pairs.iter().find(|(p, _)| p == want_payload) {
                    None => missing.push(want_payload.clone()),
                    Some((_, got)) if got != want_mime => {
                        mismatched.push((want_payload.clone(), *want_mime, got.clone()));
                    }
                    Some(_) => {}
                }
            }
            (missing, mismatched)
        };

        // Republish both sweeps on a cadence until every sample has been observed.
        // Each Put is idempotent and byte-identical, so one landing after the
        // subscription is installed suffices — this is a delivery gate, not a
        // flaky-masking retry.
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            for id in 0..=LAST_PREDEFINED_ID {
                publisher
                    .publish(
                        PUBLISH_KEYEXPR,
                        payload_for(id).as_bytes(),
                        PublishOptions::put().with_encoding(EncodingHint {
                            // The zenoh wire value IS `id << 1 | schema_bit`; no schema here.
                            packed_id: u32::from(id) << 1,
                            schema: None,
                        }),
                    )
                    .expect("encoded publish builds and routes through the send seam");
            }
            for (i, (hint, _)) in NAMED_ENCODINGS.iter().enumerate() {
                publisher
                    .publish(
                        PUBLISH_KEYEXPR,
                        named_payload_for(i).as_bytes(),
                        PublishOptions::put().with_encoding(hint.clone()),
                    )
                    .expect("named-constant publish builds and routes through the send seam");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;

            let captured = read_captured(&mut z_sub_stdout_reader);
            let (missing, mismatched) = check(&captured);

            if !mismatched.is_empty() {
                // Before declaring a cross-impl divergence, re-read once. pico is still
                // appending, and a claim this loud must not rest on a single short read.
                // (`observed_pairs` already drops a torn trailing line; this is the belt to
                // that brace, and it costs one cycle only on the failing path.)
                tokio::time::sleep(Duration::from_millis(250)).await;
                let captured = read_captured(&mut z_sub_stdout_reader);
                let (_, still) = check(&captured);
                if !still.is_empty() {
                    // A real cross-impl fidelity divergence: the payload arrives intact but
                    // the foreign decoder labels it a different media type.
                    let detail = still
                        .iter()
                        .map(|(p, want, got)| format!("  {p}: wz says {want}, pico decoded {got}"))
                        .collect::<Vec<_>>()
                        .join("\n");
                    return Err(format!(
                        "wz and zenoh-pico DISAGREE on the encoding table for {} sample(s):\n{detail}",
                        still.len()
                    ));
                }
                continue;
            }
            if missing.is_empty() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico did not decode {} of the {} expected samples within 20s: {missing:?}\n\
                     --- captured stdout ---\n{captured}",
                    missing.len(),
                    expected.len(),
                ));
            }
        }
    };

    let outcome = tokio::select! {
        driven = drive => Err(format!("session drive terminated before the sweep completed: {driven:?}")),
        scenario = scenario => scenario,
    };

    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();

    // The scenario returns Ok only once EVERY expected (payload, mime) pair has been
    // observed and none disagreed, so there is nothing left to assert here -- an extra
    // count check would read like a gate and never be able to fire.
    outcome.unwrap_or_else(|e| panic!("{e}"));
}
