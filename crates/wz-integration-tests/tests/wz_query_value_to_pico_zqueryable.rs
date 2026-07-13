// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y251 — FOREIGN-INTEROP QUERY VALUE: a watching-zenoh querier emits a
//! `Session::query` GET carrying a non-default VALUE (payload
//! `"wz-query-value"` + a non-default encoding, the Q_B / Q_E value ext 0x03),
//! and a real zenoh-pico `z_queryable` CLI decodes it in its query handler and
//! prints `with value 'wz-query-value'`.
//!
//! ## The gap this closes
//!
//! R311y248 landed the query VALUE ext codec (`RequestQueryBuilder::query_value`
//! and the `query_value_ext` SSOT) and R311y250 threaded it up to the session
//! API (`QueryOptions::with_payload` / `with_encoding` ->
//! `build_request_query_with_meta`). Both were witnessed only IN-PROCESS: the
//! codec by unit round-trips, the wire bytes by the layer3 LIVE-FFI byte-compare
//! vs pico's `_z_request_encode` (`layer3_request.rs`). This test is the first
//! FOREIGN E2E proof — a real pico `z_queryable` process decodes wz's egressed
//! query value on the Request carrier.
//!
//! ## Observation path (verified by direct read of the vendor pin)
//!
//! wz threads `QueryOptions::payload` + `encoding` onto the outbound Query body
//! VALUE ext (`ENC_ZBUF | 0x03`, `request_build.rs`, gated `query-value` which
//! R311y250 added to the wz-runtime-tokio default set). pico's Request decoder
//! reads the body ext id `0x03` into the query's `_value = {encoding, payload}`
//! (`_z_value_decode`), and the STOCK `z_queryable` example handler prints
//! `with value '<payload>'` via `z_bytes_to_string(z_query_payload(query), ..)`
//! (`vendor/zenoh-pico/examples/unix/c11/z_queryable.c` — the `z_string_len > 0`
//! guard means a dropped value prints NO `with value` line). Unlike the y244
//! source_info witness, NO pico patch is needed: the payload print is stock
//! (the y244 source_info patch, still applied by build-zenoh-pico-cli.sh, only
//! ADDS a source_info line and leaves the stock `with value` intact).
//!
//! ## Why the encoding FRAMING is exercised (its value is pinned elsewhere)
//!
//! The querier attaches a NON-DEFAULT encoding (id 5), so the value ext body is
//! `encoding(id 5) || payload`. pico's `_z_value_decode` reads the encoding
//! (consuming its VLE prefix) and takes the REMAINDER as the payload. So pico
//! can only print the correct `with value 'wz-query-value'` if it consumed the
//! encoding prefix at exactly the right BOUNDARY — a mis-framed encoding (wrong
//! prefix length) would fold encoding bytes into the payload and corrupt the
//! printed string. This proves the encoding's FRAMING, not its numeric value: a
//! same-length wrong id (or even the default encoding) would yield the identical
//! payload and also pass. The exact encoding bytes are pinned by the in-process
//! layer3 byte-compare (R311y248), not this foreign test — which witnesses the
//! payload decode plus the encoding-prefix framing boundary.
//!
//! ## Harness shape
//!
//! Mirrors `wz_query_source_info_to_pico_zqueryable.rs` (in-test wz acceptor +
//! `select!` drive-vs-scenario + pico CLI dial-in with accept-retry + a
//! readiness gate + a 150 ms burst cadence). The only delta is the query
//! metadata (`with_payload` + `with_encoding` instead of `with_source_info`) and
//! the witness line (`with value '<payload>'`).

use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;

use wz_integration_tests::common::{read_captured, zenoh_pico_cli_binary, ChildGuard};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{QueryOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{accept_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::sample::EncodingHint;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const QUERY_KEYEXPR: &str = "demo/key";
const QABL_KEYEXPR: &str = "demo/**";
// A distinct payload the pico z_queryable echoes into `with value '<..>'`; a
// dropped value prints NO `with value` line (the stock handler guards on a
// non-empty payload).
const QUERY_VALUE: &str = "wz-query-value";

// wz-proves: query-value wz->pico partial
// wz-proves: query-get wz->pico
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_queryable); Layer E runs via --ignored"]
async fn wz_query_value_decoded_by_pico_z_queryable() {
    let z_queryable = zenoh_pico_cli_binary("z_queryable");

    // wz acceptor binds first so pico's client dial lands in the listen
    // backlog and `accept()` resolves it.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz acceptor");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("tcp/{addr}");

    // Accept + handshake WITH RETRY (same rationale as the sibling witnesses):
    // pico's one-shot open transient must be a retry, not a red build.
    const OPEN_ATTEMPTS: usize = 6;
    let established = {
        let mut acc = None;
        for attempt in 1..=OPEN_ATTEMPTS {
            let z_qabl_stdout = tempfile::tempfile().expect("tempfile for z_queryable stdout");
            let z_qabl_stdout_writer = z_qabl_stdout.try_clone().expect("dup z_queryable stdout");
            let z_qabl_stdout_reader = z_qabl_stdout;
            let mut z_qabl_child = ChildGuard::wrap(
                "z_queryable client (zenoh-pico)",
                Command::new("stdbuf")
                    .args(["-oL", "-eL"])
                    .arg(&z_queryable)
                    .args(["-k", QABL_KEYEXPR, "-e", &endpoint, "-m", "client"])
                    .stdout(Stdio::from(z_qabl_stdout_writer))
                    .stderr(Stdio::inherit())
                    .spawn()
                    .expect("spawn z_queryable via stdbuf"),
            );
            let accepted = tokio::time::timeout(Duration::from_secs(8), listener.accept()).await;
            let stream = match accepted {
                Ok(Ok((stream, _peer))) => stream,
                _ => {
                    let _ = z_qabl_child.child_mut().kill();
                    let _ = z_qabl_child.child_mut().wait();
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
                    acc = Some((opened, z_qabl_child, z_qabl_stdout_reader));
                    break;
                }
                Err(e) => {
                    let _ = z_qabl_child.child_mut().kill();
                    let _ = z_qabl_child.child_mut().wait();
                    eprintln!(
                        "attempt {attempt}/{OPEN_ATTEMPTS}: wz<->pico handshake failed ({e:?}); retrying"
                    );
                    continue;
                }
            }
        }
        acc.expect(
            "wz acceptor reached Established against a pico z_queryable client within OPEN_ATTEMPTS",
        )
    };
    let (mut opened, mut z_qabl_child, mut z_qabl_stdout_reader) = established;

    // Querier over the accepted session's actions (Arc-shared); the drive loop
    // below borrows `&opened.actions`, the querier holds an independent clone.
    let querier = TokioSession::new(
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

    let query_received_witness = ">> [Queryable handler] Received Query";
    // The stock z_queryable handler prints `with value '<payload>'` only when
    // the query carries a non-empty payload; a dropped value prints no line.
    let value_witness = "with value 'wz-query-value'";
    let ready_witness = "Creating Queryable on";
    // Non-default encoding (id 5, no schema): packed_id = 5 << 1 = 0x0A. Forces
    // pico to consume a real encoding prefix before the payload — the payload
    // print is correct only if that framing is right (see the module doc).
    let encoding = EncodingHint {
        packed_id: 0x0A,
        schema: None,
    };
    let scenario = async {
        // Gate the query budget on pico's queryable-created witness before
        // querying (no-flaky; pico open latency does not eat the deadline).
        let ready_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let captured = read_captured(&mut z_qabl_stdout_reader);
            if captured.contains(ready_witness) {
                break;
            }
            if Instant::now() >= ready_deadline {
                return Err(format!(
                    "pico z_queryable did not create its queryable within 10s.\n\
                     --- captured stdout ---\n{captured}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Burst the value-bearing GET on a 150 ms cadence until pico's handler
        // prints the received-query line AND the exact `with value` line. The
        // burst (mirroring wz-e2e-zget, which carries no declare observer) makes
        // the first GET robust against racing the declare; each query is
        // byte-identical, so this is not flaky-masking retry.
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            querier
                .query(
                    QUERY_KEYEXPR,
                    QueryOptions::get()
                        .with_payload(QUERY_VALUE.as_bytes().to_vec())
                        .with_encoding(encoding.clone()),
                    |_reply| {},
                    |_rid| {},
                )
                .expect("value query builds and routes through the send seam");
            tokio::time::sleep(Duration::from_millis(150)).await;
            let captured = read_captured(&mut z_qabl_stdout_reader);
            if captured.contains(query_received_witness) && captured.contains(value_witness) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico z_queryable did not decode wz's query value within 12s.\n\
                     Expected '{query_received_witness}' + '{value_witness}' \
                     (a dropped value would print NO 'with value' line).\n\
                     --- captured stdout ---\n{captured}"
                ));
            }
        }
    };

    let result = tokio::select! {
        _ = drive => panic!(
            "wz drive loop reached a terminal state before pico decoded the query value"
        ),
        r = scenario => r,
    };

    let _ = z_qabl_child.child_mut().kill();
    let _ = z_qabl_child.child_mut().wait();

    if let Err(msg) = result {
        panic!("wz->pico query-value interop FAILED.\n{msg}");
    }
}
