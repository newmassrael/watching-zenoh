// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y244 — FOREIGN-INTEROP QUERY SOURCE_INFO: a watching-zenoh querier
//! emits a `Session::query` GET carrying a non-default `source_info` (zid
//! `[0xBE,0xEF]`, eid 77, sn 88), and a real zenoh-pico `z_queryable` CLI
//! decodes it in its query handler and prints
//! `with query source_info eid: 77 sn: 88`.
//!
//! ## The gap this closes
//!
//! R311y243 proved source_info on the PUT-body carrier (publisher ->
//! subscriber). source_info also rides the QUERY (Request) body under the
//! SAME `encode_source_info_ext_entry` SSOT (body ext `ENC_ZBUF | 0x01`), a
//! DISTINCT wire carrier decoded by a DISTINCT pico getter
//! (`z_query_source_info`, not `z_sample_source_info`) — un-witnessed until
//! now. `QueryOptions::with_source_info` (querier.rs) attaches it; this test
//! proves it foreign-decodes on the query carrier.
//!
//! ## Observation path (verified by direct read of vendor pin 3b3ab65)
//!
//! wz threads `QueryOptions::source_info` onto the outbound Query body ext
//! (`request_build.rs`, gated `query-source-info` which is in the
//! wz-runtime-tokio default set). pico's Request decoder reads the body ext
//! id `ENC_ZBUF | 0x01` into the query, and `z_query_source_info`
//! (`primitives.h:1156`) returns it, NULL when the querier set none. Unlike
//! the Put carrier's `z_sample_source_info` (UNSTABLE-gated, the
//! `primitives.h:2218` block), `z_query_source_info` + `z_source_info_id` /
//! `z_source_info_sn` are declared UNCONDITIONALLY (after the
//! `Z_FEATURE_UNSTABLE_API` block closes at `primitives.h:769`), so the
//! z_queryable patch prints the source_info line with NO `#ifdef` guard — it
//! compiles whether or not the flag is set (the build sets it ON anyway for
//! the z_sub_attachment / Put witness).
//!
//! ## Why in-process (not the wz-e2e-zget binary)
//!
//! The `wz_e2e_zget_to_zqueryable` Layer-E2 harness drives a `wz-e2e-zget`
//! facade-subset BINARY whose CLI has no source_info flag. Consistent with
//! the pub/sub metadata witnesses (y240/y242/y243), this witness drives the
//! PRODUCTION `Session::query` path IN-PROCESS with the full default feature
//! set, precisely setting one metadata field — no facade-subset perturbation.
//! wz is the acceptor + querier; the pico z_queryable DIALS in as a client
//! and its local queryable answers wz's egressed query. Like wz-e2e-zget
//! (which carries no declare-observer), the query runs as a burst so the
//! first GET cannot race the peer's queryable declare.
//!
//! ## Why these values discriminate
//!
//! `z_query_source_info` returns NULL when the querier set no source_info
//! (`primitives.h`), and the patched handler prints only inside
//! `if (wz_qsi != NULL)`. A dropped source_info prints NO `with query
//! source_info` line -> timeout -> panic. eid 77 + sn 88 (distinct from
//! y243's Put-carrier 66/153) prove the VLE fields round-trip on the query
//! carrier specifically.
//!
//! ## Harness shape
//!
//! Mirrors `wz_source_info_to_pico_zsub.rs` (in-test wz acceptor +
//! `select!` drive-vs-scenario + pico CLI dial-in with accept-retry + a
//! readiness gate + a 150 ms burst cadence). Deltas: pico runs `z_queryable`
//! (not z_sub_attachment); wz issues `Session::query` (not `publish`) with
//! `QueryOptions::with_source_info`; the witness is the query-handler line.

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
use wz_session_core::sample::SourceInfo;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const QUERY_KEYEXPR: &str = "demo/key";
const QABL_KEYEXPR: &str = "demo/**";
const SRC_EID: u32 = 77;
const SRC_SN: u32 = 88;

// wz-proves: query-source-info wz->pico
// wz-proves: query-get wz->pico
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_queryable); Layer E runs via --ignored"]
async fn wz_query_source_info_decoded_by_pico_z_queryable() {
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
    // eid 77 + sn 88; a dropped source_info prints NO `with query source_info`
    // line (the handler guards on `z_query_source_info != NULL`).
    let source_info_witness = "with query source_info eid: 77 sn: 88";
    let ready_witness = "Creating Queryable on";
    // zid [0xBE,0xEF] is arbitrary + distinct from the wz session zid.
    let source_info = SourceInfo::new(&[0xBE, 0xEF], SRC_EID, SRC_SN);
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
        // Burst the source_info-bearing GET on a 150 ms cadence until pico's
        // handler prints the received-query line AND the exact source_info
        // line. The burst (mirroring wz-e2e-zget, which carries no declare
        // observer) makes the first GET robust against racing the declare;
        // each query is byte-identical, so this is not flaky-masking retry.
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            querier
                .query(
                    QUERY_KEYEXPR,
                    QueryOptions::get().with_source_info(source_info.clone()),
                    |_reply| {},
                    |_rid| {},
                )
                .expect("source_info query builds and routes through the send seam");
            tokio::time::sleep(Duration::from_millis(150)).await;
            let captured = read_captured(&mut z_qabl_stdout_reader);
            if captured.contains(query_received_witness) && captured.contains(source_info_witness) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico z_queryable did not decode wz's query source_info within 12s.\n\
                     Expected '{query_received_witness}' + '{source_info_witness}' \
                     (a dropped source_info would print NO 'with query source_info' line).\n\
                     --- captured stdout ---\n{captured}"
                ));
            }
        }
    };

    let result = tokio::select! {
        _ = drive => panic!(
            "wz drive loop reached a terminal state before pico decoded the query source_info"
        ),
        r = scenario => r,
    };

    let _ = z_qabl_child.child_mut().kill();
    let _ = z_qabl_child.child_mut().wait();

    if let Err(msg) = result {
        panic!("wz->pico query-source_info interop FAILED.\n{msg}");
    }
}
