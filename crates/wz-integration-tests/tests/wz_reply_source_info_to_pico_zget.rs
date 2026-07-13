// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y245 — FOREIGN-INTEROP REPLY SOURCE_INFO: an in-process watching-zenoh
//! QUERYABLE answers a query with a Reply carrying a non-default `source_info`
//! (zid `[0xF0,0x0D]`, eid 90, sn 91), and a real zenoh-pico `z_get` CLI
//! decodes it from the reply sample and prints
//! `with reply source_info eid: 90 sn: 91`.
//!
//! ## The gap this closes (the third source_info carrier)
//!
//! y243 proved source_info on the PUT-body carrier (publisher -> subscriber),
//! y244 on the QUERY-body carrier (querier -> queryable). The REPLY body is
//! the third carrier: a Reply body IS a Put push-body (zenoh-pico
//! `_z_reply_encode` -> `_z_push_body_encode`), so it carries the SAME
//! `encode_source_info_ext_entry` SSOT ext (`ENC_ZBUF | 0x01`), and pico
//! decodes it into the reply SAMPLE — read back by the SAME
//! `z_sample_source_info` getter the Put carrier uses (a reply is delivered
//! to `z_get`'s reply handler as a `z_loaned_sample_t`). This closes it.
//!
//! ## Observation path (verified by direct read of vendor pin 3b3ab65)
//!
//! wz's queryable handler stamps the reply via
//! `ReplyOut::reply_keyed_sourced(.., source_info)`; the emission is gated
//! `reply-source-info` (`response_build.rs::gated_reply_source_info`), enabled
//! in this crate's wz-session-core dev-dep. pico's reply decoder reads the
//! reply-body ext `ENC_ZBUF | 0x01` into the sample, and
//! `z_sample_source_info` (`primitives.h:2243`, UNSTABLE-gated — the CLI build
//! sets `-DZ_FEATURE_UNSTABLE_API=ON`, R311y243) returns it, NULL when the
//! replier set none. The z_get patch prints the line under `#ifdef
//! Z_FEATURE_UNSTABLE_API`.
//!
//! ## Why in-process
//!
//! Consistent with the pub/sub + query metadata witnesses (y240/y242/y243/
//! y244), this drives the PRODUCTION queryable path IN-PROCESS: wz is the
//! acceptor hosting a `declare_queryable` whose handler replies WITH
//! source_info, and the pico `z_get` CLIENT dials in and queries. The wz
//! reply emits through `Session::dispatch_iteration_event` (the SSOT that
//! pairs the observer dispatch with the deferred-fire drain — Reply-before-
//! Final holds), so no facade-subset binary is involved and one metadata
//! field is set precisely.
//!
//! ## Why these values discriminate
//!
//! `z_sample_source_info` returns NULL when the replier set none, and the
//! patched z_get handler prints only inside `if (wz_rsi != NULL)`. A dropped
//! reply source_info prints NO `with reply source_info` line -> the test times
//! out -> panic. eid 90 != sn 91 discriminates field ordering; the values are
//! distinct from y243's Put 66/153 and y244's Query 77/88, proving the REPLY
//! carrier specifically.
//!
//! ## Harness shape
//!
//! Mirrors `wz_query_source_info_to_pico_zqueryable.rs` (in-test wz acceptor +
//! `select!` drive-vs-scenario + pico CLI dial-in with accept-retry), but wz
//! DECLARES a queryable (not a querier) and the drive dispatches inbound
//! queries to it via `dispatch_iteration_event`; the pico role is `z_get`
//! (the querier), whose reply handler carries the witness. `declare_queryable`
//! is done BEFORE the drive loop runs, so the queryable is registered when the
//! drive processes pico's (single, `z_get` has no `-n`) buffered query.

use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;

use wz_integration_tests::common::{read_captured, zenoh_pico_cli_binary, ChildGuard};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{QueryableOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{accept_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::sample::{SourceInfo, TimestampHint};
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const QUERY_KEYEXPR: &str = "demo/key";
const QABL_KEYEXPR: &str = "demo/**";
const REPLY_PAYLOAD: &str = "reply-from-wz-queryable";
const SRC_EID: u32 = 90;
const SRC_SN: u32 = 91;

// wz-proves: query-reply wz->pico
// wz-proves: pubsub-source-info wz->pico partial
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_get); Layer E runs via --ignored"]
async fn wz_reply_source_info_decoded_by_pico_z_get() {
    let z_get = zenoh_pico_cli_binary("z_get");

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
            let z_get_stdout = tempfile::tempfile().expect("tempfile for z_get stdout");
            let z_get_stdout_writer = z_get_stdout.try_clone().expect("dup z_get stdout");
            let z_get_stdout_reader = z_get_stdout;
            let mut z_get_child = ChildGuard::wrap(
                "z_get client (zenoh-pico)",
                Command::new("stdbuf")
                    .args(["-oL", "-eL"])
                    .arg(&z_get)
                    .args(["-k", QUERY_KEYEXPR, "-e", &endpoint, "-m", "client"])
                    .stdout(Stdio::from(z_get_stdout_writer))
                    .stderr(Stdio::inherit())
                    .spawn()
                    .expect("spawn z_get via stdbuf"),
            );
            let accepted = tokio::time::timeout(Duration::from_secs(8), listener.accept()).await;
            let stream = match accepted {
                Ok(Ok((stream, _peer))) => stream,
                _ => {
                    let _ = z_get_child.child_mut().kill();
                    let _ = z_get_child.child_mut().wait();
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
                    acc = Some((opened, z_get_child, z_get_stdout_reader));
                    break;
                }
                Err(e) => {
                    let _ = z_get_child.child_mut().kill();
                    let _ = z_get_child.child_mut().wait();
                    eprintln!(
                        "attempt {attempt}/{OPEN_ATTEMPTS}: wz<->pico handshake failed ({e:?}); retrying"
                    );
                    continue;
                }
            }
        }
        acc.expect(
            "wz acceptor reached Established against a pico z_get client within OPEN_ATTEMPTS",
        )
    };
    let (mut opened, mut z_get_child, mut z_get_stdout_reader) = established;

    // The session shares its observer with the drive loop's dispatch so the
    // declared queryable receives the inbound query. `declare_queryable` runs
    // BEFORE the drive loop, so the queryable is registered when the drive
    // processes pico's buffered query.
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(
        opened.actions.clone(),
        observer.clone(),
        Arc::new(opened.clock),
    );

    // The reply carries a distinct source_info; a timestamp rides along
    // (reply_keyed_sourced bundles it) but only source_info is asserted.
    let reply_source_info = SourceInfo::new(&[0xF0, 0x0D], SRC_EID, SRC_SN);
    let reply_timestamp = TimestampHint {
        time: 1,
        zid: vec![0xAA],
    };
    let _queryable = session
        .declare_queryable(
            QABL_KEYEXPR,
            QueryableOptions::default(),
            move |query, responder| {
                responder.reply_keyed_sourced(
                    query.keyexpr(),
                    REPLY_PAYLOAD.as_bytes(),
                    None,
                    &reply_timestamp,
                    Some(&reply_source_info),
                );
            },
        )
        .expect("declare_queryable installs the source_info-stamping reply handler");

    let timeouts = SessionTimeouts::spec_defaults();
    let session_for_dispatch = session.clone();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        |event| session_for_dispatch.dispatch_iteration_event(event),
    );

    // eid 90 + sn 91; a dropped reply source_info prints NO `with reply
    // source_info` line (the handler guards on `z_sample_source_info != NULL`).
    let source_info_witness = "with reply source_info eid: 90 sn: 91";
    let received_witness = ">> Received";
    let scenario = async {
        // z_get is a one-shot burst-and-exit querier (no `-n`); it queries on
        // connect and prints replies until its timeout. The queryable is
        // already registered (declared above, before this drive runs), so the
        // buffered query gets answered. Poll z_get's captured stdout for the
        // witness (it persists after z_get exits).
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let captured = read_captured(&mut z_get_stdout_reader);
            if captured.contains(received_witness) && captured.contains(source_info_witness) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico z_get did not decode wz's reply source_info within 15s.\n\
                     Expected '{received_witness}' + '{source_info_witness}' \
                     (a dropped reply source_info would print NO 'with reply source_info' line).\n\
                     --- captured stdout ---\n{captured}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };

    let result = tokio::select! {
        _ = drive => panic!(
            "wz drive loop reached a terminal state before pico decoded the reply source_info"
        ),
        r = scenario => r,
    };

    let _ = z_get_child.child_mut().kill();
    let _ = z_get_child.child_mut().wait();

    if let Err(msg) = result {
        panic!("wz->pico reply-source_info interop FAILED.\n{msg}");
    }
}
