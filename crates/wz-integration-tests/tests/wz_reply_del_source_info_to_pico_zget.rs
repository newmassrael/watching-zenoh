// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y247 — FOREIGN-INTEROP REPLY-DELETE SOURCE_INFO: an in-process
//! watching-zenoh QUERYABLE answers a query with a Delete-form Reply carrying a
//! non-default `source_info` (zid `[0xDE,0x1E]`, eid 71, sn 17), and a real
//! zenoh-pico `z_get` CLI decodes it — printing `>> Received DELETE` (the reply
//! sample's kind) AND `with reply source_info eid: 71 sn: 17`.
//!
//! ## The gap this closes (the FIFTH source_info carrier)
//!
//! y243 proved source_info on the PUSH-PUT carrier, y244 on the QUERY body,
//! y245 on the REPLY-PUT body, y246 on the PUSH-DEL body. The REPLY-DEL body is
//! the fifth: a Delete-form reply. The y246 review named it as the one
//! remaining WITNESSABLE carrier — wz already stamps it
//! (`ResponseReplyBuilder`'s `MsgDel` arm carries the same
//! `encode_source_info_ext_entry` body ext `ENC_ZBUF | 0x01`) and pico already
//! decodes it (a Del reply is a delete-kind `z_loaned_sample_t` read by the
//! same `z_sample_source_info` getter), but it was reachable ONLY through the
//! low-level builder: `ReplyOut::reply_del` took no source_info, so no
//! handler-level path existed. R311y247 adds `ReplyOut::reply_del_sourced`
//! (the Del-arm mirror of `reply_keyed_sourced`), so a queryable handler can
//! emit a sourced Del reply — and this test witnesses it end-to-end.
//!
//! ## What is (and is NOT) proven — do NOT read this as "exhausted"
//!
//! With y247, source_info is foreign-proven on FIVE carriers: Push-Put (y243),
//! Query (y244), Reply-Put (y245), Push-Del (y246), Reply-Del (y247). ONE
//! source_info carrier remains, and it is NOT witnessable
//! ([[feedback-ledger-claims-conservative]] — enumerate, do not claim
//! "exhausted"):
//!   - ERR: wz CAN stamp Err source_info (`ResponseErrBuilder::source_info`)
//!     and pico DECODES it internally, but pico exposes NO per-sample getter
//!     for an Err reply's source_info (`primitives.h` has only
//!     `z_reply_err_payload` / `z_reply_err_encoding`), so it is
//!     foreign-NON-observable — nothing to witness, NOT "never stamped". This
//!     is the boundary of what a foreign CLI can observe, not an omission.
//!
//! ## Why the `>> Received DELETE` assertion (not just source_info)
//!
//! `z_sample_source_info` decodes identically for a Put or a Delete reply
//! sample, so asserting only `with reply source_info eid: 71 sn: 17` would pass
//! even if `reply_del_sourced` had a bug that staged a PUT body — it would NOT
//! prove the DEL carrier. The STOCK z_get reply handler already prints the
//! sample kind via `kind_to_str(z_sample_kind(sample))`
//! (`>> Received DELETE (...)` vs `>> Received PUT (...)`, examples z_get.c:44);
//! this test asserts `>> Received DELETE`, so a mis-staged Put
//! (`>> Received PUT`) fails, genuinely proving the DEL reply send path +
//! pico's delete-sample source_info delivery. No new pico patch: the stock kind
//! print + the y245 `with reply source_info` patch already emit both lines.
//!
//! ## Why these values discriminate
//!
//! `z_sample_source_info` returns NULL when the replier set none; the y245
//! z_get patch prints the line only inside `if (wz_rsi != NULL)`. A dropped
//! reply source_info prints NO `with reply source_info` line -> timeout ->
//! panic. eid 71 + sn 17 are distinct from the Put(66/153) / Query(77/88) /
//! Reply-Put(90/91) / Push-Del(44/55) witnesses, and eid 71 != sn 17
//! discriminates field ordering.
//!
//! ## Harness shape
//!
//! Mirrors `wz_reply_source_info_to_pico_zget.rs` (y245) exactly — an in-test
//! wz acceptor DECLARES a queryable whose handler replies WITH source_info, and
//! the pico `z_get` CLIENT dials in and queries; the drive dispatches inbound
//! queries via `dispatch_iteration_event` — except the handler emits a Del
//! reply (`reply_del_sourced`, no payload / timestamp) and the witness asserts
//! `>> Received DELETE` instead of the Put-form `>> Received PUT`.

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
use wz_session_core::sample::SourceInfo;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const QUERY_KEYEXPR: &str = "demo/key";
const QABL_KEYEXPR: &str = "demo/**";
const SRC_EID: u32 = 71;
const SRC_SN: u32 = 17;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_get); Layer E runs via --ignored"]
async fn wz_reply_del_source_info_decoded_by_pico_z_get() {
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

    // The Del reply carries a distinct source_info; a Del body has no payload,
    // encoding, or timestamp (reply_del_sourced stamps source_info only).
    let reply_source_info = SourceInfo::new(&[0xDE, 0x1E], SRC_EID, SRC_SN);
    let _queryable = session
        .declare_queryable(
            QABL_KEYEXPR,
            QueryableOptions::default(),
            move |_query, responder| {
                responder.reply_del_sourced(Some(&reply_source_info));
            },
        )
        .expect("declare_queryable installs the source_info-stamping Del reply handler");

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

    // `>> Received DELETE` (the stock kind print) discriminates the DEL carrier
    // from a Put; `with reply source_info eid: 71 sn: 17` (the y245 patch)
    // proves the source_info rode the Del reply. A dropped reply source_info
    // prints NO `with reply source_info` line (the handler guards on
    // `z_sample_source_info != NULL`); a mis-staged Put prints `>> Received PUT`.
    let delete_witness = ">> Received DELETE";
    let source_info_witness = "with reply source_info eid: 71 sn: 17";
    let scenario = async {
        // z_get is a one-shot burst-and-exit querier (no `-n`); it queries on
        // connect and prints replies until its timeout. The queryable is
        // already registered (declared above, before this drive runs), so the
        // buffered query gets answered. Poll z_get's captured stdout for the
        // witness (it persists after z_get exits).
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let captured = read_captured(&mut z_get_stdout_reader);
            if captured.contains(delete_witness) && captured.contains(source_info_witness) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico z_get did not decode wz's reply-Del source_info within 15s.\n\
                     Expected '{delete_witness}' + '{source_info_witness}' \
                     (a dropped reply source_info prints NO 'with reply source_info' line; \
                     a mis-staged Put prints '>> Received PUT').\n\
                     --- captured stdout ---\n{captured}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };

    let result = tokio::select! {
        _ = drive => panic!(
            "wz drive loop reached a terminal state before pico decoded the reply-Del source_info"
        ),
        r = scenario => r,
    };

    let _ = z_get_child.child_mut().kill();
    let _ = z_get_child.child_mut().wait();

    if let Err(msg) = result {
        panic!("wz->pico reply-Del source_info interop FAILED.\n{msg}");
    }
}
