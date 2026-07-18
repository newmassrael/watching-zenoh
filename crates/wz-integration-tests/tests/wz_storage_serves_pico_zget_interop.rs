// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y359 (pico cross-impl leg) §5.24 storage — the storage QUERY-SERVE
//! witness: a real zenoh-pico `z_get` queries an in-process wz `StorageService`
//! and gets back a value held in the MemoryStorage backend. This is the
//! wz->pico SERVE direction (the storage answers a foreign querier), the
//! complement of the capture legs (`wz_storage_wildcard_update_pico_interop.rs`
//! / `wz_storage_strip_prefix_pico_interop.rs`, both pico->wz), and it closes
//! the foreign-`z_get`-against-a-wz-storage e2e that `storage_service.rs` named
//! as a NON-goal follow-up ("the wz-e2e-queryable pattern").
//!
//! ## What binds the claim (`storage-backend-memory-volume`)
//!
//! `StorageService::declare` builds a `MemoryStorage` (the FOUNDATIONAL
//! `storage-backend-memory-volume`: `MemoryVolume` creates a fresh
//! `MemoryStorage`, capability {Volatile, Latest}) and a COMPLETE `Queryable`
//! whose handler is `StorageState::answer_into`. A pre-seeded value lives ONLY
//! in that MemoryStorage; a foreign `z_get` that gets it back therefore
//! exercises the memory backend's READ/serve path — the half no capture test
//! reaches (they read the stored state in-process; this drives the query-answer
//! over the wire to a foreign impl). Separable from the capture legs: the
//! capture proof reads state in-process and would still pass if the
//! query-answer path were broken; this fails then.
//!
//! ## The observable (a foreign reply carrying the stored value)
//!
//! pico `z_get`'s reply handler prints `>> Received PUT ('<key>': '<value>')`
//! for each ok reply (`vendor/zenoh-pico/examples/unix/c11/z_get.c`
//! `reply_handler`). The storage answers the query for `demo/k1` with the
//! seeded value, so the test asserts pico printed the reply AND that it carries
//! the exact seeded key and value. If the storage did not serve (no queryable,
//! or an empty answer), pico prints only its terminating `Received query final
//! notification` and no `>> Received` line -> the poll times out -> panic. So a
//! silent non-serve self-detects.
//!
//! ## Non-flaky by construction ([[feedback-no-flaky-ever]])
//!
//! The seed is synchronous and lands before the drive future is polled; pico's
//! `z_get` is a one-shot burst-and-exit querier (it queries on connect), and its
//! query is buffered in the socket and processed by `drive_session_until_terminal`
//! after the queryable is already declared. Polling the captured stdout (which
//! persists after z_get exits) for the reply line is race-free; the 15s deadline
//! is a backstop, not a race.
//!
//! Requires the zenoh-pico CLI (`scripts/build-zenoh-pico-cli.sh` ->
//! `target/zenoh-pico-cli/z_get`). `#[ignore]` binary-dep e2e; run-ci Layer E
//! runs it via the `--ignored` sweep (the file name is caught by none of the
//! lane's `--skip` substrings, and it needs no zenohd — a wz+pico in-process leg).

use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;

use wz_integration_tests::common::{read_captured, zenoh_pico_cli_binary, ChildGuard};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::TokioSession;
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{accept_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio::storage_service::StorageService;
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::sample::TimestampHint;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::storage_config::StorageConfig;

const ITER_CAP: usize = 4096;
/// The storage keyexpr the wz `StorageService` captures + answers on.
const STORAGE_KEYEXPR: &str = "demo/**";
/// The concrete key pico `z_get`s (matched by `demo/**`).
const QUERY_KEY: &str = "demo/k1";
/// The value pre-seeded into the MemoryStorage and served back on the query.
const STORED_VALUE: &str = "served-from-wz-memory-storage";

/// A real zenoh-pico `z_get -k demo/k1 -m client` retrieves a value held in an
/// in-process wz `StorageService`'s MemoryStorage backend — the §5.24 wz->pico
/// SERVE-direction cross-impl witness of `storage-backend-memory-volume` (the
/// memory backend answering a foreign querier), and the foreign-`z_get`-against-
/// a-wz-storage harness the capture legs' NON-goal follow-up named.
// wz-proves: storage-backend-memory-volume wz->pico partial
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_get); Layer E runs via --ignored"]
async fn wz_storage_serves_a_stored_value_to_a_pico_zget() {
    let z_get = zenoh_pico_cli_binary("z_get");

    // wz acceptor binds first so pico's client dial lands in the listen backlog.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz acceptor");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("tcp/{addr}");

    // Accept + handshake WITH RETRY (pico one-shot open transient -> retry), the
    // same shape as the sibling z_get witnesses.
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
                    .args(["-k", QUERY_KEY, "-e", &endpoint, "-m", "client"])
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

    // Declare a storage on demo/** (MemoryStorage backend + COMPLETE queryable)
    // and pre-seed the value BEFORE the drive runs, so the queryable and the
    // stored value are both present when the drive processes pico's buffered
    // query. The observer is shared with the drive dispatch so the inbound query
    // routes to the storage's queryable.
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(opened.actions.clone(), observer, Arc::new(opened.clock));
    let storage = StorageService::declare(
        &session,
        &StorageConfig::new("demo", STORAGE_KEYEXPR, "mem"),
        vec![0x01],
    )
    .expect("declare the wz storage on demo/**");
    let _ = storage
        .shared_state()
        .lock()
        .expect("seed lock")
        .process_put(
            Some(QUERY_KEY),
            STORED_VALUE.as_bytes().to_vec(),
            None,
            TimestampHint {
                time: 1,
                zid: vec![0x02],
            },
        );

    let timeouts = SessionTimeouts::spec_defaults();
    let session_for_dispatch = session.clone();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        move |event| session_for_dispatch.dispatch_iteration_event(event),
    );

    let received_witness = ">> Received";
    let scenario = async {
        // z_get is a one-shot burst-and-exit querier; it queries on connect and
        // the already-declared storage queryable answers the buffered query. Poll
        // the captured stdout (persists after z_get exits) for the reply carrying
        // the stored key + value.
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let captured = read_captured(&mut z_get_stdout_reader);
            if captured.contains(received_witness)
                && captured.contains(QUERY_KEY)
                && captured.contains(STORED_VALUE)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico z_get did not receive wz's stored value within 15s.\n\
                     Expected '{received_witness}' + key '{QUERY_KEY}' + value '{STORED_VALUE}' \
                     (a storage that did not serve prints only the query-final line).\n\
                     --- captured stdout ---\n{captured}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };

    let result = tokio::select! {
        _ = drive => panic!(
            "wz drive loop reached a terminal state before pico received the stored value"
        ),
        r = scenario => r,
    };

    let _ = z_get_child.child_mut().kill();
    let _ = z_get_child.child_mut().wait();

    if let Err(msg) = result {
        panic!("wz->pico storage query-serve interop FAILED.\n{msg}");
    }
}
