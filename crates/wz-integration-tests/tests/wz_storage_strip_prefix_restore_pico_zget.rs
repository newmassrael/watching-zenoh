// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y360 (pico cross-impl leg) §5.24 storage — the `storage-mgr-strip-prefix`
//! RESTORE-on-read witness (the wz->pico half, complementing y358's capture
//! half): a value stored under the STRIPPED key `temp` in an in-process wz
//! `StorageService` (strip_prefix = `home/kitchen`) is served to a real
//! zenoh-pico `z_get home/kitchen/temp` under its RESTORED full key.
//!
//! ## What binds the claim, and why it is SEPARABLE
//!
//! `storage-mgr-strip-prefix` is strip-on-store + restore-on-read. y358 proved
//! the strip (a pico put lands under the stripped key, read in-process). This
//! proves the restore over the wire to a foreign impl: the value is seeded ONLY
//! under `temp` (the stripped form a capture would produce), and pico queries
//! the FULL key `home/kitchen/temp`. The storage's answer path
//! (`StorageState::matching_versions` -> `full_key_for`) re-prepends the prefix,
//! so the reply carries `home/kitchen/temp` and pico prints it. This is
//! SEPARABLE from a no-strip storage: without the strip wiring the stored key is
//! `temp` and a query for `home/kitchen/temp` matches nothing -> NO reply. So
//! the reply's presence AND its full restored key are both the strip's doing.
//! Together with y358 this is a both-directions cross-impl proof of the atom.
//!
//! ## The observable (a reply carrying the RESTORED full key)
//!
//! pico `z_get`'s reply handler prints `>> Received PUT ('<key>': '<value>')`
//! (`vendor/zenoh-pico/examples/unix/c11/z_get.c`). The test asserts pico
//! printed the reply carrying the FULL key `home/kitchen/temp` (the restore) and
//! the seeded value. A no-restore / no-strip storage yields no reply, and the
//! `tokio::select!` drive branch panics when pico closes before the witness
//! appears — so a silent non-serve self-detects (no vacuous pass).
//!
//! ## Non-flaky by construction ([[feedback-no-flaky-ever]])
//!
//! The strip/restore is pure logic; the seed is synchronous and lands before the
//! drive future is polled; pico's `z_get` is a one-shot querier whose query is
//! buffered and processed after the queryable is declared. Polling the captured
//! stdout is race-free; the 15s deadline is a backstop.
//!
//! Requires the zenoh-pico CLI + the `storage-mgr-strip-prefix` feature (pinned
//! in this crate's wz-runtime-tokio dev-dep since R311y358). `#[ignore]`
//! binary-dep e2e; run-ci Layer E runs it via the `--ignored` sweep (no --skip
//! match, no zenohd — a wz+pico in-process leg).

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
/// The mount keyexpr the wz `StorageService` captures + answers on.
const STORAGE_KEYEXPR: &str = "home/kitchen/**";
/// The configured mount prefix (stripped on store, restored on read).
const STRIP_PREFIX: &str = "home/kitchen";
/// The mount-relative key the value is stored under (the stripped form).
const STRIPPED_KEY: &str = "temp";
/// The FULL key pico queries — and the key the reply must carry (restored).
const FULL_KEY: &str = "home/kitchen/temp";
/// The value served back under the restored full key.
const STORED_VALUE: &str = "restored-from-wz-strip-mount";

/// A value stored under the STRIPPED key `temp` in a strip_prefix=`home/kitchen`
/// wz `StorageService` is served to a real zenoh-pico `z_get home/kitchen/temp`
/// under its RESTORED full key — the §5.24 wz->pico restore-on-read cross-impl
/// witness of `storage-mgr-strip-prefix` (the complement of y358's capture half).
// wz-proves: storage-mgr-strip-prefix wz->pico
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_get); Layer E runs via --ignored"]
async fn wz_storage_restores_the_mount_prefix_on_a_pico_zget() {
    let z_get = zenoh_pico_cli_binary("z_get");

    // wz acceptor binds first so pico's client dial lands in the listen backlog.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz acceptor");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("tcp/{addr}");

    // Accept + handshake WITH RETRY (pico one-shot open transient -> retry).
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
                    .args(["-k", FULL_KEY, "-e", &endpoint, "-m", "client"])
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

    // Declare a strip_prefix=home/kitchen storage on home/kitchen/** and seed the
    // value under the STRIPPED key `temp` (the form a capture would produce),
    // BEFORE the drive runs so the queryable + value are present for pico's query.
    let mut config = StorageConfig::new("kitchen-store", STORAGE_KEYEXPR, "mem");
    config.strip_prefix = Some(STRIP_PREFIX.to_string());
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(opened.actions.clone(), observer, Arc::new(opened.clock));
    let storage = StorageService::declare(&session, &config, vec![0x01])
        .expect("declare the wz strip-prefix storage on home/kitchen/**");
    let _ = storage
        .shared_state()
        .lock()
        .expect("seed lock")
        .process_put(
            Some(STRIPPED_KEY),
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
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let captured = read_captured(&mut z_get_stdout_reader);
            // The reply must carry the RESTORED full key AND the value. The full
            // key is the restore's fingerprint: the value lives under `temp`, so
            // only a re-prepend produces `home/kitchen/temp` in the reply.
            if captured.contains(received_witness)
                && captured.contains(FULL_KEY)
                && captured.contains(STORED_VALUE)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico z_get did not receive the restored full key within 15s.\n\
                     Expected '{received_witness}' + full key '{FULL_KEY}' + value '{STORED_VALUE}' \
                     (a no-strip storage stores under `{STRIPPED_KEY}` and matches nothing for the \
                     full-key query, so it serves no reply).\n--- captured stdout ---\n{captured}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };

    let result = tokio::select! {
        _ = drive => panic!(
            "wz drive loop reached a terminal state before pico received the restored key"
        ),
        r = scenario => r,
    };

    let _ = z_get_child.child_mut().kill();
    let _ = z_get_child.child_mut().wait();

    if let Err(msg) = result {
        panic!("wz->pico strip-prefix restore interop FAILED.\n{msg}");
    }
}
