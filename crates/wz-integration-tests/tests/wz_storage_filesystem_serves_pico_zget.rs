// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y361 (pico cross-impl leg) §5.24 storage — the `storage-backend-filesystem`
//! serve witness: a value written through to a durable FilesystemStorage (rooted
//! at a tempdir) in an in-process wz `StorageService` is served to a real
//! zenoh-pico `z_get`, and the on-disk file proves it is the FILESYSTEM backend,
//! not memory.
//!
//! ## What binds the claim, and why it is SEPARABLE from memory-volume
//!
//! `storage-backend-filesystem` (active, PARTIAL) is the durable
//! Volume/StorageBackend: `FilesystemVolume` opens a `FilesystemStorage` rooted
//! at `root/<name>`, an in-memory mirror kept write-through-consistent (atomic
//! tmp+rename, fsync file+dir before returning). This test declares a storage
//! over a `FilesystemVolume` at a tempdir (volume_id `fs`, via
//! `StorageService::declare_with_backend`), seeds a value, and asserts BOTH:
//!  1. the seed wrote a file under `tempdir/demo/` — the write-through to disk
//!     that a MemoryStorage would NOT produce (the fs discriminator; separable
//!     from `storage-backend-memory-volume`, which y359 serves with no file), and
//!  2. a foreign pico `z_get demo/k1` gets the value back (`>> Received PUT
//!     ('demo/k1': '<value>')`) — the SERVE from the fs-backed storage.
//!
//! Together: a foreign querier retrieves a value that is durably persisted on
//! disk by wz's filesystem backend.
//!
//! ## The observable
//!
//! pico `z_get`'s reply handler prints `>> Received PUT ('<key>': '<value>')`
//! (`vendor/zenoh-pico/examples/unix/c11/z_get.c`). A storage that did not serve
//! yields no `>> Received` line and the `tokio::select!` drive branch panics
//! when pico closes before the witness — no vacuous pass. The `partial`
//! qualifier: the SERVE is fully foreign-observed; the fs-vs-memory
//! discrimination (the on-disk file) is asserted in-process.
//!
//! ## Non-flaky by construction ([[feedback-no-flaky-ever]])
//!
//! The write-through is synchronous (fsync before return), so the on-disk file
//! is present the instant the seed returns; the seed lands before the drive
//! future is polled; pico's one-shot `z_get` query is buffered and answered
//! after the queryable is declared. The `TempDir` is held for the whole test
//! (dropped at the end, cleaning the dir). Polling the captured stdout is
//! race-free; the 15s deadline is a backstop.
//!
//! Requires the zenoh-pico CLI + the `storage-backend-filesystem` feature
//! (opt-in, pinned in this crate's wz-runtime-tokio dev-dep since R311y361).
//! `#[ignore]` binary-dep e2e; run-ci Layer E runs it via the `--ignored` sweep
//! (no --skip match, no zenohd — a wz+pico in-process leg).

use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;

use wz_integration_tests::common::{read_captured, zenoh_pico_cli_binary, ChildGuard};
use wz_runtime_tokio::filesystem_storage::FilesystemVolume;
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
use wz_session_core::storage_volume::Volume;

const ITER_CAP: usize = 4096;
/// The storage keyexpr the wz `StorageService` captures + answers on.
const STORAGE_KEYEXPR: &str = "demo/**";
/// The storage NAME — FilesystemVolume roots this storage at `<tempdir>/<name>`.
const STORAGE_NAME: &str = "demo";
/// The concrete key pico `z_get`s (matched by `demo/**`).
const QUERY_KEY: &str = "demo/k1";
/// The value written through to disk and served back on the query.
const STORED_VALUE: &str = "durable-on-disk-served-to-pico";

/// A value durably persisted by a wz `StorageService` over a `FilesystemVolume`
/// (rooted at a tempdir) is served to a real zenoh-pico `z_get`, with an on-disk
/// file proving the filesystem backend — the §5.24 wz->pico serve cross-impl
/// witness of `storage-backend-filesystem`, separable from memory-volume.
// wz-proves: storage-backend-filesystem wz->pico partial
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_get); Layer E runs via --ignored"]
async fn wz_filesystem_storage_serves_a_durable_value_to_a_pico_zget() {
    let z_get = zenoh_pico_cli_binary("z_get");
    let tmp = tempfile::tempdir().expect("tempdir for the fs volume root");

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

    // Declare a storage over a FilesystemVolume rooted at the tempdir (volume_id
    // `fs`) and seed a value BEFORE the drive runs. The write-through is fsync'd
    // before process_put returns, so the on-disk file is present immediately.
    let config = StorageConfig::new(STORAGE_NAME, STORAGE_KEYEXPR, "fs");
    let backend = FilesystemVolume::new(tmp.path().to_path_buf())
        .create_storage(&config)
        .expect("filesystem volume creates the backend at the tempdir");
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(opened.actions.clone(), observer, Arc::new(opened.clock));
    let storage = StorageService::declare_with_backend(&session, &config, vec![0x01], backend)
        .expect("declare the wz filesystem storage on demo/**");
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

    // Assert #1 (the fs discriminator, in-process): the write-through created a
    // file under <tempdir>/demo/. A MemoryStorage backend produces no file, so
    // this separates the claim from storage-backend-memory-volume (y359).
    let storage_dir = tmp.path().join(STORAGE_NAME);
    let on_disk = std::fs::read_dir(&storage_dir)
        .map(|rd| rd.count())
        .unwrap_or(0);
    assert!(
        on_disk > 0,
        "the seed did not write a file under {storage_dir:?} — the filesystem \
         backend's write-through did not persist to disk (a memory backend would \
         leave this empty)"
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
            if captured.contains(received_witness)
                && captured.contains(QUERY_KEY)
                && captured.contains(STORED_VALUE)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico z_get did not receive the fs-backed value within 15s.\n\
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
            "wz drive loop reached a terminal state before pico received the fs-backed value"
        ),
        r = scenario => r,
    };

    let _ = z_get_child.child_mut().kill();
    let _ = z_get_child.child_mut().wait();

    if let Err(msg) = result {
        panic!("wz->pico filesystem storage serve interop FAILED.\n{msg}");
    }
    // `tmp` is held to here so the fs volume root outlives the test.
    drop(tmp);
}
