// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y362 (pico cross-impl leg) §5.24 storage — the `storage-mgr-multi-storage-host`
//! serve witness: a `RuntimeStorageManager` hosts TWO named storages on ONE
//! session, and a real zenoh-pico `z_get` gets a value back from BOTH.
//!
//! ## What binds the claim, and why it is SEPARABLE
//!
//! `storage-mgr-multi-storage-host` (active) is the StorageManager hosting N
//! named storages over a volume registry (`RuntimeStorageManager::add_storage`
//! resolves `volume_id` -> `Volume::create_storage` -> declares a live
//! `StorageService` -> holds it by name). This test registers a `mem` volume,
//! `add_storage`s TWO configs (`sa` on `a/**`, `sb` on `b/**`) onto one session,
//! seeds one key in each, and a foreign pico `z_get -k **` (matching both) gets
//! BOTH `a/k1` and `b/k1` back. SEPARABLE from a single storage: one host serves
//! one key; only the MANAGER hosting two makes both replies appear. Binds to the
//! manager's add_storage/hold-by-name (the atom), not a bare StorageService.
//!
//! ## The observable (a reply from EACH hosted storage)
//!
//! pico `z_get`'s reply handler prints `>> Received PUT ('<key>': '<value>')`
//! per reply. `a/k1` and `b/k1` are DISTINCT keys, so query consolidation does
//! not collapse them; the test asserts BOTH values arrive. A host serving only
//! one storage yields one, and the `tokio::select!` drive branch panics if pico
//! closes before both witnesses — no vacuous pass. `partial`: the two-host serve
//! happy path is foreign-observed; add/remove lifecycle + errors are not here.
//!
//! ## Non-flaky by construction ([[feedback-no-flaky-ever]])
//!
//! Both seeds are synchronous and land before the drive future is polled; pico's
//! one-shot `z_get` query is buffered and answered after both queryables are
//! declared. Polling the captured stdout for BOTH values is race-free (both
//! replies precede the query-final); the 15s deadline is a backstop.
//!
//! Requires the zenoh-pico CLI + the `storage-mgr-multi-storage-host` feature
//! (opt-in, pinned in this crate's wz-runtime-tokio dev-dep since R311y362).
//! `#[ignore]` binary-dep e2e; run-ci Layer E runs it via the `--ignored` sweep
//! (no --skip match, no zenohd — a wz+pico in-process leg).

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
use wz_runtime_tokio::storage_manager_service::RuntimeStorageManager;
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::sample::TimestampHint;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::storage_config::StorageConfig;
use wz_session_core::storage_volume::MemoryVolume;

const ITER_CAP: usize = 4096;
/// pico queries this wildcard, which matches BOTH hosted storages' keyexprs.
const QUERY_KEY: &str = "**";
/// Storage A: name `sa`, mount `a/**`, holds `a/k1`.
const KEY_A: &str = "a/k1";
const VALUE_A: &str = "value-from-storage-a";
/// Storage B: name `sb`, mount `b/**`, holds `b/k1`.
const KEY_B: &str = "b/k1";
const VALUE_B: &str = "value-from-storage-b";

/// A `RuntimeStorageManager` hosting TWO named storages on one session serves a
/// value from EACH to a real zenoh-pico `z_get -k **` — the §5.24 wz->pico serve
/// cross-impl witness of `storage-mgr-multi-storage-host`, separable from a
/// single-storage host by the presence of both keys' values in the replies.
// wz-proves: storage-mgr-multi-storage-host wz->pico partial
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_get); Layer E runs via --ignored"]
async fn wz_multi_storage_host_serves_both_storages_to_a_pico_zget() {
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

    // Host TWO storages on one session via the manager, seed one key in each,
    // BEFORE the drive runs so both queryables + values are present for pico.
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(opened.actions.clone(), observer, Arc::new(opened.clock));
    let mut mgr = RuntimeStorageManager::new();
    mgr.register_volume("mem", Box::new(MemoryVolume));
    mgr.add_storage(
        &session,
        &StorageConfig::new("sa", "a/**", "mem"),
        vec![0x01],
    )
    .expect("host storage sa on a/**");
    mgr.add_storage(
        &session,
        &StorageConfig::new("sb", "b/**", "mem"),
        vec![0x02],
    )
    .expect("host storage sb on b/**");
    for (name, key, value) in [("sa", KEY_A, VALUE_A), ("sb", KEY_B, VALUE_B)] {
        let hosted = mgr.storage(name).expect("storage hosted");
        let shared = hosted.shared_state();
        let mut st = shared.lock().expect("seed lock");
        let _ = st.process_put(
            Some(key),
            value.as_bytes().to_vec(),
            None,
            TimestampHint {
                time: 1,
                zid: vec![0x03],
            },
        );
    }

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
            // BOTH hosted storages must reply (distinct keys -> no consolidation
            // collapse). A single-storage host would deliver only one.
            if captured.contains(received_witness)
                && captured.contains(VALUE_A)
                && captured.contains(VALUE_B)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico z_get did not receive a value from BOTH hosted storages within 15s.\n\
                     Expected '{received_witness}' + '{VALUE_A}' + '{VALUE_B}' \
                     (a single-storage host serves only one).\n--- captured stdout ---\n{captured}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };

    let result = tokio::select! {
        _ = drive => panic!(
            "wz drive loop reached a terminal state before pico received both storages' values"
        ),
        r = scenario => r,
    };

    let _ = z_get_child.child_mut().kill();
    let _ = z_get_child.child_mut().wait();

    if let Err(msg) = result {
        panic!("wz->pico multi-storage-host serve interop FAILED.\n{msg}");
    }
}
