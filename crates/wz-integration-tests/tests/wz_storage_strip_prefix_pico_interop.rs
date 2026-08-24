// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y358 (pico cross-impl leg) §5.24 storage — the `storage-mgr-strip-prefix`
//! CAPTURE-side witness: a real zenoh-pico `z_put home/kitchen/temp` crosses a
//! live unicast TCP link into an in-process wz `StorageService` configured with
//! `strip_prefix = Some("home/kitchen")`, and the sample is stored under the
//! STRIPPED key `temp` — NOT verbatim.
//!
//! ## What it proves (net-new over the in-crate unit test)
//!
//! `storage-mgr-strip-prefix` is the mount-relative key transform: strip the
//! configured prefix on store, re-prepend on read (zenoh storage-manager
//! `strip_prefix`/`prefix`). wz wires it into the LIVE capture path —
//! `declare_with_backend` -> `StorageState::with_strip_prefix`, applied in
//! `apply_sample` -> `stored_key_for` -> `storage_strip_prefix::strip_prefix`
//! (gated `storage-mgr-strip-prefix`). The existing coverage is an IN-CRATE unit
//! test that hand-builds the config and drives `apply_sample` on a synthesized
//! `SampleView` (`storage_service.rs` tests). This leg closes the wire-to-strip
//! gap: a FOREIGN pico's DeclareKeyExpr + concrete Push crosses a real socket,
//! wz's keyexpr resolver reconstructs `home/kitchen/temp`, and the capture strip
//! maps it to the stored key `temp`.
//!
//! ## The observable (stripped key present AND verbatim key absent)
//!
//! Two assertions, together anti-vacuous:
//!  1. `st.get(Some("temp"))` is `Some` carrying the pico payload — the sample
//!     was captured AND its key was stripped to the mount-relative form.
//!  2. `st.get(Some("home/kitchen/temp"))` is `None` — the full published key
//!     was NOT stored verbatim. This is what separates strip from the plain
//!     storage-backend capture (which stores verbatim): a build WITHOUT the
//!     strip wiring stores under `home/kitchen/temp`, failing assertion #1.
//!
//! ## Why the witness is IN-PROCESS
//!
//! `storage-mgr-strip-prefix` has TWO halves: strip-on-store (capture) and
//! restore-on-read (the query answer re-prepends the prefix). This leg proves
//! the CAPTURE half by reading the stored key in-process (the same shape
//! `wz_storage_wildcard_update_pico_interop.rs` uses — foreign pico DRIVE,
//! in-process state READ). The restore-on-read half — a foreign `z_get` seeing
//! the full `home/kitchen/temp` re-prepended in the reply — is a NAMED
//! follow-up: it needs the storage query-answer path exercised against a foreign
//! getter, which the in-process harness does not drive here. Hence `partial`.
//!
//! ## Non-flaky by construction ([[feedback-no-flaky-ever]])
//!
//! The strip is pure logic applied synchronously on capture — no timing. pico
//! `z_put` is one-shot (open, declare, put, undeclare, close), so the wz drive
//! legitimately reaches a terminal state after processing the whole chain;
//! reading the storage state after the drive terminates is race-free (TCP
//! in-order: the Push is processed before the peer-close). The 10s budget is a
//! backstop, not a race.
//!
//! Requires the zenoh-pico CLI (`scripts/build-zenoh-pico-cli.sh` ->
//! `target/zenoh-pico-cli/z_put`). `#[ignore]` binary-dep e2e; run-ci Layer E
//! runs it via the `--ignored` sweep (the file name is caught by none of the
//! lane's `--skip` substrings, and it needs no zenohd — a wz+pico in-process leg).

use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use wz_integration_tests::common::{zenoh_pico_cli_binary, ChildGuard};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::TokioSession;
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{accept_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio::storage_service::StorageService;
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::storage_config::StorageConfig;

const ITER_CAP: usize = 4096;
/// The mount keyexpr the wz `StorageService` captures on. The pico put's
/// `home/kitchen/temp` intersects it, so the capture subscriber delivers it.
const STORAGE_KEYEXPR: &str = "home/kitchen/**";
/// The configured mount prefix stripped on store.
const STRIP_PREFIX: &str = "home/kitchen";
/// The concrete keyexpr the pico publishes on (`<prefix>/<rest>`).
const PUT_KEY: &str = "home/kitchen/temp";
/// The mount-relative key the sample MUST be stored under after the strip.
const STRIPPED_KEY: &str = "temp";
/// The pico PUT payload (`z_put -v` sends it verbatim).
const PUT_VALUE: &str = "strip-me-from-pico";

/// A real zenoh-pico `z_put -k home/kitchen/temp -v <V> -m client` PUT is
/// captured by an in-process wz `StorageService` whose `strip_prefix` is
/// `home/kitchen`, and stored under the STRIPPED key `temp` (not verbatim) — the
/// §5.24 capture-side cross-impl witness of `storage-mgr-strip-prefix`.
// wz-proves: storage-mgr-strip-prefix pico->wz partial
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_put); Layer E runs via --ignored"]
async fn wz_storage_strips_the_mount_prefix_from_a_pico_put() {
    let z_put = zenoh_pico_cli_binary("z_put");

    // wz acceptor binds first so pico's client dial lands in the listen backlog.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz acceptor");
    let addr = listener.local_addr().expect("local_addr");

    // Foreign initiator: zenoh-pico z_put in client mode on the FULL mount key.
    let mut z_put_child = ChildGuard::wrap(
        "z_put (zenoh-pico strip-prefix initiator)",
        Command::new(&z_put)
            .args([
                "-k",
                PUT_KEY,
                "-v",
                PUT_VALUE,
                "-e",
                &format!("tcp/{addr}"),
                "-m",
                "client",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn zenoh-pico z_put"),
    );

    // wz acceptor handshake — the same accept path wz-ap-demo uses.
    let (stream, _peer) = tokio::time::timeout(Duration::from_secs(8), listener.accept())
        .await
        .expect(
            "zenoh-pico never dialled. It exits without connecting when its argv is \
             wrong or its build lacks the feature under test, and a bare accept waits \
             for that forever -- which does not fail the test, it cancels the job",
        )
        .expect("accept pico client");
    let params = fixture_session_init_params();
    let mut opened = accept_and_open_session(
        DialedLink::Tcp(stream),
        params,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .expect("wz acceptor reaches Established against the pico z_put client");

    // Declare a storage on home/kitchen/** whose strip_prefix is home/kitchen.
    let mut config = StorageConfig::new("kitchen-store", STORAGE_KEYEXPR, "mem");
    config.strip_prefix = Some(STRIP_PREFIX.to_string());
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(opened.actions.clone(), observer, Arc::new(opened.clock));
    let storage = StorageService::declare(&session, &config, vec![0x01])
        .expect("declare the wz strip-prefix storage on home/kitchen/**");

    let timeouts = SessionTimeouts::spec_defaults();
    let session_drive = session.clone();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        // Continuous drive so the post-handshake Declare + Push are processed
        // before the pico's one-shot close terminates the loop.
        None,
        &opened.clock,
        &timeouts,
        move |event| session_drive.dispatch_iteration_event(event),
    );

    // pico's z_put is one-shot, so the drive reaches terminal after the whole
    // chain; reading the storage state after the terminal is race-free.
    tokio::select! {
        _ = drive => {}
        _ = tokio::time::sleep(Duration::from_secs(10)) => {
            panic!(
                "wz drive did not terminate within 10s — the pico z_put never closed \
                 the session (handshake or Push regression?)"
            )
        }
    }

    let _ = z_put_child.child_mut().kill();
    let _ = z_put_child.child_mut().wait();

    storage.with_state(|st| {
        // Assert #1: the sample was captured AND stored under the STRIPPED key.
        assert_eq!(
            st.get(Some(STRIPPED_KEY)).map(|d| d.payload.clone()),
            Some(PUT_VALUE.as_bytes().to_vec()),
            "the pico put `{PUT_KEY}` was not stored under the stripped key \
             `{STRIPPED_KEY}` — the capture strip did not map the mount prefix \
             (or the Push did not cross the wire to the storage subscriber)"
        );
        // Assert #2 (anti-vacuity): the verbatim full key was NOT used, proving
        // the strip actually stripped — a plain storage-backend capture (no
        // strip) would store here and fail assert #1.
        assert!(
            st.get(Some(PUT_KEY)).is_none(),
            "the full published key `{PUT_KEY}` must NOT be stored verbatim under \
             a strip_prefix mount — the strip did not apply on the capture path"
        );
    });
}
