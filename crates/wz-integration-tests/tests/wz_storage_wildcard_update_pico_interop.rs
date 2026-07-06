// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311wt (pico cross-impl leg) §5.24 storage — the storage WILDCARD-UPDATE
//! LIVE-path cross-impl e2e: a real zenoh-pico `z_put` on a WILDCARD keyexpr
//! (`demo/**`) drives a wildcard-update INTO an in-process wz `StorageService`
//! over a live unicast TCP link, and the wz storage detects the wildcard
//! (`StorageState::apply_sample` -> `is_wild` -> `materialize_wildcard`),
//! registers it, and materializes the override onto a pre-existing concrete key.
//!
//! ## What it proves (net-new over the unit + loopback coverage)
//!
//! A pico wildcard `z_put` is, on the wire, an ORDINARY Push of kind Put with a
//! wildcard keyexpr — NOT a special message (zenoh-pico `_z_write` ->
//! `_z_n_msg_make_push_put`, `vendor/zenoh-pico/src/net/primitives.c:176-186`;
//! the keyexpr is `z_declare_keyexpr`'d full-length,
//! `examples/unix/c11/z_put.c:52,57`). The slice-2 write-path override engine's
//! LIVE capture path (`apply_sample_wildcard_aware`) was previously exercised
//! ONLY by unit tests that call `apply_sample` on a HAND-BUILT `SampleView`. This
//! leg closes the wire-to-`apply_sample` gap: a FOREIGN pico's DeclareKeyExpr +
//! wildcard Push crosses a real socket, wz's keyexpr resolver reconstructs
//! `demo/**`, the storage's capture subscriber fires on the wildcard-vs-wildcard
//! intersect, `is_wild` detects it, and the override MATERIALIZES over the
//! pre-seeded concrete key. No existing test covers this (the loopback unit test
//! `storage_service::tests::declared_storage_captures_a_loopback_publish_...` is
//! SessionLocal + concrete-key; `wz_reassembles_pico_fragment_tx.rs` is a real
//! pico Push but concrete + a plain observer, no storage/wildcard).
//!
//! ## The observable (registry AND materialized override, not registration alone)
//!
//! `wildcard_registry_lens() == (1, 0)` alone would pass on an EMPTY backend
//! WITHOUT exercising the override loop (`materialize_wildcard` registers, then
//! its scan of an empty store is a no-op — `apply_one_with_override` never runs).
//! To witness the "-update" semantics the feature exists for, the test pre-seeds
//! a concrete `demo/k1` (via `StorageService::shared_state` + `process_put`, at a
//! deliberately-past NTP64 so newer-wins is unambiguous) BEFORE the pico wildcard
//! arrives, then asserts BOTH: (1) the wildcard PUT is registered
//! (`wildcard_registry_lens() == (1, 0)`), AND (2) `demo/k1`'s stored value is
//! the pico's wildcard payload (the override materialized through
//! `apply_one_with_override`). pico's `z_put` attaches no timestamp, so wz stamps
//! the inbound wildcard at receive (`storage_service.rs` fallback stamper) —
//! strictly newer than the past-stamped seed, so the override wins deterministically.
//!
//! ## HONESTY — this is the LIVE-path leg; the ALIGN-path leg stays open
//!
//! zenoh runs wildcard-updates on TWO paths: the LIVE capture path (this test)
//! and the replication ALIGN path (`process_alignment_reply`). The
//! `storage_state.rs` module doc names a wz<->zenohd ALIGN-path wildcard e2e as a
//! separate cross-impl follow-up (a wz replica pulling + applying a wildcard
//! EVENT off a real zenohd's aligner) — that leg is NOT closed by this LIVE-path
//! proof and remains open. The two `storage-mgr-wildcard-updates` /
//! `storage-mgr-garbage-collection` inventory atoms are already `active` (they
//! flipped on the R311wt BUILD slices, not on this leg); this cross-impl e2e is a
//! confidence/parity proof of the LIVE path, not a state change for the track.
//!
//! ## Non-flaky by construction ([[feedback-no-flaky-ever]])
//!
//! pico `z_put` is one-shot (open, declare, put, undeclare, close), so the wz
//! drive legitimately reaches a terminal state. By TCP in-order delivery the
//! DeclareKeyExpr + Push are processed BEFORE the peer-close in the same drive
//! loop, so reading the storage state AFTER the drive terminates is race-free
//! (the same rationale as `wz_reassembles_pico_fragment_tx.rs`). The concrete
//! seed is synchronous and lands before the drive future is polled, and the
//! post-open Push is not consumed by the open loop (it is buffered in the socket
//! and read by `drive_session_until_terminal`), so the seed is always present
//! when the wildcard materializes. The 10s budget is a backstop, not a race.
//!
//! Requires the zenoh-pico CLI (`scripts/build-zenoh-pico-cli.sh` ->
//! `target/zenoh-pico-cli/z_put`). `#[ignore]` binary-dep e2e; run-ci Layer E
//! runs it via the `--ignored` sweep (the file name is not caught by any of the
//! lane's `--skip` substrings).

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
use wz_session_core::sample::TimestampHint;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::storage_config::StorageConfig;

const ITER_CAP: usize = 4096;
/// The storage keyexpr the wz `StorageService` captures + answers on. A
/// multi-chunk `**` so the pico wildcard `demo/**` intersects it wildcard-to-wildcard.
const STORAGE_KEYEXPR: &str = "demo/**";
/// The pico publishes on this WILDCARD keyexpr — the wildcard-update under test.
const WILDCARD_KEYEXPR: &str = "demo/**";
/// The pre-seeded concrete key the pico wildcard must override. It is matched by
/// `demo/**`, so `materialize_wildcard` writes the wildcard value onto it.
const SEED_KEY: &str = "demo/k1";
/// The concrete value seeded BEFORE the pico wildcard (distinct from the wildcard
/// value so the override is unambiguous). Stamped at a past NTP64 so newer-wins
/// unambiguously prefers the pico wildcard.
const SEED_VALUE: &[u8] = b"seed-concrete-v1";
/// The pico wildcard PUT payload. pico `z_put -v` sends it VERBATIM (no counter
/// prefix), so the override read-back is byte-exact.
const WILDCARD_VALUE: &str = "wildcard-put-from-pico-over-the-wire";

/// A real zenoh-pico `z_put -k demo/** -v <V> -m client` wildcard PUT is received
/// by an in-process wz `StorageService`, registered in its wildcard-PUT registry,
/// and materialized over a pre-existing concrete key — the §5.24 LIVE-path
/// cross-impl proof of the R311wt write-path override engine (slice 2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_put); Layer E runs via --ignored"]
async fn wz_storage_applies_a_pico_wildcard_update_over_the_wire() {
    let z_put = zenoh_pico_cli_binary("z_put");

    // wz acceptor binds first so pico's client dial lands in the listen backlog
    // and `accept()` resolves it (no PortReservation needed — the in-process
    // listener holds the port for the whole test, unlike a separate-process peer).
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz acceptor");
    let addr = listener.local_addr().expect("local_addr");

    // Foreign initiator: zenoh-pico z_put in client mode on a WILDCARD keyexpr.
    // It declares `demo/**`, then Puts the payload as an ordinary wildcard Push.
    let mut z_put_child = ChildGuard::wrap(
        "z_put (zenoh-pico wildcard initiator)",
        Command::new(&z_put)
            .args([
                "-k",
                WILDCARD_KEYEXPR,
                "-v",
                WILDCARD_VALUE,
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

    // wz acceptor handshake — the same accept path as wz-ap-demo (runner.rs),
    // which `ap_demo_round_trip.rs` proves interoperates with a pico z_put client.
    let (stream, _peer) = listener.accept().await.expect("accept pico client");
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

    // Build the session over the opened link and declare a storage on demo/**.
    // The observer is the crate `sync::Mutex` alias (NOT std/tokio) — the session
    // registers the storage's capture subscriber into it, and the drive loop's
    // `dispatch_iteration_event` dispatches inbound Pushes into the same observer.
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(opened.actions.clone(), observer, Arc::new(opened.clock));
    let storage = StorageService::declare(
        &session,
        &StorageConfig::new("demo", STORAGE_KEYEXPR, "mem"),
        vec![0x01],
    )
    .expect("declare the wz storage on demo/**");

    // Pre-seed a concrete key at a deliberately-past NTP64 (time = 1) so the pico
    // wildcard (stamped at receive with the current wall clock, >= 2^32) is
    // strictly newer and its override wins. `time = 1` is load-bearing: a
    // wall-clock-magnitude seed could TIE the wildcard's `time` word, and the
    // newer-wins tiebreak then compares zid — where the seed's `0x02` > the
    // storage's stamper zid `0x01`, so a tie would make the seed win and the
    // override would NOT materialize (assert #2 would fail). `time = 1` never
    // ties. Synchronous + before the drive future runs, so the seed is present
    // when the wildcard materializes. The post-open pico Push is buffered in the
    // socket (not consumed by the open loop), so this ordering holds.
    let _ = storage
        .shared_state()
        .lock()
        .expect("seed lock")
        .process_put(
            Some(SEED_KEY),
            SEED_VALUE.to_vec(),
            None,
            TimestampHint {
                time: 1,
                zid: vec![0x02],
            },
        );

    let timeouts = SessionTimeouts::spec_defaults();
    let session_drive = session.clone();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        // Continuous drive so the post-handshake Declare + wildcard Push are
        // processed before the pico's one-shot close terminates the loop.
        None,
        &opened.clock,
        &timeouts,
        move |event| session_drive.dispatch_iteration_event(event),
    );

    // pico's z_put is one-shot (declare, put, undeclare, close), so the drive
    // legitimately reaches terminal after processing the whole chain. Reading the
    // storage state after the terminal is race-free (TCP in-order: Push before Close).
    tokio::select! {
        _ = drive => {}
        _ = tokio::time::sleep(Duration::from_secs(10)) => {
            panic!(
                "wz drive did not terminate within 10s — the pico z_put never closed \
                 the session (handshake or wildcard-Push regression?)"
            )
        }
    }

    let _ = z_put_child.child_mut().kill();
    let _ = z_put_child.child_mut().wait();

    storage.with_state(|st| {
        // Assert #1 (registration): the foreign pico wildcard PUT crossed the wire,
        // fired the capture subscriber, was `is_wild`-detected, and registered as a
        // WildcardPut (one PUT, zero DELETEs). A fresh state is (0,0); the only path
        // to (1,0) is `apply_sample` firing on a delivered wildcard Push.
        assert_eq!(
            st.wildcard_registry_lens(),
            (1, 0),
            "the pico wildcard `demo/**` PUT was not registered on the LIVE capture \
             path — the wildcard Push either did not cross the wire to the storage \
             subscriber, or `is_wild` did not fire on the resolved keyexpr"
        );
        // Assert #2 (materialized override): the wildcard-update materialized over
        // the pre-seeded concrete key — `demo/k1` now holds the pico's wildcard
        // value, exercising `apply_one_with_override` (the "-update" semantics, not
        // just registration).
        assert_eq!(
            st.get(Some(SEED_KEY)).map(|d| d.payload.clone()),
            Some(WILDCARD_VALUE.as_bytes().to_vec()),
            "the pico wildcard PUT did not override the pre-seeded concrete key — \
             `demo/k1` should hold the wildcard value after materialization"
        );
    });
}
