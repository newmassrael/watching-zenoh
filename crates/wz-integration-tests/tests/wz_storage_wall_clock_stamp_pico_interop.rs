// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y357 (pico cross-impl leg) §5.18 time — the `time-system-clock` witness:
//! a real zenoh-pico `z_put` sends an UN-TIMESTAMPED sample over a live unicast
//! TCP link; the in-process wz `StorageService` captures it and stamps it with
//! the wall-clock NTP64 source (`FallbackStamp` -> `wall_clock_ntp64`), and the
//! test asserts the stored stamp's wall-clock VALUE is the current unix time.
//!
//! ## What it proves, and why it is SEPARABLE from `time-hlc`
//!
//! `time-system-clock` (FOUNDATIONAL) is the wall-clock NTP64 source
//! (`wz_runtime_tokio::timestamp_source::wall_clock_ntp64`,
//! `(unix_seconds << 32) | fraction`). It is the PHYSICAL layer the `time-hlc`
//! HLC wraps, not an alternative to it. `time-hlc`'s foreign observable is
//! "successive stamps strictly INCREASE" (monotonicity, the logical layer) —
//! which a FAKE monotonic counter would satisfy WITHOUT reading the wall clock.
//! So monotonicity does not witness the wall-clock VALUE. This test names the
//! separable observable `time-system-clock` owns: the stamp's high 32 bits (the
//! NTP64 seconds field, produced only by `wall_clock_ntp64`'s
//! `SystemTime::now()` read) equal the current unix time. A fake counter — of
//! any magnitude — fails this while still passing `time-hlc`'s monotonicity
//! proof, so the witness is the atom's own (the y349 separability discriminator).
//!
//! ## Why the witness is IN-PROCESS (the foreign-readback route is dead)
//!
//! The fallback wall-clock stamp is applied at exactly ONE site — the storage
//! CAPTURE leg (`timestamp_source.rs`: "the only auto-stamp site in wz today").
//! It is NOT re-emitted to any foreign reader:
//!  - A foreign SUBSCRIBER sees the sample wz FORWARDS, which carries the
//!    publisher's original timestamp (here: none — pico `z_put` is
//!    un-timestamped); wz does not stamp on the forward path, only on capture.
//!    (`wz_timestamp_to_pico_zsub.rs` shows a pico subscriber reading a
//!    timestamp only because THAT wz publisher SET one explicitly.)
//!  - A foreign `z_get` reply carries the payload but NOT the stored version's
//!    timestamp — a documented NON-goal of `StorageState` ("the querier does
//!    not yet read a per-reply timestamp", `storage_service.rs`).
//!
//! So the applied wall-clock stamp lives only in wz's storage state, and the
//! only witness of its VALUE is an in-process read of that state — exactly the
//! shape `wz_storage_wildcard_update_pico_interop.rs` uses (foreign pico DRIVE,
//! in-process state READ). A fully foreign-observed wall-clock readback would
//! need wz's storage reply to carry the per-reply timestamp (the storage
//! NON-goal above); that is a separate follow-up, NAMED here so this witness is
//! not over-read.
//!
//! ## The observable is engineered so ONLY the wall-clock stamp produces it
//!
//! Two assertions, together anti-vacuous:
//!  1. the stored stamp's `zid` is the STORAGE's stamper zid (`vec![0x01]`, the
//!     `local_zid` `FallbackStamp` is built over) — NOT pico's zid. This proves
//!     the timestamp is wz's applied fallback stamp, not a value the pico Put
//!     carried across the wire.
//!  2. the stored stamp's seconds (`time >> 32`) fall within the test's own
//!     wall-clock window `[start, end]` (captured with `SystemTime` around the
//!     drive). The stamp is produced when wz captures the Put, strictly between
//!     those two reads, so the bound cannot flake — and a stub source (tiny
//!     counter, or a large constant) lands nowhere near the window.
//!
//! ## Non-flaky by construction ([[feedback-no-flaky-ever]])
//!
//! pico `z_put` is one-shot (open, declare, put, undeclare, close), so the wz
//! drive legitimately reaches a terminal state after processing the whole
//! chain; reading the storage state after the drive terminates is race-free
//! (TCP in-order: the Push is processed before the peer-close). The `[start,
//! end]` window is derived from the same `SystemTime` clock the stamp reads, so
//! the containment is a tautology on a correct wall-clock source and a loud
//! failure on any other — no timing tolerance to tune. The 10s budget is a
//! backstop, not a race.
//!
//! Requires the zenoh-pico CLI (`scripts/build-zenoh-pico-cli.sh` ->
//! `target/zenoh-pico-cli/z_put`). `#[ignore]` binary-dep e2e; run-ci Layer E
//! runs it via the `--ignored` sweep (the file name is caught by none of the
//! lane's `--skip` substrings, and it needs no zenohd — a wz+pico in-process leg).

use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
/// The storage keyexpr the wz `StorageService` captures on; `demo/clock`
/// intersects it, so the capture subscriber delivers the pico Put.
const STORAGE_KEYEXPR: &str = "demo/**";
/// The concrete keyexpr the pico publishes on. With `strip_prefix = None`
/// (`StorageConfig::new`) the sample stores verbatim under this key.
const PUT_KEY: &str = "demo/clock";
/// The pico PUT payload (`z_put -v` sends it verbatim).
const PUT_VALUE: &str = "untimestamped-put-from-pico";
/// The storage's stamper identity — the `local_zid` `FallbackStamp` is built
/// over, so it is the `zid` on every fallback-stamped sample.
const STORAGE_STAMPER_ZID: &[u8] = &[0x01];

/// Current unix seconds via the same physical clock `wall_clock_ntp64` reads
/// (`SystemTime` since `UNIX_EPOCH`).
fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is post-epoch")
        .as_secs()
}

/// A real zenoh-pico `z_put -k demo/clock -v <V> -m client` UN-TIMESTAMPED PUT
/// is captured by an in-process wz `StorageService` and stamped with the
/// wall-clock NTP64 source; the stored stamp's seconds equal the current unix
/// time — the §5.18 cross-impl witness of `time-system-clock`, separable from
/// `time-hlc` (which only witnesses monotonicity).
// wz-proves: time-system-clock pico->wz partial
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_put); Layer E runs via --ignored"]
async fn wz_storage_stamps_an_untimestamped_pico_put_with_the_wall_clock() {
    let z_put = zenoh_pico_cli_binary("z_put");

    // wz acceptor binds first so pico's client dial lands in the listen backlog.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz acceptor");
    let addr = listener.local_addr().expect("local_addr");

    // The lower bound of the wall-clock window, read BEFORE the stamp can exist.
    let start_secs = unix_now_secs();

    // Foreign initiator: zenoh-pico z_put in client mode, UN-TIMESTAMPED (a
    // stock z_put attaches no body timestamp), on a concrete keyexpr.
    let mut z_put_child = ChildGuard::wrap(
        "z_put (zenoh-pico un-timestamped initiator)",
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

    // Declare a storage on demo/** over the opened session. The stamper zid is
    // STORAGE_STAMPER_ZID; an un-timestamped capture is stamped over it.
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(opened.actions.clone(), observer, Arc::new(opened.clock));
    let storage = StorageService::declare(
        &session,
        &StorageConfig::new("demo", STORAGE_KEYEXPR, "mem"),
        STORAGE_STAMPER_ZID.to_vec(),
    )
    .expect("declare the wz storage on demo/**");

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

    // The upper bound, read AFTER the stamp can no longer be produced.
    let end_secs = unix_now_secs();

    storage.with_state(|st| {
        let stored = st.get(Some(PUT_KEY)).unwrap_or_else(|| {
            panic!(
                "the pico un-timestamped PUT `{PUT_KEY}` was not captured — the Push \
                 either did not cross the wire to the storage subscriber, or the \
                 keyexpr did not resolve under `{STORAGE_KEYEXPR}`"
            )
        });

        // Assert #1 (anti-vacuity): the stamp is wz's fallback stamp, not a
        // value pico carried — its zid is the STORAGE stamper zid.
        assert_eq!(
            stored.timestamp.zid, STORAGE_STAMPER_ZID,
            "the stored stamp's zid must be the storage stamper zid {STORAGE_STAMPER_ZID:?} \
             (proving wz applied the fallback wall-clock stamp), not pico's zid — got {:?}",
            stored.timestamp.zid
        );

        // Assert #2 (the atom's observable): the stamp's NTP64 seconds field
        // (high 32 bits) is the current wall-clock time — inside the window the
        // stamp was necessarily produced in. This is what `time-system-clock`
        // (wall_clock_ntp64) uniquely produces; a monotonic-counter source
        // (which passes time-hlc's proof) lands outside the window.
        let stamp_secs = stored.timestamp.time >> 32;
        assert!(
            stamp_secs >= start_secs && stamp_secs <= end_secs,
            "the fallback stamp's wall-clock seconds {stamp_secs} must fall within the \
             test window [{start_secs}, {end_secs}] — a real `wall_clock_ntp64` read; \
             a value outside the window is not the system clock (raw ntp64={})",
            stored.timestamp.time
        );
    });
}
