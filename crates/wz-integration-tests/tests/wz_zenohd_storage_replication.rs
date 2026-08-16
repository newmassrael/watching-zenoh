// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311wo §5.11 A10 — wz <-> zenohd storage-manager REPLICATION interop: an
//! in-process wz storage replica converges to a REAL zenohd running
//! `zenoh-plugin-storage-manager` with replication enabled, over a real TCP
//! link. This is the cross-implementation analogue of A11 (which paired two wz
//! replicas): here the peer is the canonical Rust zenoh, so a pass proves wz's
//! digest + alignment wire formats interoperate byte-for-byte with the real
//! thing, not just with itself.
//!
//! ## What it proves
//!
//! 1. **Config fingerprint parity (the foundation).** The digest / aligner
//!    keyexprs embed `hash_configuration` — wz and zenohd only meet if their
//!    fingerprints are EQUAL. The test pins wz's fingerprint for a known config
//!    to the literal value a real zenohd 1.5.0 emits
//!    (`3912446778783065544`, captured from the reference router's
//!    "Published Digest" log), so a divergence in either xxh3 recipe fails here,
//!    loudly, before any I/O.
//! 2. **wz decodes zenohd's Digest.** zenohd publishes its digest on
//!    `@-digest/<zenohd-zid>/<fp>`; wz's `spawn_digest_aligner` subscriber
//!    receives + decodes it (zenoh -> wz bincode digest wire parity) and diffs.
//! 3. **wz's ASK pull interoperates with zenohd's aligner.** On detecting it
//!    diverges, wz queries zenohd's aligner queryable
//!    (`@zid/<zenohd-zid>/<fp>/aligner`) with an `AlignmentQuery`; zenohd answers
//!    with the entries wz lacks, and wz's `process_alignment_reply` lands them.
//!    wz's replica store converges to hold zenohd's entry.
//!
//! Of these, the test HARD-ASSERTS #1 (the golden fingerprint, before any I/O)
//! and #4-equivalent end-state (the replica holds zenohd's bytes); #2 and #3 are
//! established TRANSITIVELY — the convergence is unreachable unless wz both
//! decodes zenohd's digest and round-trips an `AlignmentQuery`/reply with
//! zenohd's aligner — not by separately scraping zenohd's logs.
//!
//! ## Both replication directions (ASK + ANSWER), cross-impl
//!
//! This file proves BOTH directions against the real zenoh:
//! - [`wz_replica_converges_to_zenohd_storage_manager`] — the ASK direction: an
//!   empty wz replica PULLS from a zenohd that holds an entry (wz's digest
//!   subscriber + `process_alignment_reply`).
//! - [`zenohd_converges_to_wz_replica`] — the ANSWER direction (the mirror): an
//!   empty zenohd replica PULLS from a wz replica that holds an entry,
//!   exercising wz's [`AlignerService`] answer queryable against the REAL zenoh
//!   aligner ASK. (wz's `DigestPublisher` is spawned as the faithful
//!   complete-replica setup + the steady-state fallback, but convergence here is
//!   via initial-alignment Discovery, so the digest-diff round-trip is not the
//!   load-bearing path — see that test's docstring.) This closes the gap the ASK
//!   test alone left — wz's ANSWER side was previously validated only wz<->wz
//!   (the A11 convergence e2e), never cross-impl.
//!
//! ## Divergence setup (wz's replica state starts empty)
//!
//! A foreign zenoh-pico `z_pub` seeds ONE entry into zenohd's storage (zenohd
//! captures + timestamps it). A pico client is used rather than the wz session
//! because a wz CLIENT is not told the router's storage subscription, so a
//! wz-side Put would route to nobody. wz's REPLICA `StorageState` is a SEPARATE,
//! directly-constructed, EMPTY store, so it gains the entry ONLY by pulling it
//! from zenohd through the replication aligner — the cross-impl convergence the
//! test asserts.
//!
//! ## Gating + provisioning
//!
//! `#[ignore]` (binary-dep e2e): needs `target/zenohd/zenohd` +
//! `target/zenohd/libzenoh_plugin_storage_manager.so` (both from
//! `scripts/build-zenohd.sh`; the plugin must be the SAME zenoh source as zenohd
//! so its ABI-compat hash matches and zenohd loads it). Run via Layer Z /
//! `--ignored`. Non-flaky by construction: convergence is poll-on-condition
//! (the replica store gains the entry), monotonic once pulled, with a generous
//! budget over zenohd's 1s digest interval. ([[feedback-no-flaky-ever]])

use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex as StdMutex};
use std::thread;
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    read_captured, storage_manager_plugin, wait_for_tcp_accept_alive, zenoh_pico_cli_binary,
    zenohd_binary, ChildGuard, PortReservation, ZENOHD_TCP_ACCEPT_BUDGET,
};

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::TokioSession;
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    connect_and_open_session, DialConfig, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::storage_aligner_service::{spawn_digest_aligner, AlignerService};
use wz_runtime_tokio::storage_replication_service::DigestPublisher;
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio::timestamp_source::wall_clock_ntp64;
use wz_runtime_tokio_test_support::zenohd_interop_session_init_params;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::sample::TimestampHint;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::storage_backend::MemoryStorage;
use wz_session_core::storage_replication::ReplicationConfig;
use wz_session_core::storage_state::StorageState;

const ITER_CAP: usize = 256;
/// The storage key space (the replication-config fingerprint seed). MUST match
/// the `key_expr` in the zenohd storage config below.
const STORAGE_KEYEXPR: &str = "data/test/**";
const DATA_KEY: &str = "data/test/x";
/// The value a pico `z_pub` seeds into zenohd's storage; wz must pull these
/// exact bytes back over the replication aligner.
const SEED_VALUE: &str = "hello-zenohd-replica";
/// The config fingerprint a real zenohd 1.5.0 emits for the replication config
/// `{key_expr:"data/test/**", interval:1.0s, sub_intervals:5, hot:6, warm:30,
/// propagation_delay:250ms}` (captured from its "Published Digest" trace). wz's
/// `ReplicationConfig` MUST hash to this same value or the two never meet on the
/// `@-digest/<zid>/<fp>` keyexpr — this is the cross-impl wire-parity anchor.
const ZENOHD_CONFIG_FINGERPRINT: u64 = 3912446778783065544;
/// The ANSWER-direction entry: the key/value wz holds and an empty zenohd must
/// pull off wz's aligner. A distinct key from [`DATA_KEY`] so the two tests read
/// clearly (each spawns its own zenohd, so there is no shared state). Unlike the
/// pico-seeded ASK value, wz seeds this directly, so the read-back is exact (no
/// pico "[ N] " iteration prefix).
const WZ_DATA_KEY: &str = "data/test/y";
const WZ_SEED_VALUE: &str = "hello-from-wz-replica";

/// R311wt (ALIGN-path cross-impl leg) — the WILDCARD keyexpr a foreign pico
/// `z_pub` seeds into zenohd as a wildcard-update EVENT. A sub-wildcard of
/// [`STORAGE_KEYEXPR`] (unambiguously wild, unambiguously routed to the
/// storage's `data/test/**` subscription). zenohd's `process_sample` sees
/// `is_wild()` → `register_wildcard_update` + inserts a `WildcardPut` log event
/// keyed on the wildcard itself (service.rs:233-254). wz must pull THAT event
/// off the aligner and register it in its own `wildcard_puts` registry — the
/// cross-impl proof that align-path wildcard-EVENT registration interoperates
/// with the real zenoh. Distinct from concrete-value convergence, which
/// propagates as a plain `Put` (zenoh `determine_action` collapses a
/// materialized concrete event's action, log.rs:181-202) and never touches the
/// receiver's wildcard registry.
const WC_KEYEXPR: &str = "data/test/wild/**";
const WC_SEED_VALUE: &str = "wildcard-from-zenohd";

/// Spawn a zenohd router with the storage-manager plugin loaded and one
/// memory-backed storage on `STORAGE_KEYEXPR` with replication enabled (1s
/// interval for a fast digest). Timestamping is enabled so an un-timestamped
/// wz Put is stamped + stored (a zenoh storage requires a timestamp). Blocks
/// until the TCP listener is accepting. zenohd EXITS if the plugin fails to
/// load, so a returned guard means the plugin loaded.
fn spawn_zenohd_storage_replica(port: u16) -> ChildGuard {
    let storage_cfg = format!(
        "plugins/storage_manager/storages/replica1:{{key_expr:\"{STORAGE_KEYEXPR}\",\
         volume:\"memory\",replication:{{interval:1.0,sub_intervals:5,hot:6,warm:30,\
         propagation_delay:250}}}}"
    );
    let plugin = storage_manager_plugin();
    let mut command = Command::new(zenohd_binary());
    command
        .arg("-l")
        .arg(format!("tcp/127.0.0.1:{port}"))
        .arg("--no-multicast-scouting")
        .arg("--rest-http-port")
        .arg("none")
        .arg("--plugin")
        .arg(format!("storage_manager:{}", plugin.display()))
        .arg("--cfg")
        .arg("timestamping/enabled:true")
        .arg("--cfg")
        .arg(&storage_cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut guard = ChildGuard::wrap(
        "zenohd (storage-manager replication)",
        command.spawn().expect("spawn zenohd with storage-manager"),
    );
    if let Err(e) = wait_for_tcp_accept_alive(guard.child_mut(), port, ZENOHD_TCP_ACCEPT_BUDGET) {
        panic!("zenohd (storage-manager replication): {e}");
    }
    guard
}

/// Seed zenohd's storage by spawning a zenoh-pico `z_pub` (a proven zenoh
/// client) that publishes `value` on `key` against zenohd a FEW times then
/// stops. The bounded burst (`-n 3`) is deliberate: each `z_pub` Put carries a
/// fresh timestamp, so while it is publishing the entry MOVES to a new
/// replication interval every second and a digest-driven pull chases the
/// just-vacated interval. After the burst ends the entry SETTLES at its last
/// timestamp (one fixed interval), and wz's next pull lands it. A bare
/// `z_put` (single Put then immediate `z_close`) is unreliable here — the Put
/// races the session teardown and frequently never reaches the storage; a
/// `z_pub` burst's earlier Puts land (the 1s inter-Put spacing flushes them).
/// A foreign pico client (not the wz session) is used because a wz CLIENT is
/// not told the router's storage subscription, so a wz-side Put would route to
/// nobody; the pico client routes unconditionally. Retries the foreign
/// one-shot's transient session opens.
fn spawn_seeding_zpub(key: &str, value: &str, port: u16) -> ChildGuard {
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let endpoint = format!("tcp/127.0.0.1:{port}");
    const ATTEMPTS: usize = 6;
    for attempt in 1..=ATTEMPTS {
        let out = tempfile::tempfile().expect("tempfile for z_pub stdout");
        let out_writer = out.try_clone().expect("dup z_pub stdout handle");
        let mut out_reader = out;
        let mut child = ChildGuard::wrap(
            "z_pub seed (zenoh-pico)",
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(&z_pub)
                .args([
                    "-k", key, "-v", value, "-e", &endpoint, "-m", "client", "-n", "3",
                ])
                .stderr(Stdio::from(
                    out_writer.try_clone().expect("dup stderr handle"),
                ))
                .stdout(Stdio::from(out_writer))
                .spawn()
                .expect("spawn z_pub via stdbuf"),
        );
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let cap = read_captured(&mut out_reader);
            if cap.contains("Putting Data") {
                return child; // publishing; the burst settles after `-n` Puts
            }
            if cap.contains("Unable to open session") || Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
        eprintln!("z_pub seed attempt {attempt}/{ATTEMPTS} did not start; retrying");
    }
    panic!("pico z_pub failed to seed zenohd after {ATTEMPTS} attempts");
}

/// Dial zenohd in-process and reach Established, retrying to absorb zenohd's
/// cold-start window between "listener up" (the TCP-accept gate) and
/// "handshake-ready" (transport/routing tasks scheduled). The open params are
/// the shared [`zenohd_interop_session_init_params`] (version 0x09 / real
/// batch_size / res 2) — a strict zenohd rejects the wz<->wz fixture shape
/// (version 0x05 / batch_size 0) at InitSyn.
async fn connect_to_zenohd(port: u16) -> OpenedSession {
    let locator = parse_any_locator(&format!("tcp/127.0.0.1:{port}")).expect("parse locator");
    for attempt in 1..=20 {
        let params = zenohd_interop_session_init_params();
        let cfg = DialConfig::default();
        match connect_and_open_session(
            locator.clone(),
            params,
            &cfg,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        {
            Ok(opened) => return opened,
            Err(_) if attempt < 20 => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("wz never reached Established against zenohd: {e:?}"),
        }
    }
    unreachable!("the loop returns or panics")
}

/// An in-process wz storage replica converges to a zenohd that holds an entry
/// it lacks: wz receives + decodes zenohd's replication digest, detects it
/// diverges, pulls the entry off zenohd's aligner queryable, and lands it.
// wz-proves: storage-replication zenohd->wz
// wz-proves: storage-replication wz->zenohd partial
// wz-proves: storage-aligner zenohd->wz
// wz-proves: storage-aligner wz->zenohd partial
// wz-proves: declare-subscriber wz->zenohd
// wz-proves: keyexpr-wildcard-single wz->zenohd partial
// wz-proves: query-get wz->zenohd
// wz-proves: codec-request wz->zenohd
// wz-proves: query-reply zenohd->wz
// wz-proves: codec-response zenohd->wz
// wz-proves: pubsub-sample zenohd->wz
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binary-dep e2e (zenohd storage-manager replication); needs target/zenohd/{zenohd,libzenoh_plugin_storage_manager.so}; run via Layer Z / --ignored"]
async fn wz_replica_converges_to_zenohd_storage_manager() {
    // The config wz uses MUST hash to the same fingerprint as the zenohd storage
    // config (1.0s interval, etc.) — pin the cross-impl parity before any I/O.
    let config = ReplicationConfig::new(STORAGE_KEYEXPR, None, 1000, 5, 6, 30, 250);
    assert_eq!(
        config.fingerprint().value(),
        ZENOHD_CONFIG_FINGERPRINT,
        "wz's replication config fingerprint must equal the real zenohd's, or the \
         two never meet on @-digest/<zid>/<fp>"
    );

    let port_res = PortReservation::pick();
    let port = port_res.port();
    let _zenohd = spawn_zenohd_storage_replica(port);
    // Seed zenohd's storage (via a foreign pico client) BEFORE wz joins, so
    // zenohd's digest is non-empty and wz diverges from it on first receipt.
    let _seed = spawn_seeding_zpub(DATA_KEY, SEED_VALUE, port);
    drop(port_res);

    // ── Dial zenohd in-process and bring the wz session up.
    let mut opened = connect_to_zenohd(port).await;
    let timeouts = SessionTimeouts::spec_defaults();

    // ── The wz REPLICA store: a separate, empty StorageState. The wz session has
    //    NO capture subscriber on the storage keyexpr, so it gains the seeded
    //    entry only by pulling it back from zenohd through the aligner.
    let replica: Arc<StdMutex<StorageState<MemoryStorage>>> =
        Arc::new(StdMutex::new(StorageState::new(MemoryStorage::new())));

    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(opened.actions.clone(), observer, Arc::new(opened.clock));

    // Wire the digest -> aligner handoff: wz subscribes to zenohd's digest
    // (@-digest/*/<fp>, Remote), and on detecting divergence auto-pulls off
    // zenohd's aligner (@zid/<zenohd-zid>/<fp>/aligner).
    let _digest_aligner = spawn_digest_aligner(&session, replica.clone(), config.clone())
        .expect("wz wires its digest -> aligner pull");

    let session_drive = session.clone();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        move |event| session_drive.dispatch_iteration_event(event),
    );

    let scenario = {
        let replica = replica.clone();
        async move {
            // Poll until the wz replica converges (pulled zenohd's seeded entry).
            // The pico `z_pub` value carries an "[ N] " iteration prefix, so match
            // the seed marker as a substring (CONTAINS, not exact equal) — wz
            // pulled zenohd's stored bytes verbatim, prefix included. Monotonic;
            // generous budget over zenohd's 1s digest interval.
            for _ in 0..400 {
                {
                    let guard = replica.lock().unwrap();
                    if guard
                        .get(Some(DATA_KEY))
                        .is_some_and(|s| String::from_utf8_lossy(&s.payload).contains(SEED_VALUE))
                    {
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("wz replica did not converge (never pulled {DATA_KEY}) within ~20s");
        }
    };

    tokio::select! {
        _ = drive => panic!("wz drive loop ended unexpectedly (zenohd link lost?)"),
        _ = scenario => {}
    }

    // ── Converged: the wz replica holds zenohd's entry, pulled over the wire via
    //    the real zenoh replication aligner protocol.
    let guard = replica.lock().unwrap();
    let stored = guard
        .get(Some(DATA_KEY))
        .expect("wz replica converged: zenohd's entry is present");
    let got = String::from_utf8_lossy(&stored.payload);
    assert!(
        got.contains(SEED_VALUE),
        "wz pulled zenohd's value (containing the seed marker) via cross-impl alignment; got {got:?}"
    );
}

/// An in-process wz storage replica REGISTERS a zenohd wildcard-update EVENT it
/// pulls over the aligner — the ALIGN-path twin of the LIVE-path pico leg
/// (`wz_storage_wildcard_update_pico_interop`), and the cross-impl proof for the
/// `Action::WildcardPut` receive arm of `process_alignment_reply`.
///
/// ## What it proves (distinct from the concrete-value ASK test above)
///
/// The ASK test proves a concrete Put/Delete converges. A wildcard update is
/// DIFFERENT on the wire: zenohd's `determine_action` (log.rs:181-202) collapses
/// a *materialized concrete* event's action back to a plain `Put` (the concrete
/// key differs from the wildcard keyexpr), so a wildcard's EFFECT on real keys
/// propagates — and converges — as ordinary `Put`s that never touch a receiver's
/// wildcard registry. The ONE event that carries `Action::WildcardPut` is the
/// wildcard-KEYED event (key == the wildcard keyexpr, service.rs:243-254), which
/// zenohd inserts into its replication log and its aligner serves verbatim
/// (`reply_events_metadata` → `reply_event_retrieval`'s `WildcardPut` arm reads
/// the value from `wildcard_puts`, aligner_query.rs:256/320). wz must DECODE
/// that event as `WildcardPut(ke)` (storage_aligner.rs:763) and, on the align
/// path, call `materialize_wildcard` → `register_wildcard_update`
/// (storage_state.rs:1344/577), landing the wildcard in its own `wildcard_puts`
/// registry. `wildcard_registry_lens().0 >= 1` witnesses exactly that — the
/// registration the materialized-value convergence alone does NOT exercise.
///
/// ## Divergence setup (empty backend, wildcard-only)
///
/// A foreign pico `z_pub` seeds ONLY a wildcard update ([`WC_KEYEXPR`]) into an
/// otherwise-empty zenohd storage. No concrete keys exist, so zenohd's
/// `get_matching_keys` materializes onto nothing (service.rs:257) — the log holds
/// the single wildcard-keyed `WildcardPut` event and no concrete `Put`. That
/// isolates the property under test: the registry can only become non-empty by
/// wz registering the pulled wildcard EVENT, never as a side effect of a
/// concrete Put (which would be a plain `Put` on the wire regardless).
///
/// Non-flaky by construction: convergence is poll-on-condition (the replica's
/// `wildcard_puts` gains an entry), monotonic once pulled (a `BTreeMap` insert,
/// never removed absent GC, which this test does not drive), with a generous
/// budget over zenohd's 1s digest interval. ([[feedback-no-flaky-ever]])
// wz-proves: storage-mgr-wildcard-updates zenohd->wz partial
// wz-proves: storage-aligner zenohd->wz
// wz-proves: storage-aligner wz->zenohd partial
// wz-proves: storage-replication zenohd->wz partial
// wz-proves: declare-subscriber wz->zenohd
// wz-proves: query-get wz->zenohd
// wz-proves: query-reply zenohd->wz
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binary-dep e2e (zenohd storage-manager replication); needs target/zenohd/{zenohd,libzenoh_plugin_storage_manager.so}; run via Layer Z / --ignored"]
async fn wz_replica_registers_wildcard_event_from_zenohd_storage_manager() {
    // The config wz uses MUST hash to the same fingerprint as the zenohd storage
    // config — pin the cross-impl parity before any I/O (identical to the ASK
    // test; the two only meet on @-digest/<zid>/<fp> if their fingerprints are
    // EQUAL).
    let config = ReplicationConfig::new(STORAGE_KEYEXPR, None, 1000, 5, 6, 30, 250);
    assert_eq!(
        config.fingerprint().value(),
        ZENOHD_CONFIG_FINGERPRINT,
        "wz's replication config fingerprint must equal the real zenohd's, or the \
         two never meet on @-digest/<zid>/<fp>"
    );

    let port_res = PortReservation::pick();
    let port = port_res.port();
    let _zenohd = spawn_zenohd_storage_replica(port);
    // Seed zenohd's storage with a WILDCARD update BEFORE wz joins (a foreign pico
    // `z_pub` on a wildcard keyexpr is an ordinary Push with a wildcard KE; zenohd
    // registers it as a wildcard update + logs a `WildcardPut` event). No concrete
    // key is seeded, so the ONLY replicated event is the wildcard-keyed one.
    let _seed = spawn_seeding_zpub(WC_KEYEXPR, WC_SEED_VALUE, port);
    drop(port_res);

    // ── Dial zenohd in-process and bring the wz session up.
    let mut opened = connect_to_zenohd(port).await;
    let timeouts = SessionTimeouts::spec_defaults();

    // ── The wz REPLICA store: a separate, empty StorageState with no capture
    //    subscriber, so it can only gain the wildcard update by pulling it off
    //    zenohd's aligner.
    let replica: Arc<StdMutex<StorageState<MemoryStorage>>> =
        Arc::new(StdMutex::new(StorageState::new(MemoryStorage::new())));

    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(opened.actions.clone(), observer, Arc::new(opened.clock));

    let _digest_aligner = spawn_digest_aligner(&session, replica.clone(), config.clone())
        .expect("wz wires its digest -> aligner pull");

    let session_drive = session.clone();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        move |event| session_drive.dispatch_iteration_event(event),
    );

    let scenario = {
        let replica = replica.clone();
        async move {
            // Poll until the wz replica registers the pulled wildcard EVENT: its
            // wildcard_puts registry gains an entry. Monotonic; generous budget
            // over zenohd's 1s digest interval.
            for _ in 0..400 {
                {
                    let guard = replica.lock().unwrap();
                    if guard.wildcard_registry_lens().0 >= 1 {
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!(
                "wz replica never registered a wildcard update (wildcard_puts stayed \
                 empty) within ~20s"
            );
        }
    };

    tokio::select! {
        _ = drive => panic!("wz drive loop ended unexpectedly (zenohd link lost?)"),
        _ = scenario => {}
    }

    // ── Converged: the wz replica registered zenohd's wildcard-update EVENT in
    //    its own wildcard_puts registry, pulled over the real zenoh replication
    //    aligner and decoded as `Action::WildcardPut` (not collapsed to a plain
    //    concrete Put). This is the align-path registration the concrete-value
    //    convergence does not exercise.
    let (puts, deletes) = replica.lock().unwrap().wildcard_registry_lens();
    assert!(
        puts >= 1,
        "wz replica registered zenohd's WildcardPut event via cross-impl alignment; \
         wildcard_puts len = {puts} (deletes = {deletes})"
    );
}

/// Run a ONE-SHOT foreign pico `z_get` against zenohd for `key` and return its
/// captured stdout. zenohd answers from its storage queryable (the
/// storage-manager declares a COMPLETE queryable on the storage keyexpr), so
/// once zenohd has converged (pulled wz's entry over the aligner) the reply line
/// `>> Received ... ('<key>': '<value>')` carries wz's value. `z_get` is a
/// one-shot client, so the caller RE-PROBES until the value appears
/// (poll-on-condition, [[feedback-no-flaky-ever]]) rather than relying on a
/// single query winning the convergence race. A foreign pico client is used (not
/// the wz session) so the read-back is an independent witness of zenohd's store,
/// decoupled from wz's own aligner/digest machinery.
fn zget_once(key: &str, port: u16) -> String {
    let z_get = zenoh_pico_cli_binary("z_get");
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let out = tempfile::tempfile().expect("tempfile for z_get stdout");
    let out_writer = out.try_clone().expect("dup z_get stdout handle");
    let mut out_reader = out;
    let mut child = ChildGuard::wrap(
        "z_get probe (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_get)
            .args(["-k", key, "-e", &endpoint, "-m", "client"])
            .stderr(Stdio::from(
                out_writer.try_clone().expect("dup stderr handle"),
            ))
            .stdout(Stdio::from(out_writer))
            .spawn()
            .expect("spawn z_get via stdbuf"),
    );
    // z_get opens, queries once, prints replies, then idles; give it a bounded
    // window to receive a reply, then reap it (the next probe re-queries).
    let deadline = Instant::now() + Duration::from_millis(1500);
    let mut captured;
    loop {
        captured = read_captured(&mut out_reader);
        if captured.contains(">> Received") || Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.child_mut().kill();
    let _ = child.child_mut().wait();
    captured
}

/// The MIRROR of [`wz_replica_converges_to_zenohd_storage_manager`] — the ANSWER
/// direction: an EMPTY zenohd storage replica converges to an in-process wz
/// replica that HOLDS an entry zenohd lacks, exercising wz's ANSWER side
/// (`AlignerService`) over the wire against the REAL zenoh aligner ASK — the
/// cross-impl direction A11 proved only wz<->wz.
///
/// ## Convergence path (initial alignment)
///
/// An empty zenohd replica bootstraps via INITIAL ALIGNMENT
/// (`replication/service.rs:71-80` awaits `initial_alignment()` when its log is
/// empty, BEFORE the steady-state digest pub/sub starts). zenohd GETs
/// `@zid/*/<fp>/aligner` (a WILDCARD selector) with `AlignmentQuery::Discovery`
/// (core.rs:73-112); wz's aligner queryable, declared on the concrete
/// `@zid/<wz-zid>/<fp>/aligner`, answers `Discovery(wz-zid)`; zenohd then GETs
/// wz's concrete aligner with `AlignmentQuery::All` and lands every streamed
/// `Retrieval`. The steady-state digest path (wz's `DigestPublisher` → zenohd's
/// `@-digest/*` subscriber → a CONCRETE `Diff` query) is the fallback once
/// initial alignment's one-shot GET times out; the `z_get` poll budget covers
/// both, which is why this e2e stays robust if the Discovery race is ever lost.
///
/// This e2e SURFACED the wz fidelity fix in `Queryable::matches`: the
/// initial-alignment Discovery is a WILDCARD query selector, and wz previously
/// matched the inbound query as a concrete literal (so `@zid/*/..` never reached
/// the concrete `@zid/<wz-zid>/..` queryable; query routing is keyexpr
/// INTERSECTION). The fix makes wz answer it on the FAST path. This e2e is NOT
/// the fix's strict regression guard, though: zenohd's concrete-`Diff` fallback
/// issues a CONCRETE aligner query that reaches wz's queryable WITHOUT the fix,
/// so it would also converge here — the strict guard is the kernel unit test
/// `concrete_queryable_answers_wildcard_query_selector` (which fails pre-fix).
/// This test's value is the cross-impl integration: a REAL zenohd aligning FROM
/// wz's `AlignerService`.
///
/// No wz-side seeding race: wz holds the entry in its own `StorageState` for the
/// whole test (not a one-shot Put) and the aligner queryable stays declared for
/// the session lifetime. Convergence is witnessed by an INDEPENDENT foreign pico
/// `z_get` against zenohd's store.
// wz-proves: storage-aligner wz->zenohd
// wz-proves: declare-queryable wz->zenohd
// wz-proves: query-queryable wz->zenohd
// wz-proves: query-reply wz->zenohd
// wz-proves: codec-response wz->zenohd
// wz-proves: codec-request zenohd->wz
// wz-proves: codec-declare wz->zenohd
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binary-dep e2e (zenohd storage-manager replication); needs target/zenohd/{zenohd,libzenoh_plugin_storage_manager.so}; run via Layer Z / --ignored"]
async fn zenohd_converges_to_wz_replica() {
    // Same replication config as the ASK test — pin the cross-impl fingerprint
    // parity before any I/O (wz and zenohd only meet on @-digest/<zid>/<fp> and
    // @zid/<zid>/<fp>/aligner if their config fingerprints are EQUAL).
    let config = ReplicationConfig::new(STORAGE_KEYEXPR, None, 1000, 5, 6, 30, 250);
    assert_eq!(
        config.fingerprint().value(),
        ZENOHD_CONFIG_FINGERPRINT,
        "wz's replication config fingerprint must equal the real zenohd's, or the \
         two never meet on @-digest/<zid>/<fp>"
    );

    let port_res = PortReservation::pick();
    let port = port_res.port();
    // zenohd's storage starts EMPTY (no seed) — it must gain the entry ONLY by
    // aligning FROM wz.
    let _zenohd = spawn_zenohd_storage_replica(port);
    drop(port_res);

    // ── Dial zenohd in-process. wz's storage zid is its session zid, read from
    //    the SAME SSOT `connect_to_zenohd` opens the session with (deterministic,
    //    so no drift) — zenohd learns this zid (from wz's `Discovery` reply, or
    //    its digest keyexpr) and GETs the concrete `@zid/<that-zid>/<fp>/aligner`
    //    with `All`, which is exactly where wz declares its aligner queryable.
    let wz_zid = zenohd_interop_session_init_params().zid;
    let mut opened = connect_to_zenohd(port).await;
    let timeouts = SessionTimeouts::spec_defaults();

    // ── The wz SOURCE replica: a StorageState holding the entry zenohd lacks,
    //    stamped with a wall-clock NTP64 timestamp so it lands in a live era (a
    //    zenoh storage requires a timestamp).
    let replica: Arc<StdMutex<StorageState<MemoryStorage>>> =
        Arc::new(StdMutex::new(StorageState::new(MemoryStorage::new())));
    replica
        .lock()
        .unwrap()
        .process_put(
            Some(WZ_DATA_KEY),
            WZ_SEED_VALUE.as_bytes().to_vec(),
            None,
            TimestampHint {
                time: wall_clock_ntp64(),
                zid: wz_zid.clone(),
            },
        )
        .expect("the in-memory backend commits");

    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(opened.actions.clone(), observer, Arc::new(opened.clock));

    // ── wz's ANSWER side: declare the aligner answer queryable
    //    (@zid/<wz-zid>/<fp>/aligner, Remote) + spawn the periodic digest
    //    publisher (@-digest/<wz-zid>/<fp>). Both reach zenohd through its
    //    routing tables; the handles are held for the whole test (RAII).
    let _aligner =
        AlignerService::declare(&session, replica.clone(), config.clone(), wz_zid.clone())
            .expect("wz declares its aligner answer queryable");
    let _digest_pub =
        DigestPublisher::spawn(&session, replica.clone(), config.clone(), wz_zid.clone());

    let session_drive = session.clone();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        move |event| session_drive.dispatch_iteration_event(event),
    );

    // ── Witness convergence: poll a foreign pico z_get against zenohd until it
    //    returns wz's value. z_get is one-shot + blocking, so each probe runs on
    //    a blocking thread, leaving the wz drive loop free to answer zenohd's
    //    inbound alignment queries. Generous budget over zenohd's 1s digest
    //    interval; converges once zenohd has pulled + stored wz's entry.
    let scenario = async move {
        for _ in 0..30 {
            let captured = tokio::task::spawn_blocking(move || zget_once(WZ_DATA_KEY, port))
                .await
                .expect("z_get probe thread");
            if captured.contains(WZ_SEED_VALUE) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        panic!("zenohd did not converge (foreign z_get never returned wz's value) within budget");
    };

    tokio::select! {
        _ = drive => panic!("wz drive loop ended unexpectedly (zenohd link lost?)"),
        _ = scenario => {}
    }

    // ── Converged: zenohd pulled wz's entry over the real zenoh replication
    //    aligner. wz still holds its source entry (sanity — the source side is
    //    unchanged by answering an alignment query).
    let guard = replica.lock().unwrap();
    let stored = guard
        .get(Some(WZ_DATA_KEY))
        .expect("wz still holds its source entry after answering zenohd's alignment");
    assert_eq!(
        stored.payload,
        WZ_SEED_VALUE.as_bytes(),
        "wz's source entry is unchanged by serving the cross-impl alignment"
    );
}
