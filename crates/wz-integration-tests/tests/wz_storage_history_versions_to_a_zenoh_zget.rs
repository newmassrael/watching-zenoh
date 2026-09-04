// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2350 §5.11 storage — the FOREIGN witness that `storage-history` replies EVERY
//! version, seen by a real zenoh (Rust) `z_get` that asks for NO consolidation.
//!
//! ## Why this file exists, and what it replaces
//!
//! `wz_storage_history_serves_pico_zget.rs` is the sibling pico leg. Until R2350 it
//! carried the `history()` discriminator, through an observable that turned out to
//! be the atom's own defect: an `All` delete cleared the key's version list, so a
//! put replayed underneath the delete became the key's live value and pico
//! retrieved it. R2350 made a delete a versioned tombstone, that value is no longer
//! served, and with it the pico leg lost the ability to tell the two capabilities
//! apart — structurally, not by an unlucky choice of sequence:
//!
//! - a LATEST-consolidating querier keeps only the newest reply per key;
//! - the newer-wins gate rejects only writes OLDER than the latest accepted one,
//!   which are by construction never the newest;
//! - so `All` and `Latest` agree on the newest live value for every single-key
//!   sequence, and only the reply COUNT differs.
//!
//! pico's `z_get` cannot see a count: it hardcodes empty selector parameters
//! (`vendor/zenoh-pico/examples/unix/c11/z_get.c` @ `z_get(z_loan(s), z_loan(ke), ""`)
//! so its `AUTO` consolidation resolves to `LATEST`, and it drops every
//! non-newest same-key reply inside the querier before the callback. Its
//! getopt string
//! (`vendor/zenoh-pico/examples/unix/c11/z_get.c` @ `getopt(argc, argv, "k:v:e:m:l:")`)
//! has no consolidation flag, so there is no way to ask it for anything else.
//!
//! ## The observable this file uses instead
//!
//! zenoh's own `z_get` takes a full `Selector` on `-s`, and zenoh resolves `AUTO`
//! to `ConsolidationMode::None` when the selector carries a `_time` parameter
//! (`zenoh/src/api/session.rs` @ `ConsolidationMode::Auto if parameters.time_range().is_some()`,
//! with the key at `zenoh/src/api/selector.rs` @ `const TIME_RANGE_KEY`).
//! Under `None` every reply reaches the
//! application callback, which prints one [`GET_RECEIVED`] line each — so the
//! version count becomes foreign-observable, and it is the capability's own
//! definition ("History::All saves all the values including historical values",
//! `plugins/zenoh-backend-traits/src/lib.rs` @ `History::All saves all the values`)
//! rather than a proxy for it.
//!
//! ## Three legs, and why the third is not optional
//!
//! Every leg seeds the SAME three ascending versions of ONE key and differs in one
//! variable:
//!
//! | leg | backend          | `_time` param | expected replies |
//! |-----|------------------|---------------|------------------|
//! | 1   | `HistoryStorage` | yes           | 3 (every version)|
//! | 2   | `MemoryStorage`  | yes           | 1 (newest only)  |
//! | 3   | `HistoryStorage` | no            | 1 (consolidated) |
//!
//! Leg 2 varies `history()` alone and is what makes leg 1 a claim about the
//! capability. Leg 3 varies the CONSOLIDATION alone, on the same `All` storage, and
//! is what stops leg 1 being read as "wz sends three replies to everybody": it
//! shows the three are on the wire in both cases and that the querier's
//! consolidation is what collapses them. Without leg 3 a wz that duplicated replies
//! would look like a working `History::All`.
//!
//! ## Non-flaky by construction ([[feedback-no-flaky-ever]])
//!
//! Seeding is synchronous and completes before the drive future is first polled;
//! `z_get` is a one-shot burst-and-exit querier whose query is buffered in the
//! socket and processed after the queryable is already declared. Each leg keys its
//! readiness on the CHILD PROCESS EXITING rather than on a line appearing, so the
//! capture is complete by construction — and the count assertions are read from
//! that final capture, never from a partially-written one.
//!
//! Requires the zenoh core example binaries (`scripts/build-zenohd.sh` ->
//! `target/zenohd/zenoh_z_get`) and a `wz-runtime-tokio` dev-dep build carrying
//! `storage-history`. `#[ignore]` binary-dep e2e; run-ci Layer E runs it via the
//! `--ignored` sweep — it needs no zenohd, being a wz + zenoh-client leg.

use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;

use wz_integration_tests::common::{read_captured, zenoh_core_example_binary, ChildGuard};
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
use wz_session_core::storage_backend::{MemoryStorage, StorageBackend, StorageInsertionResult};
use wz_session_core::storage_config::StorageConfig;
use wz_session_core::storage_history::HistoryStorage;

const ITER_CAP: usize = 4096;
/// The keyexpr the wz storage captures + answers on.
const STORAGE_KEYEXPR: &str = "demo/**";
/// The ONE key every version is stored under, and the key `z_get` queries.
const QUERY_KEY: &str = "demo/hist";
/// The `_time` selector parameter that flips zenoh's `AUTO` consolidation to
/// `None` (`zenoh/src/api/session.rs` @ `ConsolidationMode::Auto if parameters.time_range().is_some()`).
/// The RANGE is deliberately wide: the
/// branch turns on the parameter being PRESENT, not on what it selects, and wz
/// does not filter replies by it — narrowing it would add a second variable.
const TIME_PARAM: &str = "?_time=[now(-1h)..]";
/// `z_get`'s per-reply print
/// (`examples/examples/z_get.rs` @ `">> Received ('{}': '{}')"`). Counting these lines
/// IS the measurement.
const GET_RECEIVED: &str = ">> Received (";
/// The three versions, seeded in ascending timestamp order so that the `Latest`
/// leg accepts all three too (each is newer than the last) and keeps exactly one.
/// Ascending matters: a descending seed would make leg 2 reject writes and the two
/// legs would then differ in what they STORED, not in what they REPLY.
const V1: (u64, &str) = (10, "history-version-alpha");
const V2: (u64, &str) = (20, "history-version-bravo");
const V3: (u64, &str) = (30, "history-version-charlie");
/// `z_get -o`, the query deadline it hands the router, in milliseconds.
const GET_TIMEOUT_MS: &str = "8000";

/// What one leg observed: the storage's own version count, and the querier's
/// complete captured stdout.
struct LegOutcome {
    /// How many versions the wz storage actually holds for [`QUERY_KEY`] — the
    /// in-process number the foreign count is compared against.
    stored_versions: usize,
    zenoh_stdout: String,
}

impl LegOutcome {
    /// How many replies the foreign querier's application callback saw.
    fn replies(&self) -> usize {
        self.zenoh_stdout.matches(GET_RECEIVED).count()
    }
}

/// Seed three ascending versions of one key into a wz storage backed by `backend`,
/// then let a real zenoh `z_get` query it, and return both numbers.
///
/// Generic over the backend so legs 1 and 2 share ONE body; `time_param` is the
/// only other variable, which is what isolates leg 3.
async fn zenoh_zget_over_three_versions<B>(backend: B, time_param: bool) -> LegOutcome
where
    B: StorageBackend + Send + 'static,
{
    let z_get = zenoh_core_example_binary("z_get");
    let selector = if time_param {
        format!("{QUERY_KEY}{TIME_PARAM}")
    } else {
        QUERY_KEY.to_string()
    };

    // wz acceptor binds first so the zenoh client's dial lands in the listen backlog.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz acceptor");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("tcp/{addr}");

    // Accept + handshake WITH RETRY, the same shape as the sibling pico witness: a
    // one-shot client's open is transient, and a retry is cheaper than a flake.
    const OPEN_ATTEMPTS: usize = 6;
    let established = {
        let mut acc = None;
        for attempt in 1..=OPEN_ATTEMPTS {
            let stdout = tempfile::tempfile().expect("tempfile for z_get stdout");
            let stdout_writer = stdout.try_clone().expect("dup z_get stdout");
            let stdout_reader = stdout;
            let mut child = ChildGuard::wrap(
                "z_get client (zenoh)",
                Command::new("stdbuf")
                    .args(["-oL", "-eL"])
                    .arg(&z_get)
                    .args([
                        "-s",
                        &selector,
                        "-o",
                        GET_TIMEOUT_MS,
                        "-m",
                        "client",
                        "-e",
                        &endpoint,
                        "--no-multicast-scouting",
                    ])
                    .stdout(Stdio::from(
                        stdout_writer.try_clone().expect("dup stdout handle"),
                    ))
                    .stderr(Stdio::from(stdout_writer))
                    .spawn()
                    .expect("spawn z_get via stdbuf"),
            );
            let accepted = tokio::time::timeout(Duration::from_secs(8), listener.accept()).await;
            let stream = match accepted {
                Ok(Ok((stream, _peer))) => stream,
                _ => {
                    let _ = child.child_mut().kill();
                    let _ = child.child_mut().wait();
                    eprintln!(
                        "attempt {attempt}/{OPEN_ATTEMPTS}: zenoh z_get did not connect \
                         within 8s; retrying"
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
                    acc = Some((opened, child, stdout_reader));
                    break;
                }
                Err(e) => {
                    let _ = child.child_mut().kill();
                    let _ = child.child_mut().wait();
                    eprintln!(
                        "attempt {attempt}/{OPEN_ATTEMPTS}: wz<->zenoh handshake failed \
                         ({e:?}); retrying"
                    );
                    continue;
                }
            }
        }
        acc.expect("wz acceptor reached Established against a zenoh z_get client")
    };
    let (mut opened, mut child, mut stdout_reader) = established;

    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(opened.actions.clone(), observer, Arc::new(opened.clock));
    let storage = StorageService::declare_with_backend(
        &session,
        &StorageConfig::new("demo", STORAGE_KEYEXPR, "hist"),
        vec![0x01],
        backend,
    )
    .expect("declare the wz storage on demo/**");

    // Seed the three versions, ascending. Every seed is asserted to have landed:
    // an `Outdated` here would make the reply count a statement about the seed
    // rather than about the capability.
    for (time, value) in [V1, V2, V3] {
        let verdict = storage
            .shared_state()
            .lock()
            .expect("seed lock")
            .process_put(
                Some(QUERY_KEY),
                value.as_bytes().to_vec(),
                None,
                TimestampHint {
                    time,
                    zid: vec![0x02],
                },
            )
            .expect("the in-memory backend commits");
        assert!(
            !matches!(verdict, StorageInsertionResult::Outdated),
            "the t={time} seed was rejected ({verdict:?}); the seeds are ascending, so \
             NEITHER capability may refuse one and the reply count below would be \
             measuring a broken fixture"
        );
    }
    let stored_versions = storage
        .shared_state()
        .lock()
        .expect("count lock")
        .matching_versions(QUERY_KEY)
        .first()
        .map_or(0, |(_key, versions)| versions.len());

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

    // Readiness is the CHILD EXITING, not a line appearing: `z_get` is one-shot, so
    // its exit is the happens-after edge that makes the capture complete. A count
    // read while it is still printing would be a lower bound, and every leg here
    // asserts an exact number.
    let scenario = async {
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            match child.child_mut().try_wait().expect("try_wait on z_get") {
                Some(_) => return Ok(()),
                None if Instant::now() >= deadline => {
                    return Err(format!(
                        "zenoh z_get did not exit within 25s, so its reply set is not \
                         readable.\n--- captured so far ---\n{}",
                        read_captured(&mut stdout_reader)
                    ));
                }
                None => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    };

    // The drive finishing is NOT a failure: the querier is one-shot, so the session
    // ending is the ordinary consequence of it exiting. Neither branch decides the
    // outcome; the final capture does.
    let scenario_result = tokio::select! {
        _ = drive => None,
        r = scenario => Some(r),
    };

    let zenoh_stdout = read_captured(&mut stdout_reader);
    let _ = child.child_mut().kill();
    let _ = child.child_mut().wait();

    if let Some(Err(msg)) = scenario_result {
        // The child may still have printed a complete reply set before stalling on
        // exit; judge that capture rather than the stall.
        assert!(
            zenoh_stdout.contains(GET_RECEIVED) || zenoh_stdout.contains("Sending Query"),
            "wz->zenoh storage history interop FAILED.\n{msg}"
        );
    }
    LegOutcome {
        stored_versions,
        zenoh_stdout,
    }
}

/// Leg 1 — THE HEADLINE: a `History::All` storage replies EVERY version, and a real
/// zenoh `z_get` that asked for no consolidation receives all three.
///
/// This is the capability's own definition observed across an implementation
/// boundary: three replies, built and encoded by wz, decoded and surfaced by a
/// foreign client.
// wz-proves: storage-history wz->zenoh
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh core example z_get); Layer E runs via --ignored"]
async fn wz_history_storage_replies_every_version_to_a_none_consolidating_zenoh_zget() {
    let leg = zenoh_zget_over_three_versions(HistoryStorage::new(), true).await;

    assert_eq!(
        leg.stored_versions, 3,
        "the fixture must hold three versions before the count below means anything"
    );
    assert_eq!(
        leg.replies(),
        3,
        "a History::All storage must reply every version, and a `_time` selector \
         resolves zenoh's AUTO consolidation to None, so all three \
         reach the callback. Got {} — if it is 1, either the consolidation did not \
         flip (leg 3 is the control for that) or wz replied only the newest.\n\
         --- captured stdout ---\n{}",
        leg.replies(),
        leg.zenoh_stdout
    );
    for (_, value) in [V1, V2, V3] {
        assert!(
            leg.zenoh_stdout.contains(value),
            "version {value:?} never reached the foreign querier, so the three \
             replies were not the three versions.\n--- captured stdout ---\n{}",
            leg.zenoh_stdout
        );
    }
}

/// Leg 2 — the CAPABILITY twin: the IDENTICAL sequence and the IDENTICAL selector
/// on a `History::Latest` `MemoryStorage` yields ONE reply, because that backend
/// kept one value.
///
/// Only `history()` differs from leg 1, which is what makes leg 1 a statement about
/// the capability rather than about the harness or the selector.
// wz-proves: storage-history wz->zenoh
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh core example z_get); Layer E runs via --ignored"]
async fn wz_latest_storage_replies_one_version_to_the_same_zenoh_zget() {
    let leg = zenoh_zget_over_three_versions(MemoryStorage::new(), true).await;

    assert_eq!(
        leg.stored_versions, 1,
        "a History::Latest storage keeps exactly one value per key"
    );
    assert_eq!(
        leg.replies(),
        1,
        "the same no-consolidation query against a Latest storage must yield ONE \
         reply. More than one here would mean the count in leg 1 does not track \
         `history()`.\n--- captured stdout ---\n{}",
        leg.zenoh_stdout
    );
    assert!(
        leg.zenoh_stdout.contains(V3.1),
        "the single reply must be the NEWEST value {:?}.\n--- captured stdout ---\n{}",
        V3.1,
        leg.zenoh_stdout
    );
}

/// Leg 3 — the CONSOLIDATION control: the SAME `History::All` storage, the same
/// three versions, queried WITHOUT the `_time` parameter, yields ONE reply.
///
/// This is the leg that stops leg 1 from being read as "wz sends three replies to
/// every querier". wz sends three either way; here zenoh's `AUTO` stays `LATEST`
/// (the `ConsolidationMode::Auto => ConsolidationMode::Latest` arm of the same
/// match) and the querier collapses them before the callback — the
/// same thing pico's `z_get` does unconditionally, which is precisely why the pico
/// sibling can no longer see this capability.
// wz-proves: storage-history wz->zenoh
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh core example z_get); Layer E runs via --ignored"]
async fn a_consolidating_zenoh_zget_collapses_the_same_three_versions_to_one() {
    let leg = zenoh_zget_over_three_versions(HistoryStorage::new(), false).await;

    assert_eq!(
        leg.stored_versions, 3,
        "the storage side is identical to leg 1; only the selector changed"
    );
    assert_eq!(
        leg.replies(),
        1,
        "without `_time` zenoh's AUTO consolidation stays LATEST, so the three \
         replies wz sent must collapse to one at the querier. Three here would mean \
         leg 1's count came from the consolidation being off by default, not from \
         the selector.\n--- captured stdout ---\n{}",
        leg.zenoh_stdout
    );
    assert!(
        leg.zenoh_stdout.contains(V3.1),
        "the surviving reply must be the newest version {:?}.\n\
         --- captured stdout ---\n{}",
        V3.1,
        leg.zenoh_stdout
    );
}
