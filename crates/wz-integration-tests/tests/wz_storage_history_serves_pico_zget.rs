// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y475 (pico cross-impl leg) §5.11 storage — the FOREIGN witness for
//! `storage-history`, the atom Layer A4 carried as UNPROVEN with no cross-impl
//! evidence of any kind.
//!
//! `storage-history` is wz's `History::All` capability. zenoh's own `History` enum
//! defines it — "History::Latest saves only the latest value per key / History::All
//! saves all the values including historical values"
//! (`plugins/zenoh-backend-traits/src/lib.rs:161-165`) — and the mechanism that
//! implements it is a GATE SKIP: the newer-wins guard runs only for
//! `History::Latest` (`plugins/zenoh-plugin-storage-manager/src/storages_mgt/service.rs:319`,
//! mirrored by `StorageState::latest_mode` / `process_put`).
//!
//! ## The observable, and why it is NOT a reply count
//!
//! The obvious witness — seed N versions of one key, count N replies at a foreign
//! querier — was built first and MEASURED to be unobservable, which is worth
//! recording because it looks correct on paper. pico's `z_get` sends EMPTY selector
//! parameters (`examples/unix/c11/z_get.c`: `z_get(..., "", ...)`), so its
//! `Z_CONSOLIDATION_MODE_AUTO` resolves to `LATEST` rather than `NONE` — that branch
//! turns on the presence of a `_time` parameter (`src/net/primitives.c:567-571`) —
//! and pico then drops every same-key reply that is not the newest, in the QUERIER,
//! before the application callback (`src/session/query.c:133-150`). Three versions of
//! one key therefore print as ONE line no matter what wz sent. (The `z_querier` CLI
//! does take a `?params` selector, but in this harness it received no replies at all
//! — a separate question, not pursued here.)
//!
//! Both legs run the IDENTICAL mutation sequence:
//!
//!   1. put `charlie` at t=3
//!   2. DELETE at t=4
//!   3. replay a STRICTLY OLDER put, `bravo` at t=2
//!
//! ## R2350 CHANGED WHAT THIS FILE WITNESSES, and the change is the point
//!
//! Until R2350 this file asserted that leg 1 (`History::All`) served `bravo` to
//! pico. That was true, and it was the BUG the `storage-history` atom carried as
//! its named residual: an `All` delete cleared the key's whole version list, so a
//! put replayed underneath it became the key's live value and a real foreign
//! querier was served a value that had been deleted. R2350 made a delete a
//! VERSIONED TOMBSTONE (`wz_session_core::storage_history`), so `bravo` is stored
//! as history and is NOT served. The assertion inverted because the behaviour it
//! described was wrong — the witness had encoded the defect as the capability.
//!
//! What the two legs still prove, foreign-side, is the TOMBSTONE: on either
//! capability a real zenoh-pico client, over a real session, is served NO value
//! for a key a delete removed — including the older replay that the gate-free
//! `All` path accepts into storage. That is the residual's own correctness
//! property, witnessed across an implementation boundary.
//!
//! ## `history()` is no longer observable HERE, and that is a measured claim
//!
//! The two legs' in-process verdicts still differ (`Outdated` under `Latest`,
//! accepted under `All`) and are asserted, so the legs are not one test. Their
//! FOREIGN observation, though, is now identical — and not because this sequence
//! was chosen badly. At a LATEST-consolidating querier only the newest reply
//! survives, and the newer-wins gate rejects only writes OLDER than the latest
//! accepted one, which are by definition never the newest. So once deletes
//! tombstone correctly, no single-key sequence can make the gate skip visible to
//! such a querier: it was visible before R2350 only because the delete had erased
//! everything above the replay.
//!
//! Reaching it needs a querier that asks for NONE consolidation, which pico's
//! `z_get` cannot: it hardcodes empty selector parameters
//! (`vendor/zenoh-pico/examples/unix/c11/z_get.c` @ `z_get(z_loan(s), z_loan(ke), ""`)
//! and its getopt string
//! (`vendor/zenoh-pico/examples/unix/c11/z_get.c` @ `getopt(argc, argv, "k:v:e:m:l:")`)
//! has no consolidation flag. `wz_storage_history_versions_
//! to_a_zenoh_zget.rs` is the leg that does reach it, through zenoh's own `z_get`
//! and a `_time` selector parameter.
//!
//! ## Non-flaky by construction ([[feedback-no-flaky-ever]])
//!
//! Seeding is synchronous and completes before the drive future is first polled;
//! pico's `z_get` is a one-shot burst-and-exit querier whose query is buffered in the
//! socket and processed by `drive_session_until_terminal` after the queryable is
//! already declared. Both legs key their readiness on pico's own TERMINATOR line
//! (`Received query final notification`), which it prints whether or not any value
//! came back — so the absent-value leg has a positive edge to wait for rather than a
//! sleep, and neither leg can pass by reading a partially-written capture.
//!
//! Requires the zenoh-pico CLI (`scripts/build-zenoh-pico-cli.sh` ->
//! `target/zenoh-pico-cli/z_get`) and a `wz-runtime-tokio` dev-dep build carrying
//! `storage-history` (pinned in this crate's Cargo.toml). `#[ignore]` binary-dep e2e;
//! run-ci Layer E runs it via the `--ignored` sweep — neither fn name matches any of
//! that lane's `--skip` substrings (`wz_storage_host` is a different token), and it
//! needs no zenohd, being a wz+pico in-process leg.

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
use wz_session_core::storage_backend::{MemoryStorage, StorageBackend, StorageInsertionResult};
use wz_session_core::storage_config::StorageConfig;
use wz_session_core::storage_history::HistoryStorage;

const ITER_CAP: usize = 4096;
/// The keyexpr the wz storage captures + answers on.
const STORAGE_KEYEXPR: &str = "demo/**";
/// The ONE key every mutation targets, and the key pico `z_get`s.
const QUERY_KEY: &str = "demo/hist";
/// The value stored at t=3 and then deleted at t=4. Must be ABSENT from both legs'
/// replies — the delete removed it on either capability.
const V_DELETED: &str = "history-version-charlie";
/// The STRICTLY OLDER value replayed at t=2 after the delete. Its IN-PROCESS fate
/// is the capability — accepted under `History::All`, rejected `Outdated` under
/// `History::Latest` — but on NEITHER capability may it reach the querier: under
/// `All` the t=4 tombstone shadows it (R2350), under `Latest` the gate refused it.
const V_OLDER: &str = "history-version-bravo";
/// pico `z_get`'s terminator, printed whether or not any reply arrived
/// (`examples/unix/c11/z_get.c`). The readiness edge for both legs.
const PICO_QUERY_FINAL: &str = "Received query final notification";

/// What one leg observed: the storage's own verdict on the replayed older put, and
/// pico's complete captured stdout.
struct LegOutcome {
    replayed_older: StorageInsertionResult,
    pico_stdout: String,
}

/// Run the mutation sequence against a storage backed by `backend`, then let a real
/// pico `z_get -k demo/hist` query it, and return both the in-process verdict and
/// pico's stdout.
///
/// Generic over the backend so the two legs share ONE body: the only difference
/// between them is the value passed here, which is what isolates `history()`.
async fn pico_zget_after_delete_then_older_put<B>(backend: B) -> LegOutcome
where
    B: StorageBackend + Send + 'static,
{
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

    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(opened.actions.clone(), observer, Arc::new(opened.clock));
    let storage = StorageService::declare_with_backend(
        &session,
        &StorageConfig::new("demo", STORAGE_KEYEXPR, "hist"),
        vec![0x01],
        backend,
    )
    .expect("declare the wz storage on demo/**");

    // ── The sequence that separates the two capabilities, identical on both legs.
    //
    // Only `Outdated` is a rejection; `Inserted` / `Replaced` both mean the value
    // landed. The two structural steps are asserted so a harness slip can never wear
    // the costume of a capability verdict — that already happened once while this
    // file was being written, when an over-strict `Inserted` assertion made both legs
    // fail for a reason that had nothing to do with storage.
    let seed_put = |time: u64, value: &str| {
        storage
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
            // The seam is fallible since R311y831; this fixture's backend is
            // in-memory, so an Err here is a harness fault, not a verdict.
            .expect("the in-memory backend commits")
    };

    let put_deleted = seed_put(3, V_DELETED);
    assert!(
        !matches!(put_deleted, StorageInsertionResult::Outdated),
        "the t=3 seed was rejected ({put_deleted:?}); the storage never held it, so \
         neither the delete nor the replay below means anything"
    );
    let deleted = storage
        .shared_state()
        .lock()
        .expect("seed lock")
        .process_delete(
            Some(QUERY_KEY),
            TimestampHint {
                time: 4,
                zid: vec![0x02],
            },
        )
        .expect("the in-memory backend commits");
    assert!(
        matches!(deleted, StorageInsertionResult::Deleted),
        "the t=4 delete did not land ({deleted:?}); without it there is no tombstone \
         for the replay to run against — in the gate record under Latest, in the \
         version timeline under All (R2350)"
    );
    // The discriminating mutation. Its IN-PROCESS verdict is the capability; both
    // legs must keep it away from the querier.
    let replayed_older = seed_put(2, V_OLDER);

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

    // Wait for pico's TERMINATOR, not for a value: it is printed on both legs, so the
    // absent-value leg has a real happens-after edge instead of a sleep, and whatever
    // replies exist have already been printed by the time it appears.
    let scenario = async {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let captured = read_captured(&mut z_get_stdout_reader);
            if captured.contains(PICO_QUERY_FINAL) {
                return Ok(captured);
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico z_get never printed its query terminator {PICO_QUERY_FINAL:?} \
                     within 15s, so neither leg's reply set is readable.\n\
                     --- captured stdout ---\n{captured}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };

    // The drive finishing is NOT a failure: pico is a one-shot querier, so the
    // session ending is the ORDINARY consequence of it exiting -- and on a leg whose
    // answer is empty (the Latest twin, whose key is deleted) pico exits almost
    // immediately, which made an earlier version of this harness race its own poll
    // loop and fail with the terminator already in the capture. So neither branch
    // decides the outcome; pico's TERMINATOR in the final capture does.
    let scenario_result = tokio::select! {
        _ = drive => None,
        r = scenario => Some(r),
    };

    // Read the capture AFTER the select!, once the borrow is released. It persists
    // past pico's exit, so it is complete by construction here.
    let final_capture = read_captured(&mut z_get_stdout_reader);
    let _ = z_get_child.child_mut().kill();
    let _ = z_get_child.child_mut().wait();

    let pico_stdout = match scenario_result {
        Some(Ok(captured)) => captured,
        // Either the poll loop timed out, or the session ended before it observed
        // the terminator. Both are judged the same way, against the final capture.
        Some(Err(msg)) => {
            assert!(
                final_capture.contains(PICO_QUERY_FINAL),
                "wz->pico storage history interop FAILED.\n{msg}"
            );
            final_capture
        }
        None => {
            assert!(
                final_capture.contains(PICO_QUERY_FINAL),
                "the wz session ended before pico completed its query, and pico never \
                 printed {PICO_QUERY_FINAL:?} -- so its reply set is not readable and \
                 an absence assertion below would be vacuous.\n\
                 --- captured pico z_get stdout ---\n{final_capture}"
            );
            final_capture
        }
    };
    LegOutcome {
        replayed_older,
        pico_stdout,
    }
}

/// Leg 1 — the PROOF (R2350): on a `History::All` storage the newer-wins gate is
/// SKIPPED, so a put replayed AFTER a newer delete is ACCEPTED INTO STORAGE — and
/// a real pico `z_get` is still served nothing, because the t=4 tombstone shadows
/// it.
///
/// Both halves are needed. The acceptance is what makes this an `All` storage at
/// all; the absence is what makes the acceptance safe. Before R2350 the second
/// half was false: the delete had cleared the version list, so the replay was the
/// key's only version and pico was served a deleted value.
// wz-proves: storage-history wz->pico
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_get); Layer E runs via --ignored"]
async fn wz_history_storage_accepts_a_post_delete_older_put_but_serves_pico_nothing() {
    let leg = pico_zget_after_delete_then_older_put(HistoryStorage::new()).await;

    assert!(
        !matches!(leg.replayed_older, StorageInsertionResult::Outdated),
        "a History::All storage has NO newer-wins gate (zenoh gates it on \
         `history == History::Latest`), so the t=2 put \
         after the t=4 delete must be accepted into storage; got {:?}",
        leg.replayed_older
    );
    // The terminator first, so both absences below are completed observations
    // rather than "nothing yet".
    assert!(
        leg.pico_stdout.contains(PICO_QUERY_FINAL),
        "the terminator must be present for the absences below to be a completed \
         observation.\n--- captured stdout ---\n{}",
        leg.pico_stdout
    );
    assert!(
        !leg.pico_stdout.contains(V_OLDER),
        "pico z_get received the post-delete older value {V_OLDER:?}. It is stamped \
         BELOW the t=4 delete, so the R2350 tombstone must shadow it: storing it as \
         history is right, serving it is not. Its presence means the delete dropped \
         the timeline instead of tombstoning it \
         (wz_session_core::storage_history).\n--- captured stdout ---\n{}",
        leg.pico_stdout
    );
    assert!(
        !leg.pico_stdout.contains(V_DELETED),
        "pico z_get received the DELETED value {V_DELETED:?}. It sits below the same \
         t=4 tombstone, so nothing from before the delete may come back.\n\
         --- captured stdout ---\n{}",
        leg.pico_stdout
    );
}

/// Leg 2 — the TWIN: the IDENTICAL sequence on the `History::Latest` `MemoryStorage`
/// leaves the key GONE by the OTHER mechanism — the newer-wins gate — and the same
/// pico binary retrieves no value at all.
///
/// Since R2350 the two legs' FOREIGN observation agrees (see the module doc: at a
/// LATEST-consolidating querier it must). What this leg still separates is the
/// mechanism: it asserts the `Outdated` verdict leg 1 asserts the absence of, so a
/// build that skipped the gate unconditionally — `latest_mode` ignored — reds here
/// while leg 1 stays green. Without it, leg 1 alone would pass on a storage that
/// had no gate at all.
// wz-proves: storage-history wz->pico
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_get); Layer E runs via --ignored"]
async fn wz_latest_storage_rejects_the_same_older_put_and_serves_a_pico_zget_nothing() {
    let leg = pico_zget_after_delete_then_older_put(MemoryStorage::new()).await;

    assert!(
        matches!(leg.replayed_older, StorageInsertionResult::Outdated),
        "a History::Latest storage RUNS the newer-wins gate, and the t=4 delete left \
         a tombstone, so the t=2 put must be rejected as Outdated; got {:?}. If both \
         legs accept it then the verdict does not track `history()` and leg 1 proves \
         nothing.",
        leg.replayed_older
    );
    // The negative is bounded by pico's own terminator, which the harness already
    // waited for — so this is "pico finished and got nothing", not "nothing yet".
    assert!(
        leg.pico_stdout.contains(PICO_QUERY_FINAL),
        "the terminator must be present for the absence below to be a completed \
         observation.\n--- captured stdout ---\n{}",
        leg.pico_stdout
    );
    for (label, value) in [("older", V_OLDER), ("deleted", V_DELETED)] {
        assert!(
            !leg.pico_stdout.contains(value),
            "pico z_get received the {label} value {value:?} from a History::Latest \
             storage. After a t=4 delete the key is gone and a t=2 put cannot \
             resurrect it, so any value here means the newer-wins gate did not \
             run.\n--- captured stdout ---\n{}",
            leg.pico_stdout
        );
    }
}
