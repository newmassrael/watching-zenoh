// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2376 (open-debt item 15, `session-reconnect`) — the reopen PLAN, over a
//! real loopback TCP link.
//!
//! `session_reconnect_e2e.rs` proves the supervisor re-dials and replays. What
//! it cannot see is WHERE the address came from, because until this round there
//! was only ever one and it was resolved before the first open. pico resolves
//! per attempt: `_z_client_reopen_task_fn` re-enters `_z_open`, whose
//! no-locator branch scouts again and then walks the answer's locators "until
//! we successfully open one" (`vendor/zenoh-pico/src/net/session.c`).
//!
//! These two tests pin exactly the halves that distinguish the two designs, and
//! each is written so the PRE-ROUND behaviour fails it:
//!
//! * [`a_reopen_falls_over_to_the_next_candidate`] — a plan whose first
//!   candidate is dead and whose second is live. A supervisor that dials only
//!   `candidates[0]` (the retained-locator shape) never reaches the listener.
//! * [`a_reopen_asks_the_plan_again_on_every_attempt`] — a plan that answers
//!   with NOTHING twice before answering with the listener. A supervisor that
//!   resolved its address once cannot benefit from the third answer, and one
//!   that treated an empty answer as permanent gives up on the first.
//!
//! The `ReconnectTargets` double is deliberately a COUNTER plus a script rather
//! than a real scouting socket: the property under test is the supervisor's
//! contract with the plan, and a live multicast group would make the test
//! depend on the host's networking to prove something that has nothing to do
//! with it. `reconnect_scout.rs` owns the scouting implementation's own tests.

#![cfg(feature = "session-reconnect")]

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;

use wz_runtime_tokio::reconnect::{
    open_session_with_reconnect, ReconnectDriveOutcome, ReconnectLocator, ReconnectPolicy,
    ReconnectTargets,
};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, DialConfig, DialedLink, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;

/// A scripted [`ReconnectTargets`]: hands out one answer per call and counts
/// the calls.
///
/// The COUNT is the instrument. "The plan is consulted once per reopen attempt"
/// is the whole difference between re-entering `_z_open` and re-dialing a
/// remembered address, and it is invisible to any assertion about the session
/// itself — a supervisor that cached the first answer would reconnect exactly
/// as successfully in every scenario where the address never changes, which is
/// every scenario the pre-round tests had.
struct ScriptedTargets {
    /// One entry per call, consumed front to back; the LAST entry repeats once
    /// exhausted so a test cannot hang on an over-long retry run.
    script: Mutex<Vec<Vec<ReconnectLocator>>>,
    calls: AtomicUsize,
}

impl ScriptedTargets {
    fn new(script: Vec<Vec<ReconnectLocator>>) -> Arc<Self> {
        assert!(!script.is_empty(), "a script needs at least one answer");
        Arc::new(Self {
            script: Mutex::new(script),
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}

impl ReconnectTargets for ScriptedTargets {
    fn candidates<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Vec<ReconnectLocator>> + Send + 'a>> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let mut script = self.script.lock().expect("script mutex");
        let answer = if script.len() > 1 {
            script.remove(0)
        } else {
            script[0].clone()
        };
        Box::pin(async move { answer })
    }

    fn describe(&self) -> String {
        "scripted test plan".to_string()
    }
}

/// Narrow a `tcp/HOST:PORT` string to the reconnectable subset, panicking on a
/// shape this test wrote wrong (as opposed to one the supervisor rejected).
fn locator(addr: &str) -> ReconnectLocator {
    ReconnectLocator::try_from(parse_any_locator(&format!("tcp/{addr}")).expect("parse locator"))
        .expect("tcp locator is reconnectable")
}

/// An address nothing is listening on: bind, read the port the OS chose, drop
/// the listener. Loopback refuses a connect to a closed port immediately, so
/// this is a FAST failure rather than a timeout — the test's runtime does not
/// depend on any dial deadline.
async fn dead_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr").to_string();
    drop(listener);
    addr
}

/// How long the acceptor half waits for a reopen to arrive before calling the
/// scenario failed.
///
/// Generous against the retry cadences below (25 ms, at most 16 attempts) and
/// still far short of any CI timeout, because it exists to convert a REGRESSION
/// into a failure rather than a hang: both scenarios pair the supervisor with an
/// `accept` that only completes if the reopen reached this listener, so a
/// supervisor that stopped reaching it would leave that half pending forever.
/// The first control probe for this file did exactly that — it hung instead of
/// failing, which is a worse signal than the red it was supposed to produce.
const REOPEN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// [`accept_one`] under [`REOPEN_DEADLINE`], with a message that names what the
/// missing connection MEANS rather than reporting a bare timeout.
async fn accept_one_before_deadline(listener: &TcpListener, what: &str) -> OpenedSession {
    match tokio::time::timeout(REOPEN_DEADLINE, accept_one(listener)).await {
        Ok(opened) => opened,
        Err(_) => panic!(
            "no reopen reached the listener within {REOPEN_DEADLINE:?}: {what}. \
             The supervisor never dialed this address, so the plan was not \
             walked the way this test asserts."
        ),
    }
}

/// Accept one connection and bring it to Established, the acceptor half of
/// every scenario here.
async fn accept_one(listener: &TcpListener) -> OpenedSession {
    let (stream, _peer) = listener.accept().await.expect("accept");
    let mut params = fixture_session_init_params();
    params.zid = vec![0x02; 4]; // distinct zid from the initiator
    accept_and_open_session(
        DialedLink::Tcp(stream),
        params,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .expect("acceptor reaches Established")
}

/// Open a reconnect-supervised client against `listener`, with the acceptor
/// running concurrently. Returns the supervisor and the accepted session.
async fn open_supervised(
    listener: &TcpListener,
    live: &ReconnectLocator,
    policy: ReconnectPolicy,
) -> (
    wz_runtime_tokio::reconnect::ReconnectingSession,
    OpenedSession,
) {
    let mut params = fixture_session_init_params();
    params.zid = vec![0x01; 4];
    tokio::join!(
        async {
            open_session_with_reconnect(
                live.clone(),
                params,
                DialConfig::default(),
                TokioTime::new(),
                policy,
                Some(ITER_CAP),
                DEFAULT_OPEN_TICK_MS,
            )
            .await
            .expect("client reaches Established")
        },
        accept_one(listener),
    )
}

/// THE FAILOVER GATE. A reopen walks its candidates until one opens — pico's
/// `_z_open` scout branch, whose loop `break`s only on success.
///
/// The plan's first candidate is an address nothing listens on. A supervisor
/// that dials only the first candidate — which is what a retained
/// `ReconnectLocator` amounts to — never reaches the listener, so the acceptor
/// half of the `join!` never completes and the drive returns `GaveUp` on the
/// attempt cap instead of `Stopped`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reopen_falls_over_to_the_next_candidate() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let live = locator(&listener.local_addr().expect("local addr").to_string());
    let dead = locator(&dead_address().await);

    let policy = ReconnectPolicy {
        retry_delay_ms: 25, // test cadence; production default is pico's 1s
        max_attempts: Some(8),
        ..ReconnectPolicy::default()
    };
    let (mut client, conn1) = open_supervised(&listener, &live, policy).await;

    // The plan answers with the dead address FIRST and the live one second, on
    // every call. Nothing about it changes across attempts, so a pass here is
    // the candidate LOOP and not a lucky retry.
    let targets = ScriptedTargets::new(vec![vec![dead.clone(), live.clone()]]);
    client.set_targets(targets.clone());

    // Sever abruptly: no Close frame, so the client sees a link loss.
    drop(conn1);

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_server = stop.clone();
    let timeouts = SessionTimeouts::spec_defaults();
    let (outcome, _conn2) = tokio::join!(
        client.drive(&timeouts, &stop, Some(ITER_CAP), |_| {}),
        async {
            let conn2 = accept_one_before_deadline(
                &listener,
                "the first candidate is dead, so only a walk to the second one arrives",
            )
            .await;
            stop_for_server.store(true, Ordering::Release);
            drop(conn2);
        },
    );

    assert!(
        matches!(outcome, ReconnectDriveOutcome::Stopped),
        "the reopen must reach the SECOND candidate and then stop; got {outcome:?}"
    );
    assert_eq!(
        client.reconnects(),
        1,
        "exactly one survived link loss, reached over the second candidate"
    );
    assert_eq!(
        targets.calls(),
        1,
        "ONE attempt sufficed: the failover happens INSIDE an attempt (pico's \
         open loop over one Hello's locators), not by burning a retry per \
         candidate — a supervisor that took one candidate per attempt would \
         reconnect too, and this is what tells the two apart"
    );
}

/// THE RE-ENTRY GATE. The plan is consulted on EVERY attempt, and an empty
/// answer is transient.
///
/// The script answers with nothing twice before naming the listener. Two
/// distinct pre-round behaviours fail this:
///
/// * a supervisor that resolved its target once can never see the third
///   answer — it is the whole point of re-entering `_z_open` that it can;
/// * a supervisor that treated "no candidate" as permanent gives up on the
///   first empty answer, where pico lists `_Z_ERR_SCOUT_NO_RESULTS` in the
///   RETRY set.
///
/// The call count is asserted as `>= 3` rather than `== 3`: the drive may make
/// further attempts after the reconnect if the acceptor's drop races the stop
/// flag, and pinning an exact count would make this test about that race
/// instead of about re-entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reopen_asks_the_plan_again_on_every_attempt() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let live = locator(&listener.local_addr().expect("local addr").to_string());

    let policy = ReconnectPolicy {
        retry_delay_ms: 25,
        max_attempts: Some(16),
        ..ReconnectPolicy::default()
    };
    let (mut client, conn1) = open_supervised(&listener, &live, policy).await;

    // Two silent windows, then a peer. `vec![]` is pico's
    // `_Z_ERR_SCOUT_NO_RESULTS` — nobody answered THIS window.
    let targets = ScriptedTargets::new(vec![vec![], vec![], vec![live.clone()]]);
    client.set_targets(targets.clone());

    drop(conn1);

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_server = stop.clone();
    let timeouts = SessionTimeouts::spec_defaults();
    let (outcome, _conn2) = tokio::join!(
        client.drive(&timeouts, &stop, Some(ITER_CAP), |_| {}),
        async {
            let conn2 = accept_one_before_deadline(
                &listener,
                "two empty answers precede the live one, so only a per-attempt \
                 re-ask reaches this listener",
            )
            .await;
            stop_for_server.store(true, Ordering::Release);
            drop(conn2);
        },
    );

    assert!(
        matches!(outcome, ReconnectDriveOutcome::Stopped),
        "two empty answers are RETRYABLE, so the third must reconnect; got {outcome:?}"
    );
    assert_eq!(
        client.reconnects(),
        1,
        "the third answer is the one that reconnects"
    );
    assert!(
        targets.calls() >= 3,
        "the plan must be re-asked per attempt (pico re-enters `_z_open`); \
         it was asked {} time(s), so a cached first answer would have been \
         enough — which is the design this round replaced",
        targets.calls()
    );
}
