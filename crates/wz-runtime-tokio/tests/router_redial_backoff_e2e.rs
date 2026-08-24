// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "router-connect-reconcile",
    feature = "routing-peer",
    feature = "transport-link-tcp",
))]

//! R311y786 (`router-connect-reconcile`) — proves the production `peer_loop`
//! paces its peer auto-reconnect by [`RetryPolicy`], and that the wait GROWS
//! across the retries of one outage.
//!
//! This is the LOOP-level witness, and it exists because the unit tests on
//! `RedialSchedule` cannot supply it: they prove the schedule computes a growing
//! sequence, not that `schedule_redial` consults one. Until R311y786 the loop
//! sleeps a `const RECONNECT_BACKOFF_MS = 1000` — a build with a perfectly
//! correct `RedialSchedule` sitting unused would pass every unit test in the
//! crate while re-dialing an unreachable configured peer at a fixed cadence
//! forever.
//!
//! # Why an unreachable address is the right stimulus
//!
//! The loop re-dials a still-DESIRED target whether the dial FAILED or an
//! established face dropped. The failed-dial arm is the one that repeats without
//! bound — a peer that is simply switched off — so it is both the arm the defect
//! actually hurt and the only one that can be driven many times from a single
//! setup. A closed loopback port refuses immediately, so the interval between
//! consecutive `FaceFailed` events is the backoff and almost nothing else.
//!
//! # What is asserted, and what deliberately is not
//!
//! The assertion is a RATIO between a late gap and the first gap, not absolute
//! durations: the wall clock under a loaded CI runner can stretch any single
//! interval, but it cannot make a fixed schedule's gaps grow in proportion to
//! each other. `>= 2x` against a schedule whose gaps rise 60 -> 120 -> 240 -> 480
//! leaves a wide margin above the fixed-delay answer of `1x`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use wz_runtime_tokio::accept_loop::{peer_loop, AcceptEvent, FaceSources, NoOpForwarder};
use wz_runtime_tokio::link_pipeline::bind_tcp;
use wz_runtime_tokio::retry_period::RetryPolicy;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_open::{BoundListener, SessionOffer, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio_test_support::fixture_session_init_params;

/// A loopback address with NOTHING listening: bind it, read the port, drop the
/// listener. A connect there is REFUSED immediately rather than timing out, which
/// is what keeps the observed interval equal to the backoff instead of to a
/// TCP handshake timeout.
fn closed_port() -> SocketAddr {
    let l = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral");
    let addr = l.local_addr().expect("local_addr");
    drop(l);
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
}

async fn shutdown_on(mut rx: watch::Receiver<bool>) {
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Collect the instants of the first `want` `FaceFailed` events the loop emits
/// while re-dialing one unreachable desired peer, and return the gaps between
/// consecutive attempts in milliseconds.
async fn observed_gaps_ms(retry: RetryPolicy, want: usize) -> Vec<u128> {
    let target = closed_port();
    let listener = BoundListener::Tcp(
        bind_tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), None)
            .await
            .expect("bind SUT listener"),
    );
    let (shut_tx, shut_rx) = watch::channel(false);

    let stamps: Arc<StdMutex<Vec<Instant>>> = Arc::new(StdMutex::new(Vec::new()));
    let sink = stamps.clone();
    let done = shut_tx.clone();

    let loop_fut = peer_loop(
        FaceSources {
            listener,
            // The ONE unreachable desired peer. Seeded statically, so it enters
            // `desired` and every failed dial is re-scheduled.
            dial_targets: vec![target],
            dial_intents: None,
            mcast_ingress: None,
            mcast_members: None,
            mcast_group_subs: None,
            reconcile: None,
            #[cfg(feature = "transport-multilink")]
            max_links: 1,
            #[cfg(feature = "transport-multilink")]
            qos: false,
            offer: SessionOffer::universal(),
            retry,
        },
        fixture_session_init_params(),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(shut_rx),
        move |event: &AcceptEvent| {
            if let AcceptEvent::FaceFailed { .. } = event {
                let mut v = sink.lock().expect("stamps");
                v.push(Instant::now());
                if v.len() >= want {
                    // Stop the loop from inside its own observer: the schedule
                    // only grows, so waiting for a further attempt costs more
                    // wall clock than the assertion needs.
                    let _ = done.send(true);
                }
            }
        },
        &NoOpForwarder,
    );

    tokio::time::timeout(Duration::from_secs(20), loop_fut)
        .await
        .expect("the re-dial loop must reach its attempt budget well inside 20s");

    let v = stamps.lock().expect("stamps");
    assert!(
        v.len() >= want,
        "expected {want} failed dials, saw {}",
        v.len()
    );
    v.windows(2)
        .map(|w| w[1].duration_since(w[0]).as_millis())
        .collect()
}

/// The peer auto-reconnect BACKS OFF: with `60,480,x2` the gaps between
/// consecutive failed dials climb (60 -> 120 -> 240 -> 480). The discriminator is
/// the RATIO — the fixed `RECONNECT_BACKOFF_MS` this replaced produced equal
/// gaps, so a loop that ignores the policy answers `1x` here.
#[tokio::test(flavor = "current_thread")]
async fn an_unreachable_desired_peer_is_redialed_with_a_growing_wait() {
    let gaps = observed_gaps_ms(
        RetryPolicy {
            period_init_ms: 60,
            period_max_ms: 480,
            period_increase_factor: 2.0,
        },
        5,
    )
    .await;
    assert!(gaps.len() >= 4, "need 4 gaps, got {gaps:?}");

    let first = gaps[0];
    let late = gaps[gaps.len() - 1];
    assert!(
        late >= first.saturating_mul(2),
        "the wait must GROW: first gap {first}ms, last gap {late}ms (all gaps {gaps:?}) \
         — equal gaps are the fixed-backoff behaviour this round replaced"
    );
    // Monotone non-decreasing up to scheduler jitter: each gap is at least the
    // previous one less a 30ms slack. Catches a schedule that grows once and then
    // falls back, which the endpoint ratio alone would not see.
    for w in gaps.windows(2) {
        assert!(
            w[1] + 30 >= w[0],
            "gaps must not shrink: {:?} (all {gaps:?})",
            w
        );
    }
}

/// R311y786 — the loop FORGETS an address's grown wait when the address stops
/// being desired, so a peer the operator removes and later re-adds starts over at
/// `period_init_ms` instead of inheriting the ceiling of the outage that preceded
/// its removal.
///
/// This is the loop-level witness for `RedialSchedule::forget`. The unit tests
/// prove `forget` resets a schedule; only this proves the LOOP calls it — a build
/// that grew the wait correctly and never forgot would pass every one of them
/// while making a freshly re-added peer wait the ceiling on its first retry.
///
/// The contrast is deliberately x16 (50ms init, x4, 800ms ceiling) rather than the
/// x2 the growth test uses: this assertion has to separate "waited 50ms" from
/// "waited 800ms" across a reconcile round-trip, and a wide gap is what keeps it
/// from being a wall-clock coin flip on a loaded runner.
#[tokio::test(flavor = "current_thread")]
async fn a_peer_removed_and_re_added_starts_over_at_the_initial_wait() {
    let target = closed_port();
    let listener = BoundListener::Tcp(
        bind_tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), None)
            .await
            .expect("bind SUT listener"),
    );
    let (shut_tx, shut_rx) = watch::channel(false);
    let (reconcile_tx, reconcile_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<SocketAddr>>();

    let stamps: Arc<StdMutex<Vec<Instant>>> = Arc::new(StdMutex::new(Vec::new()));
    let sink = stamps.clone();
    let done = shut_tx.clone();

    let loop_fut = peer_loop(
        FaceSources {
            listener,
            dial_targets: vec![target],
            dial_intents: None,
            mcast_ingress: None,
            mcast_members: None,
            mcast_group_subs: None,
            reconcile: Some(reconcile_rx),
            #[cfg(feature = "transport-multilink")]
            max_links: 1,
            #[cfg(feature = "transport-multilink")]
            qos: false,
            offer: SessionOffer::universal(),
            retry: RetryPolicy {
                period_init_ms: 50,
                period_max_ms: 800,
                period_increase_factor: 4.0,
            },
        },
        fixture_session_init_params(),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(shut_rx),
        move |event: &AcceptEvent| {
            if !matches!(event, AcceptEvent::FaceFailed { .. }) {
                return;
            }
            let mut v = sink.lock().expect("stamps");
            v.push(Instant::now());
            match v.len() {
                // Gaps so far: 50, 200. The schedule is now AT the 800ms ceiling,
                // and the re-dial scheduled by this very failure will wait it.
                3 => {
                    reconcile_tx.send(Vec::new()).expect("send remove");
                }
                // That ceiling-length wait has now elapsed and failed, and because
                // the address was no longer desired the loop dropped it instead of
                // re-scheduling — which is the moment `forget` runs. Re-add it.
                4 => {
                    reconcile_tx.send(vec![target]).expect("send re-add");
                }
                // 5 = the reconcile-add's immediate dial failing. 6 = the retry it
                // scheduled, whose wait is the value under test.
                6 => {
                    let _ = done.send(true);
                }
                _ => {}
            }
        },
        &NoOpForwarder,
    );

    tokio::time::timeout(Duration::from_secs(20), loop_fut)
        .await
        .expect("the remove/re-add cycle must complete well inside 20s");

    let v = stamps.lock().expect("stamps");
    assert!(
        v.len() >= 6,
        "expected 6 failed dials across the remove/re-add cycle, saw {}",
        v.len()
    );
    let gaps: Vec<u128> = v
        .windows(2)
        .map(|w| w[1].duration_since(w[0]).as_millis())
        .collect();
    // Gap 3->4 is the pre-removal ceiling wait; gap 5->6 is the first retry AFTER
    // the re-add. Forgetting is the only thing that separates them.
    let ceiling_gap = gaps[2];
    let after_readd = gaps[4];
    assert!(
        ceiling_gap >= 400,
        "the pre-removal wait should have reached the 800ms ceiling, got {ceiling_gap}ms \
         (all gaps {gaps:?}) — without that this test proves nothing"
    );
    assert!(
        after_readd < 200,
        "a re-added peer's FIRST retry must be ~50ms (period_init_ms), got \
         {after_readd}ms vs a pre-removal ceiling of {ceiling_gap}ms (all gaps {gaps:?}) \
         — a loop that never forgets makes it wait the ceiling"
    );
}

/// The mirror image, and the reason it is here: a `constant` policy must keep the
/// PRE-y786 cadence, so the growth is a POLICY the loop applies and not something
/// welded in. Without this arm the test above would also pass a loop that ignored
/// the policy and hardcoded a doubling.
#[tokio::test(flavor = "current_thread")]
async fn a_constant_policy_keeps_the_redial_cadence_flat() {
    let gaps = observed_gaps_ms(RetryPolicy::constant(80), 5).await;
    assert!(gaps.len() >= 4, "need 4 gaps, got {gaps:?}");

    let first = gaps[0];
    let late = gaps[gaps.len() - 1];
    assert!(
        late < first.saturating_mul(2),
        "a constant policy must NOT grow: first gap {first}ms, last gap {late}ms \
         (all gaps {gaps:?})"
    );
}
