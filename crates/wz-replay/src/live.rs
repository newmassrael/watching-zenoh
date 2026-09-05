// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y702 ([REDACTED-REQ]) — the LIVE sink: a real session, and real Pushes on it.
//!
//! # What R311y700 left and why it was left
//!
//! That round built the plan, the schedule, the mutations and the extraction,
//! and stopped at a `Sink` trait with only a recording implementation. The
//! reason it stopped there is good and still holds: a decision that can only be
//! observed by putting packets on a wire is a decision nobody tests, so the
//! decisions became values first. What it left behind is the half a requirement
//! that says "re-inject into a new session" is actually about — this one.
//!
//! # Why it DIALS rather than listens
//!
//! Every `wz-e2e-*` binary in this workspace is an ACCEPTOR: it binds and waits
//! for a peer. That is the right shape for a fixture whose peer is a test
//! harness, and the wrong one for a replay tool: an operator replaying captured
//! traffic points it AT a running deployment, and asking that deployment to
//! connect out to the replay tool inverts who has to be reconfigured. So this
//! dials, and the peer it dials is any zenoh peer that accepts the link.
//!
//! # Why the emission runs on a blocking thread
//!
//! [`crate::play`] is the single driver of a plan, and it is synchronous
//! because the delay belongs to the sink -- the contract [`crate::Sink`]
//! states. A synchronous wait on a runtime worker would stall the writer task
//! that has to put the previous sample on the wire, so `play` runs under
//! `spawn_blocking` while the session FSM is driven on the runtime. Duplicating
//! `play` as an async loop was the alternative and it is worse: the dry run and
//! the live run would then iterate the plan in two places, and the property
//! this crate sells is that `--dry-run` prints what a live run does.

use std::sync::Arc;

use wz::runtime_tokio::observer::ApplicationLayerObserver;
use wz::runtime_tokio::runtime_impl::TokioTime;
use wz::runtime_tokio::sample::SampleKind;
use wz::runtime_tokio::session::{PublishOptions, TokioSession};
use wz::runtime_tokio::session_glue::{
    drive_session_until_terminal, IterationEvent, SessionInitParams, SessionTimeouts, WhatAmI,
};
use wz::runtime_tokio::session_open::{
    connect_and_open_session, DialConfig, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz::runtime_tokio::sync::Mutex;
use wz::runtime_tokio::Reliability;
use wz_session_core::locator::parse_any_locator;

use crate::{play, Plan, Sink};

/// Inbound-poll bound for the drive loop, the same guard every acceptor in this
/// workspace runs with: a handshake regression fails fast instead of hanging.
const DRIVE_MAX_ITERS: usize = 10_000;

/// The zid this tool announces. Fixed rather than random for the reason every
/// mutation in this crate is seeded: a replay a reader cannot repeat is a
/// report nobody can act on, and the zid is what a capture of the replay
/// identifies the sender by.
const REPLAY_ZID: [u8; 4] = [0x77, 0x7A, 0x72, 0x70];

/// A sink that publishes onto an Established session.
///
/// Holds the session rather than the actions handle because `publish` is the
/// seam that builds a `NetworkMessage` and routes it -- reaching past it to the
/// action sender would be a second encoding of a Put.
struct LiveSink {
    session: TokioSession,
    /// Named in the error a failed emission returns, so a reader learns WHICH
    /// sample the peer refused rather than only that one was refused.
    emitted: usize,
}

impl Sink for LiveSink {
    fn emit(&mut self, delay_millis: u64, keyexpr: &str, payload: &[u8]) -> Result<(), String> {
        // The sink honours the delay, per the trait's contract. A blocking
        // sleep is correct HERE and only here: this runs under
        // `spawn_blocking`, off the runtime's workers, so the writer task
        // draining the previous sample is not held up by it.
        if delay_millis > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay_millis));
        }
        let mut opts = PublishOptions::default().with_reliability(Reliability::Reliable);
        opts.kind = SampleKind::Put;
        self.session.publish(keyexpr, payload, opts).map_err(|e| {
            format!(
                "emission {} to `{keyexpr}` was refused: {e:?}",
                self.emitted
            )
        })?;
        log::info!(
            "wz-replay: emitted {} `{keyexpr}` {} byte(s)",
            self.emitted,
            payload.len()
        );
        self.emitted += 1;
        Ok(())
    }
}

/// Why a live replay could not run.
#[derive(Debug)]
pub enum LiveError {
    /// The `--connect` value is not a locator this build can dial.
    Locator(String),
    /// The runtime could not be built.
    Runtime(String),
    /// The peer did not complete a session handshake.
    Open(String),
    /// A sample was refused. Carries the index, so the reader knows where the
    /// replay stopped rather than only how many got through.
    Emission(usize, String),
}

impl core::fmt::Display for LiveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Locator(why) => write!(f, "--connect: {why}"),
            Self::Runtime(why) => write!(f, "could not build a runtime: {why}"),
            Self::Open(why) => write!(f, "the peer did not open a session: {why}"),
            Self::Emission(at, why) => {
                write!(f, "stopped at emission {at}: {why}")
            }
        }
    }
}

/// Dial `connect`, open a session, and play `plan` into it.
///
/// Returns how many emissions reached the wire. The count is what the caller
/// prints; a short one beside a longer plan is the signal that the peer refused
/// something, and [`LiveError::Emission`] says where.
pub fn run(connect: &str, plan: Plan) -> Result<usize, LiveError> {
    let locator = parse_any_locator(connect)
        .map_err(|e| LiveError::Locator(format!("`{connect}` is not a locator: {e:?}")))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| LiveError::Runtime(e.to_string()))?;
    runtime.block_on(async move { play_into_session(locator, plan).await })
}

async fn play_into_session(
    locator: wz_session_core::locator::AnyLocator,
    plan: Plan,
) -> Result<usize, LiveError> {
    let clock = TokioTime::new();
    let cfg = DialConfig::default();
    let OpenedSession {
        mut engine,
        actions,
        inbound,
        writer_handle,
        clock: _,
    } = connect_and_open_session(
        locator,
        session_init_params().map_err(|e| {
            LiveError::Open(format!("no OS entropy for the cookie signing key: {e}"))
        })?,
        &cfg,
        clock,
        None,
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .map_err(|e| LiveError::Open(format!("{e:?}")))?;
    log::info!(
        "wz-replay: session Established; replaying {} emission(s)",
        plan.emissions.len()
    );

    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(actions.clone(), observer, Arc::new(clock));

    // The emission runs OFF the runtime's workers; see this module's header.
    let sink_session = session.clone();
    // APPLICATION, and `spawn_blocking` rather than `spawn`: the emission is a
    // synchronous `play` over the plan, so it must not occupy a worker at all.
    // This is the one caller that spends a subsystem's `max_blocking_threads` —
    // that ceiling is per runtime, so naming the subsystem is what turns the
    // configured number into a dial. zenoh spends its own the same way
    // (`ZRuntime::Application.spawn_blocking`,
    // `io/zenoh-transport/src/common/shm/interop.rs`
    // @ `ZRuntime::Application.spawn_blocking(`).
    let emitting =
        wz::runtime_tokio::runtime_pool::WzRuntime::Application.spawn_blocking(move || {
            let mut sink = LiveSink {
                session: sink_session,
                emitted: 0,
            };
            play(&plan, &mut sink)
        });

    let mut driver = inbound;
    let actions_for_loop = actions.clone();
    let session_for_dispatch = session.clone();
    let timeouts = SessionTimeouts::spec_defaults();
    // RACED against the drive loop rather than sequenced after it, because the
    // two are mutually necessary: the FSM has to keep running for the writer to
    // put a Push on the wire, and the loop only ends when the session does.
    // Whichever finishes first ends the steady state, which is the same shape
    // the e2e harness uses for SIGTERM.
    let played = tokio::select! {
        done = emitting => match done {
            Ok(Ok(n)) => Ok(n),
            Ok(Err((at, why))) => Err(LiveError::Emission(at, why)),
            Err(e) => Err(LiveError::Runtime(format!("the emission task failed: {e}"))),
        },
        outcome = drive_session_until_terminal(
            &mut driver,
            &actions_for_loop,
            &mut engine,
            Some(DRIVE_MAX_ITERS),
            &clock,
            &timeouts,
            |event: IterationEvent<'_>| {
                session_for_dispatch.dispatch_iteration_event(event);
            },
        ) => Err(LiveError::Open(format!(
            "the session ended before the replay finished: {outcome:?}"
        ))),
    };

    // Teardown, in the order the e2e harness established: drop every action
    // sender clone so the writer observes its channel close, then await the
    // drain. A wall-clock tail window would cut a writer still making progress.
    drop(session);
    drop(actions_for_loop);
    drop(actions);
    writer_handle.drain().await;
    played
}

/// The handshake parameters this tool opens with.
///
/// The same shape every wz peer in this workspace announces. `WhatAmI::Peer`
/// rather than Client because a replay is a data source that a router treats as
/// an ordinary peer, which is what the captured publisher was.
/// R311y820 — FALLIBLE: the cookie signing key is drawn from OS entropy rather
/// than written as `vec![0xAB; 32]`, a literal this repository publishes.
fn session_init_params(
) -> Result<SessionInitParams, wz::runtime_tokio::session_glue::EntropyUnavailable> {
    Ok(SessionInitParams {
        version: 0x09,
        whatami: WhatAmI::Peer,
        zid: REPLAY_ZID.to_vec(),
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 65535,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: Vec::new(),
        cookie_signing_key: wz::runtime_tokio::session_glue::SigningKey::from_entropy(
            &mut wz::runtime_tokio::session_glue::OsEntropy,
        )?,
    })
}
