// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Shared acceptor scaffolding for the single-purpose `wz-e2e-*`
//! facade-subset e2e binaries.
//!
//! Every `wz-e2e-*` binary is an ACCEPTOR that runs the same five-step
//! flow — bind + accept one peer, open the session to Established,
//! perform a plane-specific setup, drive the session FSM until a
//! terminal state or SIGTERM, tear down — differing ONLY in the setup
//! step (a publish burst, or a `declare_*` registration). This module
//! provides that flow as [`run_acceptor_e2e`] plus the
//! env_logger + tokio-runtime `main` wrapper [`run_main`], so each
//! binary carries just its CLI parsing + its plane-specific setup
//! closure.
//!
//! See this crate's `Cargo.toml` for why the shared scaffolding does not
//! break the per-binary subset pinning.

use std::future::Future;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use wz::runtime_tokio::observer::ApplicationLayerObserver;
use wz::runtime_tokio::runtime_impl::TokioTime;
use wz::runtime_tokio::session::Session;
use wz::runtime_tokio::session_glue::{
    drive_session_until_terminal, IterationEvent, SessionInitParams, SigningKey,
};
use wz::runtime_tokio::session_open::{
    accept_and_open_session, DialedLink, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz::runtime_tokio::sync::Mutex;

/// Inbound-poll iteration bound for the drive loop (test determinism;
/// the SIGTERM race is the production stop path). Shared by every
/// `wz-e2e-*` binary.
const DRIVE_MAX_ITERS: usize = 10_000;

/// The Established session surface a plane-specific setup closure
/// registers into. Exposes only what the four setups need: the
/// [`Session`] (for `publish` / `declare_*`) and the shared monotonic
/// `clock` (for a publish burst's inter-emit sleeps). The action sink,
/// observer, FSM engine, and writer handle stay internal to
/// [`run_acceptor_e2e`].
pub struct OpenedE2e {
    /// The Established session. The setup calls `publish` / `declare_*`
    /// on it; any returned RAII handle is held by the harness across the
    /// drive loop (see [`run_acceptor_e2e`]).
    pub session: Session,
    /// The shared monotonic clock (one epoch across the open helper,
    /// Session, and drive loop). `Copy`, so a setup may capture it into a
    /// spawned emission task.
    pub clock: TokioTime,
}

/// RAII wrapper that aborts a spawned tokio task on drop. The pubsub
/// binary's publish burst runs as a background task; returning it wrapped
/// in `AbortOnDrop` from the setup closure lets the harness stop the
/// emission at teardown with the same drop-ordered cleanup it uses for
/// the reactive planes' RAII handles (a bare `JoinHandle` detaches rather
/// than aborts on drop).
pub struct AbortOnDrop(pub tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The `main` wrapper every `wz-e2e-*` binary shares: initialise
/// env_logger (info default so the integration tests see the "listening
/// on" line), build a multi-thread tokio runtime, and block on `body`,
/// mapping its `io::Result` to a process exit code. `binary_name` tags
/// the runtime-build / body-error log lines.
pub fn run_main(
    binary_name: &'static str,
    body: impl Future<Output = std::io::Result<()>>,
) -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().filter_or("RUST_LOG", "info")).init();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log::error!("{binary_name}: failed to build tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(body) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("{binary_name}: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Run the standard acceptor e2e flow.
///
///   1. bind a TCP listener on `listen` and accept one peer;
///   2. open the session to Established via `accept_and_open_session`;
///   3. call `setup(&OpenedE2e)` — the plane-specific registration /
///      emission; its return value `H` is held alive across the drive
///      loop (an RAII `declare_*` handle, or an [`AbortOnDrop`] publish
///      task) and dropped FIRST at teardown, so a wire-emitting Drop
///      (e.g. `LivelinessToken`'s `UndeclToken`) is enqueued before the
///      writer channel closes;
///   4. drive the session FSM until terminal or SIGTERM, fanning every
///      inbound event through `observer.dispatch` (this is what routes
///      an inbound Query / Interest / Declare to the registry `setup`
///      registered);
///   5. tear down — drop the hold, then the session + action senders so
///      the writer task drains, with a brief tail window.
///
/// `binary_name` tags the harness log lines (`listening on`, `accepted
/// peer`, `session Established`, `session ended`); the integration tests
/// gate on `listening on`, and each binary's setup logs its own plane
/// witness.
pub async fn run_acceptor_e2e<H>(
    binary_name: &'static str,
    listen: String,
    setup: impl FnOnce(&OpenedE2e) -> std::io::Result<H>,
) -> std::io::Result<()> {
    // ── Step 1: bind + accept one peer.
    let listener = TcpListener::bind(&listen).await?;
    log::info!("{binary_name}: listening on {}", listener.local_addr()?);
    let (stream, peer) = listener.accept().await?;
    log::info!("{binary_name}: accepted peer {peer}");

    // ── Step 2: open the session to Established. TokioTime is Copy, so
    //           one epoch is shared across the open helper, Session, and
    //           the drive loop.
    let clock = TokioTime::new();
    let OpenedSession {
        mut engine,
        actions,
        inbound,
        writer_handle,
        clock: _,
    } = accept_and_open_session(
        DialedLink::Tcp(stream),
        session_init_params(),
        clock,
        None,
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .map_err(|e| std::io::Error::other(format!("session open failed: {e:?}")))?;
    log::info!("{binary_name}: session Established; entering steady state");

    // ── Step 3: plane-specific setup. The observer is the same Arc the
    //           Session registers into and the drive loop dispatches into.
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = Session::new(actions.clone(), observer.clone(), Arc::new(clock));
    let opened = OpenedE2e { session, clock };
    let hold = setup(&opened)?;

    // ── Step 4: drive the FSM until terminal or SIGTERM. The dispatch
    //           closure fans inbound events into the observer, which
    //           routes them to whatever registry `setup` registered.
    let mut driver = inbound;
    let observer_for_dispatch = observer.clone();
    let actions_for_loop = actions.clone();
    let outcome = tokio::select! {
        o = drive_session_until_terminal(
            &mut driver,
            &actions_for_loop,
            &mut engine,
            Some(DRIVE_MAX_ITERS),
            &clock,
            |event: IterationEvent<'_>| {
                observer_for_dispatch
                    .lock()
                    .expect("observer mutex poisoned")
                    .dispatch(event, &actions_for_loop);
            },
        ) => Some(o),
        _ = shutdown_signal() => None,
    };
    match &outcome {
        Some(o) => log::info!("{binary_name}: session ended: {o:?}"),
        None => log::info!("{binary_name}: shutdown signal received; draining writer"),
    }

    // ── Step 5: teardown. Drop the hold FIRST (RAII unregister /
    //           UndeclToken emit / publish-task abort), then every action
    //           sender clone so the writer task observes its channel close
    //           and drains; give it a brief tail window to flush.
    drop(hold);
    drop(opened);
    drop(actions_for_loop);
    drop(actions);
    let _ = tokio::time::timeout(Duration::from_millis(50), writer_handle).await;
    Ok(())
}

/// Acceptor-side session parameters shared by every `wz-e2e-*` binary.
/// Peer-role defaults; the demo signing key is a fixed 0xAB pattern (a
/// real deployment supplies per-process entropy).
fn session_init_params() -> SessionInitParams {
    SessionInitParams {
        version: 0x09,
        whatami: 0x02, // Peer
        zid: vec![0x01, 0x02, 0x03, 0x04],
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 65535,
        lease: 10_000,
        lease_in_seconds: false,
        initial_sn: 0,
        cookie: Vec::new(),
        cookie_signing_key: SigningKey::new(vec![0xAB; 32])
            .expect("32-byte demo key satisfies >= 32 invariant"),
    }
}

/// Resolve on the first SIGTERM / SIGINT (unix) or Ctrl-C (other). The
/// Layer E2 integration tests send SIGTERM after they witness the
/// round-trip, so this is the binaries' production stop path.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut intr = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = intr.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
