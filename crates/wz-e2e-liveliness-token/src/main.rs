// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Minimal liveliness-token-DECLARER facade-subset e2e consumer binary.
//!
//! Pins EXACTLY the liveliness-token declarer subset (see this crate's
//! `Cargo.toml`) and drives the smallest possible declarer flow that
//! proves the R283 inbound-Interest response interoperates with a
//! foreign zenoh-pico `z_get_liveliness` querier on the wire:
//!
//!   1. bind a TCP listener (acceptor role) and accept one peer;
//!   2. open the session to Established via `accept_and_open_session`;
//!   3. declare ONE LivelinessToken — SYNCHRONOUSLY, before the drive
//!      loop. `Session::declare_token` both emits the proactive
//!      `Declare(DeclToken)` and registers the token in the observer's
//!      declarer-side `local_tokens` registry. Doing this before the
//!      loop guarantees the token is registered before ANY inbound
//!      Interest is processed — the deterministic R283 ordering a
//!      one-shot CURRENT querier (no future subscription) needs;
//!   4. drive the session FSM until terminal or SIGTERM — when the
//!      foreign querier's non-final liveliness Interest arrives, the
//!      observer's `local_tokens` registry stages the interest-response
//!      (an interest_id-tagged `Declare(DeclToken)` for the held token +
//!      a terminating `Declare(DeclFinal)`) and the drain phase emits it
//!      through the action sink (R283);
//!   5. minimal teardown — the held token's Drop emits
//!      `Declare(UndeclToken)`, then the action senders drop so the
//!      writer task drains.
//!
//! Symmetric sibling of `wz-e2e-liveliness` (the subscriber side).
//! Deliberately uses ONLY the liveliness-token declare surface, so the
//! source compiles under the pinned subset with zero `#[cfg]`.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use wz::runtime_tokio::observer::ApplicationLayerObserver;
use wz::runtime_tokio::runtime_impl::TokioTime;
use wz::runtime_tokio::session::{LivelinessOptions, Session};
use wz::runtime_tokio::session_glue::{
    drive_session_until_terminal, IterationEvent, SessionInitParams, SigningKey,
};
use wz::runtime_tokio::session_open::{
    accept_and_open_session, DialedLink, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz::runtime_tokio::sync::Mutex;

/// Inbound-poll iteration bound for the drive loop (test determinism;
/// the SIGTERM race is the production stop path). Mirrors the sibling
/// wz-e2e-* binaries.
const DRIVE_MAX_ITERS: usize = 10_000;

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().filter_or("RUST_LOG", "info")).init();

    let Some(args) = CliArgs::parse(std::env::args().skip(1)) else {
        eprintln!("usage: wz-e2e-liveliness-token --listen <ADDR> --token <KEY>");
        return ExitCode::FAILURE;
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log::error!("wz-e2e-liveliness-token: failed to build tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("wz-e2e-liveliness-token: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Parsed `--listen / --token` pair. Both are mandatory; this binary has
/// exactly one mode.
struct CliArgs {
    listen: String,
    token_key: String,
}

impl CliArgs {
    fn parse(mut args: impl Iterator<Item = String>) -> Option<Self> {
        let mut listen = None;
        let mut token_key = None;
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--listen" => listen = args.next(),
                "--token" => token_key = args.next(),
                _ => return None,
            }
        }
        Some(Self {
            listen: listen?,
            token_key: token_key?,
        })
    }
}

async fn run(args: CliArgs) -> std::io::Result<()> {
    // ── Step 1: bind + accept one peer (acceptor role).
    let listener = TcpListener::bind(&args.listen).await?;
    log::info!(
        "wz-e2e-liveliness-token: listening on {}",
        listener.local_addr()?
    );
    let (stream, peer) = listener.accept().await?;
    log::info!("wz-e2e-liveliness-token: accepted peer {peer}");

    // ── Step 2: open the session to Established.
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
    log::info!("wz-e2e-liveliness-token: session Established; entering steady state");

    // ── Step 3: declare the token SYNCHRONOUSLY, before the drive loop.
    //           declare_token both emits the proactive Declare(DeclToken)
    //           AND registers the token in observer.local_tokens. Doing it
    //           here — not in a background task — guarantees the token is
    //           registered before any inbound Interest is processed in the
    //           loop below, which is the deterministic ordering a one-shot
    //           CURRENT querier (z_get_liveliness) needs for the R283
    //           reply. The handle is held until after the loop so its Drop
    //           (UndeclToken) fires at teardown, not early.
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = Session::new(actions.clone(), observer.clone(), Arc::new(clock));
    let _token = session
        .declare_token(args.token_key.clone(), LivelinessOptions::default())
        .map_err(|e| std::io::Error::other(format!("declare_token failed: {e:?}")))?;
    log::info!(
        "wz-e2e-liveliness-token: DECLARED TOKEN keyexpr='{}'",
        args.token_key
    );

    // ── Step 4: drive the session FSM until terminal or SIGTERM. The
    //           dispatch closure fans inbound events into the observer,
    //           whose local_tokens registry replies to a matching inbound
    //           liveliness Interest with the held token (R283) — the
    //           interest-response is emitted through `actions`.
    let mut driver = inbound;
    let observer_for_dispatch = observer.clone();
    let outcome = tokio::select! {
        o = drive_session_until_terminal(
            &mut driver,
            &actions,
            &mut engine,
            Some(DRIVE_MAX_ITERS),
            &clock,
            |event: IterationEvent<'_>| {
                observer_for_dispatch
                    .lock()
                    .expect("observer mutex poisoned")
                    .dispatch(event, &actions);
            },
        ) => Some(o),
        _ = shutdown_signal() => None,
    };
    match &outcome {
        Some(o) => log::info!("wz-e2e-liveliness-token: session ended: {o:?}"),
        None => log::info!("wz-e2e-liveliness-token: shutdown signal received; draining writer"),
    }

    // ── Step 5: minimal teardown. Drop the token first (emits
    //           UndeclToken), then the action senders so the writer task
    //           drains; give it a brief tail window to flush.
    drop(_token);
    drop(session);
    drop(actions);
    let _ = tokio::time::timeout(Duration::from_millis(50), writer_handle).await;
    Ok(())
}

/// Acceptor-side session parameters. Mirrors the sibling wz-e2e-*
/// binaries' Peer-role defaults.
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

/// Resolve on the first SIGTERM / SIGINT (unix) or Ctrl-C (other).
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
