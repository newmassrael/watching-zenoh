// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Minimal pubsub-only facade-subset e2e consumer binary.
//!
//! Pins EXACTLY the pubsub-only coherent facade subset (see this
//! crate's `Cargo.toml`) and drives the smallest possible publisher
//! flow that proves the pub/sub data plane interoperates with a
//! foreign zenoh-pico peer on the wire:
//!
//!   1. bind a TCP listener (acceptor role) and accept one peer;
//!   2. open the session to Established via the public
//!      `accept_and_open_session` helper (wall-clock bounded by the
//!      SCXML handshake timers);
//!   3. emit a small burst of literal-keyexpr Put Pushes;
//!   4. drive the session FSM until a terminal state or SIGTERM;
//!   5. minimal teardown — drop the action senders so the writer task
//!      drains, with a brief tail window.
//!
//! Deliberately uses ONLY the pub/sub surface (no query / declare /
//! liveliness): the source compiles under the pinned subset with zero
//! `#[cfg]`, which is the whole reason this is a separate crate rather
//! than a feature-gated mode of wz-ap-demo. The CLI contract
//! (`--listen ADDR --publish KEY --value VAL` + the "listening on"
//! stderr witness) mirrors wz-ap-demo's publisher mode so the Layer E2
//! integration test can drive it the same way it drives the full demo.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use wz::runtime_core::{Runtime, TimeSource};
use wz::runtime_tokio::observer::ApplicationLayerObserver;
use wz::runtime_tokio::runtime_impl::{TokioRuntime, TokioTime};
use wz::runtime_tokio::sample::SampleKind;
use wz::runtime_tokio::session::{PublishOptions, Session};
use wz::runtime_tokio::session_glue::{
    drive_session_until_terminal, IterationEvent, SessionInitParams, SigningKey,
};
use wz::runtime_tokio::session_open::{
    accept_and_open_session, DialedLink, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz::runtime_tokio::sync::Mutex;
use wz::runtime_tokio::Reliability;

/// Number of Put Pushes emitted once Established. A short burst (rather
/// than a single Push) makes the round-trip robust against the foreign
/// subscriber's receive-task scheduling without depending on exact
/// timing — the same rationale as wz-ap-demo's publisher burst.
const PUBLISH_BURST: usize = 8;
/// Spacing between burst Pushes; keeps the burst well inside the
/// integration test's receive window while not hammering the link.
const BURST_INTERVAL_MS: u64 = 150;
/// Inbound-poll iteration bound for the drive loop (test determinism;
/// the SIGTERM race is the production stop path). Mirrors wz-ap-demo.
const DRIVE_MAX_ITERS: usize = 10_000;

fn main() -> ExitCode {
    // env_logger writes to stderr; the integration test polls for the
    // "listening on" line, so default the filter to info when RUST_LOG
    // is unset (mirrors wz-ap-demo).
    env_logger::Builder::from_env(env_logger::Env::default().filter_or("RUST_LOG", "info")).init();

    let Some(args) = CliArgs::parse(std::env::args().skip(1)) else {
        eprintln!("usage: wz-e2e-pubsub --listen <ADDR> --publish <KEY> --value <VALUE>");
        return ExitCode::FAILURE;
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log::error!("wz-e2e-pubsub: failed to build tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("wz-e2e-pubsub: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Parsed `--listen / --publish / --value` triple. All three are
/// mandatory; this binary has exactly one mode.
struct CliArgs {
    listen: String,
    publish_key: String,
    value: String,
}

impl CliArgs {
    fn parse(mut args: impl Iterator<Item = String>) -> Option<Self> {
        let mut listen = None;
        let mut publish_key = None;
        let mut value = None;
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--listen" => listen = args.next(),
                "--publish" => publish_key = args.next(),
                "--value" => value = args.next(),
                _ => return None,
            }
        }
        Some(Self {
            listen: listen?,
            publish_key: publish_key?,
            value: value?,
        })
    }
}

async fn run(args: CliArgs) -> std::io::Result<()> {
    // ── Step 1: bind + accept one peer (acceptor role).
    let listener = TcpListener::bind(&args.listen).await?;
    log::info!("wz-e2e-pubsub: listening on {}", listener.local_addr()?);
    let (stream, peer) = listener.accept().await?;
    log::info!("wz-e2e-pubsub: accepted peer {peer}");

    // ── Step 2: open the session to Established. TokioTime is Copy, so
    //           the one epoch is shared across the open helper, Session,
    //           and the drive loop.
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
    log::info!("wz-e2e-pubsub: session Established; entering steady state");

    // ── Step 3: build a Session and spawn the publish burst. The
    //           handshake exchanged no application frames, so the bare
    //           observer wired here drops nothing; a pure publisher
    //           registers no subscriber callbacks.
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = Session::new(actions.clone(), observer.clone(), Arc::new(clock));

    let publish_key = args.publish_key.clone();
    let value = args.value.clone();
    let publisher = TokioRuntime.spawn(async move {
        for idx in 0..PUBLISH_BURST {
            let mut opts = PublishOptions::default().with_reliability(Reliability::Reliable);
            opts.kind = SampleKind::Put;
            let fired = session.publish(&publish_key, value.as_bytes(), opts);
            log::info!(
                "wz-e2e-pubsub: PUBLISHER EMITTED idx={idx} keyexpr='{publish_key}' \
                 payload_len={} loopback_fired={fired}",
                value.len()
            );
            clock.sleep(BURST_INTERVAL_MS).await;
        }
        log::info!("wz-e2e-pubsub: publisher burst complete");
    });

    // ── Step 4: drive the session FSM until terminal or SIGTERM. The
    //           dispatch closure fans inbound events into the observer
    //           (a pure publisher mostly observes keepalives).
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
        Some(o) => log::info!("wz-e2e-pubsub: session ended: {o:?}"),
        None => log::info!("wz-e2e-pubsub: shutdown signal received; draining writer"),
    }

    // ── Step 5: minimal teardown. Abort the burst task and drop every
    //           action-sender clone so the writer task observes its
    //           channel close and drains; give it a brief tail window
    //           to flush any queued frames before the process exits.
    publisher.abort();
    drop(actions);
    let _ = tokio::time::timeout(Duration::from_millis(50), writer_handle).await;
    Ok(())
}

/// Acceptor-side session parameters. Mirrors wz-ap-demo's Peer-role
/// defaults; the demo signing key is a fixed 0xAB pattern (a real
/// deployment supplies per-process entropy).
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
/// The Layer E2 integration test sends SIGTERM after it witnesses the
/// round-trip, so this is the binary's production stop path.
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
