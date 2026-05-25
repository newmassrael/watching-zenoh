// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-ap-demo::teardown — R292 typestate sequence wrapper that
// compile-time-enforces the R284 graceful-Close ordering
// invariant. Pre-R292 the invariant lived only in a multi-line
// doc-comment inside `run_demo`; a hypothetical refactor that
// reordered the steps would compile cleanly and only surface at
// e2e time as a `wz_liveliness_subscriber_round_trip_against_
// wz_acceptor` regression. R292 promotes the contract from
// doc-only to types: the canonical chain
//
//   TeardownInitial
//     -> abort_sweep_join_tasks().await
//     -> TasksJoined
//     -> drop_liveliness_token().await
//     -> TokenDropped
//     -> emit_close_if_cancelled()
//     -> CloseEmitted
//     -> drop_actions()
//     -> ActionsDropped
//     -> drain_writer().await
//     -> WriterDrained
//
// is the only path from drive_session exit to a returned
// `WriterDrained`; the compiler rejects reversal because each
// step consumes its predecessor by value. The ordering
// rationale (LivelinessToken Drop emits Declare(UndeclToken) on
// the writer channel; Close emits a session-teardown frame; if
// Close lands before UndeclToken the peer terminates on Close
// and never processes the retraction) lives in the per-step
// doc-comments below, anchored against R277 + R278 + R284.

use std::sync::Arc;

use tokio::sync::oneshot;
// R311at — JoinHandle types migrate from raw `tokio::task::JoinHandle`
// to wz's [`TokioJoinHandle`] so the typestate handoff inside this
// teardown chain stays type-uniform with `runner.rs::SpawnedTasks`
// (which holds the same wrapper). The wrapper's `.abort()` surface is
// preserved (step 2 sweep_task abort), and `.await` resolves to
// `Result<(), wz_runtime_core::RuntimeError>` instead of
// `Result<(), tokio::task::JoinError>`; the timeout-join sites in
// step 3 + step 7 already discard the result via `let _`, so the
// error-type shift is consumer-invisible.
use wz::runtime_tokio::runtime_impl::{TokioJoinHandle, TokioTime};
use wz::runtime_core::TimeSource;
use wz::runtime_tokio::session::LivelinessToken;
use wz::runtime_tokio::session_glue::{CloseReason, SessionLinkActions};

/// Initial state. Every teardown input is owned by this struct;
/// no step has run yet. `was_cancelled` distinguishes the
/// signal-cancel arm (Close emit required at step 5) from the
/// natural-exit arm (FSM Closing state already fired the
/// script-side Close, so the rust-side emit is suppressed).
pub(crate) struct TeardownInitial {
    pub sweep_task: TokioJoinHandle<()>,
    pub publisher_handle: Option<TokioJoinHandle<()>>,
    pub query_handle: Option<TokioJoinHandle<()>>,
    pub declare_handle: Option<TokioJoinHandle<()>>,
    pub token_rx: Option<oneshot::Receiver<LivelinessToken>>,
    pub actions: Arc<SessionLinkActions>,
    pub writer_handle: TokioJoinHandle<()>,
    pub was_cancelled: bool,
    /// R311ad — clock used by every timeout-bounded step in the
    /// chain. Passing it in (instead of letting each step construct
    /// `TokioTime::new()` afresh) keeps the typestate self-contained
    /// and lets a future MCU profile bind the same field to a non-
    /// tokio TimeSource. Concrete `TokioTime` here because the
    /// ap-demo binary is AP-only; the Session<T: TimeSource> reparam
    /// round will generalise this to `T: TimeSource`.
    pub clock: TokioTime,
}

impl TeardownInitial {
    /// Steps 2-3 of the R284 ordering invariant.
    ///
    /// (2) Abort the R264 sweep_task ticker. `abort()` rather than
    /// `join()` because R264 declared the sweep body to hold no
    /// on-Drop cleanup beyond the shared observer mutex (cleanly
    /// released on task drop), and a `join()` here would block on
    /// the in-flight `sleep(sweep_cadence_ms)` arm for up to one
    /// cadence interval.
    ///
    /// (3) Give the publisher / query / declare tasks each a 200ms
    /// timeout-join window. The 200ms ceiling absorbs publisher's
    /// normal emission tail (one Push, 200ms spacing window not
    /// yet elapsed); a wedged task drops via timeout rather than
    /// blocking shutdown indefinitely.
    pub(crate) async fn abort_sweep_join_tasks(self) -> TasksJoined {
        self.sweep_task.abort();
        if let Some(h) = self.publisher_handle {
            let _ = self.clock.timeout(200, h).await;
        }
        if let Some(h) = self.query_handle {
            let _ = self.clock.timeout(200, h).await;
        }
        if let Some(h) = self.declare_handle {
            let _ = self.clock.timeout(200, h).await;
        }
        TasksJoined {
            token_rx: self.token_rx,
            actions: self.actions,
            writer_handle: self.writer_handle,
            was_cancelled: self.was_cancelled,
            clock: self.clock,
        }
    }
}

/// Tasks joined; LivelinessToken still owned by the declare_task
/// side of the oneshot. Step 4 receives the token (with a 200ms
/// timeout that tolerates the no-token path) and drops it so the
/// RAII Drop enqueues `Declare(UndeclToken)` on the writer
/// channel. The drop MUST precede the Close emit at step 5 — if
/// Close enqueues first the peer terminates on Close before
/// processing the trailing UndeclToken and the liveliness
/// subscriber never observes the DELETE sample (regression
/// originally caught by
/// `wz_liveliness_subscriber_round_trip_against_wz_acceptor`).
pub(crate) struct TasksJoined {
    token_rx: Option<oneshot::Receiver<LivelinessToken>>,
    actions: Arc<SessionLinkActions>,
    writer_handle: TokioJoinHandle<()>,
    was_cancelled: bool,
    clock: TokioTime,
}

impl TasksJoined {
    pub(crate) async fn drop_liveliness_token(self) -> TokenDropped {
        if let Some(rx) = self.token_rx {
            let token = match self.clock.timeout(200, rx).await {
                Ok(Ok(token)) => Some(token),
                _ => None,
            };
            drop(token);
        }
        TokenDropped {
            actions: self.actions,
            writer_handle: self.writer_handle,
            was_cancelled: self.was_cancelled,
            clock: self.clock,
        }
    }
}

/// LivelinessToken dropped (its RAII Drop has now enqueued
/// `Declare(UndeclToken)` on the writer channel). Step 5 emits a
/// graceful `Close(Generic)` AFTER the UndeclToken on the
/// signal-cancel arm only; on the natural-exit arm the FSM's
/// `Closing` state already fired a script-driven
/// `send_close_frame_with_reason`, so a duplicate emit would
/// double-send. `was_cancelled` is the discriminator.
pub(crate) struct TokenDropped {
    actions: Arc<SessionLinkActions>,
    writer_handle: TokioJoinHandle<()>,
    was_cancelled: bool,
    clock: TokioTime,
}

impl TokenDropped {
    pub(crate) fn emit_close_if_cancelled(self) -> CloseEmitted {
        if self.was_cancelled {
            // R311g — `send_close_with_reason` is signature-stable
            // across feature states (body cfg-gated on `codec-close`
            // inside wz-runtime-tokio). When the wz facade is built
            // without `codec-close` the body silently no-ops and the
            // peer observes an abrupt link drop instead of the MID
            // 0x03 + reason byte; ap-demo no longer needs a
            // consumer-side `cfg` mirror or its own `codec-close`
            // feature declaration to keep this call site valid.
            self.actions.send_close_with_reason(CloseReason::Generic);
        }
        CloseEmitted {
            actions: self.actions,
            writer_handle: self.writer_handle,
            clock: self.clock,
        }
    }
}

/// Close frame (if any) enqueued. Step 6 drops the FSM-side
/// `Arc<SessionLinkActions>` so the writer task's
/// `mpsc::UnboundedSender` clones drain via Arc-drop. Every
/// Sender clone must drop for `rx.recv()` in the writer task to
/// return `None` and exit cleanly; the BoxedLinkDriver Arc that
/// `actions` was cloned into during `install_session_actions`
/// also drops on the FSM's Drop path, so this local drop is the
/// last sender by construction.
pub(crate) struct CloseEmitted {
    actions: Arc<SessionLinkActions>,
    writer_handle: TokioJoinHandle<()>,
    clock: TokioTime,
}

impl CloseEmitted {
    pub(crate) fn drop_actions(self) -> ActionsDropped {
        drop(self.actions);
        ActionsDropped {
            writer_handle: self.writer_handle,
            clock: self.clock,
        }
    }
}

/// Local `actions` dropped. Step 7 gives the writer task a 50ms
/// drain window to push any tail frame (e.g. a Close the FSM
/// enqueued during the final transition, an UndeclToken from a
/// late RAII Drop) to the peer before `run_demo` returns and the
/// runtime shuts down. The timeout is intentionally short — the
/// writer is a length-prefixed shim, not a blocking flush, so
/// 50ms is generous on every link we test.
pub(crate) struct ActionsDropped {
    writer_handle: TokioJoinHandle<()>,
    clock: TokioTime,
}

impl ActionsDropped {
    pub(crate) async fn drain_writer(self) -> WriterDrained {
        let _ = self.clock.timeout(50, self.writer_handle).await;
        WriterDrained
    }
}

/// Terminal state. Holding a `WriterDrained` value is the
/// compile-time witness that all seven R284 teardown steps ran
/// in canonical order. `run_demo` accepts this value and returns
/// `Ok(())` to the binary entry point.
pub(crate) struct WriterDrained;
