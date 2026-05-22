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
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use wz_runtime_tokio::session::LivelinessToken;
use wz_runtime_tokio::session_glue::{CloseReason, SessionLinkActions};

/// Initial state. Every teardown input is owned by this struct;
/// no step has run yet. `was_cancelled` distinguishes the
/// signal-cancel arm (Close emit required at step 5) from the
/// natural-exit arm (FSM Closing state already fired the
/// script-side Close, so the rust-side emit is suppressed).
pub(crate) struct TeardownInitial {
    pub sweep_task: JoinHandle<()>,
    pub publisher_handle: Option<JoinHandle<()>>,
    pub query_handle: Option<JoinHandle<()>>,
    pub declare_handle: Option<JoinHandle<()>>,
    pub token_rx: Option<oneshot::Receiver<LivelinessToken>>,
    pub actions: Arc<SessionLinkActions>,
    pub writer_handle: JoinHandle<()>,
    pub was_cancelled: bool,
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
            let _ = tokio::time::timeout(Duration::from_millis(200), h).await;
        }
        if let Some(h) = self.query_handle {
            let _ = tokio::time::timeout(Duration::from_millis(200), h).await;
        }
        if let Some(h) = self.declare_handle {
            let _ = tokio::time::timeout(Duration::from_millis(200), h).await;
        }
        TasksJoined {
            token_rx: self.token_rx,
            actions: self.actions,
            writer_handle: self.writer_handle,
            was_cancelled: self.was_cancelled,
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
    writer_handle: JoinHandle<()>,
    was_cancelled: bool,
}

impl TasksJoined {
    pub(crate) async fn drop_liveliness_token(self) -> TokenDropped {
        if let Some(rx) = self.token_rx {
            let token = match tokio::time::timeout(Duration::from_millis(200), rx).await {
                Ok(Ok(token)) => Some(token),
                _ => None,
            };
            drop(token);
        }
        TokenDropped {
            actions: self.actions,
            writer_handle: self.writer_handle,
            was_cancelled: self.was_cancelled,
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
    writer_handle: JoinHandle<()>,
    was_cancelled: bool,
}

impl TokenDropped {
    pub(crate) fn emit_close_if_cancelled(self) -> CloseEmitted {
        if self.was_cancelled {
            self.actions.send_close_with_reason(CloseReason::Generic);
        }
        CloseEmitted {
            actions: self.actions,
            writer_handle: self.writer_handle,
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
    writer_handle: JoinHandle<()>,
}

impl CloseEmitted {
    pub(crate) fn drop_actions(self) -> ActionsDropped {
        drop(self.actions);
        ActionsDropped {
            writer_handle: self.writer_handle,
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
    writer_handle: JoinHandle<()>,
}

impl ActionsDropped {
    pub(crate) async fn drain_writer(self) -> WriterDrained {
        let _ = tokio::time::timeout(Duration::from_millis(50), self.writer_handle).await;
        WriterDrained
    }
}

/// Terminal state. Holding a `WriterDrained` value is the
/// compile-time witness that all seven R284 teardown steps ran
/// in canonical order. `run_demo` accepts this value and returns
/// `Ok(())` to the binary entry point.
pub(crate) struct WriterDrained;
