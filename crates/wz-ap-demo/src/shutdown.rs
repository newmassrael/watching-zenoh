// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-ap-demo — graceful-shutdown signal future.
//
// R285 — extracted from `main.rs` as part of Phase 1 module
// decomposition (the R281 carry). Pure code-move, no behaviour
// change. The two cfg arms (unix vs non-unix) mirror what was
// inlined into `main.rs`; the unix arm listens for the first of
// SIGTERM / SIGINT, the non-unix fallback only handles Ctrl-C.

/// R278 — graceful-shutdown signal future. Resolves on the first of
/// SIGTERM or SIGINT (Ctrl-C). Used as the cancellation arm of a
/// `tokio::select!` around `drive_session_until_terminal` so the demo
/// can unwind cleanly — joining its tasks, dropping the held
/// `LivelinessToken` (which emits `Declare(UndeclToken)` on the wire
/// per R277 RAII contract), then dropping `actions` so the writer
/// task drains. SIGKILL still bypasses all of this; for that path
/// the peer only sees connection EOF, no `UndeclToken`.
///
/// Why two signals: SIGINT is the Ctrl-C path for interactive shell
/// sessions, SIGTERM is what `kill <pid>` / process-supervision
/// frameworks (systemd, k8s) emit during planned shutdown. Both
/// should route through the same graceful path. SIGQUIT and
/// SIGKILL are intentionally not handled — SIGQUIT signals
/// abnormal termination (core dump) and SIGKILL cannot be caught
/// from userspace at all.
///
/// Failure handling: if the signal handler install fails (rare —
/// usually only when running outside a tokio runtime or in a
/// container that filters `signalfd`), we log a warning and fall
/// back to the Ctrl-C-only path. A wedged demo can still be
/// `kill -9`'d in the worst case.
#[cfg(unix)]
pub(crate) async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            log::warn!(
                "wz-ap-demo: failed to install SIGTERM handler ({e}); \
                 falling back to ctrl_c-only graceful shutdown"
            );
            let _ = tokio::signal::ctrl_c().await;
            log::info!("wz-ap-demo: SIGINT received (SIGTERM unavailable)");
            return;
        }
    };
    tokio::select! {
        _ = sigterm.recv() => {
            log::info!("wz-ap-demo: SIGTERM received; graceful shutdown");
        }
        r = tokio::signal::ctrl_c() => {
            if let Err(e) = r {
                log::warn!("wz-ap-demo: ctrl_c handler error: {e}");
            }
            log::info!("wz-ap-demo: SIGINT received; graceful shutdown");
        }
    }
}

/// Windows — the first of Ctrl-C or a stop request on the named event
/// (see [`crate::stop_event`]).
///
/// SIGTERM has no analogue a process without a console can be sent, so the
/// event is the Windows path for a parent that starts the demo that way; both
/// routes run the same graceful shutdown. A Ctrl-C handler that cannot be
/// installed no longer ends the wait: the process would otherwise stop at once
/// for a reason that is not a request to stop, so the event is then the only
/// path left and the warning says so.
#[cfg(windows)]
pub(crate) async fn shutdown_signal() {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => log::info!("wz-ap-demo: Ctrl-C received; graceful shutdown"),
            Err(e) => {
                log::warn!(
                    "wz-ap-demo: ctrl_c handler error: {e}; \
                     only the stop event can end this wait"
                );
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        () = ctrl_c => {}
        () = crate::stop_event::requested() => {
            log::info!("wz-ap-demo: stop event received; graceful shutdown");
        }
    }
}

/// R278 — the remaining non-Unix fallback (WASM). Only Ctrl-C is supported
/// here; the Unix-only SIGTERM path is omitted because there is no
/// portable analogue.
#[cfg(all(not(unix), not(windows)))]
pub(crate) async fn shutdown_signal() {
    if let Err(e) = tokio::signal::ctrl_c().await {
        log::warn!("wz-ap-demo: ctrl_c handler error: {e}");
    }
    log::info!("wz-ap-demo: Ctrl-C received; graceful shutdown");
}
