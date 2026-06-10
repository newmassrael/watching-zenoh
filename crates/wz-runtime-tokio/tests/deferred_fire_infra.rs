// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ky — deferred-fire infrastructure tests (the F-6 building
//! blocks) over the `TokioRuntime` binding: stage/drain ordering, the
//! drain-until-empty loop, and the take-call-restore listener cell's
//! kill semantics (including self-kill from inside the callback — the
//! self-undeclare shape the cell exists to make safe).
//!
//! Lives in the tokio crate (not wz-session-core) because the infra is
//! generic over `R: Runtime` and the unit assertions need a concrete
//! runtime — the `check_lease_deadline` testing convention.

#![cfg(feature = "session-matching")]

use std::sync::{Arc, Mutex};

use wz_runtime_tokio::runtime_impl::TokioRuntime;
use wz_session_core::deferred_fire::{DeferredFireQueue, DeferredListenerCell};

type Queue = DeferredFireQueue<TokioRuntime>;
type Cell<F> = DeferredListenerCell<TokioRuntime, F>;
type BoxedCallback = Box<dyn FnMut() + Send>;
/// Two-phase self-handle slot for the self-kill test (the callback
/// needs its own cell handle, which exists only after construction).
type CellSlot = Arc<Mutex<Option<Cell<BoxedCallback>>>>;

/// Jobs run in stage order, the queue is empty after a drain, and an
/// empty drain is a zero-cost no-op.
#[test]
fn drain_runs_jobs_in_stage_order() {
    let queue = Queue::new();
    let log: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    for i in 0..3 {
        let log = log.clone();
        queue.stage(Box::new(move || log.lock().unwrap().push(i)));
    }
    assert_eq!(queue.len(), 3);
    assert_eq!(queue.drain_and_fire(), 3);
    assert_eq!(*log.lock().unwrap(), vec![0, 1, 2]);
    assert!(queue.is_empty());
    assert_eq!(queue.drain_and_fire(), 0);
}

/// A job staged BY a running job (a callback whose session call flips
/// another watch synchronously) runs in the SAME drain — the
/// drain-until-empty loop, so no fire waits for the next iteration
/// event.
#[test]
fn drain_loops_until_empty() {
    let queue = Queue::new();
    let log: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
    let queue_inner = queue.clone();
    let log_outer = log.clone();
    let log_inner = log.clone();
    queue.stage(Box::new(move || {
        log_outer.lock().unwrap().push("outer");
        queue_inner.stage(Box::new(move || {
            log_inner.lock().unwrap().push("inner");
        }));
    }));
    assert_eq!(queue.drain_and_fire(), 2);
    assert_eq!(*log.lock().unwrap(), vec!["outer", "inner"]);
}

/// A staged-but-undrained fire for a killed cell is suppressed: the
/// callback never observes a post-undeclare event (the late-fire
/// contract).
#[test]
fn kill_suppresses_staged_fire() {
    let fired = Arc::new(Mutex::new(0u32));
    let f = fired.clone();
    let cell: Cell<BoxedCallback> = Cell::new(Box::new(move || {
        *f.lock().unwrap() += 1;
    }));
    let queue = Queue::new();
    let job_cell = cell.clone();
    queue.stage(Box::new(move || job_cell.invoke(|cb| cb())));

    cell.kill();
    assert!(cell.is_dead());
    queue.drain_and_fire();
    assert_eq!(*fired.lock().unwrap(), 0, "dead cell must not fire");
}

/// Self-kill from inside the running callback (the self-undeclare
/// shape): no deadlock on the cell's own mutex (the callback runs with
/// the cell unlocked), and the restore drops the callback instead of
/// resurrecting it — a later fire is suppressed.
#[test]
fn self_kill_inside_callback_is_safe_and_final() {
    let fired = Arc::new(Mutex::new(0u32));
    // Two-phase init: the callback needs its own cell handle.
    let slot: CellSlot = Arc::new(Mutex::new(None));
    let slot_for_cb = slot.clone();
    let f = fired.clone();
    let cell: Cell<BoxedCallback> = Cell::new(Box::new(move || {
        *f.lock().unwrap() += 1;
        // Self-undeclare: kill the very cell this callback lives in.
        slot_for_cb.lock().unwrap().as_ref().unwrap().kill();
    }));
    *slot.lock().unwrap() = Some(cell.clone());

    cell.invoke(|cb| cb());
    assert_eq!(*fired.lock().unwrap(), 1, "first fire runs");
    assert!(cell.is_dead());
    cell.invoke(|cb| cb());
    assert_eq!(*fired.lock().unwrap(), 1, "killed cell never fires again");
}
