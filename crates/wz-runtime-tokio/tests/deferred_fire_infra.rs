// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

/// R311lm — a trivial serializer for the single-threaded infra tests.
/// `DeferredFireQueue::drain` (the sole public emptier since `take_batch`
/// went `pub(crate)`) takes each batch while holding a caller-supplied
/// serializer; production passes the observer mutex, but the queue is
/// opaque to the serializer's identity, so any same-runtime mutex
/// serializes the (uncontended) take here. These tests now exercise the
/// REAL production drain path, not a separate single-thread version.
fn serializer() -> <TokioRuntime as wz_runtime_core::Runtime>::Mutex<()> {
    <TokioRuntime as wz_runtime_core::Runtime>::new_mutex(())
}

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
    assert_eq!(queue.drain(&serializer()), 3);
    assert_eq!(*log.lock().unwrap(), vec![0, 1, 2]);
    assert!(queue.is_empty());
    assert_eq!(queue.drain(&serializer()), 0);
}

/// R311li/R311lj/R311lm — the Reply-before-Final contiguity guarantee,
/// now STRUCTURAL. A queryable handler ("reply") job and the
/// ResponseFinal ("final") job staged after it in ONE window are emptied
/// by the single serialized `drain` (the only public emptier —
/// `take_batch` is `pub(crate)`), so they run on one drainer in stage
/// order. There is no public path that could `mem::take` a half-staged
/// window and emit the Final ahead of its Reply (the Finding-A hazard
/// the R311li review surfaced); this pins the observable ordering the
/// structure now enforces by construction.
#[test]
fn serialized_drain_keeps_reply_before_final() {
    let queue = Queue::new();
    let order: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
    let o_reply = order.clone();
    queue.stage(Box::new(move || o_reply.lock().unwrap().push("reply")));
    let o_final = order.clone();
    queue.stage(Box::new(move || o_final.lock().unwrap().push("final")));
    assert_eq!(queue.drain(&serializer()), 2);
    assert_eq!(
        *order.lock().unwrap(),
        vec!["reply", "final"],
        "serialized drain runs the staged pair in order: Reply before Final",
    );
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
    assert_eq!(queue.drain(&serializer()), 2);
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
    queue.drain(&serializer());
    assert_eq!(*fired.lock().unwrap(), 0, "dead cell must not fire");
}

type LogCell = Cell<Arc<Mutex<Vec<&'static str>>>>;

/// R3137 -- calls run in the order their places were taken, not the order
/// their drainers reach the cell.
///
/// Two drainers holding consecutive batches reach a cell in either order, and
/// one of them can find the callback at rest between the other's calls, so
/// "whoever arrives runs" reorders a stream: a GET's Final ran between its
/// replies and retired the cell, and the replies after it were dropped. The
/// places are taken where the calls are staged; here, in a row, with the
/// calls then made in the reverse order.
#[test]
fn calls_run_in_the_order_of_their_tickets_whichever_arrives_first() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let cell: LogCell = Cell::new(log.clone());
    let (first, second, third) = (cell.ticket(), cell.ticket(), cell.ticket());

    third.invoke(|log| log.lock().unwrap().push("third"));
    second.invoke(|log| log.lock().unwrap().push("second"));
    assert!(
        log.lock().unwrap().is_empty(),
        "a call whose turn has not come is held, not run ahead of the first"
    );
    first.invoke(|log| log.lock().unwrap().push("first"));
    assert_eq!(
        *log.lock().unwrap(),
        vec!["first", "second", "third"],
        "the call that completes the order runs everything that was waiting on it"
    );
}

/// R3137 -- the terminal call keeps its place: arriving before the calls
/// ahead of it, it is held for them, and then retires the cell.
#[test]
fn a_last_call_that_arrives_early_waits_for_the_calls_ahead_of_it() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let cell: LogCell = Cell::new(log.clone());
    let (reply, last) = (cell.ticket(), cell.ticket());

    last.invoke_last(|log| log.lock().unwrap().push("final"));
    assert!(
        log.lock().unwrap().is_empty(),
        "the Final waits for the reply"
    );
    assert!(
        !cell.is_dead(),
        "the cell is not retired before its last call ran"
    );
    reply.invoke(|log| log.lock().unwrap().push("reply"));
    assert_eq!(*log.lock().unwrap(), vec!["reply", "final"]);
    assert!(cell.is_dead());
}

/// R3137 -- a place that is given up does not hold the calls behind it.
#[test]
fn a_ticket_dropped_unused_does_not_hold_up_the_calls_behind_it() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let cell: LogCell = Cell::new(log.clone());
    let (abandoned, behind) = (cell.ticket(), cell.ticket());

    behind.invoke(|log| log.lock().unwrap().push("behind"));
    assert!(log.lock().unwrap().is_empty(), "held for the place ahead");
    drop(abandoned);
    assert_eq!(
        *log.lock().unwrap(),
        vec!["behind"],
        "giving the place up lets the waiting call run"
    );
}

/// R3137 -- a terminal call handed to the active drainer is still run, after
/// the calls queued ahead of it, and the cell is retired once it has.
///
/// The second drainer of a GET's reply cell is modelled by the one deterministic
/// way a cell is ever "mid-fire": a call made from inside the callback itself,
/// which the cell backlogs for the running call to carry out before it restores.
#[test]
fn a_last_call_handed_to_the_active_drainer_runs_after_the_calls_ahead_of_it() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let cell: LogCell = Cell::new(log.clone());
    let inner = cell.clone();
    cell.invoke(move |log| {
        log.lock().unwrap().push("first");
        // Both arrive while this call is running, so both are only backlogged.
        inner.invoke(|log| log.lock().unwrap().push("reply"));
        inner.invoke_last(|log| log.lock().unwrap().push("final"));
    });
    assert_eq!(
        *log.lock().unwrap(),
        vec!["first", "reply", "final"],
        "the active drainer carries out the backlog in order, the last call included"
    );
    assert!(cell.is_dead(), "the cell is retired by its last call");
    cell.invoke(|log| log.lock().unwrap().push("late"));
    assert_eq!(
        log.lock().unwrap().len(),
        3,
        "nothing follows the last call"
    );
}

/// R3137 -- the shape `invoke_last` replaces, pinned so the reason stays
/// visible: `invoke` followed by `kill` loses a call that was only backlogged.
/// Were this to start delivering, `invoke_last` would have nothing left to fix.
#[test]
fn invoke_then_kill_discards_a_call_that_was_only_backlogged() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let cell: LogCell = Cell::new(log.clone());
    let inner = cell.clone();
    cell.invoke(move |log| {
        log.lock().unwrap().push("first");
        inner.invoke(|log| log.lock().unwrap().push("reply"));
        inner.invoke(|log| log.lock().unwrap().push("final"));
        inner.kill();
    });
    assert_eq!(
        *log.lock().unwrap(),
        vec!["first"],
        "a kill right after an invoke that backlogged discards the backlog"
    );
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
