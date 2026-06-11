// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ky — deferred callback firing (the F-6 structural fix).
//!
//! ## The problem this solves
//!
//! The AP session wraps the whole [`crate::observer::ApplicationLayerObserver`]
//! in one `Arc<R::Mutex<…>>`, and the drive-loop dispatch fires
//! application callbacks while that mutex is held. Any callback that
//! calls back into an observer-locking session API —
//! `get_matching_status`, a declare, a registry consult —
//! self-deadlocks (std `Mutex`) or RefCell-panics (MCU). R311kj
//! documented the constraint on every decl/matching sink; this module
//! removes it structurally for listeners registered through the
//! deferred seam: the registry-installed sink only RECORDS the fire,
//! and the user callback runs AFTER the observer lock is released.
//!
//! (zenoh-pico fires matching callbacks under its own write-filter ctx
//! mutex, never the session lock — `_z_write_filter_ctx_update_state`,
//! src/net/filtering.c:69-84 — so its callbacks may use the session
//! freely. The deferred queue is wz's equivalent decoupling, one tier
//! up: callbacks here run under NO framework lock at all.)
//!
//! ## Shape
//!
//! Two pieces, both Model B sinks' building blocks rather than a
//! registry redesign (the registries and the observer bundle are
//! UNCHANGED — a deferred listener is just another sink impl):
//!
//! - [`DeferredFireQueue`] — the per-session staging queue. The sink
//!   installed in a registry captures a queue handle and pushes one
//!   [`FireJob`] per fire (still under the observer lock — the push
//!   takes only the queue's own lock, strictly INSIDE the observer
//!   hold, never the reverse, so the lock order `observer > queue` is
//!   acyclic). The dispatch SSOT drains the queue after the observer
//!   lock drops and runs each job lock-free.
//! - [`DeferredListenerCell`] — the per-listener callback slot a job
//!   fires through. Take-call-restore: the job takes the callback OUT
//!   of the cell, runs it with the cell unlocked, and restores it
//!   afterwards — so a callback may undeclare ITSELF (the undeclare
//!   marks the cell dead; the restore then drops the callback instead
//!   of resurrecting it) without deadlocking on its own cell.
//!
//! ## Contracts
//!
//! - **Drain discipline.** Whoever dispatches the observer must drain
//!   the queue after releasing the observer lock (the session-tier
//!   dispatch SSOT does this); an undrained queue delays fires until
//!   the next drain, it never drops them.
//! - **Ordering.** Jobs run in stage order — wire order across planes
//!   (a matching flip staged before a decl fire runs before it),
//!   single-drainer. Production has one drive loop per session, so a
//!   single drainer is the operating shape; two concurrent drainers
//!   would interleave batches (each batch internally ordered).
//! - **Late fires.** A fire staged before an undeclare but drained
//!   after it is suppressed by the dead-marked cell — the callback
//!   never observes a post-undeclare event.
//!
//! ## Gating
//!
//! `alloc::sync::Arc` needs `target_has_atomic = "ptr"` (absent on
//! ARMv6-M), so the module rides the consumer-feature union — exactly
//! the envelope of the session tier that needs it, keeping the
//! thumbv6m session-unicast lane (G.10) Arc-free. R311lb grew the
//! union from `session-matching` alone to the decl-sink planes
//! (`declare-subscriber` / `declare-queryable` / `liveliness-token`,
//! each under `alloc`) for the Session-tier deferred decl listeners
//! (R311lc). The single-task MCU profile that drives registries
//! directly (no outer observer mutex) does not need deferral and
//! keeps the inline-fire path.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use wz_runtime_core::Runtime;

/// One staged callback invocation: the listener cell handle + the fire
/// arguments, pre-bound into an invocable. `Send` because the AP queue
/// handle crosses worker threads (the `R::Mutex` GAT requires its
/// payload `Send` anyway).
pub type FireJob = Box<dyn FnOnce() + Send + 'static>;

/// Per-session staging queue for deferred callback fires. Cheap-`Clone`
/// handle (an `Arc` over the runtime mutex); the session keeps one end,
/// every deferred sink installed in a registry keeps another.
pub struct DeferredFireQueue<R: Runtime> {
    jobs: Arc<R::Mutex<Vec<FireJob>>>,
}

// Manual Clone: a derive would add the unwanted `R: Clone` bound
// (the PublisherAliased / Querier R267 convention).
impl<R: Runtime> Clone for DeferredFireQueue<R> {
    fn clone(&self) -> Self {
        Self {
            jobs: Arc::clone(&self.jobs),
        }
    }
}

impl<R: Runtime> Default for DeferredFireQueue<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Runtime> DeferredFireQueue<R> {
    /// New empty queue.
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(R::new_mutex(Vec::new())),
        }
    }

    /// Stage one fire. Called by a deferred sink while the OBSERVER
    /// lock is held — this takes only the queue's own lock for the
    /// push (lock order `observer > queue`, never reversed: the drain
    /// swaps the batch out under the queue lock and runs it after
    /// release, so no path holds the queue lock and then wants the
    /// observer).
    pub fn stage(&self, job: FireJob) {
        R::with_mutex_mut(&self.jobs, |jobs| jobs.push(job));
    }

    /// Drain and run every staged job OUTSIDE every framework lock.
    /// Call with the observer lock RELEASED. Loops until the queue is
    /// empty so fires staged by the running callbacks themselves (a
    /// callback's own declare can flip another watch synchronously via
    /// a loopback dispatch) run in the same drain. Returns the number
    /// of jobs run.
    pub fn drain_and_fire(&self) -> usize {
        let mut fired = 0;
        loop {
            let batch = R::with_mutex_mut(&self.jobs, core::mem::take);
            if batch.is_empty() {
                return fired;
            }
            for job in batch {
                job();
                fired += 1;
            }
        }
    }

    /// Number of currently staged (not yet drained) jobs.
    pub fn len(&self) -> usize {
        R::with_mutex_mut(&self.jobs, |jobs| jobs.len())
    }

    /// Whether no jobs are staged.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Slot state behind a [`DeferredListenerCell`]: the callback (absent
/// while a job is mid-fire — taken out so the user code runs with the
/// cell unlocked) and the dead marker an undeclare sets.
struct CellState<F> {
    callback: Option<F>,
    dead: bool,
}

/// Per-listener callback slot fired through by a deferred [`FireJob`].
/// Cheap-`Clone` handle: the session-tier listener handle keeps one end
/// (for [`kill`](Self::kill) on undeclare), each staged job captures
/// another.
pub struct DeferredListenerCell<R: Runtime, F: Send + 'static> {
    state: Arc<R::Mutex<CellState<F>>>,
}

impl<R: Runtime, F: Send + 'static> Clone for DeferredListenerCell<R, F> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<R: Runtime, F: Send + 'static> DeferredListenerCell<R, F> {
    /// New live cell holding `callback`.
    pub fn new(callback: F) -> Self {
        Self {
            state: Arc::new(R::new_mutex(CellState {
                callback: Some(callback),
                dead: false,
            })),
        }
    }

    /// Mark the listener dead and drop the callback if it is at rest.
    /// The undeclare path: a staged-but-undrained job for this cell
    /// becomes a no-op, and a job CURRENTLY mid-fire (callback taken
    /// out) drops the callback at restore instead of resurrecting it —
    /// which is what makes self-undeclare from inside the callback
    /// safe.
    pub fn kill(&self) {
        R::with_mutex_mut(&self.state, |s| {
            s.dead = true;
            s.callback = None;
        });
    }

    /// Whether [`kill`](Self::kill) has run.
    pub fn is_dead(&self) -> bool {
        R::with_mutex_mut(&self.state, |s| s.dead)
    }

    /// Take-call-restore: run `f` over the callback with the cell
    /// UNLOCKED (the callback may re-enter any session API, including
    /// [`kill`](Self::kill) on this very cell). Skips silently when the
    /// cell is dead or the callback is mid-fire elsewhere (single-
    /// drainer production never overlaps; a second drainer's overlap
    /// skips rather than blocks).
    pub fn invoke(&self, f: impl FnOnce(&mut F)) {
        let taken = R::with_mutex_mut(&self.state, |s| s.callback.take());
        let Some(mut callback) = taken else {
            return;
        };
        f(&mut callback);
        R::with_mutex_mut(&self.state, |s| {
            if !s.dead {
                s.callback = Some(callback);
            }
        });
    }
}
