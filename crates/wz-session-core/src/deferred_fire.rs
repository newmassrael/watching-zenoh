// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//!   of resurrecting it) without deadlocking on its own cell. R311lg —
//!   an invoke that finds the callback mid-fire on another drainer
//!   BACKLOGS its call instead of skipping it (lossless overlap): the
//!   active drainer runs the backlog FIFO before restoring, so every
//!   accepted fire is delivered exactly once even when two drain
//!   sites overlap on one cell (drive loop + a query-tail or
//!   sweep-task drain — the data-plane shape).
//!
//! ## Contracts
//!
//! - **Drain discipline.** Whoever dispatches the observer must drain
//!   the queue after releasing the observer lock (the session-tier
//!   dispatch SSOT does this); an undrained queue delays fires until
//!   the next drain, it never drops them.
//! - **Batch atomicity (R311lj behaviour, R311lm structure).** The
//!   ONLY way to empty the queue is [`DeferredFireQueue::drain`], which
//!   takes each batch while holding a caller-supplied *serializer* lock
//!   (the AP session passes its observer mutex). Since every `stage`
//!   runs inside that same lock's window, the take cannot interleave a
//!   half-staged window: it observes a whole number of complete windows.
//!   This guarantees a queryable handler job and its trailing
//!   ResponseFinal job (both staged in one dispatch window) land in one
//!   batch on one drainer, so Reply precedes Final on the wire even when
//!   an auxiliary drainer (a query-tail / publish / sweep drain) races
//!   the drive loop. R311li's session review surfaced the Finding-A
//!   hazard — an auxiliary drainer `mem::take`-ing the queue mid-window
//!   without the serializer and splitting that pair. R311lj closed it by
//!   making the production drain take under the observer lock; R311lm
//!   makes that the *only representable* drain: `take_batch` is
//!   `pub(crate)` and `drain` is the sole public emptier, so a bypassing
//!   take is a compile-time impossibility, not a convention to uphold.
//! - **Ordering.** Jobs run in stage order — wire order across planes
//!   (a matching flip staged before a decl fire runs before it). With
//!   the observer-lock take, every batch is a whole number of complete
//!   staging windows in stage order; a single drainer runs each batch
//!   FIFO. Auxiliary drainers take disjoint batches (the take is
//!   serialized by the observer lock), and per-cell delivery stays
//!   FIFO + lossless via the cell backlog when two batches touch one
//!   cell.
//! - **Late fires.** A fire staged before an undeclare but drained
//!   after it is suppressed by the dead-marked cell — the callback
//!   never observes a post-undeclare event.
//!
//! ## Gating
//!
//! `alloc::sync::Arc` needs `target_has_atomic = "ptr"` (absent on
//! ARMv6-M), so this module is gated on the `deferred-fire` feature
//! ALONE (R311me; the feature implies `alloc`). Its sole consumer is the
//! AP Session tier (wz-runtime-tokio), which enables `deferred-fire`
//! unconditionally; every other profile keeps the inline-fire path. The
//! single-task MCU profile drives registries directly (no outer observer
//! mutex) and stages its multicast liveliness / queryable replies through
//! the Rc-backed `MulticastReplyQueue`, so it never enables
//! `deferred-fire` and stays Arc-free on thumbv6m. (Before R311me the gate
//! also fired on the decl-sink / data-plane features — a pre-R311lh
//! artifact, grown by R311lb/lc/lg, that compiled this module *unused*
//! wherever `liveliness-token` et al. were on; that is what dragged `Arc`
//! onto the M0 multicast profile. See the lib.rs module-decl comment for
//! the full history.)

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
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

    /// Swap the staged jobs out as one batch and return them, leaving
    /// the queue empty. Takes ONLY the queue lock.
    ///
    /// R311lm — `pub(crate)`: the ONLY caller is [`Self::drain`], which
    /// performs the take while holding the serializer lock. There is no
    /// public path that takes a batch without that lock, so a batch can
    /// never be taken mid-staging-window — the Finding-A half-window
    /// split (R311li session review) is *unrepresentable*, not merely
    /// guarded by convention. R311lj established the take-under-the-lock
    /// discipline by documentation; R311lm makes it structural by
    /// removing every public take that bypasses the serializer.
    pub(crate) fn take_batch(&self) -> Vec<FireJob> {
        R::with_mutex_mut(&self.jobs, core::mem::take)
    }

    /// THE single drain entry point: take the staged batch while holding
    /// `serializer`, then run the batch with every lock RELEASED, looping
    /// until the queue is empty. The drain-until-empty loop catches fires
    /// staged by the running callbacks themselves (a callback's own
    /// declare can flip another watch synchronously via a loopback
    /// dispatch). Returns the number of jobs run.
    ///
    /// `serializer` is the SAME lock every [`stage`](Self::stage) site
    /// holds for the duration of its staging window (the AP session
    /// passes its observer mutex). Because the take and the stages share
    /// that lock, the take observes only WHOLE staging windows: a
    /// queryable handler job and its trailing ResponseFinal job (staged
    /// in one window) always land in one batch, run on one drainer, in
    /// order (Reply-before-Final) — even when an auxiliary drainer (a
    /// query/publish tail, the sweep task) races the drive loop. R311lm —
    /// because [`take_batch`](Self::take_batch) is `pub(crate)`, this
    /// serialized form is the ONLY way to empty the queue, so the
    /// Finding-A split (R311li) is structurally impossible rather than
    /// convention-enforced. The serializer type `G` is opaque: the queue
    /// does not know it is an observer, only that some lock serializes
    /// staging against draining (the honest contract, zero coupling to
    /// the observer type).
    ///
    /// MUST be called with `serializer` RELEASED (the jobs run between
    /// re-takes may re-enter any serializer-locking API); calling it
    /// while holding `serializer` self-deadlocks on the first take.
    pub fn drain<G>(&self, serializer: &<R as Runtime>::Mutex<G>) -> usize
    where
        G: Send + 'static,
    {
        let mut fired = 0;
        loop {
            let batch = R::with_mutex_mut(serializer, |_serialized| self.take_batch());
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

/// One call that reached its cell before its turn, or while the callback
/// was mid-fire on another drainer (R311lg), parked for whichever drainer
/// is, or becomes, the cell's runner.
type ParkedCall<F> = Box<dyn FnOnce(&mut F) + Send + 'static>;

/// Slot state behind a [`DeferredListenerCell`]: the callback (absent
/// while a call is mid-fire — taken out so the user code runs with the
/// cell unlocked), the dead marker an undeclare sets, and the TURN
/// bookkeeping that makes the cell's calls run in the order they were
/// accepted (R3137).
///
/// `issued` hands out the next ticket; `next` is the ticket whose turn it
/// is. A call whose ticket is not `next` waits in `parked` however many
/// drainers are running and in whatever order they arrive.
struct CellState<F> {
    callback: Option<F>,
    dead: bool,
    issued: u64,
    next: u64,
    parked: BTreeMap<u64, ParkedCall<F>>,
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
                issued: 0,
                next: 0,
                parked: BTreeMap::new(),
            })),
        }
    }

    /// Mark the listener dead, drop the callback if it is at rest, and
    /// discard any backlogged calls. The undeclare path: a
    /// staged-but-undrained job for this cell becomes a no-op, a
    /// backlogged call is dropped, and a job CURRENTLY mid-fire
    /// (callback taken out) drops the callback at restore instead of
    /// resurrecting it — which is what makes self-undeclare from
    /// inside the callback safe.
    pub fn kill(&self) {
        R::with_mutex_mut(&self.state, |s| {
            s.dead = true;
            s.callback = None;
            s.parked.clear();
        });
    }

    /// Whether [`kill`](Self::kill) has run.
    pub fn is_dead(&self) -> bool {
        R::with_mutex_mut(&self.state, |s| s.dead)
    }

    /// Take a place in the cell's order. The call made through the returned
    /// [`Ticket`] runs after every call that took an earlier ticket and
    /// before every call that takes a later one, whichever drainers carry
    /// them and in whatever order those drainers arrive (R3137).
    ///
    /// Taken where the call is ACCEPTED, which is where its place in the
    /// order is decided; [`stage`](Self::stage) does exactly that for a
    /// deferred fire. A ticket that is never used must be dropped, which
    /// gives its place up; one that is leaked would hold up every call
    /// behind it.
    pub fn ticket(&self) -> Ticket<R, F> {
        let number = R::with_mutex_mut(&self.state, |s| {
            let number = s.issued;
            s.issued += 1;
            number
        });
        Ticket {
            cell: self.clone(),
            number,
            spent: false,
        }
    }

    /// Stage a call for this cell on `queue`, in the order staged.
    ///
    /// The place in the cell's order is taken HERE, inside the staging
    /// window, not when the job is eventually run: two drainers can hold
    /// consecutive batches at the same time and reach the cell in either
    /// order, and the order the calls were staged in is the one that must
    /// survive that.
    pub fn stage(&self, queue: &DeferredFireQueue<R>, f: impl FnOnce(&mut F) + Send + 'static) {
        let ticket = self.ticket();
        queue.stage(Box::new(move || ticket.invoke(f)));
    }

    /// [`stage`](Self::stage) for the cell's LAST call; see
    /// [`invoke_last`](Self::invoke_last).
    pub fn stage_last(
        &self,
        queue: &DeferredFireQueue<R>,
        f: impl FnOnce(&mut F) + Send + 'static,
    ) {
        let ticket = self.ticket();
        queue.stage(Box::new(move || ticket.invoke_last(f)));
    }

    /// Take-call-restore: run `f` over the callback with the cell
    /// UNLOCKED (the callback may re-enter any session API, including
    /// [`kill`](Self::kill) on this very cell). Silently drops the call
    /// when the cell is dead.
    ///
    /// The call takes its place in the order when it is made. A caller that
    /// must fix its place EARLIER than that, because it will be made later
    /// from a job some other drainer may reach first, takes a
    /// [`ticket`](Self::ticket) (or uses [`stage`](Self::stage)).
    ///
    /// R311lg — lossless overlap: when the callback is mid-fire on
    /// another drainer (drive loop vs a query-tail / sweep-task drain —
    /// the data-plane multi-drainer shape), the call is PARKED instead of
    /// skipped; the active drainer runs what is parked, in order, before
    /// restoring the callback, so every call accepted by a live cell runs
    /// exactly once, serialized, still outside every framework lock. A
    /// re-entrant invoke from INSIDE this cell's own callback parks the
    /// same way and runs before the restore.
    pub fn invoke(&self, f: impl FnOnce(&mut F) + Send + 'static) {
        self.ticket().invoke(f);
    }

    /// Run the call with ticket `number`, in its turn.
    ///
    /// The call is parked under its number. If the callback is at rest and
    /// it is that number's turn, this drainer becomes the cell's runner: it
    /// takes the callback and runs the parked calls in order, the one it
    /// arrived with and every later number that has arrived, until the next
    /// number is still missing; then it restores the callback. If the
    /// callback is out, its runner picks the call up. If it is at rest but
    /// the turn is an earlier number's, whoever holds that number runs this
    /// call after its own.
    fn run_ticket(&self, number: u64, call: ParkedCall<F>) {
        let mut pending = Some(call);
        let taken = R::with_mutex_mut(&self.state, |s| {
            if s.dead {
                // Drop the call; `pending` falls out of scope at fn
                // exit, outside the cell lock.
                return None;
            }
            let call = pending.take().expect("pending set just above");
            s.parked.insert(number, call);
            if s.parked.contains_key(&s.next) {
                s.callback.take()
            } else {
                None
            }
        });
        let Some(callback) = taken else {
            return;
        };
        // Run-or-restore loop: run the parked calls in their order until
        // the next number is missing, then restore — unless a kill arrived,
        // in which case the callback (and whatever is still parked) is
        // dropped. `callback_slot` is taken by the restore arm, so a
        // surviving `Some` after the loop drops outside the cell lock.
        let mut callback_slot = Some(callback);
        loop {
            let next = R::with_mutex_mut(&self.state, |s| {
                if s.dead {
                    s.parked.clear();
                    return None;
                }
                let turn = s.next;
                match s.parked.remove(&turn) {
                    Some(call) => {
                        s.next += 1;
                        Some(call)
                    }
                    None => {
                        s.callback = callback_slot.take();
                        None
                    }
                }
            });
            let Some(call) = next else { return };
            let callback = callback_slot
                .as_mut()
                .expect("parked calls are handed to the cell's runner only");
            call(callback);
        }
    }

    /// Run `f` as the cell's LAST call, then retire the cell: the terminal
    /// fire of a stream (a GET's Final), which no later call may follow.
    ///
    /// This is NOT [`invoke`](Self::invoke) followed by [`kill`](Self::kill),
    /// and the difference is the reason it exists. `invoke` returns before
    /// `f` has run whenever the callback is mid-fire on another drainer: the
    /// call is only parked, for that drainer to run. A `kill` issued right
    /// after it clears what is parked, so it discards `f` together with
    /// every earlier call still waiting behind the active one, and a stream
    /// whose replies and Final were handed over in that window ends having
    /// delivered neither the last replies nor its Final. Measured on a local
    /// GET with a second drainer: three of four replies heard, the Final
    /// never, nothing staged anywhere.
    ///
    /// Here the retirement runs INSIDE the call, after `f`, on whichever
    /// drainer runs it. Calls run in ticket order, so every call accepted
    /// before this one has already run by then; the runner's loop sees the
    /// cell dead, drops what is left and does not restore the callback. A
    /// call that finds the cell already dead is dropped, as for `invoke`.
    pub fn invoke_last(&self, f: impl FnOnce(&mut F) + Send + 'static) {
        self.ticket().invoke_last(f);
    }
}

/// A place in a [`DeferredListenerCell`]'s order of calls, taken with
/// [`DeferredListenerCell::ticket`].
///
/// Using it runs the call in its turn; dropping it unused gives the place up
/// so the calls behind it are not held for a call that will never be made
/// (a staged job discarded unrun, a panic unwinding past it).
pub struct Ticket<R: Runtime, F: Send + 'static> {
    cell: DeferredListenerCell<R, F>,
    number: u64,
    spent: bool,
}

impl<R: Runtime, F: Send + 'static> Ticket<R, F> {
    /// Run `f` over the cell's callback in this ticket's turn; see
    /// [`DeferredListenerCell::invoke`].
    pub fn invoke(mut self, f: impl FnOnce(&mut F) + Send + 'static) {
        self.spent = true;
        self.cell.run_ticket(self.number, Box::new(f));
    }

    /// Run `f` as the cell's last call in this ticket's turn; see
    /// [`DeferredListenerCell::invoke_last`].
    pub fn invoke_last(mut self, f: impl FnOnce(&mut F) + Send + 'static) {
        self.spent = true;
        let state = Arc::clone(&self.cell.state);
        self.cell.run_ticket(
            self.number,
            Box::new(move |callback| {
                f(callback);
                R::with_mutex_mut(&state, |s| {
                    s.dead = true;
                    s.parked.clear();
                });
            }),
        );
    }
}

impl<R: Runtime, F: Send + 'static> Drop for Ticket<R, F> {
    fn drop(&mut self) {
        if !self.spent {
            // An empty call in this place: the calls behind it can run.
            self.cell.run_ticket(self.number, Box::new(|_| {}));
        }
    }
}
