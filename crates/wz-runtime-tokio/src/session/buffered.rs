// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2703 §5.26 — a subscription whose delivery can say "not now".
//!
//! ## The defect this exists for
//!
//! A [`declare_subscriber`](super::Session::declare_subscriber) callback runs
//! INLINE on the drive loop. The R311ky deferred-fire queue moved those
//! callbacks outside the observer lock, not off the loop, so a callback that
//! blocks stalls keepalive, lease and every other subscription on the session.
//! Every consumer that needs a queue therefore drops on overflow —
//! `wz-rest`'s SSE bridge says so in its own comment — and dropping is the one
//! thing this tree has already decided against on the TX side:
//!
//! > steady state keeps its unbounded await, because there the peer's
//! > backpressure IS the flow control and cutting a write short would be the
//! > same data loss in a different place.
//! > — `crates/wz-runtime-tokio/src/writer_queue.rs`
//!
//! So wz contradicts itself: wait-don't-drop outbound, drop-don't-wait inbound.
//! Upstream does not — its SSE subscribes through a blocking FIFO handler
//! (`plugins/zenoh-plugin-rest/src/lib.rs` @ `_subscriber: Subscriber<FifoChannelHandler<Sample>>`),
//! and a slow client applies backpressure all the way into the session.
//!
//! ## Why the fix is a STAGE and not a blocking callback
//!
//! Upstream blocks its caller too — that is what backpressure IS. The
//! difference is the RADIUS: upstream stalls one transport's rx task while its
//! keepalive lives on another, and wz has one drive loop per session. So wz
//! cannot block where the callback runs; it has to block somewhere the stall
//! costs only this session's progress, which is the loop itself, at an await.
//!
//! ## Two stages, and why the staging half can be unbounded
//!
//! The callback stages into [`BufferedStage`] without waiting (it is on the
//! loop, and must not wait there). A separate drain — awaited BY the loop —
//! moves staged items into the consumer's bounded channel and waits for
//! capacity. That queue cannot grow without bound even though nothing caps it:
//! while the drain is awaiting, the loop is not polling, so no further samples
//! arrive to stage. Backpressure holds the staging queue down by construction,
//! which is why putting a bound there would be belt-and-braces that only hides
//! a stall as a drop.
//!
//! ⚠ Nothing here is in the `no_std` core, deliberately. The callback is a
//! CLOSURE, so it can capture runtime-side state; staging needs no session-core
//! type and no async reaches a profile that has no executor.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::mpsc;

/// One buffered subscription's drain, type-erased so a session can hold several
/// carrying different item types.
///
/// A trait rather than a closure because the drain is an `async fn` in all but
/// name: it must be callable by the loop, own its future's lifetime, and be
/// `Send + Sync` to sit in shared session state.
pub(crate) trait BufferedDrain: Send + Sync {
    /// Move every staged item into the consumer's channel, AWAITING capacity,
    /// and return when the stage is empty or the consumer has gone away.
    fn drain(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// The staging half of a buffered subscription: what the drive-loop callback
/// pushes into, and what the loop's drain empties.
pub(crate) struct BufferedStage<I> {
    staged: Mutex<VecDeque<I>>,
    tx: mpsc::Sender<I>,
    /// Capacity the consumer's queue was sized at — the threshold past which a
    /// staging backlog means nobody is draining. See [`Self::stage`].
    capacity: usize,
    /// Whether the "nobody is draining" diagnostic has already been emitted, so
    /// a wedged deploy logs once rather than per sample.
    warned: AtomicBool,
}

impl<I> BufferedStage<I> {
    fn new(tx: mpsc::Sender<I>, capacity: usize) -> Self {
        Self {
            staged: Mutex::new(VecDeque::new()),
            tx,
            capacity,
            warned: AtomicBool::new(false),
        }
    }

    /// Stage one item. Called from the subscriber callback, ON the drive loop,
    /// so it never waits — the waiting is [`BufferedDrain::drain`]'s job.
    ///
    /// Poison is absorbed rather than unwrapped, as `dynamic_volume`'s registry
    /// lock does: a panic elsewhere must not turn sample delivery into a
    /// data-plane panic.
    /// ⚠ It also carries the one diagnostic this seam needs. A staging backlog
    /// past the consumer's own capacity cannot happen while the loop drains —
    /// the drain empties the stage before the loop polls again — so it means the
    /// drive loop is NOT awaiting [`BufferedDrain::drain`]: a host wired
    /// `on_event` to its session and forgot `after_dispatch`. The symptom
    /// otherwise is a subscription that answers healthily and delivers nothing,
    /// which is precisely the failure R2423 spent a round diagnosing on this
    /// same SSE path. Logged ONCE per subscription, not per sample.
    fn stage(&self, item: I) {
        // R2705 — DELIVER HERE WHEN THE CONSUMER HAS ROOM, and stage only when
        // it does not. The staging seam was built for the full-channel case,
        // where the wait has to leave the callback; it made delivery in EVERY
        // case depend on a host wiring `LoopStages::after_dispatch`, and
        // `drive_session_until_terminal` defaults that stage to a no-op. So a
        // subscription declared through the simple entry point answered
        // healthily and delivered nothing — measured as the hosted Layer Z red
        // on `wz_rest_sse_renders_the_same_sample_as_the_zenohd_rest_plugin`,
        // where zenohd's own SSE carried the sample and wz's carried only
        // heartbeats. The diagnostic below had already named this exact cause;
        // what was missing was a path that does not need the host to know.
        //
        // ORDERING: taken ONLY when nothing is staged and no drain holds a
        // popped item, so a direct send can never overtake an earlier sample.
        // The lock is held across `try_send` deliberately — it does not await,
        // and holding it is what makes "stage is empty" and "sent" one step.
        let item = {
            let staged = self
                .staged
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if staged.is_empty() {
                match self.tx.try_send(item) {
                    Ok(()) => return,
                    Err(mpsc::error::TrySendError::Full(item)) => item,
                    // The consumer is gone; its subscription is being torn down.
                    Err(mpsc::error::TrySendError::Closed(_)) => return,
                }
            } else {
                item
            }
        };
        let depth = {
            let mut staged = self
                .staged
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            staged.push_back(item);
            staged.len()
        };
        if depth > self.capacity && !self.warned.swap(true, Ordering::Relaxed) {
            log::error!(
                "buffered subscription has {depth} samples staged with a consumer \
                 capacity of {}: the drive loop is not awaiting its drain, so this \
                 subscription will deliver nothing. Drive it with \
                 `drive_session_until_terminal_with_extra_deadline` and a \
                 `LoopStages::after_dispatch` that awaits `Session::drain_buffered`.",
                self.capacity
            );
        }
    }
}

impl<I: Send + 'static> BufferedDrain for BufferedStage<I> {
    fn drain(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            loop {
                // The lock is taken and RELEASED before the await below. Holding
                // it across the send would let a slow consumer block the
                // callback that stages, which is the stall this seam exists to
                // keep off the loop's critical section.
                let next = {
                    let staged = self
                        .staged
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    staged.is_empty()
                };
                if next {
                    return;
                }
                // THE AWAIT THAT IS THE WHOLE POINT. A full channel suspends the
                // drive loop here rather than dropping the sample.
                //
                // R2705 — it awaits a PERMIT and pops only once it holds one, so
                // two things hold that a pop-then-send did not. Cancellation:
                // `park_on_drain` races this future in a `select!`, and a future
                // cancelled while awaiting a permit has taken nothing out of the
                // stage, where one cancelled between a pop and its send would
                // have dropped that sample. Ordering: the pop and the permit's
                // send happen under one hold of the stage lock, and the direct
                // send in `stage` needs that same lock, so nothing can overtake
                // an item that is on its way out.
                let Ok(permit) = self.tx.reserve().await else {
                    // The consumer is gone; its subscription is being torn down
                    // and the remaining staged items have nowhere to go.
                    return;
                };
                {
                    let mut staged = self
                        .staged
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    match staged.pop_front() {
                        Some(item) => permit.send(item),
                        None => return,
                    }
                }
            }
        })
    }
}

/// R2708 (open-debt item 785) — A HANDLE TO THIS SESSION'S DRAIN, for an
/// embedder that drives a loop of its own.
///
/// # What it is NOT any more
///
/// R2707 introduced this as an OBLIGATION: a buffered subscription's samples
/// moved only while the drive loop awaited it, so the declaration handed the
/// duty back as a `#[must_use]` value. That was the honest repair available at
/// the time, because the loop had no way to reach a session's drains — it never
/// holds a `Session`, and its one route to one (`on_event`) is synchronous.
///
/// R2708 removed the reason. The drains now hang off
/// `SessionRuntime::IterationWork` on the kernel the loop already holds, so
/// `drive_session_until_terminal*` awaits them unasked. A host that drops this
/// value is correct.
///
/// # What it is still for
///
/// Reaching the same drain WITHOUT holding the session — an embedder driving
/// through a loop wz does not own, which is the one case the kernel route does
/// not cover. It drains EVERY buffered subscription of its session, not just
/// the one whose declaration returned it, so one handle is the whole session.
// R2708 (item 785) — THE `#[must_use]` IS GONE, and its removal is the point
// rather than a tidy-up. R2707 put one here saying "drop this and your
// subscription stalls", which was true then and is FALSE now: the loop awaits
// this session's drains whether or not anybody holds this value. A lint that
// states a consequence which no longer follows is worse than no lint — it
// teaches a reader something untrue about the code it sits on, which is the
// class this workspace files as a rule with no subject.
#[derive(Clone)]
pub struct BufferedDrainStage {
    registry: BufferedRegistry,
}

impl BufferedDrainStage {
    /// Move every staged sample into its consumer's queue, awaiting capacity.
    ///
    /// The same walk as `Session::drain_buffered`, reachable without holding
    /// the session — which is what lets a host wire the stage into a loop it
    /// built before the subscription existed.
    pub async fn drain(&self) {
        self.registry.drain_all().await;
    }
}

impl core::fmt::Debug for BufferedDrainStage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BufferedDrainStage")
    }
}

/// Every buffered subscription a session is currently delivering to.
///
/// WEAK handles: a dropped subscription must not be kept alive by this list,
/// and a drain that finds its entry dead simply prunes it. The alternative —
/// unregistering on `Drop` — would make the subscriber handle's teardown depend
/// on reaching the session, which is exactly the coupling the `Subscriber`
/// retraction closure was built to avoid.
/// R2708 (open-debt item 785) — what a profile's
/// [`SessionRuntime::IterationWork`](wz_session_core::link::SessionRuntime::IterationWork)
/// must offer a generic-`R` session.
///
/// The kernel bounds that associated type by `Default` alone, because creating
/// an empty one is its whole interaction with it. `Session<R, ..>` is generic
/// too, so it needs a little more — and exactly a little: REGISTER a drain, and
/// hand out a stage. Both are SYNCHRONOUS, which is why no future appears in
/// this trait and none has to cross into a profile that has no executor. The
/// awaiting is done by the tokio loop, which knows the concrete type and calls
/// the inherent `drain_all` directly.
pub trait BufferedWork {
    /// Take a handle to one subscription's drain.
    ///
    /// ⚠ The argument is OPAQUE on purpose. What a drain is — a
    /// `dyn BufferedDrain` returning a boxed future — is this crate's private
    /// vocabulary, and a public trait naming it would widen the API to say
    /// something no consumer can act on. [`RegisteredDrain`] carries it across
    /// the trait boundary without spelling it.
    fn register(&self, drain: &RegisteredDrain);
    /// A handle to this session's drain, for an embedder driving its own loop.
    fn stage(&self) -> BufferedDrainStage;
}

/// One buffered subscription's drain, opaque. See [`BufferedWork::register`].
pub struct RegisteredDrain(Arc<dyn BufferedDrain>);

/// R2708 (item 785) — PUBLIC because it is now this profile's
/// `SessionRuntime::IterationWork`, which is an associated type on a public
/// trait. Its methods stay `pub(crate)`: a consumer names the type only where
/// the trait forces it to, and drives nothing through it.
#[derive(Clone, Default)]
pub struct BufferedRegistry {
    drains: Arc<Mutex<Vec<Weak<dyn BufferedDrain>>>>,
}

impl BufferedWork for BufferedRegistry {
    /// A handle to this session's drain. See [`BufferedDrainStage`].
    fn stage(&self) -> BufferedDrainStage {
        BufferedDrainStage {
            registry: self.clone(),
        }
    }

    fn register(&self, drain: &RegisteredDrain) {
        self.drains
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Arc::downgrade(&drain.0));
    }
}

impl BufferedRegistry {
    /// Drain every live buffered subscription, awaiting capacity on each, and
    /// prune the entries whose subscription has been dropped.
    ///
    /// SEQUENTIAL on purpose: a slow consumer delays the others on the same
    /// session, which is the same radius the session already has for every other
    /// kind of work the loop does. Draining them concurrently would let one
    /// subscription's backpressure be hidden by another's idleness.
    pub(crate) async fn drain_all(&self) {
        let live: Vec<Arc<dyn BufferedDrain>> = {
            let mut drains = self
                .drains
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            drains.retain(|weak| weak.strong_count() > 0);
            drains.iter().filter_map(Weak::upgrade).collect()
        };
        for drain in live {
            drain.drain().await;
        }
    }
}

/// Build a staging pair for a buffered subscription of `capacity` items.
///
/// Returns the stage the callback pushes into, the type-erased drain the
/// session registers, and the receiver the caller drains. `capacity` is the
/// CALLER's argument rather than a constant here, and that is load-bearing
/// twice over: a deploy sizes the memory a slow reader may pin, and a test can
/// reach the full-buffer branch without publishing a thousand samples first.
pub(crate) fn buffered_pair<I: Send + 'static>(
    capacity: usize,
) -> (Arc<BufferedStage<I>>, RegisteredDrain, mpsc::Receiver<I>) {
    // Fail fast and NAME the contract. `mpsc::channel(0)` panics from inside
    // tokio with a message that mentions nothing in this tree, so a caller who
    // passed a computed capacity would be told about a buffer rather than about
    // the subscription they declared. Zero is also meaningless here rather than
    // merely unsupported: a queue that can hold nothing cannot be the thing the
    // loop waits on, so there is no behaviour to define for it.
    assert!(
        capacity > 0,
        "a buffered subscription needs a capacity of at least 1; \
         0 would leave the drive loop waiting on a queue nothing can enter"
    );
    let (tx, rx) = mpsc::channel(capacity);
    let stage = Arc::new(BufferedStage::new(tx, capacity));
    let drain: Arc<dyn BufferedDrain> = stage.clone();
    (stage, RegisteredDrain(drain), rx)
}

/// Stage one item through a shared handle — the body a subscriber callback
/// runs. Free function rather than a method so the callback captures only an
/// `Arc`, keeping the closure `Send + 'static` without naming `BufferedStage`
/// at the call site.
pub(crate) fn stage_into<I>(stage: &Arc<BufferedStage<I>>, item: I) {
    stage.stage(item);
}
