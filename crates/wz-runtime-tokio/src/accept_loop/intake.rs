// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The intake of a face loop: its listeners, and the handshake of every link they yield, up to
//! the moment the link is a session the loop can hold.
//!
//! Upstream keeps the two apart from whoever holds the transports. Each listener accepts on a
//! task of its own and hands the link over a channel
//! (`io/zenoh-links/zenoh-link-tcp/src/unicast.rs` @ `async fn accept_task(`); the manager
//! closes the link unanswered when `accept_pending`
//! accepts are already in flight and otherwise spawns the accept, bounded as a whole by
//! `accept_timeout` (`io/zenoh-transport/src/unicast/manager.rs` @
//! `pub(crate) async fn handle_new_link_unicast(`). Nothing that is waiting for the routing
//! tables, or for anything else of the node, is in the way of either.
//!
//! The face loop is where a face is admitted, and an admission, a face's leaving and the
//! forwarder's tick write the node's tables: synchronously, on the loop's task, waiting for every
//! reader. When the listeners and the handshakes are arms of that same task, every link that
//! arrives while a write waits is neither accepted nor answered, and the accept deadline of a
//! handshake in flight does not run either, since its timer is only read when its future is
//! polled. [`IntakeOn::OwnTasks`] takes them off the loop's task: the intake is a task of its own
//! and each handshake another, and the loop receives finished handshakes over a channel.
//! [`IntakeOn::LoopTask`] keeps the intake one of the loop's arms, for a node whose links are
//! served by one task by contract (the `one-task` value of `routing-face-drive`, and the C
//! interfaces, whose node gate pauses the loop's task and everything polled inside it).
//!
//! An accept counts against `accept_pending` from the moment it is taken off its listener until
//! the loop has taken its finished handshake ([`PendingAccept`]), as upstream counts it until its
//! transport is up.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use tokio::sync::mpsc;

use super::accept_any;
use crate::accept_bounds::AcceptBounds;
use crate::session_open::{AcceptedLink, AcceptedPeer, BoundListener, OpenError, OpenedSession};

/// Backoff applied after an `accept()` error before the listeners are asked again: zenoh's
/// `TCP_ACCEPT_THROTTLE_TIME` (100 ms, `io/zenoh-links/zenoh-link-tcp/src/lib.rs`). The usual
/// cause is fd exhaustion (EMFILE/ENFILE): the pending connection stays in the kernel queue, so an
/// accept asked again at once returns the same error and spins. Only the listeners wait it out;
/// the handshakes in flight go on.
const ACCEPT_ERROR_THROTTLE: Duration = Duration::from_millis(100);

/// Where an intake runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IntakeOn {
    /// As one of the arms of the face loop's own task, its handshakes polled with it.
    LoopTask,
    /// As a task of its own on the runtime the loop runs on, each handshake a task of its own
    /// beside it.
    OwnTasks,
}

/// The handshake of one accepted link, from the link's own handshake (ws, tls) to the session's
/// Established, under the node's accept bound.
pub(super) type Handshake =
    Pin<Box<dyn Future<Output = Result<OpenedSession, OpenError>> + Send + 'static>>;

/// What starts the handshake of a link the intake accepted. The second argument numbers the
/// accepts of this intake from zero, in the order the listeners yielded them.
pub(super) type Opener = Box<dyn FnMut(AcceptedLink, u64) -> Handshake + Send>;

/// A handshake that has ended, either way, with the accept it came from.
pub(super) struct Handshaken {
    /// The accepted peer, as its listener tagged it.
    pub(super) peer: AcceptedPeer,
    /// The session, or how its handshake failed.
    pub(super) result: Result<OpenedSession, OpenError>,
    /// The accept's place against `accept_pending`, given back when this is dropped.
    pub(super) pending: PendingAccept,
}

/// What the intake tells the loop.
pub(super) enum IntakeEvent {
    /// A handshake ended. Boxed: a session is large, and an event is moved through a channel.
    Handshaken(Box<Handshaken>),
    /// A listener failed to accept; the intake waits [`ACCEPT_ERROR_THROTTLE`] before it asks the
    /// listeners again.
    AcceptError(io::Error),
}

/// What the intake counted since it started, read by the loop for its summary.
#[derive(Default)]
struct IntakeCounts {
    /// Links taken off a listener whose handshake was started.
    accepted: AtomicUsize,
    /// Links closed unanswered because `accept_pending` accepts were in flight.
    refused_over_pending: AtomicUsize,
    /// Accepts in flight: started and not yet taken by the loop.
    pending: AtomicUsize,
}

/// One accept in flight, counted against `accept_pending` until it is dropped.
pub(super) struct PendingAccept(Arc<IntakeCounts>);

impl PendingAccept {
    fn count(counts: &Arc<IntakeCounts>) -> Self {
        counts.pending.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(counts))
    }
}

impl Drop for PendingAccept {
    fn drop(&mut self) {
        self.0.pending.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A handshake with the accept it came from, as it is polled or spawned.
type Ending = Pin<Box<dyn Future<Output = Handshaken> + Send + 'static>>;

/// The handshakes in flight.
enum Handshakes {
    /// Polled by whoever polls the intake.
    Polled(FuturesUnordered<Ending>),
    /// Each a task of its own.
    Tasks(tokio::task::JoinSet<Handshaken>),
}

impl Handshakes {
    fn new(on: IntakeOn) -> Self {
        match on {
            IntakeOn::LoopTask => Self::Polled(FuturesUnordered::new()),
            IntakeOn::OwnTasks => Self::Tasks(tokio::task::JoinSet::new()),
        }
    }

    fn push(&mut self, ending: Ending) {
        match self {
            Self::Polled(set) => set.push(ending),
            Self::Tasks(set) => {
                set.spawn(ending);
            }
        }
    }

    /// The next handshake to end; `None` when none is in flight. Cancel-safe, as both sets'
    /// `next` are.
    async fn next(&mut self) -> Option<Handshaken> {
        match self {
            Self::Polled(set) => set.next().await,
            Self::Tasks(set) => {
                loop {
                    match set.join_next().await? {
                        Ok(ended) => return Some(ended),
                        // A handshake that panicked has no session to hand over; its accept was
                        // given back when its task unwound.
                        Err(failed) => {
                            log::error!("an accept's handshake gave no result: {failed}")
                        }
                    }
                }
            }
        }
    }
}

/// Park until `throttle` has elapsed, or for ever when there is none.
async fn throttled(throttle: &mut Option<Pin<Box<tokio::time::Sleep>>>) {
    match throttle {
        Some(sleep) => sleep.as_mut().await,
        None => std::future::pending().await,
    }
}

/// Accept on `listeners` and run each link's handshake until the loop is gone. Never ends while
/// the receiving half of `events` lives.
async fn run(
    mut listeners: Vec<BoundListener>,
    bounds: AcceptBounds,
    mut opener: Opener,
    on: IntakeOn,
    counts: Arc<IntakeCounts>,
    events: mpsc::UnboundedSender<IntakeEvent>,
) -> Infallible {
    let mut handshakes = Handshakes::new(on);
    let mut throttle: Option<Pin<Box<tokio::time::Sleep>>> = None;
    let mut seq: u64 = 0;
    loop {
        tokio::select! {
            Some(ended) = handshakes.next() => {
                if events.send(IntakeEvent::Handshaken(Box::new(ended))).is_err() {
                    break;
                }
            }
            () = throttled(&mut throttle) => throttle = None,
            accepted = accept_any(&mut listeners), if throttle.is_none() => match accepted {
                Ok((link, peer)) => {
                    // Upstream's guard against a peer that fills the node with handshakes it
                    // never finishes: closed at once, with nothing said, since a reply costs the
                    // node what the peer spends.
                    if counts.pending.load(Ordering::SeqCst) >= bounds.pending {
                        counts.refused_over_pending.fetch_add(1, Ordering::SeqCst);
                        log::debug!(
                            "closing {peer:?} unanswered: {} accepts are already mid-handshake",
                            bounds.pending
                        );
                        drop(link);
                        continue;
                    }
                    counts.accepted.fetch_add(1, Ordering::SeqCst);
                    let pending = PendingAccept::count(&counts);
                    let handshake = opener(link, seq);
                    seq += 1;
                    handshakes.push(Box::pin(async move {
                        let result = handshake.await;
                        Handshaken { peer, result, pending }
                    }));
                }
                Err(e) => {
                    if events.send(IntakeEvent::AcceptError(e)).is_err() {
                        break;
                    }
                    throttle = Some(Box::pin(tokio::time::sleep(ACCEPT_ERROR_THROTTLE)));
                }
            },
        }
    }
    // The loop dropped its receiver: it is ending, and drops this intake with it.
    std::future::pending().await
}

/// How the intake is run.
enum Running {
    /// Polled from [`Intake::next`].
    Polled(Pin<Box<dyn Future<Output = Infallible> + Send>>),
    /// Its own task.
    Task(tokio::task::JoinSet<Infallible>),
}

/// The loop's handle on its intake.
pub(super) struct Intake {
    events: mpsc::UnboundedReceiver<IntakeEvent>,
    running: Running,
    counts: Arc<IntakeCounts>,
}

impl Intake {
    /// Accept on `listeners` within `bounds`, starting each link's handshake with `opener`, run as
    /// `on` says. A node with no listener accepts nothing, and its intake has nothing to tell.
    pub(super) fn start(
        listeners: Vec<BoundListener>,
        bounds: AcceptBounds,
        opener: Opener,
        on: IntakeOn,
    ) -> Self {
        let (tx, events) = mpsc::unbounded_channel();
        let counts = Arc::new(IntakeCounts::default());
        let intake = run(listeners, bounds, opener, on, Arc::clone(&counts), tx);
        let running = match on {
            IntakeOn::LoopTask => Running::Polled(Box::pin(intake)),
            IntakeOn::OwnTasks => {
                let mut task = tokio::task::JoinSet::new();
                task.spawn(intake);
                Running::Task(task)
            }
        };
        Self {
            events,
            running,
            counts,
        }
    }

    /// The next thing the intake has to tell. Cancel-safe: an event is taken off the channel only
    /// when it is returned, and the intake polled here keeps its own state between calls.
    pub(super) async fn next(&mut self) -> IntakeEvent {
        let Self {
            events, running, ..
        } = self;
        match running {
            Running::Polled(intake) => tokio::select! {
                event = received(events) => event,
                never = intake.as_mut() => match never {},
            },
            Running::Task(_) => received(events).await,
        }
    }

    /// Links whose handshake was started, since the intake started.
    pub(super) fn accepted(&self) -> usize {
        self.counts.accepted.load(Ordering::SeqCst)
    }

    /// Links closed unanswered over `accept_pending`, since the intake started.
    pub(super) fn refused_over_pending(&self) -> usize {
        self.counts.refused_over_pending.load(Ordering::SeqCst)
    }

    /// Stop accepting and end every handshake in flight. A task of its own is waited for, so the
    /// listeners are closed when this returns, as they are when a polled intake is dropped.
    pub(super) async fn close(&mut self) {
        if let Running::Task(task) = &mut self.running {
            task.shutdown().await;
        }
        self.events.close();
    }
}

/// The next event on `events`, or never once every sender is gone (an intake task that ended
/// without a result, which [`Intake::close`] or a panic in it can cause).
async fn received(events: &mut mpsc::UnboundedReceiver<IntakeEvent>) -> IntakeEvent {
    match events.recv().await {
        Some(event) => event,
        None => std::future::pending().await,
    }
}
