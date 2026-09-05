// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y519 — the outbound writer's lifecycle: a SEALABLE queue, and the handle
//! that seals it.
//!
//! ## Why this exists
//!
//! Every stream / datagram pipeline hands its outbound frames to a spawned
//! writer task over an unbounded channel, and teardown has to answer one
//! question: *when has the writer finished?* Until R311y519 the answer was a
//! wall-clock budget — `drain_to_close` dropped the `Arc<SessionLinkActions>`
//! holders and awaited the task under a 50 ms timeout.
//!
//! That budget cannot tell a WEDGED peer from a SLOW one. On a loaded host it
//! expires while the writer is still making progress, and the frames still in
//! the channel are discarded — including frames the C ABI's `z_put` already
//! answered `Z_OK` for. That is a data-loss defect, and it is what made
//! `a_put_immediately_before_z_close_is_drained_not_discarded` red on hosted CI
//! while every local run won the race.
//!
//! Awaiting the writer WITHOUT a budget is not the fix on its own, because the
//! channel closes only when the last sender clone drops and on the accept path
//! one survives: `accept_loop::drive_face` drains as soon as the drive loop
//! returns, while the forwarder's `FaceEntry` — which holds a `TokioSession`,
//! hence a clone of the sender — is released later, in the loop's `Step::Driven`
//! arm. Deregistering earlier is not available either: under
//! `transport-multilink` that release is CONDITIONAL, because the session
//! survives while at least one link remains.
//!
//! So the close signal has to stop being sender liveness. A SEAL is that signal:
//!
//! - **Seal** = *finish the queue, then exit*. It closes the receiving half, so
//!   no further enqueue can land and the queue is finite; the writer then drains
//!   what is already in it and terminates on its own — regardless of how many
//!   sender clones the routing lifecycle still holds.
//! - It is deliberately NOT
//!   [`close_blocking`](crate::stream_link::StreamWriteDriver::close_blocking),
//!   whose no-op body documents why *close now* is wrong: it would race
//!   in-flight enqueues. *Finish the queue, then exit* races nothing, which is
//!   the whole reason it can be a new signal rather than a re-use of that one.
//!
//! ## The wedged-peer defence moves, it does not disappear
//!
//! The 50 ms budget was also what stopped a peer that has stopped reading
//! entirely from holding teardown open forever. That defence moves onto ONE
//! write, and is armed only once the queue is sealed — steady state keeps its
//! unbounded await, because there the peer's backpressure IS the flow control
//! and cutting a write short would be the same data loss in a different place.
//! [`OutboundQueue::guarded`] arms the bound even under a write already in
//! flight when the seal lands, since that is precisely the write a wedged peer
//! stalls on. Expiry ends the writer rather than skipping one frame, so a wedged
//! teardown costs [`WRITER_STALL_MS`] once, not once per queued frame.
//!
//! ## Why the handle is the only constructor
//!
//! [`WriterHandle::spawn`] is the sole way to obtain a handle, and it is what
//! builds the queue. A new pipeline therefore cannot spawn a writer that no one
//! can seal — the seal wiring is not a step to remember, it is the only step
//! available.

use std::future::Future;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

use crate::runtime_impl::TokioJoinHandle;
use crate::runtime_pool::WzRuntime;

/// Bound on a SINGLE outbound write once the queue is sealed — the wedged-peer
/// defence that the wall-clock drain budget used to provide, at the one place
/// that can distinguish "the peer is not reading" from "the drain is taking a
/// while".
///
/// It has to outlast a LEGITIMATE peer-side stall, because a peer that is merely
/// slow must still be delivered to: a subscriber callback that blocks its drive
/// task stops the peer reading, fills its receive buffer, fills this side's send
/// buffer behind it, and blocks the write for as long as the callback runs. The
/// `wz-capi-pico` teardown fixture reproduces exactly that with a 200 ms
/// callback, so the bound carries an order of magnitude over it rather than a
/// margin that a loaded CI host can eat.
///
/// Note the granularity is one `write_all`, not one byte: bounding partial
/// writes instead would buy nothing here, because a peer that is not reading
/// stalls a one-byte write exactly as long as a whole-frame one.
pub const WRITER_STALL_MS: u64 = 2_000;

/// The receiving half of a writer's outbound channel, plus the seal that ends
/// it. Constructed by [`WriterHandle::spawn`] and consumed by a writer task.
pub struct OutboundQueue {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    /// `None` once the seal has been observed, or once the [`WriterHandle`] has
    /// been dropped without sealing — in the latter case the task is detached
    /// and sender liveness is the only close signal left, which is the
    /// pre-R311y519 behaviour and the right one for a detached writer.
    seal: Option<watch::Receiver<bool>>,
    sealed: bool,
}

impl OutboundQueue {
    /// Take the next frame, or `None` once the queue is finished.
    ///
    /// Before the seal this is the plain channel receive. After it, the channel
    /// is closed, so the remaining frames are handed over and then `None`
    /// arrives — deterministically, with no dependence on who still holds a
    /// sender.
    pub async fn next(&mut self) -> Option<Vec<u8>> {
        loop {
            if self.sealed || self.seal.is_none() {
                return self.rx.recv().await;
            }
            let seal = self.seal.as_mut().expect("checked directly above");
            let mut sealed_now = false;
            let mut detached = false;
            let frame = tokio::select! {
                biased;
                frame = self.rx.recv() => Some(frame),
                changed = seal.changed() => {
                    match changed {
                        Ok(()) => sealed_now = *seal.borrow_and_update(),
                        Err(_) => detached = true,
                    }
                    None
                }
            };
            if let Some(frame) = frame {
                return frame;
            }
            if detached {
                self.seal = None;
            }
            if sealed_now {
                self.apply_seal();
            }
        }
    }

    /// Run ONE outbound write under the teardown bound.
    ///
    /// Steady state is an unbounded await — the peer's backpressure is the flow
    /// control there, and a bound would drop frames a caller was told were sent.
    /// Once the queue is sealed the write is bounded by [`WRITER_STALL_MS`]. The
    /// seal is watched CONCURRENTLY with the write rather than checked before
    /// it, so a write already blocked on a wedged peer when teardown lands still
    /// gets the bound armed under it; checking first would leave exactly that
    /// write unbounded, which is the one that hangs.
    ///
    /// `None` means the bound expired. Callers end the writer on it rather than
    /// moving to the next frame: a wedged peer does not un-wedge for frame N+1,
    /// and retrying would multiply one bound by the queue depth.
    pub async fn guarded<F>(&mut self, write: F) -> Option<F::Output>
    where
        F: Future,
    {
        tokio::pin!(write);
        while !self.sealed {
            let Some(seal) = self.seal.as_mut() else {
                return Some(write.await);
            };
            let mut sealed_now = false;
            let mut detached = false;
            let out = tokio::select! {
                biased;
                out = &mut write => Some(out),
                changed = seal.changed() => {
                    match changed {
                        Ok(()) => sealed_now = *seal.borrow_and_update(),
                        Err(_) => detached = true,
                    }
                    None
                }
            };
            if let Some(out) = out {
                return Some(out);
            }
            if detached {
                self.seal = None;
            }
            if sealed_now {
                self.apply_seal();
            }
        }
        timeout(Duration::from_millis(WRITER_STALL_MS), write)
            .await
            .ok()
    }

    /// Whether the queue has been sealed — true once teardown has asked the
    /// writer to finish what it holds and exit.
    pub fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Close the receiving half: no further enqueue can land, so what is already
    /// buffered is a FINITE set the writer can drain to the end. Already-sent
    /// frames survive `close` — that is what makes this "finish the queue" and
    /// not "drop the queue".
    fn apply_seal(&mut self) {
        self.sealed = true;
        self.seal = None;
        self.rx.close();
    }
}

/// A spawned writer task's lifecycle handle: the join handle, plus the seal that
/// lets teardown end the task without depending on sender liveness.
///
/// Dropping it detaches the writer, exactly as dropping a bare
/// [`TokioJoinHandle`] did — the queue then falls back to the sender-liveness
/// close signal.
pub struct WriterHandle {
    join: TokioJoinHandle<()>,
    seal: watch::Sender<bool>,
}

impl WriterHandle {
    /// Wire an outbound channel's receiving half into a sealable queue, spawn
    /// `task` over it, and return the handle that owns both ends of teardown.
    ///
    /// Taking the receiver rather than a ready-made queue is deliberate: it
    /// makes this the only route from a channel to a running writer, so a
    /// pipeline cannot end up with a task no one can seal.
    ///
    /// The writer lands on the TRANSMIT subsystem
    /// ([`WzRuntime::Tx`](crate::runtime_pool::WzRuntime)), which is what makes
    /// this one call the whole of wz's TX partition: every stream and datagram
    /// pipeline reaches its writer through here, so an operator lowering
    /// `tx:worker_threads` narrows all ten of them at once. zenoh names the same
    /// subsystem at the same seam — `ZRuntime::TX.spawn` around the unicast
    /// `tx_task` (`io/zenoh-transport/src/unicast/universal/link.rs`
    /// @ `ZRuntime::TX.spawn(async move {`) and around the multicast one
    /// (`io/zenoh-transport/src/multicast/link.rs`
    /// @ `ZRuntime::TX.spawn(async move {`).
    pub fn spawn<F, Fut>(rx: mpsc::UnboundedReceiver<Vec<u8>>, task: F) -> Self
    where
        F: FnOnce(OutboundQueue) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self::spawn_on(WzRuntime::Tx.handle().clone(), rx, task)
    }

    /// [`Self::spawn`] onto a NAMED tokio runtime rather than the TX subsystem.
    ///
    /// The general form, and the escape a caller needs when the writer must
    /// share a runtime with whoever is observing it. That is not a niche:
    /// tokio's paused clock is per-runtime, so a test that advances time and a
    /// writer on another runtime are measuring two different clocks — the
    /// [`WRITER_STALL_MS`] bound would then be spent in real seconds while the
    /// test believes it moved instantly. A host embedding wz inside its own
    /// reactor has the same need for the same reason.
    pub fn spawn_on<F, Fut>(
        handle: tokio::runtime::Handle,
        rx: mpsc::UnboundedReceiver<Vec<u8>>,
        task: F,
    ) -> Self
    where
        F: FnOnce(OutboundQueue) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (seal, seal_rx) = watch::channel(false);
        let queue = OutboundQueue {
            rx,
            seal: Some(seal_rx),
            sealed: false,
        };
        WriterHandle {
            join: TokioJoinHandle::from_tokio(handle.spawn(task(queue))),
            seal,
        }
    }

    /// Terminal drain: seal the queue, then await the writer to COMPLETION.
    ///
    /// The await is unbounded on purpose and is safe to be: the seal makes the
    /// queue finite and [`OutboundQueue::guarded`] bounds the one write a wedged
    /// peer can stall on, so the task terminates in bounded time without a
    /// wall-clock budget that would cut a writer still making progress.
    pub async fn drain(self) {
        let _ = self.seal.send(true);
        let _ = self.join.await;
    }

    /// Abort the writer where it stands, dropping whatever it still holds. The
    /// deliberate opposite of [`Self::drain`] — for callers tearing down a
    /// session whose link is already gone.
    pub fn abort(&self) {
        self.join.abort();
    }

    /// Release the join handle alone, dropping the seal. The writer then closes
    /// on sender liveness, so this is for callers that have already released
    /// every sender and want the raw join.
    pub fn into_join(self) -> TokioJoinHandle<()> {
        self.join
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// The seal ends the writer even though a sender clone is still ALIVE.
    ///
    /// This is the accept-path shape in miniature: the routing registry holds a
    /// `TokioSession`, hence a clone of the outbound sender, past the drain. Under
    /// the pre-R311y519 close signal (sender liveness) the drain could only ever
    /// end on its wall clock; here it ends because the queue was sealed, and the
    /// surviving sender is held to the end of the test to prove it.
    #[tokio::test]
    async fn a_seal_ends_the_writer_while_a_sender_clone_survives() {
        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let seen = Arc::new(AtomicUsize::new(0));
        let seen_task = seen.clone();
        let handle = WriterHandle::spawn(rx, move |mut queue| async move {
            while let Some(frame) = queue.next().await {
                seen_task.fetch_add(frame.len(), Ordering::SeqCst);
            }
        });

        tx.send(vec![0u8; 3]).expect("enqueue");
        tx.send(vec![0u8; 4]).expect("enqueue");

        // The clone that the drain cannot make go away.
        let survivor = tx.clone();
        handle.drain().await;

        assert_eq!(
            seen.load(Ordering::SeqCst),
            7,
            "the sealed writer must hand over every frame that was already queued"
        );
        assert!(
            survivor.send(vec![0u8; 5]).is_err(),
            "the seal must CLOSE the channel, so a surviving sender cannot enqueue \
             behind the drain"
        );
        drop(tx);
    }

    /// A write that is already blocked when the seal lands is bounded, not left
    /// to hang — the wedged-peer case the wall-clock budget used to cover.
    ///
    /// The bound is exercised through a pending-forever future, so the test
    /// measures the arming of the bound rather than a real socket.
    ///
    /// [`WriterHandle::spawn_on`] with THIS runtime's handle, not
    /// [`WriterHandle::spawn`]: the paused clock belongs to the test's runtime,
    /// and a writer on the TX subsystem would spend the bound in two real
    /// seconds of wall clock while `start_paused` reported instants.
    #[tokio::test(start_paused = true)]
    async fn a_write_in_flight_when_the_seal_lands_is_bounded() {
        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let bailed = Arc::new(AtomicUsize::new(0));
        let bailed_task = bailed.clone();
        let handle = WriterHandle::spawn_on(
            tokio::runtime::Handle::current(),
            rx,
            move |mut queue| async move {
                while let Some(_frame) = queue.next().await {
                    if queue.guarded(std::future::pending::<()>()).await.is_none() {
                        bailed_task.fetch_add(1, Ordering::SeqCst);
                        return;
                    }
                }
            },
        );

        tx.send(vec![0u8; 1]).expect("enqueue");
        // Let the writer reach the wedged write before teardown lands.
        tokio::task::yield_now().await;
        handle.drain().await;

        assert_eq!(
            bailed.load(Ordering::SeqCst),
            1,
            "a write still in flight at seal time must inherit the {WRITER_STALL_MS} ms \
             bound; without it the drain's unbounded await never returns"
        );
    }

    /// Dropping the handle without sealing leaves the pre-R311y519 behaviour
    /// intact: the writer is detached and closes on sender liveness.
    #[tokio::test]
    async fn dropping_the_handle_leaves_sender_liveness_as_the_close_signal() {
        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let seen = Arc::new(AtomicUsize::new(0));
        let seen_task = seen.clone();
        let handle = WriterHandle::spawn(rx, move |mut queue| async move {
            while let Some(frame) = queue.next().await {
                seen_task.fetch_add(frame.len(), Ordering::SeqCst);
            }
        });
        let join = handle.into_join();

        tx.send(vec![0u8; 2]).expect("enqueue");
        drop(tx);
        join.await
            .expect("the writer joins once every sender has dropped");

        assert_eq!(seen.load(Ordering::SeqCst), 2);
    }
}
