// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The sends a sender's owner defers while it holds a lock of its own, and the order they and
//! the sender's other sends leave in. The sender is a unicast session
//! (`SessionLinkActions`, whose queued send is the message's encoded body) or a multicast
//! group's producer (`wz_runtime_tokio`'s `MulticastTxProducer`, whose queued send is the
//! group's own transmit item): each keeps one [`DeferredSends`] of its own kind of send.
//!
//! A send that may not be dropped waits for room on its link, up to `wait_before_close` (5 s by
//! default), and one that may be dropped waits up to `wait_before_drop`. An owner that sends to
//! several senders under one lock of its own, as a node's registry of faces declares to each face
//! and each group under the registry's lock, would hold that lock for as long as the most
//! congested of those links keeps it waiting, and every other reader of the lock (the other
//! faces' drives, a get choosing its faces) would wait with it. Upstream's router collects the
//! declarations it decides under its tables' lock and sends them once the lock is let go
//! (`zenoh/src/net/routing/dispatcher/face.rs` @ `let mut declares = vec![];`,
//! then `drop(ctrl_lock);` before `p.send_declare(m)`), the ones bound for a multicast group
//! among them: the peer hat hands a group's declaration to the same collector
//! (`zenoh/src/net/routing/hat/peer/pubsub.rs` @ `for group in self.multicast_groups(ctx.tables) {`).
//!
//! This is that structure, kept per sender and kept in order. While the owner's
//! [`SendDeferral`] says the calling thread defers, a send of the caller's own is queued here
//! instead of being written, and the owner is told so; the thread flushes the queue
//! ([`DeferredSender::flush_deferred_sends`]) once it holds no lock the deferral stands for. The
//! queue is first in, first out, so what the owner decided under its lock leaves in the order it
//! decided it. A send of any other thread that finds the queue holding something (or a send of
//! it on its way out) waits for the queue to empty and leaves after it, under the one lock that
//! orders them ([`DeferredSends::after_queued`]): a send that follows a deferred one, because it
//! was decided after it (the retraction of a declaration still queued, a put on a key whose
//! declaration is), can never leave first. A sender whose queue is empty sends at once, as one
//! with no deferral does.
//!
//! Why "decided after it" is all the order there is to keep: the deferring thread marks the queue
//! busy before it lets go of its lock, so a thread that learns of the deferred decision through
//! that lock (or through anything ordered after it) finds the queue busy and leaves behind it. A
//! send no such chain orders after the deferred one is concurrent with it, and either order is
//! one the two threads could have had without the deferral.
//!
//! The deferral is the owner's because only the owner knows which of its locks a thread holds;
//! the sender reads none of them. A sender no owner gave a deferral to sends as before.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::link::SessionRuntime;

/// What a sender's owner tells the sender about the thread that sends on it.
pub trait SendDeferral: Send + Sync {
    /// Whether the calling thread holds a lock of the owner's that no wait for room may be made
    /// under: its sends are then queued, and not written.
    fn defers(&self) -> bool;

    /// The calling thread queued a send on this sender while it deferred. The owner owes the
    /// sender a [`DeferredSender::flush_deferred_sends`] from this thread once it holds none of
    /// those locks.
    fn deferred(&self);
}

/// A sender an owner may owe a flush to: what the owner holds, weakly, for each sender a thread
/// deferred a send on, whatever kind of send the sender queues.
pub trait DeferredSender: Send + Sync {
    /// Write what the calling thread's deferral queued on this sender, in the order it was
    /// queued, waiting for room as each send would have; whatever another thread queued
    /// meanwhile goes out with it, in its turn. Nothing to do when nothing is queued.
    ///
    /// A thread that still defers may not flush: its flush would wait for room under the lock
    /// the deferral exists to keep free of that wait, which a debug build refuses.
    fn flush_deferred_sends(&self);
}

/// A sender's deferral and the sends of kind `S` it deferred.
pub struct DeferredSends<R: SessionRuntime, S: Send + 'static> {
    /// Whether an owner installed a deferral: a sender no owner gave one to reads this flag and
    /// nothing else.
    engaged: AtomicBool,
    /// Whether `queue` holds a send, or one taken off it is still on its way out. Written under
    /// `queue`'s lock; read without it by a sender asking whether it may go at once.
    busy: AtomicBool,
    deferral: R::Mutex<Option<Box<dyn SendDeferral>>>,
    queue: R::Mutex<VecDeque<S>>,
    /// Held by whoever sends the queue, and by any send made while the queue is not empty, for
    /// the whole of its send: it is what puts every such send in one order. Never taken by a
    /// thread that defers, which only adds to `queue`.
    ///
    /// A send held here may wait for room on its link, up to `wait_before_close`, so it is made
    /// as a lock held across a wait for an event (`Runtime::new_mutex_held_across_waits`), as a
    /// sender's conduit is: a lock-order check of a debug build refuses a wait for room under
    /// any other lock.
    order: R::Mutex<()>,
}

impl<R: SessionRuntime, S: Send + 'static> Default for DeferredSends<R, S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: SessionRuntime, S: Send + 'static> DeferredSends<R, S> {
    /// No deferral, nothing deferred.
    pub fn new() -> Self {
        Self {
            engaged: AtomicBool::new(false),
            busy: AtomicBool::new(false),
            deferral: R::new_mutex(None),
            queue: R::new_mutex(VecDeque::new()),
            order: R::new_mutex_held_across_waits(()),
        }
    }

    /// Give the sender its owner's deferral, in place of any it had.
    pub fn install(&self, deferral: Box<dyn SendDeferral>) {
        R::with_mutex_mut(&self.deferral, |slot| *slot = Some(deferral));
        self.engaged.store(true, Ordering::Release);
    }

    /// Whether an owner installed a deferral.
    #[inline(always)]
    pub fn engaged(&self) -> bool {
        self.engaged.load(Ordering::Acquire)
    }

    /// Whether the calling thread defers its sends on this sender.
    pub fn defers_here(&self) -> bool {
        R::with_mutex_mut(&self.deferral, |slot| {
            slot.as_deref().is_some_and(|deferral| deferral.defers())
        })
    }

    /// Queue `send` behind what is queued already, and tell the owner the thread owes a flush.
    pub fn defer(&self, send: S) {
        R::with_mutex_mut(&self.queue, |queue| {
            queue.push_back(send);
            self.busy.store(true, Ordering::Release);
        });
        R::with_mutex_mut(&self.deferral, |slot| {
            if let Some(deferral) = slot.as_deref() {
                deferral.deferred();
            }
        });
    }

    /// Whether nothing is queued and nothing taken off the queue is still on its way out: a send
    /// may then go at once, there being nothing it could pass.
    #[inline(always)]
    fn is_idle(&self) -> bool {
        !self.busy.load(Ordering::Acquire)
    }

    /// The oldest queued send, for the caller to send before it asks for the next; `None` once
    /// the queue is empty, and the send taken before is then out. Called under [`Self::in_order`].
    fn next(&self) -> Option<S> {
        R::with_mutex_mut(&self.queue, |queue| {
            let next = queue.pop_front();
            if next.is_none() {
                self.busy.store(false, Ordering::Release);
            }
            next
        })
    }

    /// Run `send` as the one sender of the sender's ordered sends: the queue's sender, or a send
    /// that waits for the queue to empty.
    fn in_order<U>(&self, send: impl FnOnce() -> U) -> U {
        R::with_mutex_mut(&self.order, |_| send())
    }

    /// Send what is queued with `send`, oldest first. Called under [`Self::in_order`].
    fn send_queued(&self, send: &mut impl FnMut(S)) {
        while let Some(next) = self.next() {
            send(next);
        }
    }

    /// The flush a [`DeferredSender`] owes: every queued send, sent with `send`, oldest first,
    /// as the one sender of the ordered sends. Nothing to do when nothing is queued. A thread that
    /// still defers may not flush (see [`DeferredSender::flush_deferred_sends`]).
    pub fn flush(&self, mut send: impl FnMut(S)) {
        if self.is_idle() {
            return;
        }
        debug_assert!(
            !self.defers_here(),
            "a thread flushed its deferred sends while it still defers them"
        );
        self.in_order(|| self.send_queued(&mut send));
    }

    /// A send of a thread that does not defer, made by `own`: at once when nothing is queued,
    /// and otherwise after every queued send, sent with `send`, oldest first, as the one sender
    /// of the ordered sends. A message decided after one still queued leaves after it.
    pub fn after_queued<U>(&self, mut send: impl FnMut(S), own: impl FnOnce() -> U) -> U {
        if self.is_idle() {
            return own();
        }
        self.in_order(|| {
            self.send_queued(&mut send);
            own()
        })
    }
}
