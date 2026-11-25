// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The sends a session's owner defers while it holds a lock of its own, and the order they and
//! the session's other sends leave in.
//!
//! A send that may not be dropped waits for room on its link, up to `wait_before_close` (5 s by
//! default). An owner that sends to several sessions under one lock of its own, as a node's
//! registry of faces declares to each face under the registry's lock, would hold that lock for
//! as long as the most congested of those links keeps it waiting, and every other reader of the
//! lock (the other faces' drives, a get choosing its faces) would wait with it. Upstream's router
//! collects the declarations it decides under its tables' lock and sends them once the lock is
//! let go (`zenoh/src/net/routing/dispatcher/face.rs` @ `let mut declares = vec![];`,
//! then `drop(ctrl_lock);` before `p.send_declare(m)`).
//!
//! This is that structure, kept per session and kept in order. While the owner's
//! [`SendDeferral`] says the calling thread defers, a send of the caller's own is encoded and
//! queued here instead of being written, and the owner is told so; the thread sends the queue
//! ([`SessionLinkActions::flush_deferred_sends`](super::SessionLinkActions::flush_deferred_sends))
//! once it holds no lock the deferral stands for. The queue is first in, first out, so what the
//! owner decided under its lock leaves in the order it decided it. A send of any other thread
//! that finds the queue holding something (or a send of it on its way out) waits for the queue
//! to empty and leaves after it, under the one lock that orders them
//! (`DeferredSends::in_order`): a send that follows a deferred one, because it was decided
//! after it (the retraction of a declaration still queued, a put on a key whose declaration is),
//! can never leave first. A session whose queue is empty sends at once, as one with no deferral
//! does.
//!
//! The deferral is the owner's because only the owner knows which of its locks a thread holds;
//! the session reads none of them. A session no owner gave a deferral to sends as before.

#[cfg(all(
    not(feature = "no_std"),
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    )
))]
use alloc::boxed::Box;
#[cfg(all(
    not(feature = "no_std"),
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    )
))]
use alloc::collections::VecDeque;
#[cfg(all(
    not(feature = "no_std"),
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    )
))]
use alloc::vec::Vec;
#[cfg(all(
    not(feature = "no_std"),
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    )
))]
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(all(
    not(feature = "no_std"),
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    )
))]
use crate::link::SessionRuntime;

/// What a session's owner tells the session about the thread that sends on it.
pub trait SendDeferral: Send + Sync {
    /// Whether the calling thread holds a lock of the owner's that no wait for room may be made
    /// under: its sends are then queued, and not written.
    fn defers(&self) -> bool;

    /// The calling thread queued a send on this session while it deferred. The owner owes the
    /// session a [`flush_deferred_sends`](super::SessionLinkActions::flush_deferred_sends) from
    /// this thread once it holds none of those locks.
    fn deferred(&self);
}

/// One send that was deferred: the message's body as the dispatch encodes it, and what the
/// dispatch is told about it, as a block-first job carries them ([`super::BlockFirstJob`]).
#[cfg(all(
    not(feature = "no_std"),
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    )
))]
pub(super) struct DeferredSend {
    pub(super) conduit: super::Conduit,
    pub(super) qos: crate::sample::QosLevel,
    pub(super) stats_class: crate::stats::NetworkStatsClass,
    pub(super) body: Vec<u8>,
}

/// A session's deferral and the sends it deferred.
#[cfg(all(
    not(feature = "no_std"),
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    )
))]
pub(super) struct DeferredSends<R: SessionRuntime> {
    /// Whether an owner installed a deferral: a session no owner gave one to reads this flag and
    /// nothing else.
    engaged: AtomicBool,
    /// Whether `queue` holds a send, or one taken off it is still on its way out. Written under
    /// `queue`'s lock; read without it by a sender asking whether it may go at once.
    busy: AtomicBool,
    deferral: R::Mutex<Option<Box<dyn SendDeferral>>>,
    queue: R::Mutex<VecDeque<DeferredSend>>,
    /// Held by whoever sends the queue, and by any send made while the queue is not empty, for
    /// the whole of its send: it is what puts every such send in one order. Never taken by a
    /// thread that defers, which only adds to `queue`.
    order: R::Mutex<()>,
}

#[cfg(all(
    not(feature = "no_std"),
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    )
))]
impl<R: SessionRuntime> DeferredSends<R> {
    /// No deferral, nothing deferred.
    pub(super) fn new() -> Self {
        Self {
            engaged: AtomicBool::new(false),
            busy: AtomicBool::new(false),
            deferral: R::new_mutex(None),
            queue: R::new_mutex(VecDeque::new()),
            order: R::new_mutex(()),
        }
    }

    /// Give the session its owner's deferral, in place of any it had.
    pub(super) fn install(&self, deferral: Box<dyn SendDeferral>) {
        R::with_mutex_mut(&self.deferral, |slot| *slot = Some(deferral));
        self.engaged.store(true, Ordering::Release);
    }

    /// Whether an owner installed a deferral.
    #[inline(always)]
    pub(super) fn engaged(&self) -> bool {
        self.engaged.load(Ordering::Acquire)
    }

    /// Whether the calling thread defers its sends on this session.
    pub(super) fn defers_here(&self) -> bool {
        R::with_mutex_mut(&self.deferral, |slot| {
            slot.as_deref().is_some_and(|deferral| deferral.defers())
        })
    }

    /// Queue `send` behind what is queued already, and tell the owner the thread owes a flush.
    pub(super) fn defer(&self, send: DeferredSend) {
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
    pub(super) fn is_idle(&self) -> bool {
        !self.busy.load(Ordering::Acquire)
    }

    /// The oldest queued send, for the caller to send before it asks for the next; `None` once
    /// the queue is empty, and the send taken before is then out. Called under [`Self::in_order`].
    pub(super) fn next(&self) -> Option<DeferredSend> {
        R::with_mutex_mut(&self.queue, |queue| {
            let next = queue.pop_front();
            if next.is_none() {
                self.busy.store(false, Ordering::Release);
            }
            next
        })
    }

    /// Run `send` as the one sender of the session's ordered sends: the queue's sender, or a
    /// send that waits for the queue to empty.
    pub(super) fn in_order<U>(&self, send: impl FnOnce() -> U) -> U {
        R::with_mutex_mut(&self.order, |_| send())
    }
}
