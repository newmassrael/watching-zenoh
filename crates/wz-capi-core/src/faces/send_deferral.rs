// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the registry sends to a face or a group while a thread holds the registry's lock: queued
//! on the face's session or the group's producer, in the order the registry decided it, and
//! written once the thread holds no registry lock any more.
//!
//! A declaration, an Interest, a `DeclareFinal`, the gossip of a new link and the replay of
//! everything a new face is owed are messages that may not be dropped, and such a message waits
//! for room on its link up to `wait_before_close` (5 s by default); what the registry tells a
//! group (its announcements, retractions and Interests) waits for room on the group's link up to
//! `wait_before_drop`, and behind a full transmit pool for a free slot. The registry decides each
//! of them under its lock, and the drive of every face, and every get that chooses its faces,
//! reads the registry under the same lock: a send made under it would stop all of those for as
//! long as one congested link keeps the sender waiting.
//!
//! So no send waits under it. Each face's session is given a [`SendDeferral`] when the face
//! comes up ([`defer_under_the_registry`]), and so is each group's producer
//! ([`defer_group_under_the_registry`]); a send the sender is asked for while the calling thread
//! holds a registry lock is queued on the sender and asks its link for nothing, and the thread
//! writes what it queued when it lets go of its last registry lock ([`RegistryHold`], the last
//! field of the registry's guard, so its drop runs after the lock is released). A send of the
//! sender's that the thread did not defer leaves after what is queued, so the queue keeps the
//! registry's order against everything else the face or the group sends
//! (`wz_session_core::send_deferral`).
//!
//! What a deferred send's failure would have told the thread reaches it no more, and the
//! registry needs none of it: every send it makes under its lock is best effort per face and per
//! group, its result discarded, and what a failed send costs a face (its close, when a message
//! that may not be dropped found no room in its deadline) is settled by the face's session in the
//! send itself, whichever thread makes it (`SessionLinkActions`' `send_deferred`).

use std::cell::{Cell, RefCell};
use std::marker::PhantomData;
use std::sync::{Arc, Weak};

use wz_runtime_tokio::session_glue::SessionLinkActions;
use wz_session_core::send_deferral::{DeferredSender, SendDeferral};

std::thread_local! {
    /// How many registry locks this thread holds, counted from before it waits for each.
    static HELD: Cell<usize> = const { Cell::new(0) };
    /// The senders (faces' sessions and groups' producers) this thread queued a send on since it
    /// took its first registry lock, each once, in the order of the first send it queued on each.
    static OWED: RefCell<Vec<Weak<dyn DeferredSender>>> = const { RefCell::new(Vec::new()) };
}

/// This thread's hold of one registry lock, as the sends of the faces and the groups count it.
/// Made before the lock is taken and dropped after it is released: when the last such hold of the
/// thread goes, the thread writes every send it queued meanwhile, holding no registry lock.
///
/// Not `Send`: the count it keeps is this thread's.
pub(super) struct RegistryHold {
    _this_thread: PhantomData<*const ()>,
}

impl RegistryHold {
    /// Count one more registry lock held by this thread.
    pub(super) fn enter() -> Self {
        HELD.with(|held| held.set(held.get().saturating_add(1)));
        Self {
            _this_thread: PhantomData,
        }
    }
}

impl Drop for RegistryHold {
    fn drop(&mut self) {
        let left = HELD.with(|held| {
            let left = held.get().saturating_sub(1);
            held.set(left);
            left
        });
        if left == 0 {
            send_what_this_thread_queued();
        }
    }
}

/// Write, sender by sender, what this thread queued while it held a registry lock. Each flush
/// waits for that sender's room alone, and no registry lock is held while it waits.
fn send_what_this_thread_queued() {
    let owed = OWED.with(|owed| std::mem::take(&mut *owed.borrow_mut()));
    for sender in owed {
        if let Some(sender) = sender.upgrade() {
            sender.flush_deferred_sends();
        }
    }
}

/// The deferral a face's session or a group's producer is given: a thread that holds a registry
/// lock defers, and is owed the flush of each sender it deferred a send on.
struct UnderTheRegistry {
    sender: Weak<dyn DeferredSender>,
}

impl SendDeferral for UnderTheRegistry {
    fn defers(&self) -> bool {
        HELD.with(|held| held.get() > 0)
    }

    fn deferred(&self) {
        OWED.with(|owed| {
            let mut owed = owed.borrow_mut();
            if !owed.iter().any(|sender| sender.ptr_eq(&self.sender)) {
                owed.push(self.sender.clone());
            }
        });
    }
}

/// Give the session of a face the registry sends to under its lock the deferral that keeps every
/// wait for room out of that lock. Called before the registry sends the face anything.
pub(super) fn defer_under_the_registry(actions: &Arc<SessionLinkActions>) {
    // Unsized before it is downgraded: `Arc::downgrade` takes `&Arc<T>` and answers `Weak<T>`,
    // so a `Weak<dyn DeferredSender>` asked of it directly makes `T` the trait object, and a
    // reference to the session's `Arc` is no `&Arc<dyn DeferredSender>`.
    let session: Arc<dyn DeferredSender> = actions.clone();
    actions.install_send_deferral(Box::new(UnderTheRegistry {
        sender: Arc::downgrade(&session),
    }));
}

/// [`defer_under_the_registry`] for the producer of a group the registry sends to under its
/// lock. Called before the registry sends the group anything.
#[cfg(feature = "multicast-transport")]
pub(super) fn defer_group_under_the_registry(
    producer: &wz_runtime_tokio::multicast_glue::MulticastTxProducer,
) {
    producer.install_send_deferral(Box::new(UnderTheRegistry {
        sender: producer.deferred_sender(),
    }));
}
