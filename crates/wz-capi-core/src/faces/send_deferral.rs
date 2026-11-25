// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the registry sends to a face while a thread holds the registry's lock: queued on the
//! face's session, in the order the registry decided it, and written once the thread holds no
//! registry lock any more.
//!
//! A declaration, an Interest, a `DeclareFinal`, the gossip of a new link and the replay of
//! everything a new face is owed are messages that may not be dropped, and such a message waits
//! for room on its link up to `wait_before_close` (5 s by default). The registry decides each
//! of them under its lock, and the drive of every face, and every get that chooses its faces,
//! reads the registry under the same lock: a send made under it would stop all of those for as
//! long as one congested link keeps the sender waiting.
//!
//! So no send waits under it. Each face's session is given a [`SendDeferral`] when the face
//! comes up ([`defer_under_the_registry`]); a send the session is asked for while the calling
//! thread holds a registry lock is queued on the session and asks its link for nothing, and
//! the thread writes what it queued when it lets go of its last registry lock
//! ([`RegistryHold`], the last field of the registry's guard, so its drop runs after the
//! lock is released). A send of the session's that the thread did not defer leaves after what
//! is queued, so the queue keeps the registry's order against everything else the face sends
//! (`wz_session_core::session_actions`'s `send_deferral`).

use std::cell::{Cell, RefCell};
use std::marker::PhantomData;
use std::sync::{Arc, Weak};

use wz_runtime_tokio::session_glue::SessionLinkActions;
use wz_session_core::session_actions::SendDeferral;

std::thread_local! {
    /// How many registry locks this thread holds, counted from before it waits for each.
    static HELD: Cell<usize> = const { Cell::new(0) };
    /// The faces this thread queued a send on since it took its first registry lock, each once,
    /// in the order of the first send it queued on each.
    static OWED: RefCell<Vec<Weak<SessionLinkActions>>> = const { RefCell::new(Vec::new()) };
}

/// This thread's hold of one registry lock, as the sends of the faces count it. Made before the
/// lock is taken and dropped after it is released: when the last such hold of the thread goes,
/// the thread writes every send it queued meanwhile, holding no registry lock.
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

/// Write, face by face, what this thread queued while it held a registry lock. Each face's
/// flush waits for that face's room alone, and no registry lock is held while it waits.
fn send_what_this_thread_queued() {
    let owed = OWED.with(|owed| std::mem::take(&mut *owed.borrow_mut()));
    for face in owed {
        if let Some(actions) = face.upgrade() {
            actions.flush_deferred_sends();
        }
    }
}

/// The deferral a face's session is given: a thread that holds a registry lock defers, and is
/// owed the flush of each session it deferred a send on.
struct UnderTheRegistry {
    face: Weak<SessionLinkActions>,
}

impl SendDeferral for UnderTheRegistry {
    fn defers(&self) -> bool {
        HELD.with(|held| held.get() > 0)
    }

    fn deferred(&self) {
        OWED.with(|owed| {
            let mut owed = owed.borrow_mut();
            if !owed.iter().any(|face| face.ptr_eq(&self.face)) {
                owed.push(self.face.clone());
            }
        });
    }
}

/// Give the session of a face the registry sends to under its lock the deferral that keeps every
/// wait for room out of that lock. Called before the registry sends the face anything.
pub(super) fn defer_under_the_registry(actions: &Arc<SessionLinkActions>) {
    actions.install_send_deferral(Box::new(UnderTheRegistry {
        face: Arc::downgrade(actions),
    }));
}
