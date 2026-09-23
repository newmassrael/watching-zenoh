// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2814 — the set of C listeners declared on ONE C-level entity.
//!
//! A C program declares listeners on the handle it holds — a sample-miss
//! listener on an advanced subscriber is the first user — while the wz objects
//! that detect the events live one per face and come and go with connections.
//! So each C ABI needs a fan-in that belongs to the C handle: every face's wz
//! callback reports into it, and the C side adds and removes entries at will.
//!
//! # Why a set and not the slot both ABIs had
//!
//! Each ABI used to hold `Mutex<Option<closure>>`, and a listener "installed
//! into" it. Upstream allows any number of listeners, each retracted on its own
//! (zenoh-c `ze_advanced_subscriber_declare_sample_miss_listener`, zenoh-pico
//! the same name). With one slot a second listener REPLACED the first, and
//! dropping the first then cleared the slot out from under the second — a C
//! program holding the second heard nothing more, with no error anywhere.
//!
//! Each entry is keyed by the id its listener handle holds, so a handle can
//! only ever remove itself.
//!
//! # Locking
//!
//! [`ListenerSet::snapshot`] copies the entries out and releases the lock
//! before any of them is called, and [`ListenerSet::remove`] hands the removed
//! entry back instead of dropping it under the lock. Both for the reason this
//! crate states at its root: calling into C, or releasing the last reference to
//! a C closure (which runs its `drop(context)`), may re-enter the session — and
//! a listener that undeclares itself from inside its own callback must not find
//! the set locked.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

/// The listeners declared on one C-level entity; see the module doc.
pub struct ListenerSet<C> {
    inner: Mutex<Entries<C>>,
}

struct Entries<C> {
    next_id: u64,
    by_id: BTreeMap<u64, Arc<C>>,
}

impl<C> Default for ListenerSet<C> {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Entries {
                next_id: 0,
                by_id: BTreeMap::new(),
            }),
        }
    }
}

impl<C> ListenerSet<C> {
    /// A new, empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `listener`; the returned id is the only way to remove it.
    pub fn insert(&self, listener: Arc<C>) -> u64 {
        let mut entries = self.lock();
        let id = entries.next_id;
        entries.next_id += 1;
        entries.by_id.insert(id, listener);
        id
    }

    /// Remove the listener `id`, handing it back so the caller releases it
    /// OUTSIDE the lock. `None` when it was already removed.
    #[must_use = "drop the returned listener after this call, not inside it"]
    pub fn remove(&self, id: u64) -> Option<Arc<C>> {
        self.lock().by_id.remove(&id)
    }

    /// Every current listener, in declaration order, copied out so they can
    /// be called with the set unlocked.
    pub fn snapshot(&self) -> Vec<Arc<C>> {
        self.lock().by_id.values().cloned().collect()
    }

    /// A poisoned lock still holds a consistent map — nothing here panics
    /// between two writes — so it is recovered rather than propagated: a C
    /// program must not lose its listeners because some earlier callback
    /// panicked.
    fn lock(&self) -> MutexGuard<'_, Entries<C>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two claims the slot this replaced got wrong: a second listener
    /// does not displace the first, and removing one leaves the other.
    #[test]
    fn listeners_coexist_and_leave_one_at_a_time() {
        let set = ListenerSet::new();
        let first = set.insert(Arc::new("first"));
        let _second = set.insert(Arc::new("second"));
        assert_eq!(
            set.snapshot().iter().map(|l| **l).collect::<Vec<_>>(),
            vec!["first", "second"],
            "a second listener joins the first rather than replacing it"
        );

        let removed = set.remove(first);
        assert_eq!(
            removed.as_deref(),
            Some(&"first"),
            "the handle removes its own entry"
        );
        assert_eq!(
            set.snapshot().iter().map(|l| **l).collect::<Vec<_>>(),
            vec!["second"],
            "removing one listener leaves the other in place"
        );
        assert!(
            set.remove(first).is_none(),
            "a second removal finds nothing"
        );
    }
}
