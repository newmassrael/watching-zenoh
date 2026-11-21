// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The lock the cache ring and the subscriber's state are under: `std`'s with `std`, and without
//! it the host's own (`wz-host-sync`), which a panic does not poison because a build without `std`
//! aborts on one.

#[cfg(feature = "std")]
pub(crate) use std::sync::{Mutex, MutexGuard};
#[cfg(not(feature = "std"))]
pub(crate) use wz_host_sync::{Mutex, MutexGuard};

/// `mutex`, locked. A lock a panic of its holder poisoned panics here with `poisoned`: what it
/// guards may be half changed.
pub(crate) fn lock_or_panic<'a, T>(mutex: &'a Mutex<T>, poisoned: &str) -> MutexGuard<'a, T> {
    #[cfg(feature = "std")]
    {
        mutex.lock().expect(poisoned)
    }
    #[cfg(not(feature = "std"))]
    {
        let _ = poisoned;
        mutex.lock()
    }
}

/// `mutex`, locked, a poisoned one as a healthy one: for a lock whose data no panic can leave half
/// changed.
#[cfg(feature = "advanced-recovery")]
pub(crate) fn lock_past_poison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    #[cfg(feature = "std")]
    {
        mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    #[cfg(not(feature = "std"))]
    {
        mutex.lock()
    }
}
