// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The lock the cache ring and the subscriber's state are under: the host's (`wz-host-sync`), with
//! `std` or without, which takes no memory when it is first taken on any host. A panic of its
//! holder leaves it poisoned in a build with `std`; a build without `std` aborts on one.

pub(crate) use wz_host_sync::{Mutex, MutexGuard};

/// `mutex`, locked. A lock a panic of its holder poisoned panics here with `poisoned`: what it
/// guards may be half changed.
pub(crate) fn lock_or_panic<'a, T>(mutex: &'a Mutex<T>, poisoned: &str) -> MutexGuard<'a, T> {
    let guard = mutex.lock();
    assert!(!mutex.is_poisoned(), "{poisoned}");
    guard
}

/// `mutex`, locked, a poisoned one as a healthy one: for a lock whose data no panic can leave half
/// changed.
#[cfg(feature = "advanced-recovery")]
pub(crate) fn lock_past_poison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock()
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    use std::sync::Arc;

    /// A lock whose holder panicked with the value at 2, after the panic.
    fn poisoned() -> Arc<Mutex<u32>> {
        let mutex = Arc::new(Mutex::new(1_u32));
        let holder = {
            let mutex = Arc::clone(&mutex);
            std::thread::spawn(move || {
                let mut value = mutex.lock();
                *value = 2;
                panic!("the holder panics with the lock held");
            })
        };
        assert!(holder.join().is_err(), "the holder panicked");
        mutex
    }

    /// A lock no holder panicked in is handed out; one whose holder panicked is refused with the
    /// message the caller gives, as `std`'s `expect` refused it. Turned red by a host lock that
    /// does not read as poisoned after its holder's panic.
    #[test]
    fn a_lock_its_holder_panicked_in_is_refused_with_the_message() {
        let healthy = Mutex::new(1_u32);
        assert_eq!(*lock_or_panic(&healthy, "not poisoned"), 1);
        let mutex = poisoned();
        let refused = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
            drop(lock_or_panic(&mutex, "the ring is poisoned"));
        }));
        let payload = refused.expect_err("a poisoned lock is refused");
        assert_eq!(
            payload.downcast_ref::<String>().map(String::as_str),
            Some("the ring is poisoned")
        );
    }

    /// A lock whose data no panic can leave half changed is handed out past a poison, with the
    /// value its holder left.
    #[cfg(feature = "advanced-recovery")]
    #[test]
    fn a_lock_past_poison_hands_out_what_the_holder_left() {
        let mutex = poisoned();
        assert_eq!(*lock_past_poison(&mutex), 2);
    }
}
