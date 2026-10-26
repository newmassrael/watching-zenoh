// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The one lock the port's shared state is held under, on a host and on an MCU.
//!
//! The port's sets ([`ListenerSet`](crate::listeners::ListenerSet), the pending legs of a
//! [`CancellableFan`](crate::cancellation::CancellableFan)) are reached from any thread a C
//! program calls in from, so each sits behind a lock. On a host the lock is the process's
//! (`std::sync::Mutex`). An MCU image has no `std`; there the lock is a critical section, which the
//! image provides by linking a `critical-section` implementation, as the cooperative runtime's
//! cells do (`wz-runtime-coop`'s `cs`). Which one is chosen is the `std` feature: it adds the host
//! lock, and without it the critical section is the lock.
//!
//! The API is a closure ([`Lock::with`]) and not a guard, because a critical section cannot hand
//! out a guard that outlives the call that entered it. The closure form also says at every call
//! site what the engines' rule asks: nothing taken out of the set is called or dropped while the
//! lock is held, so whatever the closure returns is released after it.
//!
//! A host lock is recovered when poisoned: every closure here leaves the state consistent before
//! it can panic, and a C program must not lose its listeners or its pending legs because an
//! earlier callback panicked.

/// A value reached from any thread, one closure at a time.
pub struct Lock<T> {
    #[cfg(feature = "std")]
    inner: std::sync::Mutex<T>,
    #[cfg(not(feature = "std"))]
    inner: critical_section::Mutex<core::cell::RefCell<T>>,
}

impl<T> Lock<T> {
    /// `value`, behind the lock.
    pub const fn new(value: T) -> Self {
        Self {
            #[cfg(feature = "std")]
            inner: std::sync::Mutex::new(value),
            #[cfg(not(feature = "std"))]
            inner: critical_section::Mutex::new(core::cell::RefCell::new(value)),
        }
    }

    /// Run `f` on the value with the lock held, and hand back what it returns, which is released
    /// after the lock is.
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        #[cfg(feature = "std")]
        {
            let mut guard = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            f(&mut guard)
        }
        #[cfg(not(feature = "std"))]
        {
            critical_section::with(|cs| f(&mut self.inner.borrow_ref_mut(cs)))
        }
    }
}

impl<T: Default> Default for Lock<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_the_closure_returns_is_handed_back() {
        let lock = Lock::new(alloc::vec![1, 2]);
        let taken = lock.with(|v| v.pop());
        assert_eq!(taken, Some(2));
        assert_eq!(lock.with(|v| v.len()), 1);
    }

    #[cfg(feature = "std")]
    #[test]
    fn a_poisoned_host_lock_still_holds_its_value() {
        let lock = std::sync::Arc::new(Lock::new(7));
        let held = std::sync::Arc::clone(&lock);
        let _ = std::thread::spawn(move || held.with(|_| panic!("poison the lock"))).join();
        assert_eq!(
            lock.with(|v| *v),
            7,
            "the value outlives the panic that poisoned its lock"
        );
    }
}
