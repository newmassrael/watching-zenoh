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
//! lock, and without it the critical section is the lock. A host library built without `std`
//! (`os-sys`) links no `critical-section` implementation, which a C library would export: its
//! lock is the host's own, the port's [`crate::os::Mutex`].
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
    #[cfg(all(not(feature = "std"), feature = "os-sys"))]
    inner: crate::os::Mutex<T>,
    #[cfg(all(not(feature = "std"), not(feature = "os-sys")))]
    inner: critical_section::Mutex<core::cell::RefCell<T>>,
}

impl<T> Lock<T> {
    /// `value`, behind the lock.
    pub const fn new(value: T) -> Self {
        Self {
            #[cfg(feature = "std")]
            inner: std::sync::Mutex::new(value),
            #[cfg(all(not(feature = "std"), feature = "os-sys"))]
            inner: crate::os::Mutex::new(value),
            #[cfg(all(not(feature = "std"), not(feature = "os-sys")))]
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
        #[cfg(all(not(feature = "std"), feature = "os-sys"))]
        {
            f(&mut self.inner.lock())
        }
        #[cfg(all(not(feature = "std"), not(feature = "os-sys")))]
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

/// The mark of a session's state lock held by the calling thread, from [`Self::enter`] to its
/// drop: an engine marks each hold of its session's lock, so that a path that would take that
/// lock again on the same thread (a place given back, a key let go of, by a drop made under the
/// lock) fails at once in a debug build instead of waiting on itself, and a place's last holder
/// can say that no session is held where it gives the place back ([`Self::any_here`]). Kept in a
/// debug build on a host; a release build, and one with no `std`, keeps nothing and reads that
/// none is held.
pub struct SessionHeld {
    #[cfg(all(feature = "std", debug_assertions))]
    session: usize,
}

/// The sessions each thread marks held, the innermost last; a thread holds a few at most, and
/// one past the room is not recorded, which only makes the check miss it.
#[cfg(all(feature = "std", debug_assertions))]
mod held_here {
    use core::cell::Cell;

    pub(super) const ROOM: usize = 4;

    std::thread_local! {
        pub(super) static HELD: Cell<([usize; ROOM], usize)> = const { Cell::new(([0; ROOM], 0)) };
    }
}

impl SessionHeld {
    /// Mark the session whose state lies at `session` held by this thread. A debug build fails
    /// when this thread holds it already: the lock is not reentrant, so the take would wait on
    /// itself.
    pub fn enter(session: *const ()) -> Self {
        #[cfg(all(feature = "std", debug_assertions))]
        {
            let session = session as usize;
            held_here::HELD.with(|held| {
                let (mut sessions, len) = held.get();
                let taken = sessions.get(..len).unwrap_or(&[]);
                debug_assert!(
                    !taken.contains(&session),
                    "a session's lock is taken again on the thread that holds it"
                );
                if let Some(slot) = sessions.get_mut(len) {
                    *slot = session;
                    held.set((sessions, len.saturating_add(1)));
                }
            });
            Self { session }
        }
        #[cfg(not(all(feature = "std", debug_assertions)))]
        {
            let _ = session;
            Self {}
        }
    }

    /// Whether this thread holds any session's lock, as far as the marks say: never in a release
    /// build.
    pub fn any_here() -> bool {
        #[cfg(all(feature = "std", debug_assertions))]
        {
            held_here::HELD.with(|held| held.get().1 != 0)
        }
        #[cfg(not(all(feature = "std", debug_assertions)))]
        {
            false
        }
    }
}

impl Drop for SessionHeld {
    fn drop(&mut self) {
        #[cfg(all(feature = "std", debug_assertions))]
        held_here::HELD.with(|held| {
            let (mut sessions, len) = held.get();
            let taken = sessions.get(..len).unwrap_or(&[]);
            if let Some(at) = taken.iter().rposition(|&s| s == self.session) {
                // The marks are let go of in any order a program's guards drop in.
                let last = len.saturating_sub(1);
                sessions.copy_within(at.saturating_add(1)..len, at);
                if let Some(slot) = sessions.get_mut(last) {
                    *slot = 0;
                }
                held.set((sessions, last));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session marked held is held on its thread until its mark is dropped, another session may
    /// be held inside it, and a release build reads none.
    #[test]
    fn a_session_is_held_from_its_mark_to_its_drop() {
        let one = 1_u8;
        let other = 2_u8;
        assert!(!SessionHeld::any_here());
        let outer = SessionHeld::enter(core::ptr::from_ref(&one).cast());
        let inner = SessionHeld::enter(core::ptr::from_ref(&other).cast());
        assert_eq!(
            SessionHeld::any_here(),
            cfg!(all(feature = "std", debug_assertions))
        );
        drop(outer);
        assert_eq!(
            SessionHeld::any_here(),
            cfg!(all(feature = "std", debug_assertions))
        );
        drop(inner);
        assert!(
            !SessionHeld::any_here(),
            "none is held once every mark is dropped"
        );
    }

    /// A session's lock taken again on the thread that holds it fails at once in a debug build.
    #[cfg(all(feature = "std", debug_assertions))]
    #[test]
    #[should_panic(expected = "taken again on the thread that holds it")]
    fn a_session_held_twice_on_one_thread_fails() {
        let one = 1_u8;
        let _held = SessionHeld::enter(core::ptr::from_ref(&one).cast());
        let _again = SessionHeld::enter(core::ptr::from_ref(&one).cast());
    }

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
