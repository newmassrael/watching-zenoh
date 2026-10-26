// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What an engine asks of the operating system it runs on: a mutex held across a step, the
//! identity of the calling thread, a thread of its own, and a sleep.
//!
//! An engine that the program steps still has a lock and may have a thread: the session is shared
//! between the C session handle and every entity on it and is called from any thread, and
//! zenoh-pico's multi-threaded arm runs a read task beside the program (`docs/upstream-parity.md`
//! section 5a, E1). On a host these are `std`'s. On an MCU they are the kernel's, reached through
//! the functions below, which the image links (a Zephyr image's are in
//! `deploy/zephyr-common/wz_os_zephyr.c`), as it links a `critical-section` implementation for
//! [`crate::sync::Lock`].
//!
//! The mutex is not a critical section. It is held while a session is stepped, which reads and
//! dispatches a message: masking interrupts for that long would hold off the network driver that
//! delivers the next one. It is the kernel's blocking mutex, and a thread that waits on it sleeps.
//!
//! What `std` gives is what the engine had before this seam, so a host build behaves as it did:
//! the same `std::sync::Mutex` (a poisoned one recovered, as the engine always did), the same
//! `std::thread`.
//!
//! The functions an image provides without `std`:
//!
//! ```c
//! void *wz_os_mutex_new(void);                 /* a new unlocked mutex, NULL when none is left */
//! void  wz_os_mutex_lock(void *mutex);         /* waits until it is this thread's */
//! void  wz_os_mutex_unlock(void *mutex);
//! void  wz_os_mutex_free(void *mutex);
//! uintptr_t wz_os_thread_current(void);        /* never 0 */
//! int   wz_os_thread_spawn(void (*entry)(void *), void *arg, uintptr_t *id);  /* 0 on success */
//! int   wz_os_thread_join(uintptr_t id);       /* waits for it to end, then frees it */
//! int   wz_os_thread_is_finished(uintptr_t id); /* 1 once it has ended, without waiting */
//! void  wz_os_sleep_ms(uint32_t ms);
//! ```

pub use imp::*;

#[cfg(feature = "std")]
mod imp {
    use std::sync::PoisonError;

    /// The identity of a thread, comparable with another's.
    pub type ThreadId = std::thread::ThreadId;

    /// The calling thread's identity.
    pub fn current() -> ThreadId {
        std::thread::current().id()
    }

    /// A thread [`spawn`] started, until it is joined.
    pub struct JoinHandle(std::thread::JoinHandle<()>);

    impl JoinHandle {
        /// Wait until the thread has ended. A thread that panicked has ended too.
        pub fn join(self) {
            let _ = self.0.join();
        }

        /// Whether the thread has ended, without waiting for it.
        pub fn is_finished(&self) -> bool {
            self.0.is_finished()
        }
    }

    /// Run `body` on a thread of its own: its handle and its identity, or `None` when the system
    /// gave no thread.
    pub fn spawn(body: impl FnOnce() + Send + 'static) -> Option<(JoinHandle, ThreadId)> {
        let thread = std::thread::Builder::new().spawn(body).ok()?;
        let id = thread.thread().id();
        Some((JoinHandle(thread), id))
    }

    /// Sleep the calling thread for `ms` milliseconds.
    pub fn sleep_ms(ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }

    /// The process's mutex, as the engine held it before this seam.
    pub struct Mutex<T>(std::sync::Mutex<T>);

    /// What [`Mutex::lock`] hands back; the mutex is released when it is dropped.
    pub type MutexGuard<'a, T> = std::sync::MutexGuard<'a, T>;

    impl<T> Mutex<T> {
        /// `value`, behind a new mutex.
        pub fn new(value: T) -> Self {
            Self(std::sync::Mutex::new(value))
        }

        /// Wait until the mutex is this thread's. A mutex poisoned by a panic still holds a
        /// consistent value (every critical section of an engine leaves it so), and is recovered.
        pub fn lock(&self) -> MutexGuard<'_, T> {
            self.0.lock().unwrap_or_else(PoisonError::into_inner)
        }

        /// The value, through the only reference there is.
        pub fn get_mut(&mut self) -> &mut T {
            self.0.get_mut().unwrap_or_else(PoisonError::into_inner)
        }
    }

    impl<T: Default> Default for Mutex<T> {
        fn default() -> Self {
            Self::new(T::default())
        }
    }
}

#[cfg(not(feature = "std"))]
mod imp {
    use alloc::boxed::Box;
    use core::cell::UnsafeCell;
    use core::ffi::{c_int, c_void};
    use core::ops::{Deref, DerefMut};
    use core::ptr::NonNull;

    extern "C" {
        fn wz_os_mutex_new() -> *mut c_void;
        fn wz_os_mutex_lock(mutex: *mut c_void);
        fn wz_os_mutex_unlock(mutex: *mut c_void);
        fn wz_os_mutex_free(mutex: *mut c_void);
        fn wz_os_thread_current() -> usize;
        fn wz_os_thread_spawn(
            entry: unsafe extern "C" fn(*mut c_void),
            arg: *mut c_void,
            id: *mut usize,
        ) -> c_int;
        fn wz_os_thread_join(id: usize) -> c_int;
        fn wz_os_thread_is_finished(id: usize) -> c_int;
        fn wz_os_sleep_ms(ms: u32);
    }

    /// The identity of a thread, comparable with another's: the kernel's handle of it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct ThreadId(usize);

    /// The calling thread's identity.
    pub fn current() -> ThreadId {
        // SAFETY: the image's contract (module doc): no argument, any thread.
        ThreadId(unsafe { wz_os_thread_current() })
    }

    /// A thread [`spawn`] started, until it is joined.
    pub struct JoinHandle(usize);

    impl JoinHandle {
        /// Wait until the thread has ended.
        pub fn join(self) {
            // SAFETY: the id is one `wz_os_thread_spawn` gave, joined once (this consumes it).
            unsafe {
                wz_os_thread_join(self.0);
            }
        }

        /// Whether the thread has ended, without waiting for it.
        pub fn is_finished(&self) -> bool {
            // SAFETY: the id is one `wz_os_thread_spawn` gave, not yet joined.
            unsafe { wz_os_thread_is_finished(self.0) != 0 }
        }
    }

    type Body = Box<dyn FnOnce() + Send + 'static>;

    unsafe extern "C" fn trampoline(arg: *mut c_void) {
        // SAFETY: `arg` is the `Box<Body>` `spawn` leaked for this thread, taken back once here.
        let body = unsafe { Box::from_raw(arg.cast::<Body>()) };
        body();
    }

    /// Run `body` on a thread of its own: its handle and its identity, or `None` when the kernel
    /// gave no thread.
    pub fn spawn(body: impl FnOnce() + Send + 'static) -> Option<(JoinHandle, ThreadId)> {
        let arg = Box::into_raw(Box::new(Box::new(body) as Body)).cast::<c_void>();
        let mut id = 0usize;
        // SAFETY: `trampoline` takes `arg` back exactly once, on the new thread; on a refusal no
        // thread runs and it is taken back here instead.
        if unsafe { wz_os_thread_spawn(trampoline, arg, &mut id) } != 0 {
            drop(unsafe { Box::from_raw(arg.cast::<Body>()) });
            return None;
        }
        Some((JoinHandle(id), ThreadId(id)))
    }

    /// Sleep the calling thread for `ms` milliseconds.
    pub fn sleep_ms(ms: u64) {
        // SAFETY: the image's contract (module doc).
        unsafe { wz_os_sleep_ms(u32::try_from(ms).unwrap_or(u32::MAX)) }
    }

    /// The kernel's blocking mutex around a value.
    pub struct Mutex<T> {
        raw: NonNull<c_void>,
        value: UnsafeCell<T>,
    }

    // SAFETY: the value is reached only through a guard, and the kernel's mutex lets one thread
    // hold a guard at a time; the raw mutex is the kernel's and may be used from any thread.
    unsafe impl<T: Send> Send for Mutex<T> {}
    unsafe impl<T: Send> Sync for Mutex<T> {}

    impl<T> Mutex<T> {
        /// `value`, behind a new mutex. A kernel with no mutex left is out of memory, which this
        /// answers as an allocation that failed.
        pub fn new(value: T) -> Self {
            // SAFETY: the image's contract (module doc).
            let raw = NonNull::new(unsafe { wz_os_mutex_new() }).unwrap_or_else(|| {
                alloc::alloc::handle_alloc_error(core::alloc::Layout::new::<T>())
            });
            Self {
                raw,
                value: UnsafeCell::new(value),
            }
        }

        /// Wait until the mutex is this thread's.
        pub fn lock(&self) -> MutexGuard<'_, T> {
            // SAFETY: `raw` is this mutex's, alive until it drops.
            unsafe { wz_os_mutex_lock(self.raw.as_ptr()) };
            MutexGuard { mutex: self }
        }

        /// The value, through the only reference there is.
        pub fn get_mut(&mut self) -> &mut T {
            self.value.get_mut()
        }
    }

    impl<T> Drop for Mutex<T> {
        fn drop(&mut self) {
            // SAFETY: no guard outlives the mutex, so it is unlocked, and it is freed once.
            unsafe { wz_os_mutex_free(self.raw.as_ptr()) }
        }
    }

    impl<T: Default> Default for Mutex<T> {
        fn default() -> Self {
            Self::new(T::default())
        }
    }

    /// What [`Mutex::lock`] hands back; the mutex is released when it is dropped.
    pub struct MutexGuard<'a, T> {
        mutex: &'a Mutex<T>,
    }

    impl<T> Deref for MutexGuard<'_, T> {
        type Target = T;
        fn deref(&self) -> &T {
            // SAFETY: the guard holds the mutex, so no other reference to the value is live.
            unsafe { &*self.mutex.value.get() }
        }
    }

    impl<T> DerefMut for MutexGuard<'_, T> {
        fn deref_mut(&mut self) -> &mut T {
            // SAFETY: as for `deref`, and `&mut self` makes this the only one.
            unsafe { &mut *self.mutex.value.get() }
        }
    }

    impl<T> Drop for MutexGuard<'_, T> {
        fn drop(&mut self) {
            // SAFETY: this guard holds the mutex it unlocks.
            unsafe { wz_os_mutex_unlock(self.mutex.raw.as_ptr()) }
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn a_spawned_thread_is_another_thread_and_is_joined() {
        let here = current();
        let (handle, there) = spawn(|| {}).expect("a host gives a thread");
        handle.join();
        assert_ne!(here, there, "the spawned thread has an identity of its own");
        assert_eq!(current(), here);
    }

    #[test]
    fn a_poisoned_mutex_still_holds_its_value() {
        let shared = alloc::sync::Arc::new(Mutex::new(3));
        let held = alloc::sync::Arc::clone(&shared);
        let _ = std::thread::spawn(move || {
            let _guard = held.lock();
            panic!("poison the mutex");
        })
        .join();
        assert_eq!(*shared.lock(), 3);
    }
}
