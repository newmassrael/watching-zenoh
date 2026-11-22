// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What an engine asks of the operating system it runs on: a mutex held across a step, the
//! identity of the calling thread, a thread of its own, and a sleep; and what a C ABI over it asks
//! besides: a condition variable that a thread waits on with that mutex held, which zenoh-pico's
//! channels and its undeclare (waiting for a callback in flight) block on.
//!
//! An engine that the program steps still has a lock and may have a thread: the session is shared
//! between the C session handle and every entity on it and is called from any thread, and
//! zenoh-pico's multi-threaded arm runs a read task beside the program (`docs/upstream-parity.md`
//! section 5a, E1). On a host these are `std`'s, or in a host library built without `std` the
//! host's own calls' (`os-sys`, `wz-host-sync`). On an MCU they are the kernel's, reached through
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
//! int   wz_os_mutex_try_lock(void *mutex);     /* 0 once it is this thread's; never waits */
//! void  wz_os_mutex_unlock(void *mutex);
//! void  wz_os_mutex_free(void *mutex);
//! void *wz_os_condvar_new(void);               /* NULL when none is left */
//! void  wz_os_condvar_wait(void *condvar, void *mutex); /* mutex held; held again on return */
//! void  wz_os_condvar_notify_one(void *condvar);
//! void  wz_os_condvar_notify_all(void *condvar);
//! void  wz_os_condvar_free(void *condvar);
//! uintptr_t wz_os_thread_current(void);        /* never 0 */
//! int   wz_os_thread_spawn(void (*entry)(void *), void *arg, uintptr_t *id);  /* 0 on success */
//! int   wz_os_thread_join(uintptr_t id);       /* waits for it to end, then frees it */
//! int   wz_os_thread_is_finished(uintptr_t id); /* 1 once it has ended, without waiting */
//! void  wz_os_sleep_ms(uint32_t ms);
//! ```

#[cfg(feature = "std")]
pub use host::*;
#[cfg(not(feature = "std"))]
pub use system::*;

// Without `std` the same names are a kernel's, through the functions an image links, or a host's
// own calls' in a host library built without `std` (`os-sys`): the feature chooses how the names
// are answered, not which names there are.
#[cfg(all(not(feature = "std"), not(feature = "os-sys")))]
use kernel as system;
#[cfg(all(not(feature = "std"), feature = "os-sys"))]
use sys as system;

/// The host's: `std`.
#[cfg(feature = "std")]
mod host {
    use std::sync::PoisonError;

    /// The identity of a thread, comparable with another's.
    pub type ThreadId = std::thread::ThreadId;

    /// The calling thread's identity.
    pub fn current() -> ThreadId {
        std::thread::current().id()
    }

    /// The calling thread's identity as a word, never 0, which no other thread has while this one
    /// runs: what an atomic can hold where [`ThreadId`] cannot. The address of a thread-local of
    /// this thread's, as `std` gives a thread's id no number.
    pub fn current_word() -> usize {
        std::thread_local! {
            static WORD: u8 = const { 0 };
        }
        WORD.with(|word| core::ptr::from_ref(word) as usize)
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

        /// A new mutex written in `place` around the value `make` writes in the place it is
        /// handed and lends back. The host's mutex is not written field by field, so the value is
        /// made in a place of this frame and moved into the mutex once: a host's stack holds it.
        /// A maker that lends back anything but the place it was handed has not written it there,
        /// and is refused with a panic. `place` is overwritten without dropping what it held.
        pub fn new_in(
            place: &mut core::mem::MaybeUninit<Self>,
            make: impl FnOnce(&mut core::mem::MaybeUninit<T>) -> &mut T,
        ) -> &mut Self {
            let mut value = core::mem::MaybeUninit::uninit();
            let cell: *const T = value.as_ptr();
            let made: *const T = make(&mut value);
            assert!(
                core::ptr::eq(made, cell),
                "the value is written in the place it was handed"
            );
            // SAFETY: `make` lent back this place as a `T`, which safe code does only by writing
            // a `T` there (`MaybeUninit::write`).
            place.write(Self::new(unsafe { value.assume_init() }))
        }

        /// Wait until the mutex is this thread's. A mutex poisoned by a panic still holds a
        /// consistent value (every critical section of an engine leaves it so), and is recovered.
        pub fn lock(&self) -> MutexGuard<'_, T> {
            self.0.lock().unwrap_or_else(PoisonError::into_inner)
        }

        /// The mutex, when no thread holds it: `None` without waiting when one does. A poisoned
        /// one is recovered, as [`Self::lock`] recovers it.
        pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
            match self.0.try_lock() {
                Ok(guard) => Some(guard),
                Err(std::sync::TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => None,
            }
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

    /// The process's condition variable, waited on with a [`Mutex`]'s guard.
    #[derive(Default)]
    pub struct Condvar(std::sync::Condvar);

    impl Condvar {
        /// A condition variable no thread waits on.
        pub fn new() -> Self {
            Self(std::sync::Condvar::new())
        }

        /// Release the guard's mutex, sleep until notified, and take the mutex again. A wake may
        /// come without a notification, so the caller waits in a loop on its own condition.
        pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
            self.0.wait(guard).unwrap_or_else(PoisonError::into_inner)
        }

        /// Wake one waiting thread, if one waits.
        pub fn notify_one(&self) {
            self.0.notify_one();
        }

        /// Wake every waiting thread.
        pub fn notify_all(&self) {
            self.0.notify_all();
        }
    }
}

/// A kernel's, through the functions the image links (the module doc).
#[cfg(all(not(feature = "std"), not(feature = "os-sys")))]
mod kernel {
    use alloc::boxed::Box;
    use core::cell::UnsafeCell;
    use core::ffi::{c_int, c_void};
    use core::mem::MaybeUninit;
    use core::ops::{Deref, DerefMut};
    use core::ptr::{addr_of_mut, NonNull};

    extern "C" {
        fn wz_os_mutex_new() -> *mut c_void;
        fn wz_os_mutex_lock(mutex: *mut c_void);
        fn wz_os_mutex_try_lock(mutex: *mut c_void) -> c_int;
        fn wz_os_mutex_unlock(mutex: *mut c_void);
        fn wz_os_mutex_free(mutex: *mut c_void);
        fn wz_os_condvar_new() -> *mut c_void;
        fn wz_os_condvar_wait(condvar: *mut c_void, mutex: *mut c_void);
        fn wz_os_condvar_notify_one(condvar: *mut c_void);
        fn wz_os_condvar_notify_all(condvar: *mut c_void);
        fn wz_os_condvar_free(condvar: *mut c_void);
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

    /// The calling thread's identity as a word, never 0, which no other thread has while this one
    /// runs: the kernel's handle of it.
    pub fn current_word() -> usize {
        current().0
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
            Self {
                raw: Self::raw(),
                value: UnsafeCell::new(value),
            }
        }

        /// A new mutex written in `place` around the value `make` writes in the place it is
        /// handed and lends back: neither the value nor the mutex is a value of its own on a
        /// stack, where `new` takes the value by value and returns the mutex by value. A maker
        /// that lends back anything but the place it was handed has not written it there, and is
        /// refused with a panic. `place` is overwritten without dropping what it held.
        pub fn new_in(
            place: &mut MaybeUninit<Self>,
            make: impl FnOnce(&mut MaybeUninit<T>) -> &mut T,
        ) -> &mut Self {
            let at = place.as_mut_ptr();
            // SAFETY: `at` is valid for writes of a `Self`, and each field is written once
            // through a pointer to it: the value in its cell (`UnsafeCell<T>` and
            // `MaybeUninit<T>` each have the layout of `T`) by `make`, which lent the cell back
            // and so wrote it, then the kernel's mutex.
            unsafe {
                let cell = &mut *addr_of_mut!((*at).value).cast::<MaybeUninit<T>>();
                let field: *const T = cell.as_ptr();
                let made: *const T = make(cell);
                assert!(
                    core::ptr::eq(made, field),
                    "the value is written in the place it was handed"
                );
                addr_of_mut!((*at).raw).write(Self::raw());
                &mut *at
            }
        }

        /// A new kernel mutex. A kernel with no mutex left is out of memory, which this answers
        /// as an allocation that failed.
        fn raw() -> NonNull<c_void> {
            // SAFETY: the image's contract (module doc).
            NonNull::new(unsafe { wz_os_mutex_new() }).unwrap_or_else(|| {
                alloc::alloc::handle_alloc_error(core::alloc::Layout::new::<T>())
            })
        }

        /// Wait until the mutex is this thread's.
        pub fn lock(&self) -> MutexGuard<'_, T> {
            // SAFETY: `raw` is this mutex's, alive until it drops.
            unsafe { wz_os_mutex_lock(self.raw.as_ptr()) };
            MutexGuard { mutex: self }
        }

        /// The mutex, when the kernel gives it at once: `None` without waiting when another
        /// thread holds it.
        pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
            // SAFETY: `raw` is this mutex's, alive until it drops; a 0 answer is the mutex taken,
            // which the guard gives back.
            if unsafe { wz_os_mutex_try_lock(self.raw.as_ptr()) } == 0 {
                Some(MutexGuard { mutex: self })
            } else {
                None
            }
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

    /// The kernel's condition variable, waited on with a [`Mutex`]'s guard.
    pub struct Condvar {
        raw: NonNull<c_void>,
    }

    // SAFETY: the kernel's condition variable may be waited on and notified from any thread; it
    // holds no value of its own.
    unsafe impl Send for Condvar {}
    unsafe impl Sync for Condvar {}

    impl Condvar {
        /// A condition variable no thread waits on. A kernel with none left is out of memory, as
        /// for a [`Mutex`].
        pub fn new() -> Self {
            // SAFETY: the image's contract (module doc).
            let raw = NonNull::new(unsafe { wz_os_condvar_new() }).unwrap_or_else(|| {
                alloc::alloc::handle_alloc_error(core::alloc::Layout::new::<Self>())
            });
            Self { raw }
        }

        /// Release the guard's mutex, sleep until notified, and take the mutex again. A wake may
        /// come without a notification, so the caller waits in a loop on its own condition.
        pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
            // SAFETY: the guard holds its mutex, which the kernel releases while this thread
            // sleeps and holds again before the call returns, so the guard still holds it after.
            unsafe { wz_os_condvar_wait(self.raw.as_ptr(), guard.mutex.raw.as_ptr()) };
            guard
        }

        /// Wake one waiting thread, if one waits.
        pub fn notify_one(&self) {
            // SAFETY: `raw` is this condition variable's, alive until it drops.
            unsafe { wz_os_condvar_notify_one(self.raw.as_ptr()) }
        }

        /// Wake every waiting thread.
        pub fn notify_all(&self) {
            // SAFETY: as for `notify_one`.
            unsafe { wz_os_condvar_notify_all(self.raw.as_ptr()) }
        }
    }

    impl Default for Condvar {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Drop for Condvar {
        fn drop(&mut self) {
            // SAFETY: a thread waiting on it borrows it, so none waits once it drops; freed once.
            unsafe { wz_os_condvar_free(self.raw.as_ptr()) }
        }
    }
}

/// A host's, over its own calls (`os-sys`): for a host library built without `std`, which runs on
/// a system with threads but has no `std::thread` or `std::sync` to reach them by. The lock and
/// the condition variable are `wz-host-sync`'s one word each; a thread is the system's, and its end
/// is a flag its body sets, since the system answers that only by joining it.
#[cfg(any(
    all(not(feature = "std"), feature = "os-sys"),
    all(test, feature = "os-sys")
))]
// A test build with `std` compiles this module for its own tests, which do not reach every item.
#[cfg_attr(all(test, feature = "std"), allow(dead_code))]
mod sys {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::cell::UnsafeCell;
    use core::mem::MaybeUninit;
    use core::ops::{Deref, DerefMut};
    use core::ptr::addr_of_mut;
    use core::sync::atomic::{AtomicBool, Ordering};

    use wz_host_sync::{RawCondvar, RawLock, ThreadStart};

    /// The identity of a thread, comparable with another's: the system's number of it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct ThreadId(usize);

    /// The calling thread's identity.
    pub fn current() -> ThreadId {
        ThreadId(wz_host_sync::current_thread())
    }

    /// The calling thread's identity as a word, never 0, which no other thread has while this one
    /// runs: the system's number of it.
    pub fn current_word() -> usize {
        current().0
    }

    /// A thread [`spawn`] started, until it is joined.
    pub struct JoinHandle {
        thread: wz_host_sync::Thread,
        finished: Arc<AtomicBool>,
    }

    impl JoinHandle {
        /// Wait until the thread has ended.
        pub fn join(self) {
            self.thread.join();
        }

        /// Whether the thread has ended, without waiting for it.
        pub fn is_finished(&self) -> bool {
            self.finished.load(Ordering::Acquire)
        }
    }

    type Body = Box<dyn FnOnce() + Send + 'static>;

    /// What a spawned thread is handed: the system's start record first, so the thread reaches the
    /// rest from it.
    #[repr(C)]
    struct Start {
        head: ThreadStart,
        body: Body,
        finished: Arc<AtomicBool>,
    }

    /// # Safety
    /// `head` is the first field of the `Start` that [`spawn`] leaked for this thread.
    unsafe fn run(head: *mut ThreadStart) {
        let start = Box::from_raw(head.cast::<Start>());
        let Start { body, finished, .. } = *start;
        body();
        finished.store(true, Ordering::Release);
    }

    /// Run `body` on a thread of its own: its handle and its identity, or `None` when the system
    /// gave no thread.
    pub fn spawn(body: impl FnOnce() + Send + 'static) -> Option<(JoinHandle, ThreadId)> {
        let finished = Arc::new(AtomicBool::new(false));
        let start = Box::into_raw(Box::new(Start {
            head: ThreadStart { run },
            body: Box::new(body),
            finished: Arc::clone(&finished),
        }));
        // SAFETY: `run` takes the record back exactly once, on the new thread; on a refusal no
        // thread runs and it is taken back here instead.
        match unsafe { wz_host_sync::spawn(start.cast::<ThreadStart>()) } {
            Some(thread) => {
                let id = ThreadId(thread.id());
                Some((JoinHandle { thread, finished }, id))
            }
            None => {
                // SAFETY: as above: no thread took it.
                drop(unsafe { Box::from_raw(start) });
                None
            }
        }
    }

    /// Sleep the calling thread for `ms` milliseconds.
    pub fn sleep_ms(ms: u64) {
        wz_host_sync::sleep_ms(ms);
    }

    /// The host's lock around a value.
    pub struct Mutex<T> {
        raw: RawLock,
        value: UnsafeCell<T>,
    }

    // SAFETY: the value is reached only through a guard, and the lock lets one thread hold a guard
    // at a time.
    unsafe impl<T: Send> Sync for Mutex<T> {}

    impl<T> Mutex<T> {
        /// `value`, behind a new mutex.
        pub const fn new(value: T) -> Self {
            Self {
                raw: RawLock::new(),
                value: UnsafeCell::new(value),
            }
        }

        /// A new mutex written in `place` around the value `make` writes in the place it is
        /// handed and lends back: neither the value nor the mutex is a value of its own on a
        /// stack. A maker that lends back anything but the place it was handed has not written it
        /// there, and is refused with a panic. `place` is overwritten without dropping what it
        /// held.
        pub fn new_in(
            place: &mut MaybeUninit<Self>,
            make: impl FnOnce(&mut MaybeUninit<T>) -> &mut T,
        ) -> &mut Self {
            let at = place.as_mut_ptr();
            // SAFETY: `at` is valid for writes of a `Self`, and each field is written once
            // through a pointer to it: the value in its cell (`UnsafeCell<T>` and
            // `MaybeUninit<T>` each have the layout of `T`) by `make`, which lent the cell back
            // and so wrote it, then the lock.
            unsafe {
                let cell = &mut *addr_of_mut!((*at).value).cast::<MaybeUninit<T>>();
                let field: *const T = cell.as_ptr();
                let made: *const T = make(cell);
                assert!(
                    core::ptr::eq(made, field),
                    "the value is written in the place it was handed"
                );
                addr_of_mut!((*at).raw).write(RawLock::new());
                &mut *at
            }
        }

        /// Wait until the mutex is this thread's.
        pub fn lock(&self) -> MutexGuard<'_, T> {
            self.raw.lock();
            MutexGuard { mutex: self }
        }

        /// The mutex, when no thread holds it: `None` without waiting when one does (this one
        /// included: the lock is not reentrant).
        pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
            if self.raw.try_lock() {
                Some(MutexGuard { mutex: self })
            } else {
                None
            }
        }

        /// The value, through the only reference there is.
        pub fn get_mut(&mut self) -> &mut T {
            self.value.get_mut()
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
            unsafe { self.mutex.raw.unlock() }
        }
    }

    /// The host's condition variable, waited on with a [`Mutex`]'s guard.
    #[derive(Default)]
    pub struct Condvar {
        raw: RawCondvar,
    }

    impl Condvar {
        /// A condition variable no thread waits on.
        pub fn new() -> Self {
            Self {
                raw: RawCondvar::new(),
            }
        }

        /// Release the guard's mutex, sleep until notified, and take the mutex again. A wake may
        /// come without a notification, so the caller waits in a loop on its own condition.
        pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
            // SAFETY: the guard holds its mutex, which the wait releases and takes again before it
            // returns, so the guard still holds it after.
            unsafe { self.raw.wait(&guard.mutex.raw) };
            guard
        }

        /// Wake one waiting thread, if one waits.
        pub fn notify_one(&self) {
            self.raw.notify_one();
        }

        /// Wake every waiting thread.
        pub fn notify_all(&self) {
            self.raw.notify_all();
        }
    }

    #[cfg(test)]
    mod tests {
        extern crate std;

        use super::*;

        /// A spawned thread runs under an identity of its own, which is the one its spawn gave; it
        /// reads as running until its body has returned, and as finished after.
        #[test]
        fn a_spawned_thread_has_its_own_identity_and_reports_its_end() {
            let here = current();
            let go = Arc::new(AtomicBool::new(false));
            let seen = Arc::new(Mutex::new(None));
            let (handle, there) = {
                let go = Arc::clone(&go);
                let seen = Arc::clone(&seen);
                spawn(move || {
                    while !go.load(Ordering::Acquire) {
                        sleep_ms(1);
                    }
                    *seen.lock() = Some(current());
                })
                .expect("a host gives a thread")
            };
            assert_ne!(here, there, "the spawned thread has an identity of its own");
            assert!(!handle.is_finished(), "the body has not returned");
            go.store(true, Ordering::Release);
            let started = std::time::Instant::now();
            while !handle.is_finished() {
                assert!(
                    started.elapsed() < std::time::Duration::from_secs(5),
                    "the thread never ended"
                );
                sleep_ms(1);
            }
            handle.join();
            assert_eq!(
                *seen.lock(),
                Some(there),
                "the thread is the one its spawn named"
            );
            assert_eq!(current(), here);
        }

        #[test]
        fn a_waiter_on_the_condvar_sees_what_the_notifier_wrote_under_the_mutex() {
            let shared = Arc::new((Mutex::new(false), Condvar::new()));
            let notifier = Arc::clone(&shared);
            let (handle, _) = spawn(move || {
                sleep_ms(20);
                *notifier.0.lock() = true;
                notifier.1.notify_one();
            })
            .expect("a host gives a thread");
            let mut ready = shared.0.lock();
            while !*ready {
                ready = shared.1.wait(ready);
            }
            drop(ready);
            handle.join();
        }

        /// A mutex made in its place holds the value its maker wrote there, and its lock is the
        /// lock a mutex made by value has.
        #[test]
        fn a_mutex_made_in_its_place_holds_what_its_maker_wrote() {
            let mut place = core::mem::MaybeUninit::<Mutex<u32>>::uninit();
            let mutex = Mutex::new_in(&mut place, |value| value.write(7));
            let guard = mutex.lock();
            assert!(mutex.try_lock().is_none(), "a held mutex is not given");
            drop(guard);
            assert_eq!(mutex.try_lock().map(|value| *value), Some(7));
            // SAFETY: `new_in` wrote the whole mutex into `place`, and it is dropped once.
            unsafe { place.assume_init_drop() };
        }

        /// A held mutex is not given to a try, by this thread or another, and is once let go;
        /// `get_mut` reaches the value with no lock.
        #[test]
        fn a_held_mutex_is_tried_without_waiting() {
            let mut mutex = Mutex::new(5);
            *mutex.get_mut() = 6;
            let guard = mutex.lock();
            assert!(mutex.try_lock().is_none(), "a held mutex is not given");
            drop(guard);
            assert_eq!(mutex.try_lock().map(|value| *value), Some(6));
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

    /// A thread's word is the same each time it asks, is never 0, and is not a word another
    /// thread running beside it has.
    #[test]
    fn a_threads_word_is_its_own_while_it_runs() {
        let here = current_word();
        assert_ne!(here, 0);
        assert_eq!(current_word(), here, "the same thread, the same word");
        let (tell, told) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let beside = std::thread::spawn(move || {
            tell.send(current_word()).expect("the test waits");
            // Kept running while the test compares, so its word is a live thread's.
            let _ = released.recv_timeout(std::time::Duration::from_secs(3));
        });
        let there = told.recv().expect("the thread's word");
        assert_ne!(there, 0);
        assert_ne!(there, here, "a thread running beside has a word of its own");
        release.send(()).expect("the thread waits");
        beside.join().expect("the thread");
    }

    #[test]
    fn a_waiter_on_the_condvar_sees_what_the_notifier_wrote_under_the_mutex() {
        let shared = alloc::sync::Arc::new((Mutex::new(false), Condvar::new()));
        let notifier = alloc::sync::Arc::clone(&shared);
        let (handle, _) = spawn(move || {
            sleep_ms(20);
            *notifier.0.lock() = true;
            notifier.1.notify_all();
        })
        .expect("a host gives a thread");
        let mut ready = shared.0.lock();
        while !*ready {
            ready = shared.1.wait(ready);
        }
        assert!(*ready, "the wait ends only once the flag is set");
        drop(ready);
        handle.join();
    }

    /// A mutex another thread holds is not waited for: the try answers at once, and takes it once
    /// it is let go.
    #[test]
    fn a_held_mutex_is_tried_without_waiting() {
        let shared = alloc::sync::Arc::new(Mutex::new(5));
        assert_eq!(
            shared.try_lock().map(|value| *value),
            Some(5),
            "CONTROL: a free mutex is taken"
        );
        let (taken, held) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let holder = alloc::sync::Arc::clone(&shared);
        let thread = std::thread::spawn(move || {
            let _guard = holder.lock();
            taken.send(()).expect("the test waits");
            // Bounded, so a try that waited cannot hold the test past it.
            let _ = released.recv_timeout(std::time::Duration::from_secs(3));
        });
        held.recv().expect("the holder took the mutex");
        let started = std::time::Instant::now();
        assert!(shared.try_lock().is_none(), "a held mutex is not given");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "the try did not wait for the holder"
        );
        release.send(()).expect("the holder waits");
        thread.join().expect("the holder");
        assert!(shared.try_lock().is_some(), "and is taken once let go");
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

    /// A mutex made in its place holds the value its maker wrote there, as one made by value.
    #[test]
    fn a_mutex_made_in_its_place_holds_what_its_maker_wrote() {
        let mut place = core::mem::MaybeUninit::<Mutex<u32>>::uninit();
        let mutex = Mutex::new_in(&mut place, |value| value.write(7));
        *mutex.lock() += 1;
        assert_eq!(*mutex.lock(), 8);
        // SAFETY: `new_in` wrote the whole mutex into `place`, and it is dropped once.
        unsafe { place.assume_init_drop() };
    }

    /// A maker that lends back a value it did not write in the place it was handed is refused.
    #[test]
    #[should_panic(expected = "the value is written in the place it was handed")]
    fn a_maker_that_lends_back_another_place_is_refused() {
        let elsewhere: &'static mut u32 = std::boxed::Box::leak(std::boxed::Box::new(1));
        let mut place = core::mem::MaybeUninit::<Mutex<u32>>::uninit();
        Mutex::new_in(&mut place, |_| elsewhere);
    }
}
