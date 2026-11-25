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
//! On a host the mutex and the condition variable are `wz-host-sync`'s typed forms, with `std` or
//! without: one lock that takes no memory when it is made, taken, waited on or notified, on every
//! host (`std`'s own where it lies in its own bytes, the in-place one where `std`'s is a pthread
//! object `std` boxes on its first take). A lock a panic let go is taken as it was left, as the
//! engine always took it. The threads are `std::thread`'s with `std`.
//!
//! A kernel's mutex and condition variable are made in their owner's memory, where they stay
//! (`mutex_in`, `condvar_in`, `StaticMutex`, `StaticCondvar`), so making one asks nothing of a
//! pool or a heap and is never refused. The place of a mutex is 16 words and that of a condition
//! variable 12, aligned to 8 bytes; an image whose kernel objects do not fit says so when it is
//! built (the Zephyr one with `BUILD_ASSERT`).
//!
//! The functions an image provides without `std`:
//!
//! ```c
//! void  wz_os_mutex_init(void *place);         /* an unlocked mutex made in place; never fails */
//! void  wz_os_mutex_lock(void *mutex);         /* waits until it is this thread's */
//! int   wz_os_mutex_try_lock(void *mutex);     /* 0 once it is this thread's; never waits */
//! void  wz_os_mutex_unlock(void *mutex);
//! void  wz_os_mutex_destroy(void *mutex);      /* ended in its place, which is the owner's */
//! void  wz_os_condvar_init(void *place);       /* made in place; never fails */
//! void  wz_os_condvar_wait(void *condvar, void *mutex); /* mutex held; held again on return */
//! int   wz_os_condvar_wait_ms(void *condvar, void *mutex, uint32_t ms); /* as above, at most ms;
//!                                                 0 when notified, otherwise the time ran out */
//! void  wz_os_condvar_notify_one(void *condvar);
//! void  wz_os_condvar_notify_all(void *condvar);
//! void  wz_os_condvar_destroy(void *condvar);
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

// The host's lock and condition variable, with `std` and without (`os-sys`): the one that takes no
// memory on any host.
#[cfg(any(feature = "std", feature = "os-sys"))]
pub use wz_host_sync::{Condvar, Mutex, MutexGuard};

// Without `std` the same names are a kernel's, through the functions an image links, or a host's
// own calls' in a host library built without `std` (`os-sys`): the feature chooses how the names
// are answered, not which names there are.
#[cfg(all(not(feature = "std"), not(feature = "os-sys")))]
use kernel as system;
#[cfg(all(not(feature = "std"), feature = "os-sys"))]
use sys as system;

/// A mutex made in `place` around the value `make` writes in the place it is handed and lends
/// back, which no stack holds on its way. Nothing is asked of a pool or a heap, so it cannot be
/// refused: a kernel's object is made where it stays, and a host's lock is a word of its owner's.
/// A maker that lends back anything but the place it was handed has not written it there, and is
/// refused with a panic.
///
/// # Safety
/// `place` is valid for writes of a [`Mutex<T>`] and aligned for it, and what it held is
/// overwritten without being dropped. The mutex is not moved from `place` until it is dropped
/// there (`drop_in_place`): a kernel's object may point at itself.
pub unsafe fn mutex_in<T>(
    place: core::ptr::NonNull<Mutex<T>>,
    make: impl FnOnce(&mut core::mem::MaybeUninit<T>) -> &mut T,
) {
    #[cfg(any(feature = "std", feature = "os-sys"))]
    {
        // SAFETY: `place` is valid for writes of a `Mutex<T>` (the caller's contract), which a
        // `MaybeUninit` of it has the layout of.
        let place = unsafe { &mut *place.as_ptr().cast::<core::mem::MaybeUninit<Mutex<T>>>() };
        Mutex::new_in(place, make);
    }
    #[cfg(all(not(feature = "std"), not(feature = "os-sys")))]
    {
        // SAFETY: the caller's contract is `init_in`'s.
        unsafe { Mutex::init_in(place, make) };
    }
}

/// A condition variable no thread waits on, made in `place`, as [`mutex_in`] makes a mutex.
///
/// # Safety
/// As for [`mutex_in`], of a [`Condvar`].
pub unsafe fn condvar_in(place: core::ptr::NonNull<Condvar>) {
    #[cfg(any(feature = "std", feature = "os-sys"))]
    {
        // SAFETY: `place` is valid for writes of a `Condvar` (the caller's contract).
        unsafe { place.as_ptr().write(Condvar::new()) };
    }
    #[cfg(all(not(feature = "std"), not(feature = "os-sys")))]
    {
        // SAFETY: the caller's contract is `init_in`'s.
        unsafe { Condvar::init_in(place) };
    }
}

/// A mutex in a `static`, made where it lies the first time it is reached ([`Self::get`]): a
/// `static` never moves, so nothing is asked of a pool or a heap for it and it cannot be refused.
#[cfg(any(feature = "std", feature = "os-sys"))]
pub struct StaticMutex<T>(Mutex<T>);

#[cfg(any(feature = "std", feature = "os-sys"))]
impl<T> StaticMutex<T> {
    /// `value`, behind the mutex.
    pub const fn new(value: T) -> Self {
        Self(Mutex::new(value))
    }

    /// The mutex, borrowed for the rest of the program.
    pub fn get(&'static self) -> &'static Mutex<T> {
        &self.0
    }
}

/// A condition variable in a `static`, as a [`StaticMutex`] is.
#[cfg(any(feature = "std", feature = "os-sys"))]
pub struct StaticCondvar(Condvar);

#[cfg(any(feature = "std", feature = "os-sys"))]
impl StaticCondvar {
    /// A condition variable no thread waits on.
    pub const fn new() -> Self {
        Self(Condvar::new())
    }

    /// The condition variable, borrowed for the rest of the program.
    pub fn get(&'static self) -> &'static Condvar {
        &self.0
    }
}

#[cfg(any(feature = "std", feature = "os-sys"))]
impl Default for StaticCondvar {
    fn default() -> Self {
        Self::new()
    }
}

/// The host's: `std`.
#[cfg(feature = "std")]
mod host {
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
}

/// A kernel's, through the functions the image links (the module doc).
#[cfg(all(not(feature = "std"), not(feature = "os-sys")))]
mod kernel {
    use alloc::boxed::Box;
    use core::cell::UnsafeCell;
    use core::ffi::{c_int, c_void};
    use core::mem::{ManuallyDrop, MaybeUninit};
    use core::ops::{Deref, DerefMut};
    use core::ptr::{addr_of_mut, NonNull};
    use core::sync::atomic::{AtomicBool, Ordering};

    /// The words a kernel's mutex and condition variable are placed in, at an alignment of 8
    /// bytes: what the image's `wz_os_mutex_init` and `wz_os_condvar_init` state their objects
    /// fit (module doc).
    const MUTEX_WORDS: usize = 16;
    const CONDVAR_WORDS: usize = 12;

    extern "C" {
        fn wz_os_mutex_init(place: *mut c_void);
        fn wz_os_mutex_lock(mutex: *mut c_void);
        fn wz_os_mutex_try_lock(mutex: *mut c_void) -> c_int;
        fn wz_os_mutex_unlock(mutex: *mut c_void);
        fn wz_os_mutex_destroy(mutex: *mut c_void);
        fn wz_os_condvar_init(place: *mut c_void);
        fn wz_os_condvar_wait(condvar: *mut c_void, mutex: *mut c_void);
        fn wz_os_condvar_wait_ms(condvar: *mut c_void, mutex: *mut c_void, ms: u32) -> c_int;
        fn wz_os_condvar_notify_one(condvar: *mut c_void);
        fn wz_os_condvar_notify_all(condvar: *mut c_void);
        fn wz_os_condvar_destroy(condvar: *mut c_void);
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

    /// The bytes a kernel object of `WORDS` words is placed in: the image states that its
    /// object fits (module doc), and the place is the owner's, where the object stays.
    #[repr(C, align(8))]
    struct RawPlace<const WORDS: usize>(UnsafeCell<MaybeUninit<[usize; WORDS]>>);

    impl<const WORDS: usize> RawPlace<WORDS> {
        const fn uninit() -> Self {
            Self(UnsafeCell::new(MaybeUninit::uninit()))
        }

        fn as_ptr(&self) -> *mut c_void {
            self.0.get().cast()
        }
    }

    /// The kernel's blocking mutex around a value, placed in its owner's memory: the kernel's
    /// object may point at itself, so it is made where it stays ([`super::mutex_in`],
    /// [`StaticMutex`]) and never moves after.
    pub struct Mutex<T> {
        raw: RawPlace<MUTEX_WORDS>,
        value: UnsafeCell<T>,
    }

    // SAFETY: the value is reached only through a guard, and the kernel's mutex lets one thread
    // hold a guard at a time; the raw mutex is the kernel's and may be used from any thread.
    unsafe impl<T: Send> Send for Mutex<T> {}
    unsafe impl<T: Send> Sync for Mutex<T> {}

    impl<T> Mutex<T> {
        /// A mutex made in `place` around the value `make` writes in the place it is handed and
        /// lends back. A maker that lends back anything but the place it was handed has not
        /// written it there, and is refused with a panic.
        ///
        /// # Safety
        /// `place` is valid for writes of a `Self` and aligned for it, and what it held is
        /// overwritten without being dropped. The mutex is not moved from `place` until it is
        /// dropped there.
        pub(super) unsafe fn init_in(
            place: NonNull<Self>,
            make: impl FnOnce(&mut MaybeUninit<T>) -> &mut T,
        ) {
            let at = place.as_ptr();
            // SAFETY: `at` is valid for writes of a `Self` (the caller's contract), and each
            // field is written once through a pointer to it: the value in its cell
            // (`UnsafeCell<T>` and `MaybeUninit<T>` each have the layout of `T`) by `make`,
            // which lent the cell back and so wrote it, then the kernel's mutex, in the place it
            // stays.
            unsafe {
                let cell = &mut *addr_of_mut!((*at).value).cast::<MaybeUninit<T>>();
                let field: *const T = cell.as_ptr();
                let made: *const T = make(cell);
                assert!(
                    core::ptr::eq(made, field),
                    "the value is written in the place it was handed"
                );
                wz_os_mutex_init(addr_of_mut!((*at).raw).cast());
            }
        }

        /// Wait until the mutex is this thread's.
        pub fn lock(&self) -> MutexGuard<'_, T> {
            // SAFETY: `raw` is this mutex's, made in place and alive until it drops.
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
            // SAFETY: no guard outlives the mutex, so it is unlocked, and it is ended once, in
            // the place it was made.
            unsafe { wz_os_mutex_destroy(self.raw.as_ptr()) }
        }
    }

    /// A mutex in a `static`, made in place the first time it is reached: a `static` does not
    /// move, so its kernel object can be made there, and making it needs nothing that can run
    /// out. Reached only through a borrow for the rest of the program ([`Self::get`]).
    pub struct StaticMutex<T> {
        made: AtomicBool,
        inner: ManuallyDrop<Mutex<T>>,
    }

    impl<T> StaticMutex<T> {
        /// `value`, behind a mutex not made yet.
        pub const fn new(value: T) -> Self {
            Self {
                made: AtomicBool::new(false),
                inner: ManuallyDrop::new(Mutex {
                    raw: RawPlace::uninit(),
                    value: UnsafeCell::new(value),
                }),
            }
        }

        /// The mutex, made in place by the first caller.
        pub fn get(&'static self) -> &'static Mutex<T> {
            if !self.made.load(Ordering::Acquire) {
                critical_section::with(|_| {
                    if !self.made.load(Ordering::Relaxed) {
                        // SAFETY: `self` is borrowed for the rest of the program, so the place
                        // never moves, and the critical section makes this caller the one that
                        // makes the mutex there, once.
                        unsafe { wz_os_mutex_init(self.inner.raw.as_ptr()) };
                        self.made.store(true, Ordering::Release);
                    }
                });
            }
            &self.inner
        }
    }

    impl<T> Drop for StaticMutex<T> {
        fn drop(&mut self) {
            if *self.made.get_mut() {
                // SAFETY: the mutex was made, and it is dropped once, here.
                unsafe { ManuallyDrop::drop(&mut self.inner) }
            } else {
                // SAFETY: no kernel object was made, so only the value is dropped, once.
                unsafe { core::ptr::drop_in_place(self.inner.value.get()) }
            }
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

    /// The kernel's condition variable, waited on with a [`Mutex`]'s guard, placed as a
    /// [`Mutex`] is ([`super::condvar_in`], [`StaticCondvar`]).
    pub struct Condvar {
        raw: RawPlace<CONDVAR_WORDS>,
    }

    // SAFETY: the kernel's condition variable may be waited on and notified from any thread; it
    // holds no value of its own.
    unsafe impl Send for Condvar {}
    unsafe impl Sync for Condvar {}

    impl Condvar {
        /// A condition variable no thread waits on, made in `place`.
        ///
        /// # Safety
        /// As for [`Mutex::init_in`].
        pub(super) unsafe fn init_in(place: NonNull<Self>) {
            // SAFETY: `place` is valid for writes of a `Self` and stays (the caller's
            // contract); the kernel writes its object there.
            unsafe { wz_os_condvar_init(addr_of_mut!((*place.as_ptr()).raw).cast()) }
        }

        /// Release the guard's mutex, sleep until notified, and take the mutex again. A wake may
        /// come without a notification, so the caller waits in a loop on its own condition.
        pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
            // SAFETY: the guard holds its mutex, which the kernel releases while this thread
            // sleeps and holds again before the call returns, so the guard still holds it after.
            unsafe { wz_os_condvar_wait(self.raw.as_ptr(), guard.mutex.raw.as_ptr()) };
            guard
        }

        /// [`Self::wait`] for at most `ms` milliseconds (a longer wait is one of `u32::MAX`): the
        /// guard, and whether the time ran out with no notification. A wake may come early, so the
        /// caller waits in a loop on its own condition and its own deadline.
        pub fn wait_timeout_ms<'a, T>(
            &self,
            guard: MutexGuard<'a, T>,
            ms: u64,
        ) -> (MutexGuard<'a, T>, bool) {
            let ms = u32::try_from(ms).unwrap_or(u32::MAX);
            // SAFETY: as for `wait`.
            let woken =
                unsafe { wz_os_condvar_wait_ms(self.raw.as_ptr(), guard.mutex.raw.as_ptr(), ms) };
            (guard, woken != 0)
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

    impl Drop for Condvar {
        fn drop(&mut self) {
            // SAFETY: a thread waiting on it borrows it, so none waits once it drops; ended once,
            // in the place it was made.
            unsafe { wz_os_condvar_destroy(self.raw.as_ptr()) }
        }
    }

    /// A condition variable in a `static`, made in place the first time it is reached, as a
    /// [`StaticMutex`] is.
    pub struct StaticCondvar {
        made: AtomicBool,
        inner: ManuallyDrop<Condvar>,
    }

    impl StaticCondvar {
        /// A condition variable not made yet.
        pub const fn new() -> Self {
            Self {
                made: AtomicBool::new(false),
                inner: ManuallyDrop::new(Condvar {
                    raw: RawPlace::uninit(),
                }),
            }
        }

        /// The condition variable, made in place by the first caller.
        pub fn get(&'static self) -> &'static Condvar {
            if !self.made.load(Ordering::Acquire) {
                critical_section::with(|_| {
                    if !self.made.load(Ordering::Relaxed) {
                        // SAFETY: as for `StaticMutex::get`.
                        unsafe { wz_os_condvar_init(self.inner.raw.as_ptr()) };
                        self.made.store(true, Ordering::Release);
                    }
                });
            }
            &self.inner
        }
    }

    impl Default for StaticCondvar {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Drop for StaticCondvar {
        fn drop(&mut self) {
            if *self.made.get_mut() {
                // SAFETY: the condition variable was made, and it is dropped once, here.
                unsafe { ManuallyDrop::drop(&mut self.inner) }
            }
        }
    }
}

/// A host's, over its own calls (`os-sys`): for a host library built without `std`, which runs on
/// a system with threads but has no `std::thread` or `std::sync` to reach them by. Its lock and
/// condition variable are `wz-host-sync`'s typed forms; a thread is the system's, its body and
/// the word its end sets (which the system answers only by joining it) in a record of
/// `wz-host-sync`'s static pool. Nothing here allocates.
#[cfg(any(
    all(not(feature = "std"), feature = "os-sys"),
    all(test, feature = "os-sys")
))]
// A test build with `std` compiles this module for its own tests, which do not reach every item.
#[cfg_attr(all(test, feature = "std"), allow(dead_code))]
mod sys {
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
    }

    impl JoinHandle {
        /// Wait until the thread has ended.
        pub fn join(self) {
            self.thread.join();
        }

        /// Whether the thread has ended, without waiting for it.
        pub fn is_finished(&self) -> bool {
            self.thread.is_finished()
        }
    }

    /// Run `body` on a thread of its own: its handle and its identity, or `None` when the system
    /// gave no thread or the host's pool of thread records has none free
    /// (`wz_host_sync::THREADS`). The body is moved into its record; nothing is allocated.
    pub fn spawn(body: impl FnOnce() + Send + 'static) -> Option<(JoinHandle, ThreadId)> {
        let thread = wz_host_sync::spawn_fn(body)?;
        let id = ThreadId(thread.id());
        Some((JoinHandle { thread }, id))
    }

    /// Sleep the calling thread for `ms` milliseconds.
    pub fn sleep_ms(ms: u64) {
        wz_host_sync::sleep_ms(ms);
    }

    #[cfg(test)]
    mod tests {
        extern crate std;

        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicBool, Ordering};

        use super::*;
        use crate::os::{Condvar, Mutex};

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

    /// A timed wait no notification ends runs out after at least its time, and one a notification
    /// ends says it did not run out. Turned red by a timed wait that never returns, returns early,
    /// or reads a notification as the time running out.
    #[test]
    fn a_timed_wait_runs_out_or_is_woken() {
        let shared = alloc::sync::Arc::new((Mutex::new(false), Condvar::new()));
        let started = std::time::Instant::now();
        let (guard, timed_out) = shared.1.wait_timeout_ms(shared.0.lock(), 30);
        assert!(timed_out, "nothing notified");
        assert!(started.elapsed() >= std::time::Duration::from_millis(30));
        drop(guard);
        let notifier = alloc::sync::Arc::clone(&shared);
        let (handle, _) = spawn(move || {
            sleep_ms(20);
            *notifier.0.lock() = true;
            notifier.1.notify_all();
        })
        .expect("a host gives a thread");
        let mut ready = shared.0.lock();
        let mut ran_out = false;
        while !*ready && !ran_out {
            (ready, ran_out) = shared.1.wait_timeout_ms(ready, 5_000);
        }
        assert!(*ready && !ran_out, "the notification ended the wait");
        drop(ready);
        handle.join();
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

    /// A mutex and a condition variable made in their places hold what their maker wrote and are
    /// waited on and notified as ones made by value, and are dropped in their places.
    #[test]
    fn a_mutex_and_a_condition_variable_made_in_place_work_as_made_by_value() {
        let mut mutex = core::mem::MaybeUninit::<Mutex<u32>>::uninit();
        let mut condvar = core::mem::MaybeUninit::<Condvar>::uninit();
        // SAFETY: both places are this frame's, unmoved until they are dropped below.
        unsafe {
            mutex_in(
                core::ptr::NonNull::from(&mut mutex).cast::<Mutex<u32>>(),
                |value| value.write(4),
            );
            condvar_in(core::ptr::NonNull::from(&mut condvar).cast::<Condvar>());
        }
        // SAFETY: both were made in place above.
        let (made, waits) = unsafe { (mutex.assume_init_ref(), condvar.assume_init_ref()) };
        *made.lock() += 1;
        let (guard, _) = waits.wait_timeout_ms(made.lock(), 1);
        assert_eq!(*guard, 5);
        drop(guard);
        waits.notify_all();
        // SAFETY: each is dropped once, in its place.
        unsafe {
            mutex.assume_init_drop();
            condvar.assume_init_drop();
        }
    }

    /// A mutex and a condition variable in `static`s are reached as the same ones each time.
    #[test]
    fn a_static_mutex_is_the_same_mutex_each_time_it_is_reached() {
        static COUNT: StaticMutex<u32> = StaticMutex::new(0);
        static WAITS: StaticCondvar = StaticCondvar::new();
        *COUNT.get().lock() += 1;
        *COUNT.get().lock() += 1;
        assert_eq!(*COUNT.get().lock(), 2);
        assert!(core::ptr::eq(WAITS.get(), WAITS.get()));
        WAITS.get().notify_one();
    }

    /// A lock and a condition variable made, the lock taken for the first time, tried, waited on
    /// with a timeout and the condition variable notified: what an object made after a session
    /// opened does with its own.
    macro_rules! first_use {
        ($mutex:ident, $condvar:ident) => {
            || {
                let mutex = $mutex::new(0_u32);
                let condvar = $condvar::new();
                *mutex.lock() += 1;
                drop(mutex.try_lock());
                let (guard, _) = condvar.wait_timeout_ms(mutex.lock(), 1);
                drop(guard);
                condvar.notify_one();
                condvar.notify_all();
            }
        };
    }

    /// Every allocation of the calling thread while `run` runs, counted.
    fn allocations(run: impl FnOnce()) -> usize {
        COUNTING.with(|count| count.set(Some(0)));
        run();
        COUNTING.with(|count| count.take()).unwrap_or(0)
    }

    std::thread_local! {
        static COUNTING: core::cell::Cell<Option<usize>> = const { core::cell::Cell::new(None) };
    }

    /// The test binary's allocator: the system's, counting on a thread that asked
    /// ([`allocations`]).
    struct Counting;

    // SAFETY: every call is the system allocator's; the count is a thread's own cell.
    unsafe impl std::alloc::GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
            let _ = COUNTING.try_with(|count| {
                if let Some(seen) = count.get() {
                    count.set(Some(seen.saturating_add(1)));
                }
            });
            // SAFETY: the caller's.
            unsafe { std::alloc::System.alloc(layout) }
        }

        unsafe fn dealloc(&self, at: *mut u8, layout: std::alloc::Layout) {
            // SAFETY: the caller's.
            unsafe { std::alloc::System.dealloc(at, layout) }
        }
    }

    #[global_allocator]
    static ALLOCATOR: Counting = Counting;

    /// The host's lock takes no memory when it is first taken, nor its condition variable when it
    /// is first waited on or notified, so an object made after a session opened allocates nothing
    /// for its lock, on every host.
    ///
    /// # Control
    ///
    /// The host's lock as `std::sync::Mutex` on macOS, which boxes a pthread mutex on its first
    /// take, counts an allocation; the box the second count makes is counted.
    #[test]
    fn the_hosts_lock_takes_no_memory_when_first_taken() {
        assert_eq!(
            allocations(first_use!(Mutex, Condvar)),
            0,
            "a lock and a condition variable live in their own bytes"
        );
        let control = allocations(|| drop(core::hint::black_box(alloc::boxed::Box::new(1_u64))));
        assert_eq!(control, 1, "the allocator counts");
    }

    /// The in-place lock, which a host library without `std` and a `std` build on macOS hold,
    /// takes no memory when first taken, waited on or notified, on the host the test runs on,
    /// whichever form the build chose for the port's own.
    ///
    /// # Control
    ///
    /// An in-place lock that kept its value or its waiters in a box of its own counts an
    /// allocation.
    #[cfg(any(unix, windows))]
    #[test]
    fn the_in_place_lock_takes_no_memory_when_first_taken() {
        use wz_host_sync::in_place::{Condvar as InPlaceCondvar, Mutex as InPlaceMutex};
        assert_eq!(
            allocations(first_use!(InPlaceMutex, InPlaceCondvar)),
            0,
            "the in-place lock lives in its own bytes"
        );
    }
}
