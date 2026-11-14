// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! FFI-boundary safety helpers shared across the exported symbols.
//!
//! Two invariants every `#[no_mangle] extern "C"` export upholds:
//!
//! 1. **No unwinding across the boundary.** A Rust panic crossing an
//!    `extern "C"` frame is undefined behaviour. [`guard`] wraps the body in
//!    `std::panic::catch_unwind` and converts a panic into a
//!    [`crate::result::Z_ERR_GENERIC`] return (or the caller-chosen fallback).
//!    Without `std` nothing unwinds: an image's panic handler stops the program
//!    (its staticlib is built `panic = "abort"`), so the body runs as it is.
//!
//! 2. **Raw C pointers can be moved across threads.** The wz drive loop runs
//!    on a worker thread; a subscriber's C `context` pointer must travel with
//!    it. [`SendPtr`] is the explicit, auditable assertion that the C side
//!    owns that pointer's thread-safety (the pico closure contract: the
//!    callback fires from the read task, the `drop` from teardown — never
//!    concurrently).

use alloc::sync::Arc;

use wz_capi_port::os::{Condvar, Mutex};

use crate::prelude::*;
use crate::result::{ZResult, Z_ERR_GENERIC};

/// Run `body`, or answer `None` when it panicked, so that no panic unwinds into the C frame that
/// called. A body that ran to the end answers `Some`.
#[cfg(feature = "std")]
#[inline]
pub(crate) fn catch<R>(body: impl FnOnce() -> R) -> Option<R> {
    std::panic::catch_unwind(core::panic::AssertUnwindSafe(body)).ok()
}

/// Run `body`. Without `std` a panic does not unwind (the module doc), so a body that returns
/// ran to the end.
#[cfg(not(feature = "std"))]
#[inline]
pub(crate) fn catch<R>(body: impl FnOnce() -> R) -> Option<R> {
    Some(body())
}

/// Run an export body, converting a panic into a status code instead of
/// unwinding across the C ABI boundary. Returns `fallback` if the body
/// panics.
#[inline]
pub(crate) fn guard<F>(fallback: ZResult, body: F) -> ZResult
where
    F: FnOnce() -> ZResult,
{
    catch(body).unwrap_or(fallback)
}

/// Run an export body that returns a status code, defaulting the panic
/// fallback to [`Z_ERR_GENERIC`].
#[inline]
pub(crate) fn guarded<F>(body: F) -> ZResult
where
    F: FnOnce() -> ZResult,
{
    guard(Z_ERR_GENERIC, body)
}

/// Run an export body returning a value (e.g. a `usize` length); a panic
/// yields `fallback`.
#[inline]
pub(crate) fn guard_val<F, T>(fallback: T, body: F) -> T
where
    F: FnOnce() -> T,
{
    catch(body).unwrap_or(fallback)
}

/// A raw C pointer the caller has asserted is safe to move across threads.
///
/// Used for a subscriber callback's `context`: pico's contract is that the
/// callback and its `drop` never run concurrently, and the C side owns the
/// pointee. Wrapping it lets the wz drive loop (a worker thread) invoke the
/// callback. This is an FFI trust boundary — the safety obligation lives
/// with the C caller, exactly as it does in zenoh-pico.
#[derive(Clone, Copy)]
pub(crate) struct SendPtr(pub(crate) *mut core::ffi::c_void);

// SAFETY: the pico closure ABI contract makes the C `context` single-owner
// and non-aliased across the call/drop lifecycle; moving the opaque pointer
// to the drive thread is what a native pico read task already does.
unsafe impl Send for SendPtr {}

/// A pico closure `{ context, call, drop }` adopted from the C side, generic
/// over the plane's `call` signature.
///
/// pico's closure families (`sample`, `query`, and the `reply` a later round
/// adds) are the SAME struct modulo the callback type, and share one lifecycle
/// rule: `drop(context)` runs exactly once, at teardown, never concurrently
/// with `call`. That rule is the whole mechanism, so it lives here once — a
/// second hand-written copy is a second place for the drop-once discipline to
/// drift.
///
/// **`Sync` is deliberately NOT implemented here.** Each plane must write its
/// own `unsafe impl Sync for CClosure<ItsCallbackType>`, because the safety
/// argument is per-plane and genuinely different: the subscriber plane's rests
/// on where a publish may go and the queryable plane's on where a queryable
/// admits a query from, in each arm of pico's local switches. A blanket
/// `unsafe impl<C> Sync for CClosure<C>` would silently hand that guarantee to
/// the next plane before anyone had made its argument — which is exactly the
/// class of bug R311y288 fixed on the publish plane. Rust allows `unsafe impl`
/// on a concrete instantiation, so per-plane proofs cost nothing.
///
/// `C` is the plane's pico callback typedef, which is itself already an
/// `Option<unsafe extern "C" fn(..)>` (a nullable C function pointer), so it is
/// held directly rather than re-wrapped.
pub(crate) struct CClosure<C> {
    pub(crate) context: SendPtr,
    pub(crate) call: C,
    pub(crate) drop: Option<unsafe extern "C" fn(*mut core::ffi::c_void)>,
    released: Arc<ReleaseLatch>,
}

impl<C> CClosure<C> {
    /// Adopt a moved C closure's fields. The caller nulls the source (pico's
    /// consume-on-all-paths contract): from here this value owns the
    /// responsibility to run `drop(context)`.
    pub(crate) fn new(
        context: *mut core::ffi::c_void,
        call: C,
        drop: Option<unsafe extern "C" fn(*mut core::ffi::c_void)>,
    ) -> Self {
        Self {
            context: SendPtr(context),
            call,
            drop,
            released: Arc::new(ReleaseLatch::default()),
        }
    }

    /// The latch that opens once this closure's `drop(context)` has run. An entity that owns the
    /// closure takes it before the closure moves into the engine, and waits on it after the
    /// engine let go, which is how an undeclare returns only when the callback is finished.
    pub(crate) fn release_latch(&self) -> Arc<ReleaseLatch> {
        self.released.clone()
    }
}

impl<C> Drop for CClosure<C> {
    fn drop(&mut self) {
        if let Some(dropfn) = self.drop.take() {
            // SAFETY: pico contract — drop runs once, never concurrently with
            // call. A panic across the C boundary is UB, so guard it.
            let ctx = self.context.0;
            let _ = catch(|| unsafe {
                dropfn(ctx);
            });
        }
        self.released.open();
    }
}

/// Opens once, when the last holder of a closure has let go of it and its `drop(context)` has
/// run. Zenoh-pico's undeclare waits for the callbacks in flight and then runs the closure's
/// drop before it returns (`_z_sync_group_wait`), so a program may free what the callback reads
/// the moment an undeclare returns; this is what gives a call here the same word.
#[derive(Default)]
pub(crate) struct ReleaseLatch {
    open: Mutex<bool>,
    opened: Condvar,
}

impl ReleaseLatch {
    fn open(&self) {
        *self.open.lock() = true;
        self.opened.notify_all();
    }

    /// Block until the closure is released, unless this thread is inside one of the program's
    /// callbacks: that callback holds the closure, so waiting would wait for itself. The
    /// closure is then released when the callback returns, as it was before there was a wait.
    pub(crate) fn wait(&self) {
        if InCallback::here() {
            return;
        }
        let mut open = self.open.lock();
        while !*open {
            open = self.opened.wait(open);
        }
    }
}

impl ReleaseLatch {
    fn is_open(&self) -> bool {
        *self.open.lock()
    }
}

/// Waits for a closure's release when it is dropped. A struct that holds what the closure's
/// callbacks run through declares this LAST: fields drop in declaration order, so the wait comes
/// after everything before it has let go, which a `Drop::drop` body cannot say. The default waits
/// for nothing, which is what an owner whose callbacks are not the program's holds.
///
/// Its holders are the advanced publisher's and subscriber's states, so it exists where they do;
/// a build without `advanced` (the client-only and reduced builds) would carry it unused.
#[cfg(feature = "advanced")]
#[derive(Default)]
pub(crate) struct AwaitRelease(LatchList);

#[cfg(feature = "advanced")]
impl AwaitRelease {
    pub(crate) fn new(latch: Arc<ReleaseLatch>) -> Self {
        let list = LatchList::default();
        list.keep(latch);
        Self(list)
    }

    /// Wait for one more closure as well, one the owner came to hold after it was made.
    pub(crate) fn add(&self, latch: Arc<ReleaseLatch>) {
        self.0.keep(latch);
    }

    /// Take the latches, so that dropping this waits for nothing: the owner hands them to
    /// whoever will wait (a session's close) because the state outlives the handle.
    pub(crate) fn disarm(&mut self) -> Vec<Arc<ReleaseLatch>> {
        self.0.take_all()
    }
}

#[cfg(feature = "advanced")]
impl Drop for AwaitRelease {
    fn drop(&mut self) {
        self.0.wait_all();
    }
}

/// The latches of the closures an owner is answerable for, to wait on together. An owner that
/// hands out many (a querier's gets, a session's background declarations) keeps only the ones
/// still closed, so the list is as long as what is still running and not as what ever ran.
#[derive(Default)]
pub(crate) struct LatchList(Mutex<Vec<Arc<ReleaseLatch>>>);

impl LatchList {
    pub(crate) fn keep(&self, latch: Arc<ReleaseLatch>) {
        let mut list = self.0.lock();
        list.retain(|kept| !kept.is_open());
        list.push(latch);
    }

    /// Block until every kept closure has run its `drop(context)`. The list is emptied first, so
    /// a waiter holds nothing a callback running meanwhile could need.
    pub(crate) fn wait_all(&self) {
        for latch in self.take_all() {
            latch.wait();
        }
    }

    pub(crate) fn take_all(&self) -> Vec<Arc<ReleaseLatch>> {
        core::mem::take(&mut *self.0.lock())
    }
}

/// Marks the thread as running one of the program's callbacks until it is dropped; held across
/// the C call at every site that makes one.
pub(crate) struct InCallback(callback_depth::Entered);

impl InCallback {
    pub(crate) fn enter() -> Self {
        Self(callback_depth::enter())
    }

    /// Whether the calling thread is inside one of the program's callbacks.
    pub(crate) fn here() -> bool {
        callback_depth::here()
    }
}

/// How many of the program's callbacks each thread is running: a thread-local count on a host,
/// whose callbacks are on the hot path of every delivery.
#[cfg(feature = "std")]
mod callback_depth {
    use core::cell::Cell;

    std::thread_local! {
        static IN_CALLBACK: Cell<usize> = const { Cell::new(0) };
    }

    /// One callback of the calling thread, from [`enter`] to drop.
    pub(super) struct Entered;

    pub(super) fn enter() -> Entered {
        IN_CALLBACK.with(|depth| depth.set(depth.get() + 1));
        Entered
    }

    pub(super) fn here() -> bool {
        IN_CALLBACK.with(|depth| depth.get()) > 0
    }

    impl Drop for Entered {
        fn drop(&mut self) {
            IN_CALLBACK.with(|depth| depth.set(depth.get() - 1));
        }
    }
}

/// How many of the program's callbacks each thread is running, without `std`: one entry for each
/// callback in the process's table, keyed by the thread's identity, because an MCU kernel gives a
/// Rust image no thread-local storage. Compiled for the host's tests too, so the table is run
/// where the tests run.
#[cfg(any(not(feature = "std"), test))]
mod callback_table {
    use alloc::vec::Vec;

    use wz_capi_port::os::{self, ThreadId};
    use wz_capi_port::sync::Lock;

    static IN_CALLBACK: Lock<Vec<ThreadId>> = Lock::new(Vec::new());

    /// One callback of the calling thread, from [`enter`] to drop.
    pub(super) struct Entered {
        thread: ThreadId,
    }

    pub(super) fn enter() -> Entered {
        let thread = os::current();
        IN_CALLBACK.with(|threads| threads.push(thread));
        Entered { thread }
    }

    pub(super) fn here() -> bool {
        let thread = os::current();
        IN_CALLBACK.with(|threads| threads.contains(&thread))
    }

    impl Drop for Entered {
        fn drop(&mut self) {
            let thread = self.thread;
            IN_CALLBACK.with(|threads| {
                if let Some(at) = threads.iter().rposition(|t| *t == thread) {
                    threads.swap_remove(at);
                }
            });
        }
    }
}

#[cfg(not(feature = "std"))]
use callback_table as callback_depth;

#[cfg(test)]
mod tests {
    use super::callback_table;

    #[test]
    fn the_callback_table_counts_each_thread_on_its_own() {
        assert!(!callback_table::here());
        let outer = callback_table::enter();
        let inner = callback_table::enter();
        assert!(callback_table::here());
        let elsewhere = std::thread::spawn(callback_table::here)
            .join()
            .expect("the probe thread ends");
        assert!(!elsewhere, "another thread is in no callback");
        drop(inner);
        assert!(callback_table::here(), "the outer callback still runs");
        drop(outer);
        assert!(!callback_table::here());
    }
}
