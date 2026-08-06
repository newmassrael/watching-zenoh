// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The THREAD family — zenoh-c's `z_owned_task_t` and its four operations.
//!
//! ## Why a C ABI ships a thread primitive at all
//!
//! zenoh-c's examples are single-file C programs with no portable threading
//! layer of their own, so upstream exports one: `z_task_init` /
//! `z_task_join` / `z_task_detach` / `z_task_drop`, alongside the mutex and
//! condvar [`crate::sync`] already provides. `z_pub_thr.c` and
//! `z_queryable_with_channels.c` are the shape that needs it — a worker thread
//! that drives the session while `main` waits.
//!
//! R311y568 — the six symbols below were the last of that plane wz did not
//! export, so a program using upstream's threading helpers failed at LINK time
//! while the mutex and condvar it uses alongside them resolved fine.
//!
//! ## `pthread` shape over a Rust thread
//!
//! Upstream's `fun` is `void *(*)(void *)` — the pthread signature — and its
//! return value is DISCARDED, because `z_task_join` reports a `z_result_t` and
//! has nowhere to put a `void*`. wz runs it on a `std::thread`, which gives the
//! same observable behaviour with one difference in the honest direction: a
//! panic (or a C-side unwind) inside the spawned function tears down one thread
//! and is reported by `z_task_join` as an error, rather than aborting the
//! process.
//!
//! ## `z_task_attr_t` is accepted and IGNORED, which is upstream's own position
//!
//! Upstream declares it as `struct z_task_attr_t { size_t _0; }` — a single
//! unnamed word — and its own `z_task_init` names the parameter `_attr`, the
//! Rust convention for "deliberately unused". There is no documented attribute
//! to honour, so honouring nothing is the faithful reading rather than a gap.

use std::ffi::c_void;

use crate::ffi::{guard_val, guarded, SendPtr};
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_OK};

/// zenoh-c `z_task_attr_t` (`zenoh_commons.h:1239-1241`) — one opaque word.
///
/// Declared so `z_task_init` has a parameter type; see the module note for why
/// its contents are not read.
#[repr(C)]
pub struct z_task_attr_t {
    /// Upstream's single unnamed `size_t`.
    pub _0: usize,
}

const _: () = {
    assert!(std::mem::size_of::<z_task_attr_t>() == 8);
};

/// Behind a `z_owned_task_t` handle: the join handle, or `None` once the task
/// has been joined or detached.
struct TaskState {
    handle: Option<std::thread::JoinHandle<()>>,
}

/// The state behind an owned task, taken OUT of the moved slot.
///
/// Every one of `join` / `detach` / `drop` consumes the task, so all three
/// reclaim the box here and gravestone the caller's slot — which makes a
/// defensive second call a no-op rather than a double free.
///
/// # Safety
/// `this_` must be null, or a valid, writable moved task.
unsafe fn take_task(this_: *mut crate::abi::z_moved_task_t) -> Option<Box<TaskState>> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_)._this.handle };
    // SAFETY: gravestoned before the box is touched, so a second call sees a
    // null handle and returns `None`.
    unsafe { (*this_)._this = crate::abi::z_owned_task_t::null_value() };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<TaskState>` this crate leaked in `z_task_init`.
    Some(unsafe { Box::from_raw(handle as *mut TaskState) })
}

/// Spawn a task running `fun(arg)` (zenoh-c `z_task_init`).
///
/// # Safety
/// `this_` must be null or valid and writable; `_attr` is ignored and may be
/// null; `fun` must be null or a valid C function pointer; `arg` is passed
/// through untouched and must satisfy whatever `fun` requires of it, INCLUDING
/// being safe to use from another thread — which is the caller's obligation
/// under upstream's contract too.
#[no_mangle]
pub unsafe extern "C" fn z_task_init(
    this_: *mut crate::abi::z_owned_task_t,
    _attr: *const z_task_attr_t,
    fun: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>,
    arg: *mut c_void,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // Gravestoned first, so a caller that ignores the code never loans a
        // stale stack value.
        // SAFETY: the caller's contract.
        unsafe { *this_ = crate::abi::z_owned_task_t::null_value() };
        let Some(fun) = fun else {
            return Z_ENULL;
        };
        // The FFI trust boundary, as everywhere else in this crate: the C caller
        // asserts `arg` is usable from the spawned thread. `SendPtr` carries
        // that assertion rather than hiding it behind an ad-hoc `unsafe impl`.
        let arg = SendPtr(arg);
        let spawned = std::thread::Builder::new().spawn(move || {
            let arg = arg;
            // SAFETY: `fun` is the caller's function pointer and `arg` is theirs
            // to interpret. The unwind guard is not optional — a panic crossing
            // back out of `extern "C"` is UB, and the return value is discarded
            // because upstream discards it too.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                fun(arg.0);
            }));
        });
        let Ok(spawned) = spawned else {
            // Thread creation genuinely failed (a resource limit). `Z_EINVAL`
            // rather than a dedicated code, for the reason `crate::ffi` gives:
            // zenoh-c's vocabulary has no "spawn failed" and inventing one would
            // put a value in a C program's error handling upstream never emits.
            return Z_EINVAL;
        };
        let boxed = Box::into_raw(Box::new(TaskState {
            handle: Some(spawned),
        })) as crate::abi::Handle;
        // SAFETY: the caller's contract.
        unsafe { *this_ = crate::abi::z_owned_task_t::from_handle(boxed) };
        Z_OK
    })
}

/// Wait for a task to finish (zenoh-c `z_task_join`).
///
/// Reports `Z_EINVAL` when the spawned function unwound, which is the honest
/// answer for "the task did not complete normally"; a task that was already
/// joined or detached, or never initialised, reports `Z_OK` because there is
/// nothing outstanding to wait for.
///
/// # Safety
/// `this_` must be null or a valid moved task.
#[no_mangle]
pub unsafe extern "C" fn z_task_join(this_: *mut crate::abi::z_moved_task_t) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated.
        let Some(mut state) = (unsafe { take_task(this_) }) else {
            return Z_OK;
        };
        match state.handle.take() {
            Some(handle) => match handle.join() {
                Ok(()) => Z_OK,
                Err(_) => Z_EINVAL,
            },
            None => Z_OK,
        }
    })
}

/// Release a task WITHOUT waiting for it (zenoh-c `z_task_detach`).
///
/// Dropping a `JoinHandle` is exactly `pthread_detach`: the thread runs to
/// completion and cleans itself up, and nothing here can be joined afterwards.
///
/// # Safety
/// `this_` must be null or a valid moved task.
#[no_mangle]
pub unsafe extern "C" fn z_task_detach(this_: *mut crate::abi::z_moved_task_t) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated. Dropping the state drops the
        // `JoinHandle`, which detaches.
        drop(unsafe { take_task(this_) });
    });
}

/// Free a task (zenoh-c `z_task_drop`).
///
/// DETACHES rather than joins, and the choice is upstream's: a `drop` that
/// blocked would make freeing a value a synchronisation point, which no other
/// `z_*_drop` in the ABI is. A program that needs the task finished calls
/// [`z_task_join`].
///
/// # Safety
/// `this_` must be null or a valid moved task.
#[no_mangle]
pub unsafe extern "C" fn z_task_drop(this_: *mut crate::abi::z_moved_task_t) {
    // SAFETY: the caller's contract, delegated.
    unsafe { z_task_detach(this_) };
}

/// `true` iff the owned task holds a live thread (zenoh-c
/// `z_internal_task_check`).
///
/// # Safety
/// `this_` must be null or a valid owned task.
#[no_mangle]
pub unsafe extern "C" fn z_internal_task_check(this_: *const crate::abi::z_owned_task_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned task (zenoh-c `z_internal_task_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned task.
#[no_mangle]
pub unsafe extern "C" fn z_internal_task_null(this_: *mut crate::abi::z_owned_task_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = crate::abi::z_owned_task_t::null_value() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// The counter the spawned function bumps, so the test observes that the
    /// thread RAN rather than only that the calls returned.
    static RAN: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn bump(_arg: *mut c_void) -> *mut c_void {
        RAN.fetch_add(1, Ordering::SeqCst);
        std::ptr::null_mut()
    }

    /// A task RUNS and `z_task_join` waits for it.
    ///
    /// The join is what makes the assertion sound: without it the counter read
    /// would race the thread and pass on a slow machine while proving nothing.
    #[test]
    fn a_task_runs_and_join_waits_for_it() {
        RAN.store(0, Ordering::SeqCst);
        let mut task = crate::abi::z_owned_task_t::null_value();
        // SAFETY: `task` is a live stack slot and `bump` is a real function.
        let rc = unsafe {
            z_task_init(
                &mut task,
                std::ptr::null(),
                Some(bump),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, Z_OK);
        // SAFETY: `task` was just initialised.
        assert!(unsafe { z_internal_task_check(&task) });
        let mut moved = crate::abi::z_moved_task_t { _this: task };
        // SAFETY: a live moved task.
        assert_eq!(unsafe { z_task_join(&mut moved) }, Z_OK);
        assert_eq!(
            RAN.load(Ordering::SeqCst),
            1,
            "join returned before the spawned function had run"
        );
        // The slot is gravestoned, so a defensive second join is a no-op rather
        // than a double free.
        // SAFETY: a gravestoned moved task.
        assert!(!unsafe { z_internal_task_check(&moved._this) });
        assert_eq!(unsafe { z_task_join(&mut moved) }, Z_OK);
    }

    /// Every entry point survives a null argument.
    #[test]
    fn the_null_arguments_are_all_no_ops() {
        // SAFETY: nulls are explicitly in each function's contract.
        unsafe {
            assert_eq!(
                z_task_init(
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    Some(bump),
                    std::ptr::null_mut()
                ),
                Z_ENULL
            );
            let mut task = crate::abi::z_owned_task_t::null_value();
            assert_eq!(
                z_task_init(&mut task, std::ptr::null(), None, std::ptr::null_mut()),
                Z_ENULL,
                "a null function pointer is refused rather than spawning a thread that calls it"
            );
            assert!(!z_internal_task_check(std::ptr::null()));
            z_internal_task_null(std::ptr::null_mut());
            z_task_detach(std::ptr::null_mut());
            z_task_drop(std::ptr::null_mut());
            assert_eq!(z_task_join(std::ptr::null_mut()), Z_OK);
        }
    }

    /// `z_task_drop` DETACHES: the thread still runs, and the owned slot is
    /// cleared without blocking.
    #[test]
    fn drop_detaches_rather_than_joining() {
        RAN.store(0, Ordering::SeqCst);
        let mut task = crate::abi::z_owned_task_t::null_value();
        // SAFETY: as above.
        unsafe {
            assert_eq!(
                z_task_init(
                    &mut task,
                    std::ptr::null(),
                    Some(bump),
                    std::ptr::null_mut()
                ),
                Z_OK
            );
            let mut moved = crate::abi::z_moved_task_t { _this: task };
            z_task_drop(&mut moved);
            assert!(
                !z_internal_task_check(&moved._this),
                "drop gravestones the slot"
            );
        }
        // No assertion on RAN here, and that is the point: a detached task has
        // no completion this thread can observe, so asserting on it would be
        // exactly the race the join test avoids.
    }
}
