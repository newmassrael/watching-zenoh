// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_mutex_*` / `z_condvar_*` — pico's MULTI-THREAD sync surface.
//!
//! Like [`crate::platform`], these carry no zenoh semantics. They are here
//! because upstream's programs block on them while waiting for a zenoh event:
//! `z_get.c` arms a condvar, fires the query, and waits for the reply closure
//! to signal it. Measured against the 32 upstream examples, the ten symbols of
//! this module are the COMPLETE missing set for `z_get.c` — the canonical
//! querier program links with nothing else added.
//!
//! ## Why these operate on the caller's bytes, and why that is not a shortcut
//!
//! Every other owned type in this crate hides a `Box::into_raw` handle in the
//! value's leading pointer slot (see [`crate::abi`]). These two cannot, and the
//! reason is measured rather than stylistic: pico's `z_owned_mutex_t` is 40 B
//! and `z_owned_condvar_t` is 48 B on Linux, which are exactly
//! `sizeof(pthread_mutex_t)` and `sizeof(pthread_cond_t)`. That is not a
//! coincidence — pico's unix backend types `_z_mutex_t` AS `pthread_mutex_t`
//! (`vendor/zenoh-pico/include/zenoh-pico/system/platform/unix.h`), its Windows
//! backend types it as `SRWLOCK`, and the C program stack-allocates the struct
//! through pico's own header before wz sees it. The layout is therefore already
//! decided by the header the program compiled against, and the only
//! implementation that can be correct is the one pico itself ships for that
//! host: call the host's own primitives on those bytes (`src/system/unix/
//! system.c:132-204`, `src/system/windows/system.c:118-233`). Those calls are the
//! host layer in `crate::os`; the exports below are the null checks and the panic
//! guards around it.
//!
//! A handle-in-slot-0 design would *compile* and then corrupt: the C side is
//! entitled to copy the struct by value (`z_mutex_take` is literally
//! `*obj = src->_this`), which is well-defined for a pthread object being moved
//! before first use and meaningless for a boxed Rust handle whose address the
//! map keyed on.
//!
//! ## The condvar clock is load-bearing
//!
//! On a Unix `z_condvar_init` sets `CLOCK_MONOTONIC` on the condattr before
//! `pthread_cond_init`, mirroring pico (`system.c:160-166`). Skipping it leaves
//! glibc's default `CLOCK_REALTIME`, and since [`crate::platform::z_clock_now`]
//! is `CLOCK_MONOTONIC`, a deadline computed from it would be interpreted
//! against a different epoch — `z_condvar_wait_until` would return immediately
//! or hang for the wall-clock/uptime skew. The two calls only agree because
//! both name the same clock. Windows has no such choice to make: its wait takes
//! a relative timeout, which the backend derives from the counter reading.

use std::ffi::c_void;
use std::sync::Arc;

use crate::ffi::guard_val;
use crate::os;
use crate::platform::z_clock_t;
use crate::result::{ZResult, Z_ERR_NULL, Z_OK};

/// pico `_Z_ERR_SYSTEM_GENERIC` (`utils/result.h:84`) — what
/// `_Z_CHECK_SYS_ERR` returns for any non-zero `pthread_*` result. Reproduced
/// exactly rather than collapsed onto [`crate::result::Z_ERR_GENERIC`]: a
/// caller distinguishing "the system refused" from "zenoh refused" reads this
/// code, and pico's own value is the only one that answers correctly.
pub const Z_ERR_SYSTEM_GENERIC: ZResult = -80;

/// pico `Z_ETIMEDOUT` (`utils/result.h:96`) — the ONE non-generic outcome
/// `z_condvar_wait_until` reports, and the reason it exists as a distinct
/// export from `z_condvar_wait`.
pub const Z_ETIMEDOUT: ZResult = -71;

// ---------------------------------------------------------------------------
// Mutex
// ---------------------------------------------------------------------------

/// pico `z_owned_mutex_t` — `{ _z_mutex_t _val }`, and `_z_mutex_t` is the host's
/// own mutex: `pthread_mutex_t` on unix (40 B measured against the vendored
/// headers on Linux) and `SRWLOCK` on Windows (one pointer).
///
/// `z_loaned_mutex_t` and `z_moved_mutex_t` are the same bytes at the same
/// address (`_val` is at offset 0 and `_this` is the whole owned struct), so
/// the loan / move / drop family below is pointer identity — pico's own macro
/// expansion is `return &obj->_val` and `return (z_moved_*_t *)(obj)`
/// (`api/olv_macros.h:102-103, 211-212`).
pub type z_owned_mutex_t = os::RawMutex;
/// Loaned mutex — see [`z_owned_mutex_t`]; identical layout at offset 0.
pub type z_loaned_mutex_t = os::RawMutex;
/// Moved mutex — see [`z_owned_mutex_t`]; identical layout at offset 0.
pub type z_moved_mutex_t = os::RawMutex;

/// Initialise a mutex in the caller's storage (pico `z_mutex_init`).
#[no_mangle]
pub unsafe extern "C" fn z_mutex_init(m: *mut z_owned_mutex_t) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if m.is_null() {
            return Z_ERR_NULL;
        }
        os::mutex_init(m)
    })
}

/// Destroy a mutex (pico `z_mutex_drop`).
#[no_mangle]
pub unsafe extern "C" fn z_mutex_drop(m: *mut z_moved_mutex_t) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if m.is_null() {
            return Z_ERR_NULL;
        }
        os::mutex_destroy(m)
    })
}

/// Loan a mutex immutably (pico `z_mutex_loan`) — `&obj->_val`, offset 0.
#[no_mangle]
pub unsafe extern "C" fn z_mutex_loan(m: *const z_owned_mutex_t) -> *const z_loaned_mutex_t {
    m
}

/// Loan a mutex mutably (pico `z_mutex_loan_mut`) — `&obj->_val`, offset 0.
#[no_mangle]
pub unsafe extern "C" fn z_mutex_loan_mut(m: *mut z_owned_mutex_t) -> *mut z_loaned_mutex_t {
    m
}

/// Move a mutex (pico `z_mutex_move`) — the identity cast pico's macro emits.
#[no_mangle]
pub unsafe extern "C" fn z_mutex_move(m: *mut z_owned_mutex_t) -> *mut z_moved_mutex_t {
    m
}

/// Take ownership out of a moved mutex (pico `z_mutex_take`).
///
/// pico's expansion is `*obj = src->_this;` followed by the null-ing hook,
/// which for a SYSTEM type is `{ (void)obj; }` — a deliberate no-op, because a
/// pthread object has no null value to write. So this is the struct copy and
/// nothing else, which is what makes the source safe to leave untouched.
#[no_mangle]
pub unsafe extern "C" fn z_mutex_take(
    obj: *mut z_owned_mutex_t,
    src: *mut z_moved_mutex_t,
) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if obj.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        std::ptr::copy_nonoverlapping(src, obj, 1);
        Z_OK
    })
}

/// Lock, blocking (pico `z_mutex_lock`).
#[no_mangle]
pub unsafe extern "C" fn z_mutex_lock(m: *mut z_loaned_mutex_t) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if m.is_null() {
            return Z_ERR_NULL;
        }
        os::mutex_lock(m)
    })
}

/// Try to lock without blocking (pico `z_mutex_try_lock`).
///
/// Exported even though no upstream example calls it. The asymmetry this crate
/// was bitten by — `z_put_options_default` absent while the get/queryable
/// siblings were present — comes from shipping only the members a witness
/// happened to exercise, so the family goes out whole.
#[no_mangle]
pub unsafe extern "C" fn z_mutex_try_lock(m: *mut z_loaned_mutex_t) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if m.is_null() {
            return Z_ERR_NULL;
        }
        os::mutex_try_lock(m)
    })
}

/// Unlock (pico `z_mutex_unlock`).
#[no_mangle]
pub unsafe extern "C" fn z_mutex_unlock(m: *mut z_loaned_mutex_t) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if m.is_null() {
            return Z_ERR_NULL;
        }
        os::mutex_unlock(m)
    })
}

// ---------------------------------------------------------------------------
// Condition variable
// ---------------------------------------------------------------------------

/// pico `z_owned_condvar_t` — `{ _z_condvar_t _val }`: `pthread_cond_t` on
/// unix (48 B measured) and `CONDITION_VARIABLE` on Windows (one pointer).
/// Loan / move share the address, as for the mutex.
pub type z_owned_condvar_t = os::RawCondvar;
/// Loaned condvar — see [`z_owned_condvar_t`].
pub type z_loaned_condvar_t = os::RawCondvar;
/// Moved condvar — see [`z_owned_condvar_t`].
pub type z_moved_condvar_t = os::RawCondvar;

/// Initialise a condvar (pico `z_condvar_init`).
///
/// On a Unix the clock is set through a `pthread_condattr_t` exactly as pico does
/// (`system.c:160-166`); see this module's header for why the choice is
/// load-bearing rather than incidental.
#[no_mangle]
pub unsafe extern "C" fn z_condvar_init(cv: *mut z_owned_condvar_t) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if cv.is_null() {
            return Z_ERR_NULL;
        }
        os::condvar_init(cv)
    })
}

/// Destroy a condvar (pico `z_condvar_drop`).
#[no_mangle]
pub unsafe extern "C" fn z_condvar_drop(cv: *mut z_moved_condvar_t) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if cv.is_null() {
            return Z_ERR_NULL;
        }
        os::condvar_destroy(cv)
    })
}

/// Loan a condvar immutably (pico `z_condvar_loan`).
#[no_mangle]
pub unsafe extern "C" fn z_condvar_loan(cv: *const z_owned_condvar_t) -> *const z_loaned_condvar_t {
    cv
}

/// Loan a condvar mutably (pico `z_condvar_loan_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_condvar_loan_mut(cv: *mut z_owned_condvar_t) -> *mut z_loaned_condvar_t {
    cv
}

/// Move a condvar (pico `z_condvar_move`).
#[no_mangle]
pub unsafe extern "C" fn z_condvar_move(cv: *mut z_owned_condvar_t) -> *mut z_moved_condvar_t {
    cv
}

/// Take ownership out of a moved condvar (pico `z_condvar_take`); the struct
/// copy, for the reason given on [`z_mutex_take`].
#[no_mangle]
pub unsafe extern "C" fn z_condvar_take(
    obj: *mut z_owned_condvar_t,
    src: *mut z_moved_condvar_t,
) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if obj.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        std::ptr::copy_nonoverlapping(src, obj, 1);
        Z_OK
    })
}

/// Wake one waiter (pico `z_condvar_signal`).
#[no_mangle]
pub unsafe extern "C" fn z_condvar_signal(cv: *mut z_loaned_condvar_t) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if cv.is_null() {
            return Z_ERR_NULL;
        }
        os::condvar_signal(cv)
    })
}

/// Wait, releasing `m` (pico `z_condvar_wait`).
#[no_mangle]
pub unsafe extern "C" fn z_condvar_wait(
    cv: *mut z_loaned_condvar_t,
    m: *mut z_loaned_mutex_t,
) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if cv.is_null() || m.is_null() {
            return Z_ERR_NULL;
        }
        os::condvar_wait(cv, m)
    })
}

/// Wait until an ABSOLUTE monotonic deadline (pico `z_condvar_wait_until`).
///
/// A timeout is [`Z_ETIMEDOUT`] and NOT the generic system error, because that
/// distinction is the whole point of the call: pico special-cases the timeout
/// ahead of its generic system-error check (`system.c:199-203` on a Unix,
/// `system.c:223-229` on Windows), and a caller that cannot tell "deadline
/// reached" from "the system refused" has no way to decide whether to retry.
#[no_mangle]
pub unsafe extern "C" fn z_condvar_wait_until(
    cv: *mut z_loaned_condvar_t,
    m: *mut z_loaned_mutex_t,
    abstime: *const z_clock_t,
) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if cv.is_null() || m.is_null() || abstime.is_null() {
            return Z_ERR_NULL;
        }
        os::condvar_wait_until(cv, m, &*abstime)
    })
}

// ---------------------------------------------------------------------------
// R311y559 — Task, cancellation token, and the `z_internal_*_null` trio
// ---------------------------------------------------------------------------
//
// Every export below is a symbol the real `libzenohpico.so` defines and this
// cdylib did not (`wz-integration-tests/tests/pico_abi_symbol_census.rs`).
// A pico program that starts its own worker — upstream's own `z_ping.c` shape
// — could not link at all.

/// pico `z_owned_task_t` — `{ _z_task_t _val }`: `pthread_t` on unix and a thread
/// `HANDLE` on Windows, one pointer-sized word either way. 8 B MEASURED against the
/// built library's own headers on a Unix, not inferred.
///
/// As with mutex and condvar, the loaned / moved forms are the same bytes at
/// the same address, so the family is pointer identity.
pub type z_owned_task_t = os::RawTask;
/// Loaned task — see [`z_owned_task_t`].
pub type z_loaned_task_t = os::RawTask;
/// Moved task — see [`z_owned_task_t`].
pub type z_moved_task_t = os::RawTask;

/// pico `z_task_attr_t` — `pthread_attr_t` on unix: 56 B on Linux, measured; 64 B
/// on macOS, where Darwin's pthread types are a signature word plus an opaque
/// block (`__sig` and `__opaque[56]`). On Windows it is `void *` and unused. The
/// sizes are pinned in the host layer, so that a target whose layout is not the
/// one a size was measured on fails the build instead of writing past the
/// caller's storage.
pub type z_task_attr_t = os::TaskAttr;

/// Start a thread running `fun(arg)` (pico `z_task_init`).
///
/// A real host thread, because upstream's is: the handle a caller gets back is a
/// real `pthread_t` (or thread `HANDLE`) it may hand to `z_task_join`, and a Rust
/// `JoinHandle` cannot be one. `attr` is passed through to `pthread_create` rather
/// than ignored — a program setting a stack size on a constrained target is the
/// reason the parameter exists — and Windows, like pico there, has no use for it.
///
/// # Safety
/// `task` must be valid and writable; `attr` must be null or a valid
/// `z_task_attr_t`; `fun` must be a valid C function pointer.
#[no_mangle]
pub unsafe extern "C" fn z_task_init(
    task: *mut z_owned_task_t,
    attr: *mut z_task_attr_t,
    fun: Option<extern "C" fn(*mut c_void) -> *mut c_void>,
    arg: *mut c_void,
) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if task.is_null() {
            return Z_ERR_NULL;
        }
        *task = os::TASK_NULL;
        let Some(entry) = fun else {
            return Z_ERR_NULL;
        };
        os::task_spawn(task, attr, entry, arg)
    })
}

/// Wait for a task to finish (pico `z_task_join`).
///
/// # Safety
/// `task` must be null or a valid moved task this crate started.
#[no_mangle]
pub unsafe extern "C" fn z_task_join(task: *mut z_moved_task_t) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if task.is_null() {
            return Z_ERR_NULL;
        }
        // A null handle is an already-joined / never-started task, which is
        // SUCCESS rather than an error: the export is idempotent in upstream
        // too, and joining a null handle is undefined behaviour.
        if *task == os::TASK_NULL {
            return Z_OK;
        }
        let handle = *task;
        *task = os::TASK_NULL;
        os::task_join(handle)
    })
}

/// Release a task WITHOUT waiting (pico `z_task_detach`).
///
/// # Safety
/// As [`z_task_join`].
#[no_mangle]
pub unsafe extern "C" fn z_task_detach(task: *mut z_moved_task_t) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if task.is_null() {
            return Z_ERR_NULL;
        }
        if *task == os::TASK_NULL {
            return Z_OK;
        }
        let handle = *task;
        *task = os::TASK_NULL;
        os::task_detach(handle)
    })
}

/// Drop a task (pico `z_task_drop`) — upstream documents this as EXACTLY
/// `z_task_detach`, so it delegates rather than repeating the body.
///
/// # Safety
/// As [`z_task_join`].
#[no_mangle]
pub unsafe extern "C" fn z_task_drop(task: *mut z_moved_task_t) -> ZResult {
    z_task_detach(task)
}

/// Borrow a task (pico `z_task_loan`) — pointer identity.
///
/// # Safety
/// `task` must be null or a valid owned task.
#[no_mangle]
pub unsafe extern "C" fn z_task_loan(task: *const z_owned_task_t) -> *const z_loaned_task_t {
    task
}

/// Mutably borrow a task (pico `z_task_loan_mut`).
///
/// # Safety
/// As [`z_task_loan`].
#[no_mangle]
pub unsafe extern "C" fn z_task_loan_mut(task: *mut z_owned_task_t) -> *mut z_loaned_task_t {
    task
}

/// Move-cast a task (pico `z_task_move`).
///
/// # Safety
/// As [`z_task_loan`].
#[no_mangle]
pub unsafe extern "C" fn z_task_move(task: *mut z_owned_task_t) -> *mut z_moved_task_t {
    task
}

/// Take a task out of a moved wrapper (pico `z_task_take`), zeroing the source.
///
/// # Safety
/// Both pointers must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_task_take(dst: *mut z_owned_task_t, src: *mut z_moved_task_t) {
    if dst.is_null() || src.is_null() {
        return;
    }
    *dst = *src;
    *src = os::TASK_NULL;
}

/// Zero an owned task (pico `z_internal_task_null`).
///
/// # Safety
/// `task` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_task_null(task: *mut z_owned_task_t) {
    if !task.is_null() {
        *task = os::TASK_NULL;
    }
}

/// Zero an owned mutex (pico `z_internal_mutex_null`).
///
/// Zeroing rather than `pthread_mutex_init`: upstream's `_null` family marks a
/// value as ABSENT, and a caller then asks `z_mutex_init` for a live one. An
/// initialised-but-"null" mutex would leak the pthread object at every
/// subsequent `z_mutex_init` on the same storage.
///
/// # Safety
/// `m` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_mutex_null(m: *mut z_owned_mutex_t) {
    if !m.is_null() {
        std::ptr::write_bytes(m.cast::<u8>(), 0, std::mem::size_of::<z_owned_mutex_t>());
    }
}

/// Zero an owned condvar (pico `z_internal_condvar_null`).
///
/// # Safety
/// `cv` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_condvar_null(cv: *mut z_owned_condvar_t) {
    if !cv.is_null() {
        std::ptr::write_bytes(cv.cast::<u8>(), 0, std::mem::size_of::<z_owned_condvar_t>());
    }
}

// --- cancellation token -----------------------------------------------------

/// The shared state behind a `z_owned_cancellation_token_t`.
///
/// Behind an `Arc`, which is what makes upstream's semantics
/// reproducible: pico's token is a REFCOUNTED value (`_Z_OWNED_TYPE_RC`), so a
/// clone and its original name the SAME cancellation state and cancelling
/// either cancels both. A plain copy of a bool would give each holder its own
/// flag and `z_cancellation_token_clone` would silently stop working.
///
/// R311y575 — the token also carries the ON-CANCEL HANDLER storage, which is
/// what makes it a cancellation plane rather than a flag two API calls agree
/// about. Upstream's token is exactly this pair: a sync group plus an intmap of
/// `_z_cancellation_token_on_cancel_handler_t`
/// (`vendor/zenoh-pico/src/session/cancellation.c:49-66`), and a get registers
/// one so that cancelling the token unregisters the get's pending query
/// (`src/session/query.c:306-334`).
///
/// R2949 — the model now lives in `wz_capi_core::cancellation`, shared with the
/// zenoh-c ABI, and it gained what this crate's copy lacked: `cancel` WAITS for
/// every registered get's callbacks to be dropped, which pico's
/// `_z_cancellation_token_cancel` does (`_z_sync_group_wait` after running the
/// handlers). The take-once handler storage and the registration refusal after
/// cancel has started are unchanged in meaning.
pub(crate) use wz_capi_core::cancellation::CancellationToken;

/// Consume a MOVED cancellation token, yielding the state it named.
///
/// Upstream's option structs declare this field as `z_moved_cancellation_token_t
/// *`, and both `z_get` and `z_liveliness_get` drop it unconditionally once the
/// call is made (`src/api/api.c:1783`, `src/api/liveliness.c:146`). So the field
/// is an ownership transfer, not a borrow: a caller that hands over a token must
/// not be left holding a live handle, and a callee that merely READ the pointer
/// would leak one per get. This takes the handle and nulls the caller's owned
/// struct, exactly as [`z_cancellation_token_drop`] does, and returns the `Arc`
/// so the caller keeps the state alive for as long as the get needs it.
///
/// # Safety
/// `moved` must be null or a valid moved token this crate produced.
pub(crate) unsafe fn take_moved_cancellation_token(
    moved: *mut z_moved_cancellation_token_t,
) -> Option<Arc<CancellationToken>> {
    if moved.is_null() {
        return None;
    }
    let handle = (*moved)._this.handle;
    (*moved)._this = z_owned_cancellation_token_t::null_value();
    if handle.is_null() {
        return None;
    }
    Some(*Box::from_raw(handle as *mut Arc<CancellationToken>))
}

/// pico `z_owned_cancellation_token_t` — `{ _z_cancellation_token_rc_t _rc }`,
/// 16 B MEASURED. Slot 0 carries this crate's `Arc` handle; slot 1 is the
/// refcount word upstream keeps there and wz leaves zero.
#[repr(C)]
pub struct z_owned_cancellation_token_t {
    handle: *mut c_void,
    _cnt: *mut c_void,
}

/// Loaned cancellation token — same footprint.
#[repr(C)]
pub struct z_loaned_cancellation_token_t {
    handle: *mut c_void,
    _cnt: *mut c_void,
}

/// Moved cancellation token.
#[repr(C)]
pub struct z_moved_cancellation_token_t {
    _this: z_owned_cancellation_token_t,
}

const _: () = {
    assert!(std::mem::size_of::<z_owned_cancellation_token_t>() == 16);
};

impl z_owned_cancellation_token_t {
    fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _cnt: std::ptr::null_mut(),
        }
    }
}

/// The `Arc` behind a token handle, or `None` on a null / spent one.
///
/// # Safety
/// `ptr` must be null or a token this crate produced.
unsafe fn token_ref<'a>(
    ptr: *const z_loaned_cancellation_token_t,
) -> Option<&'a Arc<CancellationToken>> {
    if ptr.is_null() || (*ptr).handle.is_null() {
        return None;
    }
    Some(&*((*ptr).handle as *const Arc<CancellationToken>))
}

/// Build a fresh, uncancelled token (pico `z_cancellation_token_new`).
///
/// # Safety
/// `token` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_new(
    token: *mut z_owned_cancellation_token_t,
) -> ZResult {
    crate::ffi::guarded(|| {
        if token.is_null() {
            return Z_ERR_NULL;
        }
        let arc = CancellationToken::new();
        *token = z_owned_cancellation_token_t {
            handle: Box::into_raw(Box::new(arc)) as *mut c_void,
            _cnt: std::ptr::null_mut(),
        };
        Z_OK
    })
}

/// Cancel a token (pico `z_cancellation_token_cancel`).
///
/// Visible through every CLONE, which is the whole point of the type — see
/// [`CancellationToken`].
///
/// R311y575 — this also RUNS the registered on-cancel handlers, which is what
/// makes a cancelled token stop the gets it was handed to. The handlers are run
/// AFTER the lock is released (upstream does the same: `_z_cancellation_token_
/// call_handlers` swaps the storage out under the mutex and only then calls
/// them, `src/session/cancellation.c:128-144`) because a handler unregisters a
/// pending query, whose sink drop runs the C `drop(context)`, and a C callback
/// is explicitly allowed to re-enter the session.
///
/// R2949 — and it then WAITS until every get registered on the token has
/// dropped its callbacks, as pico's `_z_cancellation_token_cancel` does
/// (`_z_sync_group_wait` after the handler run). Before R2949 it returned as
/// soon as the handlers had run, so a reply callback already executing on a
/// drive task could still be running when `cancel` returned.
///
/// # Safety
/// `token` must be null or a live loaned token.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_cancel(
    token: *mut z_loaned_cancellation_token_t,
) -> ZResult {
    crate::ffi::guarded(|| match token_ref(token as *const _) {
        Some(arc) => {
            arc.cancel();
            Z_OK
        }
        None => Z_ERR_NULL,
    })
}

/// Whether a token has been cancelled (pico
/// `z_cancellation_token_is_cancelled`).
///
/// # Safety
/// `token` must be null or a live loaned token.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_is_cancelled(
    token: *const z_loaned_cancellation_token_t,
) -> bool {
    crate::ffi::guard_val(false, || match token_ref(token) {
        Some(arc) => arc.is_cancelled(),
        None => false,
    })
}

/// Clone a token so both handles name the SAME cancellation state (pico
/// `z_cancellation_token_clone`).
///
/// # Safety
/// `dst` must be valid and writable; `src` must be null or a live loaned token.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_clone(
    dst: *mut z_owned_cancellation_token_t,
    src: *const z_loaned_cancellation_token_t,
) -> ZResult {
    crate::ffi::guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        *dst = z_owned_cancellation_token_t::null_value();
        match token_ref(src) {
            Some(arc) => {
                *dst = z_owned_cancellation_token_t {
                    handle: Box::into_raw(Box::new(Arc::clone(arc))) as *mut c_void,
                    _cnt: std::ptr::null_mut(),
                };
                Z_OK
            }
            None => Z_ERR_NULL,
        }
    })
}

/// Release a token handle (pico `z_cancellation_token_drop`).
///
/// Drops THIS handle's `Arc`; the state survives while any clone holds one.
///
/// # Safety
/// `token` must be null or a valid moved token this crate produced.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_drop(token: *mut z_moved_cancellation_token_t) {
    let _ = crate::ffi::guarded(|| {
        if token.is_null() {
            return Z_OK;
        }
        let handle = (*token)._this.handle;
        (*token)._this = z_owned_cancellation_token_t::null_value();
        if !handle.is_null() {
            drop(Box::from_raw(handle as *mut Arc<CancellationToken>));
        }
        Z_OK
    });
}

/// Borrow a token (pico `z_cancellation_token_loan`) — offset-0 identity.
///
/// # Safety
/// `token` must be null or a valid owned token.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_loan(
    token: *const z_owned_cancellation_token_t,
) -> *const z_loaned_cancellation_token_t {
    token as *const z_loaned_cancellation_token_t
}

/// Mutably borrow a token (pico `z_cancellation_token_loan_mut`).
///
/// # Safety
/// As [`z_cancellation_token_loan`].
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_loan_mut(
    token: *mut z_owned_cancellation_token_t,
) -> *mut z_loaned_cancellation_token_t {
    token as *mut z_loaned_cancellation_token_t
}

/// Move-cast a token (pico `z_cancellation_token_move`).
///
/// # Safety
/// As [`z_cancellation_token_loan`].
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_move(
    token: *mut z_owned_cancellation_token_t,
) -> *mut z_moved_cancellation_token_t {
    token as *mut z_moved_cancellation_token_t
}

/// Take a token out of a moved wrapper (pico `z_cancellation_token_take`).
///
/// # Safety
/// Both pointers must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_take(
    dst: *mut z_owned_cancellation_token_t,
    src: *mut z_moved_cancellation_token_t,
) {
    if dst.is_null() || src.is_null() {
        return;
    }
    *dst = z_owned_cancellation_token_t {
        handle: (*src)._this.handle,
        _cnt: (*src)._this._cnt,
    };
    (*src)._this = z_owned_cancellation_token_t::null_value();
}

/// Zero an owned token (pico `z_internal_cancellation_token_null`).
///
/// # Safety
/// `token` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_cancellation_token_null(
    token: *mut z_owned_cancellation_token_t,
) {
    if !token.is_null() {
        *token = z_owned_cancellation_token_t::null_value();
    }
}

/// `true` iff the owned token holds a live state (pico
/// `z_internal_cancellation_token_check`).
///
/// # Safety
/// `token` must be null or a valid owned token.
#[no_mangle]
pub unsafe extern "C" fn z_internal_cancellation_token_check(
    token: *const z_owned_cancellation_token_t,
) -> bool {
    crate::ffi::guard_val(false, || !token.is_null() && !(*token).handle.is_null())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The ABI claim this module rests on, that the owned structs a C program
    // stack-allocates through pico's header are the sizes of the host's own objects,
    // is asserted in the host layer next to each backend (`os/unix.rs` against the
    // host C compiler's `sizeof`, `os/windows.rs` at compile time), because the sizes
    // are a property of the host and not of these exports.

    /// A task started through the export runs the C function with its argument, and
    /// the join returns only after it has finished: the end-to-end proof, on every
    /// host, that `z_task_init` hands the backend a handle `z_task_join` can wait on.
    #[test]
    fn a_task_runs_its_function_and_join_waits_for_it() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static RAN: AtomicBool = AtomicBool::new(false);
        extern "C" fn body(arg: *mut c_void) -> *mut c_void {
            std::thread::sleep(std::time::Duration::from_millis(50));
            assert_eq!(arg as usize, 0x5eed);
            RAN.store(true, Ordering::SeqCst);
            std::ptr::null_mut()
        }
        let mut task: z_owned_task_t = os::TASK_NULL;
        // SAFETY: a live local, and a function with the right C signature.
        unsafe {
            assert_eq!(
                z_task_init(
                    &mut task,
                    std::ptr::null_mut(),
                    Some(body),
                    0x5eed as *mut c_void
                ),
                Z_OK
            );
            assert!(task != os::TASK_NULL, "a started task has a handle");
            assert_eq!(z_task_join(z_task_move(&mut task)), Z_OK);
            assert!(task == os::TASK_NULL, "a joined task is zeroed");
            // Joining again is the idempotent success upstream's is.
            assert_eq!(z_task_join(z_task_move(&mut task)), Z_OK);
        }
        assert!(
            RAN.load(Ordering::SeqCst),
            "join returned before the thread ran"
        );
    }

    /// A detached task is released without waiting and keeps running to its end.
    #[test]
    fn a_detached_task_keeps_running() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static RAN: AtomicBool = AtomicBool::new(false);
        extern "C" fn body(_arg: *mut c_void) -> *mut c_void {
            RAN.store(true, Ordering::SeqCst);
            std::ptr::null_mut()
        }
        let mut task: z_owned_task_t = os::TASK_NULL;
        // SAFETY: a live local, and a function with the right C signature.
        unsafe {
            assert_eq!(
                z_task_init(
                    &mut task,
                    std::ptr::null_mut(),
                    Some(body),
                    std::ptr::null_mut()
                ),
                Z_OK
            );
            assert_eq!(z_task_detach(z_task_move(&mut task)), Z_OK);
            assert!(task == os::TASK_NULL, "a detached task is zeroed");
        }
        let started = std::time::Instant::now();
        while !RAN.load(Ordering::SeqCst) {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "the detached thread never ran"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// loan / loan_mut / move are pointer identity in pico's macro expansion,
    /// so a round trip must return the address it was handed. A future
    /// "improvement" that boxed the value would break the C side's own
    /// `z_loan`/`z_move` `_Generic` dispatch silently; this catches it.
    #[test]
    fn mutex_loan_and_move_are_pointer_identity() {
        let mut m: z_owned_mutex_t = unsafe { std::mem::zeroed() };
        let p = &mut m as *mut z_owned_mutex_t;
        unsafe {
            assert_eq!(z_mutex_loan(p), p as *const _);
            assert_eq!(z_mutex_loan_mut(p), p);
            assert_eq!(z_mutex_move(p), p);
        }
    }

    /// A real lock/unlock cycle through the exported entry points, which is
    /// what `z_get.c` performs around its condvar wait. `try_lock` is expected
    /// to REFUSE while the mutex is held — the discriminator that separates a
    /// working mutex from one whose `lock` is a no-op returning `Z_OK`.
    #[test]
    fn mutex_lock_excludes_and_try_lock_refuses_while_held() {
        let mut m: z_owned_mutex_t = unsafe { std::mem::zeroed() };
        let p = &mut m as *mut z_owned_mutex_t;
        unsafe {
            assert_eq!(z_mutex_init(p), Z_OK);
            assert_eq!(z_mutex_lock(z_mutex_loan_mut(p)), Z_OK);
            assert_ne!(
                z_mutex_try_lock(z_mutex_loan_mut(p)),
                Z_OK,
                "try_lock must refuse a mutex this thread already holds"
            );
            assert_eq!(z_mutex_unlock(z_mutex_loan_mut(p)), Z_OK);
            assert_eq!(z_mutex_try_lock(z_mutex_loan_mut(p)), Z_OK);
            assert_eq!(z_mutex_unlock(z_mutex_loan_mut(p)), Z_OK);
            assert_eq!(z_mutex_drop(z_mutex_move(p)), Z_OK);
        }
    }

    /// The `z_get.c` shape end to end: a waiter blocks on the condvar under the
    /// mutex and a second thread signals it. Green proves the pair actually
    /// blocks and wakes; a `z_condvar_wait` that returned immediately would
    /// also pass, which is why the signalling thread sets the flag FIRST and
    /// the waiter loops on it — the assertion is on the flag, not on reaching
    /// the line.
    #[test]
    fn condvar_signal_wakes_a_real_waiter() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        struct Pair(z_owned_mutex_t, z_owned_condvar_t);
        // SAFETY: pthread objects are explicitly shareable across threads; the
        // pointer wrapper exists only because raw pointers are not `Send`.
        struct Ptr(*mut Pair);
        unsafe impl Send for Ptr {}

        let mut pair = Box::new(Pair(unsafe { std::mem::zeroed() }, unsafe {
            std::mem::zeroed()
        }));
        let raw = &mut *pair as *mut Pair;
        unsafe {
            assert_eq!(z_mutex_init(&mut (*raw).0), Z_OK);
            assert_eq!(z_condvar_init(&mut (*raw).1), Z_OK);
        }

        let ready = Arc::new(AtomicBool::new(false));
        let signalled = Arc::new(AtomicBool::new(false));
        let (r2, s2) = (Arc::clone(&ready), Arc::clone(&signalled));
        let moved = Ptr(raw);
        let signaller = std::thread::spawn(move || {
            let p = moved;
            while !r2.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
            unsafe {
                assert_eq!(z_mutex_lock(z_mutex_loan_mut(&mut (*p.0).0)), Z_OK);
                s2.store(true, Ordering::SeqCst);
                assert_eq!(z_condvar_signal(z_condvar_loan_mut(&mut (*p.0).1)), Z_OK);
                assert_eq!(z_mutex_unlock(z_mutex_loan_mut(&mut (*p.0).0)), Z_OK);
            }
        });

        unsafe {
            assert_eq!(z_mutex_lock(z_mutex_loan_mut(&mut (*raw).0)), Z_OK);
            ready.store(true, Ordering::SeqCst);
            while !signalled.load(Ordering::SeqCst) {
                assert_eq!(
                    z_condvar_wait(
                        z_condvar_loan_mut(&mut (*raw).1),
                        z_mutex_loan_mut(&mut (*raw).0)
                    ),
                    Z_OK
                );
            }
            assert_eq!(z_mutex_unlock(z_mutex_loan_mut(&mut (*raw).0)), Z_OK);
        }
        signaller.join().expect("signalling thread");
        assert!(signalled.load(Ordering::SeqCst));

        unsafe {
            assert_eq!(z_condvar_drop(z_condvar_move(&mut (*raw).1)), Z_OK);
            assert_eq!(z_mutex_drop(z_mutex_move(&mut (*raw).0)), Z_OK);
        }
    }

    /// `wait_until` with a deadline already in the past must report
    /// [`Z_ETIMEDOUT`], not the generic system error and not `Z_OK`. This is
    /// also the assertion that catches a condvar initialised on the WRONG
    /// clock: `z_clock_now` is the monotonic clock, so a `CLOCK_REALTIME`
    /// condvar reads a deadline taken from it as ~55 years in the past on a
    /// typical Unix host — still a timeout, but a deadline in the FUTURE would
    /// then also time out instantly, which the second half asserts against.
    /// Written against the exports alone, so it runs on every host: a past
    /// deadline is a reading taken before a short sleep, a future one a reading
    /// advanced by `z_clock_advance_ms`.
    #[test]
    fn wait_until_times_out_and_respects_the_monotonic_clock() {
        let mut m: z_owned_mutex_t = unsafe { std::mem::zeroed() };
        let mut cv: z_owned_condvar_t = unsafe { std::mem::zeroed() };
        unsafe {
            assert_eq!(z_mutex_init(&mut m), Z_OK);
            assert_eq!(z_condvar_init(&mut cv), Z_OK);
            assert_eq!(z_mutex_lock(z_mutex_loan_mut(&mut m)), Z_OK);

            let past = crate::platform::z_clock_now();
            assert_eq!(crate::platform::z_sleep_ms(20), Z_OK);
            assert_eq!(
                z_condvar_wait_until(z_condvar_loan_mut(&mut cv), z_mutex_loan_mut(&mut m), &past),
                Z_ETIMEDOUT
            );

            // A FUTURE monotonic deadline must actually wait. Measured, because
            // "it returned Z_ETIMEDOUT" alone cannot tell a correct clock from
            // a wrong one — only the elapsed time can.
            let started = std::time::Instant::now();
            let mut soon = crate::platform::z_clock_now();
            crate::platform::z_clock_advance_ms(&mut soon, 150);
            assert_eq!(
                z_condvar_wait_until(z_condvar_loan_mut(&mut cv), z_mutex_loan_mut(&mut m), &soon),
                Z_ETIMEDOUT
            );
            assert!(
                started.elapsed() >= std::time::Duration::from_millis(100),
                "a future monotonic deadline returned in {:?}; the condvar is not \
                 on the monotonic clock",
                started.elapsed()
            );

            assert_eq!(z_mutex_unlock(z_mutex_loan_mut(&mut m)), Z_OK);
            assert_eq!(z_condvar_drop(z_condvar_move(&mut cv)), Z_OK);
            assert_eq!(z_mutex_drop(z_mutex_move(&mut m)), Z_OK);
        }
    }
}
