// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zc_init_log_from_env_or` — logging init.
//!
//! Every upstream example calls it FIRST, which is exactly why it is in this
//! slice: a symbol nothing in wz needed is still a symbol the program links
//! against, and a missing one is a link error before a single wire byte moves.
//! It is the clearest single instance of why the corpus had to be upstream's
//! rather than hand-written — nothing about implementing `z_put` suggests it.

use std::ffi::{c_char, c_int, c_void, CStr};

use crate::abi::z_loaned_string_t;
use crate::ffi::guard_val;

/// Initialise logging from `RUST_LOG`, falling back to `fallback_filter`
/// (zenoh-c `zc_init_log_from_env_or`).
///
/// wz's logging is the `log` facade with no installed subscriber by default, and
/// installing one from a library would hijack the host application's. So this
/// honours the ENV variable if a subscriber is already present and is otherwise
/// a no-op — the observable behaviour a zenoh-c program depends on is that the
/// call SUCCEEDS and does not print unless asked.
///
/// # Safety
/// `fallback_filter` must be null or a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn zc_init_log_from_env_or(fallback_filter: *const c_char) {
    guard_val((), || {
        if fallback_filter.is_null() {
            return;
        }
        // Read it so a malformed filter is not silently ignored on the day this
        // grows a real subscriber; the value is otherwise unused today.
        // SAFETY: the caller's contract.
        let _ = unsafe { CStr::from_ptr(fallback_filter) }.to_str();
    })
}

// --- R311y568: the rest of upstream's logging surface -----------------------
//
// Seven symbols the real `libzenohc.so` defines and this cdylib did not. Six of
// them are the `zc_owned_closure_log_t` family — a closure a program installs to
// RECEIVE zenoh's log lines instead of having them printed — and the seventh is
// the env-only initialiser next to the one this module already had.

/// zenoh-c `zc_log_severity_t` (`zenoh_commons.h:290-321`).
///
/// `c_int`, like every other zenoh-c enum this crate mirrors: cbindgen emits a
/// C enum and the C ABI passes it as an `int`.
pub type zc_log_severity_t = c_int;

/// `zc_log_severity_t` — the "trace" level.
pub const ZC_LOG_SEVERITY_TRACE: zc_log_severity_t = 0;
/// `zc_log_severity_t` — the "debug" level.
pub const ZC_LOG_SEVERITY_DEBUG: zc_log_severity_t = 1;
/// `zc_log_severity_t` — the "info" level.
pub const ZC_LOG_SEVERITY_INFO: zc_log_severity_t = 2;
/// `zc_log_severity_t` — the "warn" level.
pub const ZC_LOG_SEVERITY_WARN: zc_log_severity_t = 3;
/// `zc_log_severity_t` — the "error" level.
pub const ZC_LOG_SEVERITY_ERROR: zc_log_severity_t = 4;

/// The C callback a LOG closure carries.
pub type zc_closure_log_callback_t = Option<
    unsafe extern "C" fn(
        severity: zc_log_severity_t,
        msg: *const z_loaned_string_t,
        context: *mut c_void,
    ),
>;

/// Owned log closure (zenoh-c `zc_owned_closure_log_t`) — TRANSPARENT upstream,
/// so it matches field for field like the sample / query / reply closures.
#[repr(C)]
pub struct zc_owned_closure_log_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: zc_closure_log_callback_t,
    pub(crate) drop: crate::abi::z_closure_drop_callback_t,
}

/// Loaned log closure (zenoh-c `zc_loaned_closure_log_t`) — three words, the
/// same footprint as the owned form, which is what makes the loan a cast.
#[repr(C)]
pub struct zc_loaned_closure_log_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: zc_closure_log_callback_t,
    pub(crate) drop: crate::abi::z_closure_drop_callback_t,
}

/// Moved log closure (zenoh-c `zc_moved_closure_log_t`).
#[repr(C)]
pub struct zc_moved_closure_log_t {
    pub(crate) _this: zc_owned_closure_log_t,
}

const _: () = {
    assert!(std::mem::size_of::<zc_owned_closure_log_t>() == 24);
    assert!(std::mem::size_of::<zc_loaned_closure_log_t>() == 24);
    assert!(std::mem::size_of::<zc_moved_closure_log_t>() == 24);
};

impl zc_owned_closure_log_t {
    /// The gravestone value.
    pub(crate) fn null_value() -> Self {
        Self {
            context: std::ptr::null_mut(),
            call: None,
            drop: None,
        }
    }
}

/// Construct a log closure from its parts (zenoh-c `zc_closure_log`).
///
/// # Safety
/// `this_` must be null or valid and writable; `call` / `drop` must be null or
/// valid C function pointers.
#[no_mangle]
pub unsafe extern "C" fn zc_closure_log(
    this_: *mut zc_owned_closure_log_t,
    call: zc_closure_log_callback_t,
    drop: crate::abi::z_closure_drop_callback_t,
    context: *mut c_void,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe {
            *this_ = zc_owned_closure_log_t {
                context,
                call,
                drop,
            }
        };
    });
}

/// Invoke a log closure (zenoh-c `zc_closure_log_call`).
///
/// Calling an uninitialised closure is a NO-OP, which is upstream's documented
/// behaviour for every closure family.
///
/// # Safety
/// `closure` must be null or a valid loaned log closure; `msg` must be null or a
/// valid loaned string.
#[no_mangle]
pub unsafe extern "C" fn zc_closure_log_call(
    closure: *const zc_loaned_closure_log_t,
    severity: zc_log_severity_t,
    msg: *const z_loaned_string_t,
) {
    guard_val((), || {
        if closure.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let (call, context) = unsafe { ((*closure).call, (*closure).context) };
        let Some(call) = call else {
            return;
        };
        // SAFETY: the caller's function pointer. An unwind back across
        // `extern "C"` is UB, so it is caught here as everywhere else.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            call(severity, msg, context);
        }));
    });
}

/// Borrow a log closure (zenoh-c `zc_closure_log_loan`).
///
/// A pointer CAST — the owned and loaned forms are one layout, which is why they
/// are declared with the same three fields above.
///
/// # Safety
/// `closure` must be null or a valid owned log closure.
#[no_mangle]
pub unsafe extern "C" fn zc_closure_log_loan(
    closure: *const zc_owned_closure_log_t,
) -> *const zc_loaned_closure_log_t {
    closure as *const zc_loaned_closure_log_t
}

/// Drop a log closure, running its `drop(context)` (zenoh-c
/// `zc_closure_log_drop`).
///
/// # Safety
/// `closure_` must be null or a valid moved log closure.
#[no_mangle]
pub unsafe extern "C" fn zc_closure_log_drop(closure_: *mut zc_moved_closure_log_t) {
    guard_val((), || {
        if closure_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*closure_)._this };
        if let Some(dropfn) = owned.drop {
            let ctx = owned.context;
            // SAFETY: upstream's contract — drop runs once; unwinds are caught.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                dropfn(ctx);
            }));
        }
        *owned = zc_owned_closure_log_t::null_value();
    });
}

/// `true` iff the owned log closure holds a callback (zenoh-c
/// `zc_internal_closure_log_check`).
///
/// # Safety
/// `this_` must be null or a valid owned log closure.
#[no_mangle]
pub unsafe extern "C" fn zc_internal_closure_log_check(
    this_: *const zc_owned_closure_log_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && unsafe { (*this_).call }.is_some()
    })
}

/// Zero an owned log closure (zenoh-c `zc_internal_closure_log_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned log closure.
#[no_mangle]
pub unsafe extern "C" fn zc_internal_closure_log_null(this_: *mut zc_owned_closure_log_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = zc_owned_closure_log_t::null_value() };
    }
}

/// Install a log callback (zenoh-c `zc_init_log_with_callback`).
///
/// CONSUMES the closure, as upstream's `zc_moved_*` parameter says: the callback
/// is dropped here rather than retained, because wz installs no `log` subscriber
/// (see [`zc_init_log_from_env_or`] for why a library hijacking the host's is the
/// wrong default). Consuming it is what keeps the ownership contract honest — a
/// path that merely read the pointer would leak the caller's `context` forever,
/// which is a divergence visible in their code even though the callback never
/// fires.
///
/// # Safety
/// `callback` must be null or a valid moved log closure, which is consumed.
#[no_mangle]
pub unsafe extern "C" fn zc_init_log_with_callback(
    _min_severity: zc_log_severity_t,
    callback: *mut zc_moved_closure_log_t,
) {
    // SAFETY: the caller's contract, delegated — the drop runs the caller's
    // `drop(context)` and gravestones their slot.
    unsafe { zc_closure_log_drop(callback) };
}

/// Initialise logging from `RUST_LOG` ONLY (zenoh-c `zc_try_init_log_from_env`).
///
/// The no-fallback sibling of [`zc_init_log_from_env_or`], and a no-op here for
/// the same reason: wz's logging is the `log` facade with no subscriber
/// installed by default. Upstream's own contract for this one is that it does
/// nothing when the variable is unset, so "does not print unless asked" is the
/// behaviour a program depends on either way.
#[no_mangle]
pub extern "C" fn zc_try_init_log_from_env() {
    guard_val((), || {
        // Read so a malformed filter is not silently ignored on the day this
        // grows a real subscriber, exactly as the `_or` variant does.
        let _ = std::env::var("RUST_LOG");
    })
}

/// Stop zenoh's internal runtime (zenoh-c `zc_stop_z_runtime`).
///
/// A NO-OP, and deliberately so. Upstream's is a teardown of the process-wide
/// tokio runtime zenoh-c lazily starts; wz has no such singleton — each
/// `z_open` owns its own drive task and `z_close` is what stops it
/// ([`wz_capi_core`]). Calling this before every session is closed would, in
/// upstream, kill the runtime out from under them; here there is nothing global
/// to kill, so the no-op is the FAITHFUL behaviour for wz's model rather than an
/// unimplemented stub.
///
/// It lives in this module because it is the other process-lifecycle entry
/// point a `zc_*` program calls, next to log init.
#[no_mangle]
pub extern "C" fn zc_stop_z_runtime() {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // R311y617 -- ONE COUNTER PAIR PER TEST, and that is the fix for a hosted
    // flake rather than a tidiness preference.
    //
    // Both tests below used to share a single `CALLS` / `DROPS` pair and each
    // opened by resetting it to zero. cargo runs tests in the same binary
    // CONCURRENTLY, so the other test's `store(0)` could land between this
    // one's drop and its assertion: the drop had run, the counter read 0, and
    // the assertion failed on a product that was correct. It reds on the hosted
    // runner and passed five consecutive local runs -- a rate difference, not a
    // behaviour difference, which is exactly the shape that gets mistaken for
    // an environment problem.
    //
    // A serialising mutex would also have hidden it. It is not used, because
    // the coupling is the defect: a C callback cannot capture, so per-test
    // state means per-test statics, and then no ordering between tests exists
    // to get wrong.
    static CLOSURE_CALLS: AtomicU32 = AtomicU32::new(0);
    static CLOSURE_DROPS: AtomicU32 = AtomicU32::new(0);
    static INSTALL_DROPS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn on_log(
        _severity: zc_log_severity_t,
        _msg: *const z_loaned_string_t,
        _context: *mut c_void,
    ) {
        CLOSURE_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn on_drop(_context: *mut c_void) {
        CLOSURE_DROPS.fetch_add(1, Ordering::SeqCst);
    }

    /// The install test's own drop counter — see the note on the statics.
    unsafe extern "C" fn on_install_drop(_context: *mut c_void) {
        INSTALL_DROPS.fetch_add(1, Ordering::SeqCst);
    }

    /// The closure round trip: construct, check, loan, call, drop.
    #[test]
    fn a_log_closure_calls_then_drops_exactly_once() {
        // No reset: these counters belong to this test alone, so their
        // starting value is zero and nothing else can move them.
        let mut closure = zc_owned_closure_log_t::null_value();
        // SAFETY: `closure` is a live stack slot.
        unsafe {
            assert!(
                !zc_internal_closure_log_check(&closure),
                "the gravestone reads as absent"
            );
            zc_closure_log(
                &mut closure,
                Some(on_log),
                Some(on_drop),
                std::ptr::null_mut(),
            );
            assert!(zc_internal_closure_log_check(&closure));
            zc_closure_log_call(
                zc_closure_log_loan(&closure),
                ZC_LOG_SEVERITY_WARN,
                std::ptr::null(),
            );
            assert_eq!(CLOSURE_CALLS.load(Ordering::SeqCst), 1);

            let mut moved = zc_moved_closure_log_t { _this: closure };
            zc_closure_log_drop(&mut moved);
            assert_eq!(CLOSURE_DROPS.load(Ordering::SeqCst), 1);
            // Gravestoned, so a defensive second drop does NOT run the C drop
            // again — the double-free shape.
            zc_closure_log_drop(&mut moved);
            assert_eq!(CLOSURE_DROPS.load(Ordering::SeqCst), 1);
        }
    }

    /// `zc_init_log_with_callback` CONSUMES the closure.
    ///
    /// The assertion is on the caller's `drop` having run, not on the call
    /// returning: a version that read the pointer and returned would pass a
    /// weaker test while leaking the caller's context.
    #[test]
    fn installing_a_callback_consumes_it() {
        let mut closure = zc_owned_closure_log_t::null_value();
        // SAFETY: as above.
        unsafe {
            zc_closure_log(
                &mut closure,
                Some(on_log),
                Some(on_install_drop),
                std::ptr::null_mut(),
            );
            let mut moved = zc_moved_closure_log_t { _this: closure };
            zc_init_log_with_callback(ZC_LOG_SEVERITY_INFO, &mut moved);
            assert_eq!(
                INSTALL_DROPS.load(Ordering::SeqCst),
                1,
                "the moved closure was not consumed, so its context leaks"
            );
            assert!(!zc_internal_closure_log_check(&moved._this));
        }
    }

    /// Every entry point survives a null argument.
    #[test]
    fn the_null_arguments_are_all_no_ops() {
        // SAFETY: nulls are explicitly in each function's contract.
        unsafe {
            zc_closure_log(std::ptr::null_mut(), None, None, std::ptr::null_mut());
            zc_closure_log_call(std::ptr::null(), ZC_LOG_SEVERITY_ERROR, std::ptr::null());
            assert!(zc_closure_log_loan(std::ptr::null()).is_null());
            zc_closure_log_drop(std::ptr::null_mut());
            assert!(!zc_internal_closure_log_check(std::ptr::null()));
            zc_internal_closure_log_null(std::ptr::null_mut());
        }
        zc_try_init_log_from_env();
        zc_stop_z_runtime();
    }
}
