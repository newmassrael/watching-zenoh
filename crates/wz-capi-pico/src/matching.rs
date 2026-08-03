// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The MATCHING plane — pico `Z_FEATURE_MATCHING`: is anybody subscribed to
//! what this publisher publishes.
//!
//! Binds wz's already-active `session-matching` atom
//! (`Publisher::get_matching_status` / `Publisher::declare_matching_listener`)
//! through [`wz_capi_core::faces::SharedSession::declare_matching_listener`],
//! which is where the cross-face aggregation lives. No new protocol: the
//! verdict is read off the remote-subscriber declarations wz already tracks.
//!
//! ## Why this closes a program rather than a symbol
//!
//! `z_pub.c` is upstream's canonical publisher, and measured against wz's
//! cdylib it was missing exactly two exports — `z_closure_matching_status_move`
//! and `z_publisher_declare_background_matching_listener`. Both are in the
//! `-a` (add-matching-listener) arm, which the program links unconditionally
//! and calls only when the flag is passed. So the ENTIRE canonical publisher
//! was un-droppable-in over an optional feature's two symbols.
//!
//! The family goes out whole (poll, one-shot listener, background listener,
//! the closure constructors, the listener ownership family) rather than just
//! the two `z_pub.c` needs. Shipping only what a witness exercises is what
//! produced this crate's `z_put_options_default`-absent-while-`z_get_options_default`-present
//! asymmetry, and an asymmetric family fails to link for the NEXT program
//! instead of this one.
//!
//! ## The background listener leaks its handle, on purpose
//!
//! pico's `*_declare_background_*` forms register a listener with no handle
//! returned: it lives for the session. wz's `MatchingListener` has no `Drop`
//! hook (dropping it leaves the watch installed — the documented wz contract),
//! so the background form is `std::mem::forget` of the id rather than a special
//! registry mode. The one-shot form hands the id back inside a
//! `z_owned_matching_listener_t` and `z_undeclare_matching_listener` retracts
//! it.

use std::ffi::c_void;

use wz_capi_core::faces::{MatchId, MatchingSink, SharedSession};

use crate::abi::handle_ref;
use crate::ffi::{guarded, CClosure};
use crate::pubsub::{z_closure_drop_callback_t, z_loaned_publisher_t, PublisherState};
use crate::result::{ZResult, Z_ERR_NULL, Z_OK};
use std::sync::Arc;

/// pico `z_matching_status_t` — `{ bool matching }`, 1 B measured, field at
/// offset 0. Passed to the callback BY POINTER, so its layout is read by C.
#[repr(C)]
pub struct z_matching_status_t {
    /// Whether at least one remote declaration currently intersects the
    /// publisher's keyexpr.
    pub matching: bool,
}

/// pico `z_closure_matching_status_callback_t`:
/// `void call(const z_matching_status_t*, void*)`.
pub type z_closure_matching_status_callback_t =
    Option<unsafe extern "C" fn(*const z_matching_status_t, *mut c_void)>;

/// Owned matching-status closure (pico `z_owned_closure_matching_status_t`,
/// 24 B: `{ context, call, drop }`, the same shape as every other pico
/// closure).
#[repr(C)]
pub struct z_owned_closure_matching_status_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_matching_status_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Loaned matching-status closure, same layout.
#[repr(C)]
pub struct z_loaned_closure_matching_status_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_matching_status_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Moved matching-status closure (pico `z_moved_closure_matching_status_t`).
#[repr(C)]
pub struct z_moved_closure_matching_status_t {
    pub(crate) _this: z_owned_closure_matching_status_t,
}

impl z_owned_closure_matching_status_t {
    #[inline]
    fn null_value() -> Self {
        Self {
            context: std::ptr::null_mut(),
            call: None,
            drop: None,
        }
    }
}

/// The Rust-side owner of one C matching closure.
///
/// `Sync` is required because the [`MatchingSink`] is an
/// `Arc<dyn Fn(bool) + Send + Sync>` shared with every face's callback. The
/// soundness argument is the same as the sample plane's and rests on the same
/// fact: `call` is only ever reached from ONE thread. Every face of a session
/// is driven on one drive task, the per-face matching callback runs from that
/// task's `drain_deferred_fires`, and the aggregate mutex serialises the fold
/// that decides whether `call` runs at all — so two faces flipping at once
/// cannot produce two concurrent `call`s. The remaining caller is the C
/// application thread inside `z_publisher_declare_matching_listener`, which
/// delivers an already-matching registration; that runs before any per-face
/// listener for this id exists, so it cannot overlap either.
type MatchingCClosure = CClosure<z_closure_matching_status_callback_t>;

// SAFETY: see [`MatchingCClosure`] — `call` is reached from the single drive
// task, or from the registering C thread before any drive-side listener exists.
unsafe impl Sync for MatchingCClosure {}

/// Behind a `z_owned_matching_listener_t`: the C listener's id in the session
/// registry, plus the session it belongs to so `undeclare` can find it.
pub(crate) struct MatchingListenerState {
    shared: Arc<SharedSession>,
    id: MatchId,
}

/// Owned matching listener (pico `z_owned_matching_listener_t`, 24 B measured).
#[repr(C)]
pub struct z_owned_matching_listener_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 2],
}

/// Loaned matching listener (pico `z_loaned_matching_listener_t`).
#[repr(C)]
pub struct z_loaned_matching_listener_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 2],
}

/// Moved matching listener (pico `z_moved_matching_listener_t`).
#[repr(C)]
pub struct z_moved_matching_listener_t {
    pub(crate) _this: z_owned_matching_listener_t,
}

impl z_owned_matching_listener_t {
    #[inline]
    fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [std::ptr::null_mut(); 2],
        }
    }
}

// --- closure exports -------------------------------------------------------

/// Build an owned matching-status closure (pico `z_closure_matching_status`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_matching_status(
    closure: *mut z_owned_closure_matching_status_t,
    call: z_closure_matching_status_callback_t,
    drop: z_closure_drop_callback_t,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        if closure.is_null() {
            return Z_ERR_NULL;
        }
        *closure = z_owned_closure_matching_status_t {
            context,
            call,
            drop,
        };
        Z_OK
    })
}

/// Null an owned matching-status closure (pico
/// `z_internal_closure_matching_status_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_matching_status_null(
    closure: *mut z_owned_closure_matching_status_t,
) {
    if !closure.is_null() {
        *closure = z_owned_closure_matching_status_t::null_value();
    }
}

/// Whether an owned matching-status closure carries a callback (pico
/// `z_internal_closure_matching_status_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_matching_status_check(
    closure: *const z_owned_closure_matching_status_t,
) -> bool {
    !closure.is_null() && (*closure).call.is_some()
}

/// Borrow an owned matching-status closure (pico
/// `z_closure_matching_status_loan`) — offset-0 identity, as pico's macro emits.
#[no_mangle]
pub unsafe extern "C" fn z_closure_matching_status_loan(
    closure: *const z_owned_closure_matching_status_t,
) -> *const z_loaned_closure_matching_status_t {
    closure as *const z_loaned_closure_matching_status_t
}

/// Move an owned matching-status closure (pico
/// `z_closure_matching_status_move`) — the identity cast pico's macro emits.
#[no_mangle]
pub unsafe extern "C" fn z_closure_matching_status_move(
    closure: *mut z_owned_closure_matching_status_t,
) -> *mut z_moved_closure_matching_status_t {
    closure as *mut z_moved_closure_matching_status_t
}

/// Take a moved matching-status closure (pico
/// `z_closure_matching_status_take`), nulling the source — pico's
/// consume-on-take contract, so the `drop` runs exactly once.
#[no_mangle]
pub unsafe extern "C" fn z_closure_matching_status_take(
    closure: *mut z_owned_closure_matching_status_t,
    src: *mut z_moved_closure_matching_status_t,
) -> ZResult {
    guarded(|| {
        if closure.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        *closure = std::mem::replace(
            &mut (*src)._this,
            z_owned_closure_matching_status_t::null_value(),
        );
        Z_OK
    })
}

/// Release a matching-status closure (pico `z_closure_matching_status_drop`),
/// invoking the caller's `drop(context)` once.
#[no_mangle]
pub unsafe extern "C" fn z_closure_matching_status_drop(
    closure: *mut z_moved_closure_matching_status_t,
) -> ZResult {
    guarded(|| {
        if closure.is_null() {
            return Z_OK;
        }
        let taken = std::mem::replace(
            &mut (*closure)._this,
            z_owned_closure_matching_status_t::null_value(),
        );
        if let Some(dropfn) = taken.drop {
            dropfn(taken.context);
        }
        Z_OK
    })
}

/// Invoke a matching-status closure (pico `z_closure_matching_status_call`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_matching_status_call(
    closure: *const z_loaned_closure_matching_status_t,
    status: *const z_matching_status_t,
) {
    if closure.is_null() {
        return;
    }
    if let Some(call) = (*closure).call {
        call(status, (*closure).context);
    }
}

// --- matching-listener ownership family ------------------------------------

/// Null an owned matching listener (pico `z_internal_matching_listener_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_matching_listener_null(
    listener: *mut z_owned_matching_listener_t,
) {
    if !listener.is_null() {
        *listener = z_owned_matching_listener_t::null_value();
    }
}

/// Whether an owned matching listener is live (pico
/// `z_internal_matching_listener_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_matching_listener_check(
    listener: *const z_owned_matching_listener_t,
) -> bool {
    !listener.is_null() && !(*listener).handle.is_null()
}

/// Borrow an owned matching listener (pico `z_matching_listener_loan`).
#[no_mangle]
pub unsafe extern "C" fn z_matching_listener_loan(
    listener: *const z_owned_matching_listener_t,
) -> *const z_loaned_matching_listener_t {
    listener as *const z_loaned_matching_listener_t
}

/// Borrow an owned matching listener mutably (pico
/// `z_matching_listener_loan_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_matching_listener_loan_mut(
    listener: *mut z_owned_matching_listener_t,
) -> *mut z_loaned_matching_listener_t {
    listener as *mut z_loaned_matching_listener_t
}

/// Move an owned matching listener (pico `z_matching_listener_move`).
#[no_mangle]
pub unsafe extern "C" fn z_matching_listener_move(
    listener: *mut z_owned_matching_listener_t,
) -> *mut z_moved_matching_listener_t {
    listener as *mut z_moved_matching_listener_t
}

/// Take a moved matching listener (pico `z_matching_listener_take`).
#[no_mangle]
pub unsafe extern "C" fn z_matching_listener_take(
    listener: *mut z_owned_matching_listener_t,
    src: *mut z_moved_matching_listener_t,
) -> ZResult {
    guarded(|| {
        if listener.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        *listener = std::mem::replace(&mut (*src)._this, z_owned_matching_listener_t::null_value());
        Z_OK
    })
}

/// Release a matching listener without retracting the watch (pico
/// `z_matching_listener_drop` is `z_undeclare_matching_listener`).
#[no_mangle]
pub unsafe extern "C" fn z_matching_listener_drop(
    listener: *mut z_moved_matching_listener_t,
) -> ZResult {
    z_undeclare_matching_listener(listener)
}

// --- publisher-side exports ------------------------------------------------

/// Poll the current matching status (pico `z_publisher_get_matching_status`).
///
/// Reads the SESSION verdict: `true` when ANY connected peer has a matching
/// subscriber, which is the same aggregation the listener delivers, so the poll
/// and the callback cannot disagree.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_get_matching_status(
    publisher: *const z_loaned_publisher_t,
    matching_status: *mut z_matching_status_t,
) -> ZResult {
    guarded(|| {
        if matching_status.is_null() {
            return Z_ERR_NULL;
        }
        let state = match handle_ref::<z_loaned_publisher_t, PublisherState>(publisher) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        (*matching_status).matching = state.shared_session().has_matching(state.keyexpr());
        Z_OK
    })
}

/// Declare a matching listener, handing back a handle (pico
/// `z_publisher_declare_matching_listener`).
///
/// The moved closure is consumed on EVERY path including the failure ones —
/// pico's ownership transfer is unconditional once the call is made, so an
/// early return that skipped the release would leak the caller's context.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_declare_matching_listener(
    publisher: *const z_loaned_publisher_t,
    listener: *mut z_owned_matching_listener_t,
    callback: *mut z_moved_closure_matching_status_t,
) -> ZResult {
    guarded(|| match declare_matching(publisher, callback) {
        Ok((shared, id)) => {
            if listener.is_null() {
                // No handle slot to fill, so the watch would be unreachable:
                // retract it rather than leaving an un-undeclarable listener.
                shared.undeclare_matching_listener(id);
                return Z_ERR_NULL;
            }
            let boxed = Box::new(MatchingListenerState { shared, id });
            *listener = z_owned_matching_listener_t {
                handle: Box::into_raw(boxed) as *mut c_void,
                _pad: [std::ptr::null_mut(); 2],
            };
            Z_OK
        }
        Err(code) => {
            if !listener.is_null() {
                *listener = z_owned_matching_listener_t::null_value();
            }
            code
        }
    })
}

/// Declare a session-lifetime matching listener with no handle (pico
/// `z_publisher_declare_background_matching_listener`).
#[no_mangle]
pub unsafe extern "C" fn z_publisher_declare_background_matching_listener(
    publisher: *const z_loaned_publisher_t,
    callback: *mut z_moved_closure_matching_status_t,
) -> ZResult {
    guarded(|| match declare_matching(publisher, callback) {
        // The id is deliberately dropped: a background listener lives for the
        // session, and the registry (not a C handle) owns it from here.
        Ok(_) => Z_OK,
        Err(code) => code,
    })
}

/// Retract a matching listener (pico `z_undeclare_matching_listener`).
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_matching_listener(
    listener: *mut z_moved_matching_listener_t,
) -> ZResult {
    guarded(|| {
        if listener.is_null() {
            return Z_OK;
        }
        let handle = (*listener)._this.handle;
        if handle.is_null() {
            return Z_OK;
        }
        (*listener)._this = z_owned_matching_listener_t::null_value();
        let state = Box::from_raw(handle as *mut MatchingListenerState);
        state.shared.undeclare_matching_listener(state.id);
        Z_OK
    })
}

/// The shared body of the two declare forms: consume the moved closure, adapt
/// it to a [`MatchingSink`], and register it on the session.
///
/// One body rather than two so the closure-consumption contract and the sink
/// adaptation cannot drift between the handle and background forms — the
/// sibling asymmetry this crate has already paid for once.
unsafe fn declare_matching(
    publisher: *const z_loaned_publisher_t,
    callback: *mut z_moved_closure_matching_status_t,
) -> Result<(Arc<SharedSession>, MatchId), ZResult> {
    // Take the closure FIRST, so an invalid publisher still releases it.
    if callback.is_null() {
        return Err(Z_ERR_NULL);
    }
    let taken = std::mem::replace(
        &mut (*callback)._this,
        z_owned_closure_matching_status_t::null_value(),
    );
    let owned: Arc<MatchingCClosure> =
        Arc::new(CClosure::new(taken.context, taken.call, taken.drop));

    let state = match handle_ref::<z_loaned_publisher_t, PublisherState>(publisher) {
        Some(s) => s,
        // `owned` drops here, running the caller's `drop(context)`.
        None => return Err(Z_ERR_NULL),
    };

    let sink: MatchingSink = Arc::new(move |matching: bool| {
        if let Some(call) = owned.call {
            let status = z_matching_status_t { matching };
            // SAFETY: `context` is the caller's, alive until `drop` runs, which
            // cannot overlap this call (the `Arc` is held for its duration).
            call(&status, owned.context.0);
        }
    });

    let shared = state.shared_session();
    let id = shared.declare_matching_listener(state.keyexpr().to_owned(), sink);
    Ok((shared, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ABI sizes a C program stack-allocates through pico's own header,
    /// measured against the vendored headers and pinned here so padding drift
    /// fails the build rather than corrupting the caller's frame.
    #[test]
    fn matching_abi_sizes_match_pico() {
        assert_eq!(std::mem::size_of::<z_owned_closure_matching_status_t>(), 24);
        assert_eq!(std::mem::size_of::<z_moved_closure_matching_status_t>(), 24);
        assert_eq!(std::mem::size_of::<z_owned_matching_listener_t>(), 24);
        assert_eq!(std::mem::size_of::<z_moved_matching_listener_t>(), 24);
        // `z_matching_status_t` is `{ bool }` — 1 B, field at offset 0, and it
        // crosses the boundary BY POINTER so C reads this layout directly.
        assert_eq!(std::mem::size_of::<z_matching_status_t>(), 1);
    }

    /// `z_closure_matching_status_call` reaches the C callback with the status
    /// it was handed, and a null closure is a silent no-op rather than a crash
    /// (pico tolerates an unset closure).
    #[test]
    fn closure_call_reaches_the_callback_and_tolerates_null() {
        use std::sync::atomic::{AtomicI32, Ordering};
        static SEEN: AtomicI32 = AtomicI32::new(-1);
        unsafe extern "C" fn cb(status: *const z_matching_status_t, _ctx: *mut c_void) {
            SEEN.store(i32::from((*status).matching), Ordering::SeqCst);
        }

        let mut closure = z_owned_closure_matching_status_t::null_value();
        unsafe {
            assert_eq!(
                z_closure_matching_status(&mut closure, Some(cb), None, std::ptr::null_mut()),
                Z_OK
            );
            assert!(z_internal_closure_matching_status_check(&closure));

            let status = z_matching_status_t { matching: true };
            z_closure_matching_status_call(z_closure_matching_status_loan(&closure), &status);
            assert_eq!(SEEN.load(Ordering::SeqCst), 1);

            let status = z_matching_status_t { matching: false };
            z_closure_matching_status_call(z_closure_matching_status_loan(&closure), &status);
            assert_eq!(SEEN.load(Ordering::SeqCst), 0);

            // Null closure: no call, no crash.
            z_closure_matching_status_call(std::ptr::null(), &status);
            assert_eq!(SEEN.load(Ordering::SeqCst), 0);
        }
    }

    /// `move` / `loan` are pointer identity and `take` NULLS the source — the
    /// consume-once contract that keeps the C `drop(context)` from running
    /// twice.
    #[test]
    fn closure_move_is_identity_and_take_nulls_the_source() {
        let mut closure = z_owned_closure_matching_status_t::null_value();
        unsafe extern "C" fn cb(_s: *const z_matching_status_t, _c: *mut c_void) {}
        unsafe {
            z_closure_matching_status(&mut closure, Some(cb), None, 0x1234 as *mut c_void);
            let p = &mut closure as *mut z_owned_closure_matching_status_t;
            assert_eq!(z_closure_matching_status_move(p) as *mut _, p);
            assert_eq!(z_closure_matching_status_loan(p) as *const _, p as *const _);

            let mut dest = z_owned_closure_matching_status_t::null_value();
            assert_eq!(
                z_closure_matching_status_take(&mut dest, z_closure_matching_status_move(p)),
                Z_OK
            );
            assert!(dest.call.is_some(), "take moves the callback across");
            assert_eq!(dest.context, 0x1234 as *mut c_void);
            assert!(
                !z_internal_closure_matching_status_check(p),
                "take must NULL the source so drop cannot run twice"
            );
        }
    }

    /// The caller's `drop(context)` runs exactly once on
    /// `z_closure_matching_status_drop`, and a second drop of the same (now
    /// nulled) moved closure does not run it again.
    #[test]
    fn closure_drop_runs_the_caller_deleter_exactly_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn dropper(_ctx: *mut c_void) {
            DROPS.fetch_add(1, Ordering::SeqCst);
        }
        unsafe extern "C" fn cb(_s: *const z_matching_status_t, _c: *mut c_void) {}

        let mut closure = z_owned_closure_matching_status_t::null_value();
        unsafe {
            z_closure_matching_status(&mut closure, Some(cb), Some(dropper), std::ptr::null_mut());
            let moved = z_closure_matching_status_move(&mut closure);
            assert_eq!(z_closure_matching_status_drop(moved), Z_OK);
            assert_eq!(DROPS.load(Ordering::SeqCst), 1);
            assert_eq!(z_closure_matching_status_drop(moved), Z_OK);
            assert_eq!(
                DROPS.load(Ordering::SeqCst),
                1,
                "a re-drop of a nulled closure must not re-run the deleter"
            );
        }
    }
}
