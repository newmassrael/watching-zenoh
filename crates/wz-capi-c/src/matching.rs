// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Matching listeners — "does anyone subscribe to what I publish?"
//!
//! ## The verdict is AGGREGATED across faces, and it has to be
//!
//! wz holds N sessions where zenoh-c holds one, so a per-face pass-through would
//! print "no more matching subscribers" the moment ONE peer went away while
//! another was still subscribed — the opposite of the truth. The aggregation (an
//! OR across faces, delivered once when the session-level verdict FLIPS) lives in
//! [`declare_matching_listener`](wz_capi_core::faces::SharedSession::declare_matching_listener)
//! and is shared with the zenoh-pico ABI. This module is the zenoh-c spelling.
//!
//! ## Only the BACKGROUND form is exported
//!
//! `z_pub.c` calls `z_publisher_declare_background_matching_listener`, whose
//! listener "will be automatically dropped when the publisher is dropped" — there
//! is no owned handle for the C side to hold. The owned form
//! (`z_publisher_declare_matching_listener`) needs a
//! `z_owned_matching_listener_t` and an undeclare, and it arrives with the
//! program that calls it: the scope rule for this crate is an upstream PROGRAM,
//! not a symbol list.
//!
//! Retiring the listener when its publisher drops is [`MatchingHold`]'s `Drop`,
//! which the publisher state owns — so the two cannot drift, the same discipline
//! the liveliness token uses for its retraction.

use std::ffi::c_void;
use std::sync::Arc;

use wz_capi_core::faces::{MatchId, SharedSession};

use crate::abi::{z_closure_drop_callback_t, z_loaned_publisher_t};
use crate::ffi::{guard_val, guarded, CClosure as FfiClosure};
use crate::result::{ZResult, Z_ENULL, Z_OK};

/// zenoh-c `z_matching_status_t` (`zenoh_commons.h:511-516`) — one `bool`.
///
/// Passed to the C callback BY POINTER, so its single field's offset is the whole
/// layout contract.
#[repr(C)]
pub struct z_matching_status_t {
    /// `true` while at least one matching entity exists.
    pub matching: bool,
}

const _: () = {
    assert!(std::mem::size_of::<z_matching_status_t>() == 1);
};

/// zenoh-c `z_closure_matching_status_callback_t`.
pub type z_closure_matching_status_callback_t =
    Option<unsafe extern "C" fn(*const z_matching_status_t, *mut c_void)>;

/// Owned matching-status closure (zenoh-c `z_owned_closure_matching_status_t`,
/// `zenoh_commons.h:523-527`).
///
/// TRANSPARENT — written directly by the C `z_closure` macro, so the field ORDER
/// is part of the ABI and not merely the size.
#[repr(C)]
pub struct z_owned_closure_matching_status_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_matching_status_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// Moved matching-status closure.
#[repr(C)]
pub struct z_moved_closure_matching_status_t {
    pub(crate) _this: z_owned_closure_matching_status_t,
}

impl z_owned_closure_matching_status_t {
    /// The gravestone: no context, no callbacks.
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            context: std::ptr::null_mut(),
            call: None,
            drop: None,
        }
    }
}

const _: () = {
    assert!(std::mem::size_of::<z_owned_closure_matching_status_t>() == 24);
    assert!(std::mem::align_of::<z_owned_closure_matching_status_t>() == 8);
    assert!(std::mem::size_of::<z_moved_closure_matching_status_t>() == 24);
};

/// The Rust-side wrapper a matching listener's callback holds.
pub(crate) type CMatchClosure = FfiClosure<z_closure_matching_status_callback_t>;

// SAFETY: the aggregated verdict is delivered from the drive task while the
// registry holds the aggregate mutex across the C call, so `call` is never
// re-entered concurrently on one context. `drop` runs only through the single
// owner the registry keeps (R311y535 made the sink OWNED rather than cloned
// precisely so that release is synchronous and single), which cannot overlap a
// live `call` for the same reason.
unsafe impl Sync for CMatchClosure {}

/// Retires a background matching listener when its publisher drops.
///
/// The retraction lives here rather than in the publisher's own `Drop` body so
/// that a publisher WITHOUT a listener costs nothing and one WITH a listener
/// cannot forget — the same reason the liveliness token's retraction is in
/// `TokenState::drop`.
pub(crate) struct MatchingHold {
    shared: Arc<SharedSession>,
    id: MatchId,
}

impl MatchingHold {
    /// Record a live listener so it is retired with its publisher.
    pub(crate) fn new(shared: Arc<SharedSession>, id: MatchId) -> Self {
        Self { shared, id }
    }
}

impl Drop for MatchingHold {
    fn drop(&mut self) {
        self.shared.undeclare_matching_listener(self.id);
    }
}

/// Construct a matching-status closure from its parts (zenoh-c
/// `z_closure_matching_status`).
///
/// Argument ORDER is `(this_, call, drop, context)`, not the struct's field
/// order — the same trap the sample and zid closures carry.
///
/// # Safety
/// `this_` must be valid and writable; `call` / `drop` must be null or valid C
/// function pointers; `context` is opaque to wz.
#[no_mangle]
pub unsafe extern "C" fn z_closure_matching_status(
    this_: *mut z_owned_closure_matching_status_t,
    call: z_closure_matching_status_callback_t,
    drop: z_closure_drop_callback_t,
    context: *mut c_void,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe {
            *this_ = z_owned_closure_matching_status_t {
                context,
                call,
                drop,
            }
        };
    });
}

/// Drop a matching-status closure that was never declared (zenoh-c
/// `z_closure_matching_status_drop`).
///
/// # Safety
/// `closure_` must be null or a valid moved closure.
#[no_mangle]
pub unsafe extern "C" fn z_closure_matching_status_drop(
    closure_: *mut z_moved_closure_matching_status_t,
) {
    let _ = guarded(|| {
        if closure_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*closure_)._this };
        let taken = std::mem::replace(owned, z_owned_closure_matching_status_t::null_value());
        if let Some(dropfn) = taken.drop {
            let ctx = taken.context;
            // SAFETY: upstream's contract — drop runs once, and an unwind across
            // the C boundary is UB, so it is caught.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                dropfn(ctx);
            }));
        }
        Z_OK
    });
}

/// Declare a background matching listener on a publisher (zenoh-c
/// `z_publisher_declare_background_matching_listener`). Consumes the moved
/// closure on every path.
///
/// # Safety
/// `publisher` must be null or a valid loaned publisher; `callback` must be a
/// valid moved closure.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_declare_background_matching_listener(
    publisher: *const z_loaned_publisher_t,
    callback: *mut z_moved_closure_matching_status_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ENULL;
        }
        // Consume the moved closure FIRST (consume-on-all-paths).
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*callback)._this };
        let cclosure = CMatchClosure::new(owned.context, owned.call, owned.drop);
        *owned = z_owned_closure_matching_status_t::null_value();

        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { crate::publisher::publisher_state(publisher) }) else {
            return Z_ENULL;
        };
        let closure = Arc::new(cclosure);
        let id = state.shared.declare_matching_listener(
            state.keyexpr.keyexpr.clone(),
            Arc::new(move |matching: bool| {
                let Some(call) = closure.call else {
                    return;
                };
                let status = z_matching_status_t { matching };
                let ctx = closure.context.0;
                // SAFETY: `call` is the C callback and `status` outlives it. An
                // unwind out of the callback across `extern "C"` is UB, so it is
                // caught — the drive loop survives a misbehaving callback.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                    call(&status, ctx);
                }));
            }),
        );
        state.attach_matching(MatchingHold::new(state.shared.clone(), id));
        Z_OK
    })
}
