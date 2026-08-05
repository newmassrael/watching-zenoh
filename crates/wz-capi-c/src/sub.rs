// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The subscriber plane: the sample closure the C side builds, and the
//! declaration it hands that closure to.
//!
//! ## One C subscription is N wz subscribers
//!
//! A zenoh-c session is "one session, many peers"; a wz unicast `Session` is
//! exactly one peer. [`wz_capi_core`](wz_capi_core) resolves that with a face
//! registry and a declaration SSOT replayed onto each face as it comes up, so a
//! `z_declare_subscriber` before any peer is connected still records the
//! subscription and every FUTURE face gets it. That is upstream's
//! declare-before-peer behaviour and it is shared with the zenoh-pico ABI rather
//! than re-derived here.
//!
//! Because the fan-out is per face, the closure is handed in as a FACTORY: the
//! registry mints one wz callback per face, all sharing one `Arc<CClosure>`, and
//! the C `drop(context)` runs when the last of them is released.
//!
//! ## Consume-on-all-paths
//!
//! `z_declare_subscriber` takes a `z_moved_closure_sample_t*`. Upstream consumes
//! it whether or not the declaration succeeds, so the closure is adopted FIRST
//! here and the source nulled immediately: an early error return then drops the
//! adopted value, which runs the C `drop(context)` exactly once. Reading the
//! session first and returning early would leak the caller's context on that
//! path — a divergence visible only as a leak in their code, not ours.

use std::ffi::c_void;
use std::sync::Arc;

use wz_runtime_tokio::sink::SampleView;

use crate::abi::{
    z_closure_drop_callback_t, z_closure_sample_callback_t, z_loaned_keyexpr_t, z_loaned_session_t,
    z_loaned_subscriber_t, z_moved_closure_sample_t, z_moved_subscriber_t,
    z_owned_closure_sample_t, z_owned_subscriber_t, Handle,
};
use crate::ffi::{guard_val, guarded, CClosure as FfiClosure};
use crate::keyexpr::keyexpr_str;
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_OK};
use crate::sample::with_marshalled;
use crate::session::session_state;

use wz_capi_core::faces::{SharedSession, SubId};

/// The Rust-side wrapper a subscription's per-face callbacks share.
pub(crate) type CClosure = FfiClosure<z_closure_sample_callback_t>;

// SAFETY: sharing one subscription's `CClosure` across per-face callbacks
// requires `Sync`, so that `Arc<CClosure>` — and therefore each callback — is
// `Send`. Written for this concrete instantiation rather than blanket, because
// the argument is specific to the subscriber plane:
//
// `call` is only ever invoked from the session's single drive task. Every face
// of a session is driven on ONE task (the accept loop multiplexes its faces
// through one `select!`; a dialed session has exactly one drive loop), and
// inbound dispatch is the only caller. It is load-bearing that the C application
// thread never invokes `call`: this crate's fan-out publishes are
// `Locality::Remote` (see `crate::put::put_options`), so a `z_put` stages no
// loopback fire and never drains a callback on the C thread. Were the publishes
// local-capable, a C-thread `z_put` whose keyexpr matched a subscription would
// drain that face's loopback fire concurrently with the drive thread's inbound
// dispatch on another face — two `call(context)`s at once on one C context,
// which upstream's single-threaded-callback contract forbids.
//
// `drop` runs only when the last `Arc` is released, which cannot overlap a live
// `call` because a running callback holds a reference.
unsafe impl Sync for CClosure {}

/// Build the wz-side subscriber callback for ONE face from a shared C closure.
///
/// The borrowed sample is valid only for the duration of the call, which is
/// zenoh-c's contract and why the C side must copy anything it keeps.
pub(crate) fn make_subscriber_callback(
    closure: Arc<CClosure>,
) -> impl FnMut(&dyn SampleView) + Send + 'static {
    move |view: &dyn SampleView| {
        let Some(call) = closure.call else {
            return;
        };
        let ctx = closure.context.0;
        with_marshalled(view, |sample| {
            // SAFETY: `call` is the C callback and `sample` is valid for exactly
            // this call. A panic unwinding OUT of the C callback across this
            // `extern "C"` boundary is UB and would tear down the drive thread,
            // so it is caught here — the drive loop survives a misbehaving
            // callback rather than taking the session with it.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                call(sample, ctx);
            }));
        });
    }
}

/// Behind a `z_owned_subscriber_t` handle: the C subscription's id in the
/// session's SSOT.
///
/// Dropping it retracts the subscription — removed from the SSOT so no future
/// face replays it, and every live face's wz subscriber dropped, which emits
/// each wire undeclare and releases the last closure reference (→ the C
/// `drop(context)`).
struct SubscriberState {
    shared: Arc<SharedSession>,
    id: SubId,
}

/// Leak a [`SubscriberState`] and hand back the handle a `z_owned_subscriber_t`
/// carries.
///
/// Shared with the LIVELINESS plane rather than duplicated there, and that is not
/// tidiness: `z_liveliness_declare_subscriber` hands the C side back the SAME
/// `z_owned_subscriber_t`, so both kinds must be undeclarable through the one
/// `z_undeclare_subscriber` below. One state type is what makes that true by
/// construction — the registry already shares [`SubId`] space between the two for
/// the same reason.
pub(crate) fn subscriber_state_handle(shared: &Arc<SharedSession>, id: SubId) -> Handle {
    Box::into_raw(Box::new(SubscriberState {
        shared: shared.clone(),
        id,
    })) as Handle
}

impl Drop for SubscriberState {
    fn drop(&mut self) {
        self.shared.undeclare_subscriber(self.id);
    }
}

/// Options for `z_declare_subscriber` (`zenoh_commons.h:464-470`).
///
/// TRANSPARENT upstream and exactly ONE field wide, which is the whole reason it
/// is declared rather than left as the `*mut c_void` this plane used until the
/// advanced subscriber needed it: `ze_advanced_subscriber_options_t` EMBEDS one
/// at offset 0, so its four bytes set every later field's offset. The pico ABI's
/// equivalent is a one-byte dummy, so the two option structs are genuinely
/// different sizes and neither may borrow the other's number.
///
/// The field is carried for layout; `allowed_origin` is a NAMED gap, the same
/// one [`z_declare_subscriber`] already records.
#[repr(C)]
pub struct z_subscriber_options_t {
    /// Restrict matching publications by their origin locality.
    pub allowed_origin: crate::publisher::zc_locality_t,
}

/// Fill in the default subscriber options (zenoh-c
/// `z_subscriber_options_default`).
///
/// # Safety
/// `this_` must be null or a valid, writable options struct.
#[no_mangle]
pub unsafe extern "C" fn z_subscriber_options_default(this_: *mut z_subscriber_options_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = z_subscriber_options_t {
            allowed_origin: crate::publisher::ZC_LOCALITY_ANY,
        }
    };
}

/// Construct a sample closure from its parts (zenoh-c `z_closure_sample`).
///
/// The `z_closure` macro dispatches here for a `z_owned_closure_sample_t*`. Note
/// upstream's argument ORDER — `(this_, call, drop, context)` — which is not the
/// struct's field order; getting it wrong compiles and then calls the context as
/// a function.
///
/// # Safety
/// `this_` must be valid and writable. `call` / `drop` must be null or valid C
/// function pointers, and `context` is opaque to wz.
#[no_mangle]
pub unsafe extern "C" fn z_closure_sample(
    this_: *mut z_owned_closure_sample_t,
    call: z_closure_sample_callback_t,
    drop: z_closure_drop_callback_t,
    context: *mut c_void,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe {
            *this_ = z_owned_closure_sample_t {
                context,
                call,
                drop,
            }
        };
    });
}

/// Drop a closure that was never declared (zenoh-c `z_closure_sample_drop`):
/// run the C `drop(context)` and null the struct.
///
/// # Safety
/// `closure_` must be null or a valid moved closure.
#[no_mangle]
pub unsafe extern "C" fn z_closure_sample_drop(closure_: *mut z_moved_closure_sample_t) {
    let _ = guarded(|| {
        if closure_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*closure_)._this };
        if let Some(dropfn) = owned.drop {
            let ctx = owned.context;
            // SAFETY: upstream's contract — drop runs once, and an unwind across
            // the C boundary is UB, so it is caught.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                dropfn(ctx);
            }));
        }
        *owned = z_owned_closure_sample_t::null_value();
        Z_OK
    });
}

/// Declare a subscriber (zenoh-c `z_declare_subscriber`). Consumes the moved
/// closure on every path.
///
/// # Safety
/// `session` must be a valid loaned session; `subscriber` must be valid and
/// writable; `key_expr` must be a valid loaned keyexpr; `callback` must be a
/// valid moved closure. `_options` is accepted for ABI compatibility and
/// ignored: `z_sub.c` passes NULL, and the one field
/// (`allowed_origin`) is a later slice.
#[no_mangle]
pub unsafe extern "C" fn z_declare_subscriber(
    session: *const z_loaned_session_t,
    subscriber: *mut z_owned_subscriber_t,
    key_expr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    _options: *mut z_subscriber_options_t,
) -> ZResult {
    guarded(|| {
        if subscriber.is_null() || callback.is_null() {
            return Z_ENULL;
        }
        // The gravestone contract, written before any fallible work: upstream
        // specifies that on failure "subscriber will be in its gravestone state".
        unsafe { *subscriber = z_owned_subscriber_t::null_value() };

        // Consume the moved closure FIRST (see the module note on
        // consume-on-all-paths): from here the `CClosure` owns the C
        // `drop(context)` responsibility, so every early return below frees the
        // caller's context exactly as upstream does.
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*callback)._this };
        let cclosure = CClosure::new(owned.context, owned.call, owned.drop);
        *owned = z_owned_closure_sample_t::null_value();

        // SAFETY: the caller's contract for both handles.
        let (Some(state), Some(ke)) = (unsafe { session_state(session) }, unsafe {
            keyexpr_str(key_expr)
        }) else {
            return Z_ENULL;
        };
        let ke = ke.to_owned();
        // Reject a non-canonical keyexpr UP FRONT rather than recording a dead
        // SSOT entry that never matches yet reported success. This is the same
        // outbound gate wz's own `Session::declare_subscriber` applies per face,
        // hoisted so the verdict is uniform whether or not a peer is connected
        // yet — the registry declares best-effort per face, so a per-face reject
        // would otherwise be swallowed.
        if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
            return Z_EINVAL;
        }

        let id = state.shared.declare_subscriber(ke, {
            let closure = Arc::new(cclosure);
            Arc::new(move || Box::new(make_subscriber_callback(closure.clone())) as Box<_>)
        });
        unsafe {
            *subscriber =
                z_owned_subscriber_t::from_handle(subscriber_state_handle(&state.shared, id))
        };
        Z_OK
    })
}

/// Declare a subscriber the C side never holds (zenoh-c
/// `z_declare_background_subscriber`): it lives until the session is closed.
///
/// The difference from [`z_declare_subscriber`] is ownership, not behaviour.
/// There is no `z_owned_subscriber_t` to hand back, so nothing can undeclare it —
/// the registry's SSOT entry (and with it the last `Arc<CClosure>`) is released
/// when the session drops, which is exactly upstream's "background" contract.
///
/// Implemented by declaring into a LOCAL owned handle and discarding it, rather
/// than by a second registry path: a background subscription is an ordinary one
/// whose handle was thrown away, and giving it its own path is how the two would
/// drift.
///
/// Discarding the local is a genuine leak and that is the intent, not an
/// oversight to be papered over with `mem::forget`. `z_owned_subscriber_t` is a
/// plain `#[repr(C)]` struct with NO `Drop` — the retraction lives in the boxed
/// [`SubscriberState`] behind its handle, and only [`z_undeclare_subscriber`]
/// reclaims that. With no handle in the C side's hands, nobody can call it, so
/// the subscription lives until the session's registry is torn down. `mem::forget`
/// here would be a no-op that merely LOOKED load-bearing.
///
/// # Safety
/// `session` must be a valid loaned session; `key_expr` must be a valid loaned
/// keyexpr; `callback` must be a valid moved closure. `options` is accepted for
/// ABI compatibility and ignored, as for [`z_declare_subscriber`].
#[no_mangle]
pub unsafe extern "C" fn z_declare_background_subscriber(
    session: *const z_loaned_session_t,
    key_expr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut z_subscriber_options_t,
) -> ZResult {
    let mut sink = z_owned_subscriber_t::null_value();
    // SAFETY: the caller's contract, delegated — the local sink absorbs the
    // handle the owned form would have written out, and then goes out of scope
    // without reclaiming it. See the doc note.
    unsafe { z_declare_subscriber(session, &mut sink, key_expr, callback, options) }
}

/// Undeclare a subscriber (zenoh-c `z_undeclare_subscriber`): drops the wz
/// subscribers (each emitting its wire undeclare) and the callback (→ the C
/// `drop(context)`).
///
/// # Safety
/// `this_` must be null or a valid moved subscriber.
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_subscriber(this_: *mut z_moved_subscriber_t) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<SubscriberState>` this crate leaked; its `Drop`
            // retracts the subscription.
            drop(unsafe { Box::from_raw(handle as *mut SubscriberState) });
            unsafe { (*this_)._this = z_owned_subscriber_t::null_value() };
        }
        Z_OK
    })
}

/// Drop a subscriber (zenoh-c `z_subscriber_drop`) — what `z_drop(z_move(sub))`
/// dispatches to. Identical to [`z_undeclare_subscriber`] but returns nothing,
/// which is upstream's split.
///
/// # Safety
/// `this_` must be null or a valid moved subscriber.
#[no_mangle]
pub unsafe extern "C" fn z_subscriber_drop(this_: *mut z_moved_subscriber_t) {
    // SAFETY: the caller's contract, delegated — the slot is nulled there, so a
    // double drop is a no-op.
    let _ = unsafe { z_undeclare_subscriber(this_) };
}

/// Borrow a subscriber (zenoh-c `z_subscriber_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned subscriber.
#[no_mangle]
pub unsafe extern "C" fn z_subscriber_loan(
    this_: *const z_owned_subscriber_t,
) -> *const z_loaned_subscriber_t {
    this_ as *const z_loaned_subscriber_t
}

/// `true` iff the owned subscriber holds a live handle (zenoh-c
/// `z_internal_subscriber_check`).
///
/// # Safety
/// `this_` must be null or a valid owned subscriber.
#[no_mangle]
pub unsafe extern "C" fn z_internal_subscriber_check(this_: *const z_owned_subscriber_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned subscriber (zenoh-c `z_internal_subscriber_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned subscriber.
#[no_mangle]
pub unsafe extern "C" fn z_internal_subscriber_null(this_: *mut z_owned_subscriber_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_subscriber_t::null_value() };
    }
}
