// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The QUERIER plane — a keyexpr plus get options bound to a session.
//!
//! A querier is exactly that in zenoh, in zenoh-pico and in wz, so
//! [`z_querier_get`] resolves its three ingredients from the declaration and
//! then calls the SAME [`issue_get`](crate::get::issue_get) `z_get` does.
//! Restating the body would have put the receive-side reply gate in two places,
//! and those two must agree or a reply is silently dropped.
//!
//! The matching listener is the querier's own: it watches for remote
//! QUERYABLES rather than subscribers, which is the one thing that differs from
//! the publisher's ([`crate::matching`]).

use std::ffi::{c_char, c_int, CStr};
// R311y547 — `c_void`'s only remaining user in this module is the
// unstable-gated `z_querier_get_options_t::source_info`, so the import carries
// the SAME cfg. The y536 rule ("a symbol's cfg is the OR of every arm that uses
// it") read backwards: when the last unconditional user goes away, an
// unconditional import becomes an unused-import error on exactly the arms the
// remaining user is absent from — and only two of the four lanes compile those.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
use std::ffi::c_void;
use std::sync::{Arc, Mutex};

use wz_runtime_tokio::session::QueryOptions;

use crate::abi::{
    z_loaned_keyexpr_t, z_loaned_querier_t, z_loaned_session_t, z_moved_bytes_t,
    z_moved_closure_reply_t, z_moved_querier_t, z_owned_querier_t, Handle,
};
use crate::ffi::{guard_val, guarded};
use crate::get::{adopt_reply_closure, issue_get, z_query_consolidation_t};
use crate::keyexpr::{keyexpr_str, KeyexprState};
use crate::matching::{
    z_matching_status_t, z_moved_closure_matching_status_t, z_owned_closure_matching_status_t,
    CMatchClosure, MatchingHold,
};
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_OK};
use crate::session::session_state;

use wz_capi_core::faces::SharedSession;

/// zenoh-c `z_querier_options_t` (`zenoh_commons.h:702-728`) — 32 bytes on the
/// no-unstable oracle, 40 with `Z_FEATURE_UNSTABLE_API`.
///
/// Mirrored field for field, both arms, so rustc computes the size.
#[repr(C)]
pub struct z_querier_options_t {
    /// Reply target hint. CARRIED.
    pub target: c_int,
    /// Reply consolidation. CARRIED.
    pub consolidation: z_query_consolidation_t,
    /// Congestion control. R311y551 — HONOURED: declared once here and packed
    /// into every `z_querier_get`'s Request QoS ext.
    pub congestion_control: c_int,
    /// Express flag. R311y551 — HONOURED (bit 4 of the Request QoS byte).
    pub is_express: bool,
    /// Destination locality. Accepted and ignored.
    pub allowed_destination: c_int,
    /// Which reply keyexprs are accepted — unstable-only.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub accept_replies: c_int,
    /// Priority. R311y551 — HONOURED (bits 0-2 of the Request QoS byte).
    pub priority: c_int,
    /// Timeout in milliseconds. CARRIED.
    pub timeout_ms: u64,
}

/// Fill default querier options (zenoh-c `z_querier_options_default`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_querier_options_default(this_: *mut z_querier_options_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = z_querier_options_t {
            target: crate::get::Z_QUERY_TARGET_BEST_MATCHING,
            consolidation: z_query_consolidation_t {
                mode: crate::get::Z_CONSOLIDATION_MODE_AUTO,
            },
            // R311y545 — BLOCK, and it is 0 in zenoh-c (the enum is
            // INVERTED against zenoh-pico's). This literal was 1, which
            // spells DROP here; upstream's request-side default is
            // `CongestionControl::DEFAULT_REQUEST` = Block. Named rather
            // than a literal now, because the literal is what went wrong.
            congestion_control: crate::publisher::Z_CONGESTION_CONTROL_BLOCK,
            is_express: false,
            allowed_destination: 0,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            // R311y545 — MATCHING_QUERY (1), MEASURED against the real
            // libzenohc on the unstable oracle; upstream's default is
            // `ReplyKeyExpr::default()`, not ANY. This was 0, and Layer
            // C1cc cannot see it: the field exists only under
            // Z_FEATURE_UNSTABLE_API, which the installed header lacks.
            accept_replies: crate::get::ZC_REPLY_KEYEXPR_MATCHING_QUERY,
            priority: 5,
            timeout_ms: 0,
        }
    };
}

/// zenoh-c `z_querier_get_options_t` (`zenoh_commons.h:993-1006`) — 24 bytes on
/// the no-unstable oracle, 32 with `Z_FEATURE_UNSTABLE_API`.
#[repr(C)]
pub struct z_querier_get_options_t {
    /// Query VALUE payload. CARRIED — consumed by [`z_querier_get`].
    pub payload: *mut z_moved_bytes_t,
    /// Value encoding for the query payload. R311y547 — READ, and carried in
    /// the Query value ext alongside the payload, the same as `z_get`'s.
    pub encoding: *mut crate::abi::z_moved_encoding_t,
    /// Querier source info — unstable-only.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub source_info: *mut c_void,
    /// Query attachment. CARRIED — consumed by [`z_querier_get`].
    pub attachment: *mut z_moved_bytes_t,
}

/// Fill default per-get querier options (zenoh-c
/// `z_querier_get_options_default`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_querier_get_options_default(this_: *mut z_querier_get_options_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = z_querier_get_options_t {
            payload: std::ptr::null_mut(),
            encoding: std::ptr::null_mut(),
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            source_info: std::ptr::null_mut(),
            attachment: std::ptr::null_mut(),
        }
    };
}

/// Behind a `z_owned_querier_t` handle: the keyexpr, the declared options, and
/// whatever matching listener the C side attached.
pub(crate) struct QuerierState {
    pub(crate) shared: Arc<SharedSession>,
    pub(crate) keyexpr: KeyexprState,
    /// The per-declaration options every `z_querier_get` starts from.
    base: QueryOptions,
    /// A background matching listener, held so it is undeclared when the
    /// querier is. `Mutex` because the C side may attach one after declaring,
    /// from a different thread than the one that declared.
    matching: Mutex<Option<MatchingHold>>,
}

impl QuerierState {
    /// Attach a matching listener, replacing (and so undeclaring) any previous.
    fn attach_matching(&self, hold: MatchingHold) {
        let mut slot = self.matching.lock().unwrap_or_else(|e| e.into_inner());
        *slot = Some(hold);
    }
}

/// Read the [`QuerierState`] behind a loaned querier.
///
/// # Safety
/// `this_` must be null or a valid loaned querier whose handle is live.
unsafe fn querier_state<'a>(this_: *const z_loaned_querier_t) -> Option<&'a QuerierState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<QuerierState>` this crate leaked.
    Some(unsafe { &*(handle as *const QuerierState) })
}

/// Declare a querier (zenoh-c `z_declare_querier`).
///
/// # Safety
/// `session` must be a valid loaned session; `querier` must be valid and
/// writable; `key_expr` must be a valid loaned keyexpr; `options` must be null
/// or valid.
#[no_mangle]
pub unsafe extern "C" fn z_declare_querier(
    session: *const z_loaned_session_t,
    querier: *mut z_owned_querier_t,
    key_expr: *const z_loaned_keyexpr_t,
    options: *mut z_querier_options_t,
) -> ZResult {
    guarded(|| {
        if querier.is_null() {
            return Z_ENULL;
        }
        // The gravestone contract, before any fallible work.
        // SAFETY: the caller's contract.
        unsafe { *querier = z_owned_querier_t::null_value() };

        // SAFETY: the caller's contract for both handles.
        let (Some(state), Some(ke)) = (unsafe { session_state(session) }, unsafe {
            keyexpr_str(key_expr)
        }) else {
            return Z_ENULL;
        };
        let ke = ke.to_owned();
        if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
            return Z_EINVAL;
        }

        let mut base = QueryOptions::default();
        if !options.is_null() {
            // SAFETY: the caller's contract.
            let o = unsafe { &*options };
            // SATURATE rather than wrap — a wrapped huge timeout becomes a tiny
            // one and expires every get immediately.
            base = base.with_timeout_ms(o.timeout_ms.min(u32::MAX as u64) as u32);
            if let Some(target) = crate::get::query_target_of(o.target) {
                base = base.with_target(target);
            }
            if let Some(mode) = crate::get::consolidation_of(o.consolidation.mode) {
                base = base.with_consolidation(mode);
            }
            // R311y551 — the request-side QoS trio, previously accepted and
            // ignored here exactly as on `z_get`. Declared ONCE on the querier
            // and inherited by every `z_querier_get`, which is upstream's shape:
            // `z_querier_get_options_t` carries no QoS fields at all, so the
            // per-get call has nothing to override them with.
            base = base
                .with_priority(crate::publisher::priority_from_c(o.priority))
                .with_congestion_control(crate::publisher::congestion_from_c(o.congestion_control))
                .with_express(o.is_express);
        }

        let handle = Box::into_raw(Box::new(QuerierState {
            shared: state.shared.clone(),
            keyexpr: KeyexprState { keyexpr: ke },
            base,
            matching: Mutex::new(None),
        })) as Handle;
        // SAFETY: the caller's contract.
        unsafe { *querier = z_owned_querier_t::from_handle(handle) };
        Z_OK
    })
}

/// Borrow a querier (zenoh-c `z_querier_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned querier.
#[no_mangle]
pub unsafe extern "C" fn z_querier_loan(
    this_: *const z_owned_querier_t,
) -> *const z_loaned_querier_t {
    this_ as *const z_loaned_querier_t
}

/// Issue one get through a querier (zenoh-c `z_querier_get`). Consumes the moved
/// closure on every path.
///
/// # Safety
/// `querier` must be null or a valid loaned querier; `parameters` must be null
/// or NUL-terminated; `callback` must be a valid moved reply closure; `options`
/// must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn z_querier_get(
    querier: *const z_loaned_querier_t,
    parameters: *const c_char,
    callback: *mut z_moved_closure_reply_t,
    options: *mut z_querier_get_options_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ENULL;
        }
        // Adopt the closure FIRST (consume-on-all-paths): the C `drop(context)`
        // is the completion signal, so an early return correctly reports "this
        // get is over".
        // SAFETY: the caller's contract.
        let closure = unsafe { adopt_reply_closure(callback) };

        // The per-get moved payload / attachment are consumed on every path
        // too, matching upstream's unconditional ownership transfer.
        let (payload, attachment, encoding) = if options.is_null() {
            (None, None, None)
        } else {
            // SAFETY: the caller's contract.
            unsafe {
                (
                    crate::bytes::take_payload((*options).payload),
                    crate::bytes::take_payload((*options).attachment),
                    crate::encoding::moved_encoding_hint((*options).encoding),
                )
            }
        };

        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { querier_state(querier) }) else {
            return Z_ENULL;
        };
        let mut opts = state.base.clone();
        if let Some(payload) = payload {
            opts = opts.with_payload(payload);
        }
        if let Some(encoding) = encoding {
            opts = opts.with_encoding(encoding);
        }
        if let Some(attachment) = attachment {
            opts = opts.with_attachment(attachment);
        }
        let params = if parameters.is_null() {
            None
        } else {
            // SAFETY: the caller's contract — NUL-terminated.
            Some(unsafe { CStr::from_ptr(parameters) }.to_bytes().to_vec())
        };
        issue_get(
            &state.shared,
            state.keyexpr.keyexpr.clone(),
            params,
            opts,
            closure,
        )
    })
}

/// Declare a background matching listener on a querier (zenoh-c
/// `z_querier_declare_background_matching_listener`). Consumes the moved closure
/// on every path.
///
/// The querier's listener watches for remote QUERYABLES, which is the one thing
/// that differs from the publisher's — everything below it (the cross-face OR,
/// the serialised delivery) is the shared registry path.
///
/// # Safety
/// `querier` must be null or a valid loaned querier; `callback` must be a valid
/// moved closure.
#[no_mangle]
pub unsafe extern "C" fn z_querier_declare_background_matching_listener(
    querier: *const z_loaned_querier_t,
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
        let Some(state) = (unsafe { querier_state(querier) }) else {
            return Z_ENULL;
        };
        let closure = Arc::new(cclosure);
        let id = state.shared.declare_querier_matching_listener(
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

/// `true` iff the owned querier holds a live handle (zenoh-c
/// `z_internal_querier_check`).
///
/// # Safety
/// `this_` must be null or a valid owned querier.
#[no_mangle]
pub unsafe extern "C" fn z_internal_querier_check(this_: *const z_owned_querier_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned querier (zenoh-c `z_internal_querier_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned querier.
#[no_mangle]
pub unsafe extern "C" fn z_internal_querier_null(this_: *mut z_owned_querier_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_querier_t::null_value() };
    }
}

/// Undeclare a querier (zenoh-c `z_undeclare_querier`) — which also releases
/// any matching listener it carries.
///
/// # Safety
/// `this_` must be null or a valid moved querier.
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_querier(this_: *mut z_moved_querier_t) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<QuerierState>` this crate leaked; dropping it
            // drops the `MatchingHold`, which undeclares the listener.
            drop(unsafe { Box::from_raw(handle as *mut QuerierState) });
            unsafe { (*this_)._this = z_owned_querier_t::null_value() };
        }
        Z_OK
    })
}

/// Drop a querier (zenoh-c `z_querier_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved querier.
#[no_mangle]
pub unsafe extern "C" fn z_querier_drop(this_: *mut z_moved_querier_t) {
    // SAFETY: delegated — the slot is nulled, so a double drop is a no-op.
    let _ = unsafe { z_undeclare_querier(this_) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two options structs default to what upstream's do, and both timeouts
    /// start at 0 meaning "resolve the default".
    #[test]
    fn the_querier_options_defaults_match_upstreams() {
        let mut opts = z_querier_options_t {
            target: 99,
            consolidation: z_query_consolidation_t { mode: 99 },
            congestion_control: 99,
            is_express: true,
            allowed_destination: 99,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            accept_replies: 99,
            priority: 99,
            timeout_ms: 99,
        };
        // SAFETY: live locals.
        unsafe { z_querier_options_default(&mut opts) };
        assert_eq!(opts.target, crate::get::Z_QUERY_TARGET_BEST_MATCHING);
        assert_eq!(
            opts.consolidation.mode,
            crate::get::Z_CONSOLIDATION_MODE_AUTO
        );
        assert_eq!(opts.timeout_ms, 0);

        let mut get_opts = z_querier_get_options_t {
            payload: 1 as *mut z_moved_bytes_t,
            encoding: 1 as *mut crate::abi::z_moved_encoding_t,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            source_info: 1 as *mut c_void,
            attachment: 1 as *mut z_moved_bytes_t,
        };
        // SAFETY: live locals.
        unsafe { z_querier_get_options_default(&mut get_opts) };
        assert!(get_opts.payload.is_null());
        assert!(get_opts.attachment.is_null());
    }

    /// Every export answers a NULL without dereferencing it.
    #[test]
    fn the_querier_exports_answer_null_without_dereferencing_it() {
        // SAFETY: passing NULL is exactly what these guards exist for.
        unsafe {
            assert!(!z_internal_querier_check(std::ptr::null()));
            assert_eq!(
                z_querier_get(
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut()
                ),
                Z_ENULL
            );
            assert_eq!(
                z_querier_declare_background_matching_listener(
                    std::ptr::null(),
                    std::ptr::null_mut()
                ),
                Z_ENULL
            );
            assert_eq!(z_undeclare_querier(std::ptr::null_mut()), Z_OK);
            z_querier_drop(std::ptr::null_mut());
        }
    }
}
