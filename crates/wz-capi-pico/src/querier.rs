// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The QUERIER plane — pico's declared-once, get-many counterpart to the
//! publisher.
//!
//! ## Why the whole family, and why now
//!
//! Two independent measurements pointed here. Upstream's `z_get_lat.c` — the
//! canonical latency benchmark — was **five** exports from linking, all of them
//! this family. And R311y527 shipped the publisher-side matching plane whole
//! (19 exports) while leaving `z_querier_get_matching_status`,
//! `z_querier_declare_matching_listener` and its background form absent, which
//! is precisely the asymmetry `matching.rs`'s own header warns against. The
//! ranking that round used — programs blocked — could not see it, because no
//! upstream example calls the querier matching form. So the gap was a BINDING
//! gap with a working implementation underneath it
//! (`Querier::declare_matching_listener` has existed all along), invisible to
//! the measurement that opened the round.
//!
//! Both are closed here, together, because they are the same family.
//!
//! ## A querier is a keyexpr plus options, in pico and in wz alike
//!
//! pico's querier holds `(session, keyexpr, get options)` and each
//! `z_querier_get` issues a query with them. wz's `Querier` is the same three
//! fields (`wz-runtime-tokio/src/session/querier.rs`), so the C handle is that
//! triple against the face registry, and `z_querier_get` delegates to the very
//! body `z_get` uses ([`crate::get::issue_get`]). Restating the get instead of
//! sharing it would have put the `_anyke` selector normalisation and the
//! receive-side reply gate in two places, and those two must agree or a reply is
//! silently dropped.
//!
//! ## The 184-byte handle
//!
//! `z_owned_querier_t` is 184 B in pico's header — measured, not guessed — and a
//! C program stack-allocates that. wz stores one pointer and pads the rest, the
//! same handle model the rest of this crate uses; the size is what has to match,
//! not the contents, because every field is reached through an exported
//! accessor.

use std::ffi::{c_char, c_int, c_void};
use std::sync::{Arc, Mutex as StdMutex};

use wz_capi_core::faces::{MatchId, MatchingSink, SharedSession};

use crate::abi::{handle_ref, impl_handle_ownership7, z_loaned_keyexpr_t, z_moved_bytes_t};
use crate::ffi::guarded;
use crate::get::{issue_get, z_moved_closure_reply_t};
use crate::get::{
    z_consolidation_mode_t, z_query_consolidation_t, z_query_target_t, Z_CONSOLIDATION_MODE_AUTO,
    Z_QUERY_TARGET_BEST_MATCHING,
};
use crate::keyexpr::keyexpr_str;
use crate::matching::{
    consume_matching_closure, z_matching_status_t, z_moved_closure_matching_status_t,
    z_owned_matching_listener_t, MatchingListenerState,
};
use crate::query::{
    z_reply_keyexpr_t, Z_CONGESTION_CONTROL_BLOCK, Z_PRIORITY_DEFAULT,
    Z_REPLY_KEYEXPR_MATCHING_QUERY,
};
use crate::result::{ZResult, Z_ERR_INVALID, Z_ERR_NULL, Z_OK};
use crate::session::{session_state, z_loaned_session_t};

// --- options ---------------------------------------------------------------

/// pico `z_querier_options_t` (`api/types.h:266-278`), 48 B measured.
///
/// `allowed_destination` is ABSENT because the generated `config.h` has
/// `Z_FEATURE_LOCAL_QUERYABLE == 0`; every offset below was read off that
/// generated header, not off a cmake flag (the R311y466 trap), and they are
/// pinned in this module's tests.
#[repr(C)]
pub struct z_querier_options_t {
    /// Moved default encoding, or NULL. Opaque here — this crate has no
    /// encoding plane yet — but the SLOT must be 8 B or everything after it
    /// lands wrong.
    pub encoding: *mut c_void,
    pub target: z_query_target_t,
    pub consolidation: z_query_consolidation_t,
    pub congestion_control: c_int,
    pub is_express: bool,
    pub priority: c_int,
    pub timeout_ms: u64,
    pub accept_replies: z_reply_keyexpr_t,
}

/// pico `z_querier_get_options_t` (`api/types.h:290-297`), 40 B measured.
///
/// The `cancellation_token` / `source_info` tail exists because
/// `Z_FEATURE_UNSTABLE_API` is defined in the generated config. Both are read as
/// opaque pointers and IGNORED — named rather than implied: wz has no
/// cancellation-token plane, and a get issued through this path cannot be
/// cancelled by one.
#[repr(C)]
pub struct z_querier_get_options_t {
    pub payload: *mut z_moved_bytes_t,
    pub encoding: *mut c_void,
    pub attachment: *mut z_moved_bytes_t,
    pub cancellation_token: *mut c_void,
    pub source_info: *mut c_void,
}

/// Default querier options (pico `z_querier_options_default`,
/// `src/api/api.c`). Mirrors `z_get_options_default` field for field — the two
/// describe the same query, so a divergence between them would make
/// `z_querier_get` and `z_get` behave differently for the same program.
#[no_mangle]
pub unsafe extern "C" fn z_querier_options_default(options: *mut z_querier_options_t) {
    if options.is_null() {
        return;
    }
    *options = z_querier_options_t {
        encoding: std::ptr::null_mut(),
        target: Z_QUERY_TARGET_BEST_MATCHING,
        consolidation: z_query_consolidation_t {
            mode: Z_CONSOLIDATION_MODE_AUTO,
        },
        congestion_control: Z_CONGESTION_CONTROL_BLOCK,
        is_express: false,
        priority: Z_PRIORITY_DEFAULT,
        // 0 means "use the library default", never "infinite" — the same
        // convention `z_get_options_default` documents.
        timeout_ms: 0,
        accept_replies: Z_REPLY_KEYEXPR_MATCHING_QUERY,
    };
}

/// Default per-get options (pico `z_querier_get_options_default`).
#[no_mangle]
pub unsafe extern "C" fn z_querier_get_options_default(options: *mut z_querier_get_options_t) {
    if options.is_null() {
        return;
    }
    *options = z_querier_get_options_t {
        payload: std::ptr::null_mut(),
        encoding: std::ptr::null_mut(),
        attachment: std::ptr::null_mut(),
        cancellation_token: std::ptr::null_mut(),
        source_info: std::ptr::null_mut(),
    };
}

// --- handle ----------------------------------------------------------------

/// Behind a `z_owned_querier_t`: the declared keyexpr, the options every get
/// through it inherits, and the registry to fan them over.
///
/// `matches` is the same back-reference `PublisherState` carries, for the same
/// reason: the matching SSOT is keyed on the SESSION (the verdict is aggregated
/// across faces), so without it a retracted querier's C closure keeps firing.
/// See `PublisherState::record_matching_listener` for the defect that taught it.
pub(crate) struct QuerierState {
    shared: Arc<SharedSession>,
    keyexpr: String,
    /// R311y559 — the `eid` half of the global id `z_querier_id` reports,
    /// allocated once at declare. See `PublisherState::eid`.
    eid: u64,
    /// R311y559 — cached `{ start, len }` over `keyexpr` for
    /// `z_querier_keyexpr`; bound after boxing, as everywhere else here.
    loaned_keyexpr: crate::abi::z_loaned_keyexpr_t,
    target: z_query_target_t,
    consolidation: z_consolidation_mode_t,
    timeout_ms: u64,
    accept_replies: z_reply_keyexpr_t,
    /// R311y551 — the request-QoS trio declared once on the querier and
    /// inherited by every `z_querier_get`. pico's `z_querier_get_options_t`
    /// carries no QoS fields, so the per-get call has nothing to override with;
    /// this is where they have to live.
    qos: crate::get::PicoQueryQos,
    matches: StdMutex<Vec<MatchId>>,
}

impl QuerierState {
    /// Point the cached view at this state's own keyexpr, after boxing.
    pub(crate) fn bind(&mut self) {
        self.loaned_keyexpr =
            crate::abi::z_loaned_keyexpr_t::borrowed(self.keyexpr.as_ptr(), self.keyexpr.len());
    }

    /// The `eid` half of the global id `z_querier_id` reports.
    pub(crate) fn entity_id(&self) -> u64 {
        self.eid
    }

    /// The SESSION's zid — the other half of that global id.
    pub(crate) fn shared_zid(&self) -> [u8; 16] {
        self.shared.zid()
    }

    /// The cached borrow `z_querier_keyexpr` hands back.
    pub(crate) fn loaned_keyexpr(&self) -> *const crate::abi::z_loaned_keyexpr_t {
        &self.loaned_keyexpr as *const crate::abi::z_loaned_keyexpr_t
    }

    pub(crate) fn keyexpr(&self) -> &str {
        &self.keyexpr
    }

    pub(crate) fn shared_session(&self) -> Arc<SharedSession> {
        self.shared.clone()
    }

    pub(crate) fn record_matching_listener(&self, id: MatchId) {
        self.matches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(id);
    }
}

/// Retract on DROP, not inside `z_undeclare_querier`: `z_querier_drop` reaches
/// the same state through `free_querier`, and putting the retraction in only one
/// of the two exports is how the publisher-side leak happened.
impl Drop for QuerierState {
    fn drop(&mut self) {
        // The guard is a temporary of this statement, so the loop runs UNLOCKED:
        // releasing the last `MatchingSink` runs the C `drop(context)`, which is
        // entitled to re-enter the session.
        let ids = std::mem::take(
            &mut *self
                .matches
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        for id in ids {
            self.shared.undeclare_matching_listener(id);
        }
    }
}

/// Owned querier (pico `z_owned_querier_t`, 184 B measured).
#[repr(C)]
pub struct z_owned_querier_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 22],
}

/// Loaned querier (pico `z_loaned_querier_t`), same footprint.
#[repr(C)]
pub struct z_loaned_querier_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 22],
}

/// Moved querier (pico `z_moved_querier_t`).
#[repr(C)]
pub struct z_moved_querier_t {
    pub(crate) _this: z_owned_querier_t,
}

impl z_owned_querier_t {
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [std::ptr::null_mut(); 22],
        }
    }
}

/// # Safety
/// `h` must be a live `Box::into_raw::<QuerierState>` pointer.
unsafe fn free_querier(h: *mut c_void) {
    drop(Box::from_raw(h as *mut QuerierState));
}

impl_handle_ownership7!(
    z_owned_querier_t,
    z_loaned_querier_t,
    z_moved_querier_t,
    free_querier,
    z_internal_querier_null,
    z_internal_querier_check,
    z_querier_loan,
    z_querier_loan_mut,
    z_querier_move,
    z_querier_take,
    z_querier_drop
);

// --- declare / get ---------------------------------------------------------

/// Declare a querier (pico `z_declare_querier`).
///
/// Emits nothing on the wire — pico's querier is caller-side state too — so the
/// keyexpr check is hoisted here rather than left to each get: a per-get reject
/// would be swallowed by the best-effort fan and the call would report `Z_OK`.
#[no_mangle]
pub unsafe extern "C" fn z_declare_querier(
    zs: *const z_loaned_session_t,
    querier: *mut z_owned_querier_t,
    keyexpr: *const z_loaned_keyexpr_t,
    options: *mut z_querier_options_t,
) -> ZResult {
    guarded(|| {
        if querier.is_null() {
            return Z_ERR_NULL;
        }
        *querier = z_owned_querier_t::null_value();
        let state = match session_state(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k.to_owned(),
            None => return Z_ERR_INVALID,
        };
        if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
            return Z_ERR_INVALID;
        }
        // pico dereferences `options` only when non-null and otherwise takes the
        // defaults, so a null `options` is a valid default querier — which is
        // exactly what `z_get_lat.c` passes.
        let (target, consolidation, timeout_ms, accept_replies, qos) = if options.is_null() {
            (
                Z_QUERY_TARGET_BEST_MATCHING,
                Z_CONSOLIDATION_MODE_AUTO,
                0u64,
                Z_REPLY_KEYEXPR_MATCHING_QUERY,
                crate::get::PicoQueryQos::defaults(),
            )
        } else {
            (
                (*options).target,
                (*options).consolidation.mode,
                (*options).timeout_ms,
                (*options).accept_replies,
                crate::get::PicoQueryQos {
                    congestion_control: (*options).congestion_control,
                    priority: (*options).priority,
                    is_express: (*options).is_express,
                },
            )
        };
        let mut boxed = Box::new(QuerierState {
            eid: state.shared.next_entity_id(),
            shared: state.shared.clone(),
            keyexpr: ke,
            loaned_keyexpr: crate::abi::z_loaned_keyexpr_t::borrowed(std::ptr::null(), 0),
            target,
            consolidation,
            timeout_ms,
            accept_replies,
            qos,
            matches: StdMutex::new(Vec::new()),
        });
        boxed.bind();
        *querier = z_owned_querier_t {
            handle: Box::into_raw(boxed) as *mut c_void,
            _pad: [std::ptr::null_mut(); 22],
        };
        Z_OK
    })
}

/// Undeclare a querier (pico `z_undeclare_querier`).
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_querier(querier: *mut z_moved_querier_t) -> ZResult {
    guarded(|| {
        if querier.is_null() {
            return Z_OK;
        }
        let handle = (*querier)._this.handle;
        if !handle.is_null() {
            (*querier)._this = z_owned_querier_t::null_value();
            // The `Drop` impl retracts this querier's matching listeners.
            drop(Box::from_raw(handle as *mut QuerierState));
        }
        Z_OK
    })
}

/// Issue a get through a querier (pico `z_querier_get`).
#[no_mangle]
pub unsafe extern "C" fn z_querier_get(
    querier: *const z_loaned_querier_t,
    parameters: *const c_char,
    callback: *mut z_moved_closure_reply_t,
    options: *mut z_querier_get_options_t,
) -> ZResult {
    let len = if parameters.is_null() {
        0
    } else {
        std::ffi::CStr::from_ptr(parameters).to_bytes().len()
    };
    z_querier_get_with_parameters_substr(querier, parameters, len, callback, options)
}

/// Issue a get through a querier with explicitly-sized parameters (pico
/// `z_querier_get_with_parameters_substr`).
///
/// Consumes the moved closure and the moved `options->payload` /
/// `options->attachment` on EVERY path, including the failure ones — pico's
/// ownership transfer is unconditional once the call is made, and here the
/// closure's `drop(context)` IS the get's completion signal, so an early error
/// also correctly reports "this get is over".
#[no_mangle]
pub unsafe extern "C" fn z_querier_get_with_parameters_substr(
    querier: *const z_loaned_querier_t,
    parameters: *const c_char,
    parameters_len: usize,
    callback: *mut z_moved_closure_reply_t,
    options: *mut z_querier_get_options_t,
) -> ZResult {
    guarded(|| {
        // Consume the moved payload / attachment FIRST — before the
        // null-callback return, which is a path they must also be freed on. The
        // sibling `z_get` takes its bytes first for the same reason.
        let (payload, attachment) = if options.is_null() {
            (None, None)
        } else {
            (
                crate::pubsub::take_moved_bytes((*options).payload),
                crate::pubsub::take_moved_bytes((*options).attachment),
            )
        };
        if callback.is_null() {
            return Z_ERR_NULL;
        }
        let closure = crate::get::adopt_reply_closure(callback);

        let state = match handle_ref::<z_loaned_querier_t, QuerierState>(querier) {
            Some(s) => s,
            // `closure` drops here, running the caller's `drop(context)`.
            None => return Z_ERR_NULL,
        };
        let params_in: &[u8] = if parameters.is_null() || parameters_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(parameters as *const u8, parameters_len)
        };
        issue_get(
            &state.shared,
            state.keyexpr.clone(),
            params_in,
            state.target,
            state.consolidation,
            state.timeout_ms,
            state.accept_replies,
            payload,
            attachment,
            state.qos,
            closure,
        )
    })
}

// --- matching (the R311y527 asymmetry, closed) ------------------------------

/// Poll a querier's matching status (pico `z_querier_get_matching_status`):
/// `true` when ANY connected peer has a matching QUERYABLE.
///
/// The querier twin of `z_publisher_get_matching_status`, and the same
/// cross-face OR — see `SharedSession::declare_matching_listener` for why a
/// per-face pass-through would report the opposite of the truth.
#[no_mangle]
pub unsafe extern "C" fn z_querier_get_matching_status(
    querier: *const z_loaned_querier_t,
    matching_status: *mut z_matching_status_t,
) -> ZResult {
    guarded(|| {
        if matching_status.is_null() {
            return Z_ERR_NULL;
        }
        let state = match handle_ref::<z_loaned_querier_t, QuerierState>(querier) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        (*matching_status).matching = state
            .shared_session()
            .has_matching_queryable(state.keyexpr());
        Z_OK
    })
}

/// Declare a querier matching listener, handing back a handle (pico
/// `z_querier_declare_matching_listener`).
#[no_mangle]
pub unsafe extern "C" fn z_querier_declare_matching_listener(
    querier: *const z_loaned_querier_t,
    listener: *mut z_owned_matching_listener_t,
    callback: *mut z_moved_closure_matching_status_t,
) -> ZResult {
    guarded(|| match declare_querier_matching(querier, callback) {
        Ok((shared, id)) => {
            if listener.is_null() {
                // No handle slot to fill, so the watch would be unreachable:
                // retract it rather than leaving an un-undeclarable listener.
                shared.undeclare_matching_listener(id);
                return Z_ERR_NULL;
            }
            *listener = MatchingListenerState::into_handle(shared, id);
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

/// Declare a session-lifetime querier matching listener with no handle (pico
/// `z_querier_declare_background_matching_listener`).
#[no_mangle]
pub unsafe extern "C" fn z_querier_declare_background_matching_listener(
    querier: *const z_loaned_querier_t,
    callback: *mut z_moved_closure_matching_status_t,
) -> ZResult {
    guarded(|| match declare_querier_matching(querier, callback) {
        // The id is deliberately dropped: a background listener lives for the
        // session, and the registry (not a C handle) owns it from here. It is
        // still retracted when the QUERIER goes away — `QuerierState::drop`
        // holds the back-reference.
        Ok(_) => Z_OK,
        Err(code) => code,
    })
}

/// The shared body of the two querier declare forms, mirroring
/// `matching::declare_matching` on the publisher side.
unsafe fn declare_querier_matching(
    querier: *const z_loaned_querier_t,
    callback: *mut z_moved_closure_matching_status_t,
) -> Result<(Arc<SharedSession>, MatchId), ZResult> {
    // Take the closure FIRST, so an invalid querier still releases it.
    let sink: MatchingSink = consume_matching_closure(callback)?;
    let state = match handle_ref::<z_loaned_querier_t, QuerierState>(querier) {
        Some(s) => s,
        // `sink` drops here, running the caller's `drop(context)`.
        None => return Err(Z_ERR_NULL),
    };
    let shared = state.shared_session();
    let id = shared.declare_querier_matching_listener(state.keyexpr().to_owned(), sink);
    state.record_matching_listener(id);
    Ok((shared, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ABI a C program stack-allocates through pico's own header, measured
    /// against the vendored headers plus the GENERATED `config.h` (the feature
    /// switches move these numbers, so the source tree alone cannot tell you
    /// them).
    #[test]
    fn querier_abi_sizes_match_pico() {
        assert_eq!(std::mem::size_of::<z_owned_querier_t>(), 184);
        assert_eq!(std::mem::size_of::<z_loaned_querier_t>(), 184);
        assert_eq!(std::mem::size_of::<z_moved_querier_t>(), 184);
        assert_eq!(std::mem::size_of::<z_querier_options_t>(), 48);
        assert_eq!(std::mem::size_of::<z_querier_get_options_t>(), 40);
    }

    /// Every offset in `z_querier_options_t`, because a C caller fills this
    /// struct field by field through pico's header and a slip is silent.
    #[test]
    fn querier_options_offsets_match_pico() {
        let o = z_querier_options_t {
            encoding: std::ptr::null_mut(),
            target: 0,
            consolidation: z_query_consolidation_t { mode: 0 },
            congestion_control: 0,
            is_express: false,
            priority: 0,
            timeout_ms: 0,
            accept_replies: 0,
        };
        let base = &o as *const _ as usize;
        assert_eq!(&o.encoding as *const _ as usize - base, 0);
        assert_eq!(&o.target as *const _ as usize - base, 8);
        assert_eq!(&o.consolidation as *const _ as usize - base, 12);
        assert_eq!(&o.congestion_control as *const _ as usize - base, 16);
        assert_eq!(&o.is_express as *const _ as usize - base, 20);
        assert_eq!(&o.priority as *const _ as usize - base, 24);
        assert_eq!(&o.timeout_ms as *const _ as usize - base, 32);
        assert_eq!(&o.accept_replies as *const _ as usize - base, 40);
    }

    /// A defaulted querier must describe the SAME query a defaulted `z_get`
    /// does. They are two spellings of one operation, so a divergence here
    /// would make `z_querier_get` and `z_get` behave differently for a program
    /// that defaulted both.
    #[test]
    fn querier_defaults_agree_with_get_defaults() {
        let mut q = z_querier_options_t {
            encoding: std::ptr::null_mut(),
            target: 99,
            consolidation: z_query_consolidation_t { mode: 99 },
            congestion_control: 99,
            is_express: true,
            priority: 99,
            timeout_ms: 99,
            accept_replies: 99,
        };
        let mut g: crate::get::z_get_options_t = unsafe { std::mem::zeroed() };
        unsafe {
            z_querier_options_default(&mut q);
            crate::get::z_get_options_default(&mut g);
        }
        assert_eq!(q.target, g.target);
        assert_eq!(q.consolidation.mode, g.consolidation.mode);
        assert_eq!(q.congestion_control, g.congestion_control);
        assert_eq!(q.is_express, g.is_express);
        assert_eq!(q.priority, g.priority);
        assert_eq!(q.timeout_ms, g.timeout_ms);
        assert_eq!(q.accept_replies, g.accept_replies);
    }
}
