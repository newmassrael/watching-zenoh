// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The liveliness plane: tokens, and subscriptions on them.
//!
//! ## Nothing below the ABI is new
//!
//! `SharedSession` already carries the token and liveliness-subscription SSOTs
//! and replays both onto every face as it comes up
//! ([`declare_liveliness_token`](wz_capi_core::faces::SharedSession::declare_liveliness_token),
//! [`declare_liveliness_subscriber`](wz_capi_core::faces::SharedSession::declare_liveliness_subscriber))
//! — built for the zenoh-pico ABI and shared. This module is the zenoh-c
//! SPELLING of that plane: different type footprints, different options structs,
//! one implementation.
//!
//! The replay is what makes upstream's `z_liveliness.c` work at all: it declares
//! a token and then sleeps, so on a listening session the declaration is recorded
//! before any peer exists and every future face announces it.
//!
//! ## Dropping a token RETRACTS it
//!
//! The retraction lives in [`TokenState`]'s `Drop`, so the explicit
//! `z_liveliness_undeclare_token` and the implicit `z_drop(z_move(token))` take
//! the identical path and cannot drift. That is upstream's contract and
//! `z_liveliness.c` depends on it — its explicit undeclare sits after an infinite
//! loop and never runs, so a drop that merely freed memory would leave every
//! subscriber believing the token is still alive.
//!
//! ## A liveliness event arrives as an ORDINARY sample
//!
//! The callback is a `z_owned_closure_sample_t`, exactly as for a data
//! subscription: a token appearing is a PUT with an EMPTY payload and one going
//! away is a DELETE. Upstream's `z_sub_liveliness.c` switches on `z_sample_kind`
//! to print "Alive"/"Dropped", which is the whole of the mapping.

use std::sync::Arc;

use wz_capi_core::faces::{SharedSession, SubId, TokenId};
use wz_runtime_tokio::declare::{LivelinessSample, LivelinessSampleKind};
use wz_runtime_tokio::session::LivelinessSubscriberOptions;

use crate::abi::{
    z_loaned_keyexpr_t, z_loaned_liveliness_token_t, z_loaned_session_t, z_moved_closure_sample_t,
    z_moved_liveliness_token_t, z_owned_closure_sample_t, z_owned_liveliness_token_t,
    z_owned_subscriber_t, z_sample_kind_t, Handle, Z_SAMPLE_KIND_DELETE, Z_SAMPLE_KIND_PUT,
};
use crate::ffi::{guard_val, guarded};
use crate::keyexpr::keyexpr_str;
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_EUNAVAILABLE, Z_OK};
use crate::sample::SampleMarshal;
use crate::sub::{subscriber_state_handle, CClosure};

/// zenoh-c `z_liveliness_token_options_t` (`zenoh_commons.h:859-861`) — a single
/// `uint8_t _dummy`, i.e. no options yet. Reproduced rather than skipped because
/// `z_liveliness_token_options_default` writes through a pointer to it and the C
/// side stack-allocates one.
#[repr(C)]
pub struct z_liveliness_token_options_t {
    /// Upstream's placeholder field. Never read.
    pub _dummy: u8,
}

/// zenoh-c `z_liveliness_subscriber_options_t` (`zenoh_commons.h:850-855`) — one
/// `bool history`: replay the state of tokens that were declared BEFORE this
/// subscription.
#[repr(C)]
pub struct z_liveliness_subscriber_options_t {
    /// Deliver the current state of already-declared tokens on subscribe.
    pub history: bool,
}

const _: () = {
    assert!(std::mem::size_of::<z_liveliness_token_options_t>() == 1);
    assert!(std::mem::size_of::<z_liveliness_subscriber_options_t>() == 1);
};

/// Behind a `z_owned_liveliness_token_t` handle: the token's id in the session's
/// SSOT.
///
/// `Drop` RETRACTS — see the module note.
struct TokenState {
    shared: Arc<SharedSession>,
    id: TokenId,
}

impl Drop for TokenState {
    fn drop(&mut self) {
        self.shared.undeclare_liveliness_token(self.id);
    }
}

/// The zenoh-c sample kind a liveliness transition maps onto.
fn liveliness_kind_of(kind: LivelinessSampleKind) -> z_sample_kind_t {
    match kind {
        LivelinessSampleKind::Put => Z_SAMPLE_KIND_PUT,
        LivelinessSampleKind::Delete => Z_SAMPLE_KIND_DELETE,
    }
}

/// Build the wz-side liveliness callback for ONE face from a shared C closure.
///
/// A liveliness sample carries no payload, so the marshal is built with an empty
/// one and no attachment; the KIND is the entire signal.
pub(crate) fn make_liveliness_callback(
    closure: Arc<CClosure>,
) -> impl for<'a> FnMut(LivelinessSample<'a>) + Send + 'static {
    move |sample: LivelinessSample<'_>| {
        let Some(call) = closure.call else {
            return;
        };
        let mut marshal = SampleMarshal::new(
            sample.keyexpr.to_owned(),
            Vec::new(),
            None,
            liveliness_kind_of(sample.kind),
        );
        // Bind AFTER the move out of `new` — see `SampleMarshal::bind`.
        marshal.bind();
        let ctx = closure.context.0;
        // SAFETY + panic discipline identical to `make_subscriber_callback`: the
        // marshal outlives the call, the borrowed sample is valid only for its
        // duration, and an unwind out of the C callback across `extern "C"` is UB
        // and would tear down the drive thread, so it is caught here.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            call(marshal.as_loaned(), ctx);
        }));
    }
}

/// Fill in the default token options (zenoh-c `z_liveliness_token_options_default`).
///
/// # Safety
/// `this_` must be null or a valid, writable options struct.
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_token_options_default(
    this_: *mut z_liveliness_token_options_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_liveliness_token_options_t { _dummy: 0 } };
    }
}

/// Fill in the default subscriber options (zenoh-c
/// `z_liveliness_subscriber_options_default`): `history = false`.
///
/// # Safety
/// `this_` must be null or a valid, writable options struct.
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_subscriber_options_default(
    this_: *mut z_liveliness_subscriber_options_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_liveliness_subscriber_options_t { history: false } };
    }
}

/// Declare a liveliness token (zenoh-c `z_liveliness_declare_token`).
///
/// # Safety
/// `session` must be a valid loaned session; `token` must be valid and writable;
/// `key_expr` must be a valid loaned keyexpr. `_options` is accepted for ABI
/// compatibility and ignored — upstream's struct has no fields.
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_declare_token(
    session: *const z_loaned_session_t,
    token: *mut z_owned_liveliness_token_t,
    key_expr: *const z_loaned_keyexpr_t,
    _options: *const z_liveliness_token_options_t,
) -> ZResult {
    guarded(|| {
        if token.is_null() {
            return Z_ENULL;
        }
        // The gravestone contract, written before any fallible work.
        unsafe { *token = z_owned_liveliness_token_t::null_value() };

        // SAFETY: the caller's contract for both handles.
        let (Some(state), Some(ke)) = (unsafe { crate::session::session_state(session) }, unsafe {
            keyexpr_str(key_expr)
        }) else {
            return Z_ENULL;
        };
        let ke = ke.to_owned();
        // The same outbound canonicity gate the data plane applies, hoisted so the
        // verdict is uniform whether or not a peer is connected yet.
        if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
            return Z_EINVAL;
        }
        let Some(id) = state.shared.declare_liveliness_token(ke) else {
            return Z_EUNAVAILABLE;
        };
        let boxed = Box::new(TokenState {
            shared: state.shared.clone(),
            id,
        });
        unsafe { *token = z_owned_liveliness_token_t::from_handle(Box::into_raw(boxed) as Handle) };
        Z_OK
    })
}

/// Retract a liveliness token (zenoh-c `z_liveliness_undeclare_token`). Consumes
/// the moved value.
///
/// # Safety
/// `this_` must be null or a valid moved token.
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_undeclare_token(
    this_: *mut z_moved_liveliness_token_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<TokenState>` this crate leaked; its `Drop` is
            // the retraction, so this is the same path `z_liveliness_token_drop`
            // takes — deliberately, so the two cannot drift.
            drop(unsafe { Box::from_raw(handle as *mut TokenState) });
            unsafe { (*this_)._this = z_owned_liveliness_token_t::null_value() };
        }
        Z_OK
    })
}

/// Drop a liveliness token (zenoh-c `z_liveliness_token_drop`) — what
/// `z_drop(z_move(token))` dispatches to. This UNDECLARES; see the module note.
///
/// # Safety
/// `this_` must be null or a valid moved token.
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_token_drop(this_: *mut z_moved_liveliness_token_t) {
    // SAFETY: the caller's contract, delegated — the slot is nulled there, so a
    // double drop is a no-op.
    let _ = unsafe { z_liveliness_undeclare_token(this_) };
}

/// Borrow a token (zenoh-c `z_liveliness_token_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned token.
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_token_loan(
    this_: *const z_owned_liveliness_token_t,
) -> *const z_loaned_liveliness_token_t {
    this_ as *const z_loaned_liveliness_token_t
}

/// `true` iff the owned token holds a live declaration (zenoh-c
/// `z_internal_liveliness_token_check`).
///
/// # Safety
/// `this_` must be null or a valid owned token.
#[no_mangle]
pub unsafe extern "C" fn z_internal_liveliness_token_check(
    this_: *const z_owned_liveliness_token_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned token (zenoh-c `z_internal_liveliness_token_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned token.
#[no_mangle]
pub unsafe extern "C" fn z_internal_liveliness_token_null(this_: *mut z_owned_liveliness_token_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_liveliness_token_t::null_value() };
    }
}

/// Declare a subscriber on liveliness tokens (zenoh-c
/// `z_liveliness_declare_subscriber`). Consumes the moved closure on every path.
///
/// # Safety
/// `session` must be a valid loaned session; `subscriber` must be valid and
/// writable; `key_expr` must be a valid loaned keyexpr; `callback` must be a
/// valid moved closure; `options` must be null or a valid options struct.
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_declare_subscriber(
    session: *const z_loaned_session_t,
    subscriber: *mut z_owned_subscriber_t,
    key_expr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut z_liveliness_subscriber_options_t,
) -> ZResult {
    guarded(|| {
        if subscriber.is_null() || callback.is_null() {
            return Z_ENULL;
        }
        unsafe { *subscriber = z_owned_subscriber_t::null_value() };

        // Consume the moved closure FIRST (consume-on-all-paths), so every early
        // return below still runs the C `drop(context)` exactly once.
        // SAFETY: the caller's contract.
        let owned = unsafe { &mut (*callback)._this };
        let cclosure = CClosure::new(owned.context, owned.call, owned.drop);
        *owned = z_owned_closure_sample_t::null_value();

        // SAFETY: the caller's contract for both handles.
        let (Some(state), Some(ke)) = (unsafe { crate::session::session_state(session) }, unsafe {
            keyexpr_str(key_expr)
        }) else {
            return Z_ENULL;
        };
        let ke = ke.to_owned();
        if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&ke).is_err() {
            return Z_EINVAL;
        }
        // A NULL options pointer is upstream's "defaults", not an error.
        let history = if options.is_null() {
            false
        } else {
            // SAFETY: the caller's contract.
            unsafe { (*options).history }
        };
        // `LivelinessSubscriberOptions` is `#[non_exhaustive]`, so it is built
        // from its default and narrowed — the shape that survives a new field.
        let mut opts = LivelinessSubscriberOptions::default();
        opts.history = history;

        let id: SubId = state.shared.declare_liveliness_subscriber(ke, opts, {
            let closure = Arc::new(cclosure);
            Arc::new(move || Box::new(make_liveliness_callback(closure.clone())) as Box<_>)
        });
        unsafe {
            *subscriber =
                z_owned_subscriber_t::from_handle(subscriber_state_handle(&state.shared, id))
        };
        Z_OK
    })
}
