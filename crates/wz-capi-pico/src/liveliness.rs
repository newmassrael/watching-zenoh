// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_liveliness_*` — the presence plane: declare a token, subscribe to tokens.
//!
//! Both halves bind to wz atoms that already exist and are ACTIVE
//! (`liveliness-token`, `liveliness-subscriber`), so nothing here is new
//! protocol; it is the C-side binding plus the per-face fan-out this crate
//! applies to every declaration.
//!
//! ## Both halves are SSOTs, for the same reason every declaration here is
//!
//! A C session is N per-face wz sessions, so a token declared before a peer
//! connects must still reach that peer, and a token declared while three peers
//! are connected must reach all three. The registry therefore records both a
//! token entry and a liveliness-subscription entry and replays them in
//! `face_up`, exactly as it does for subscriptions, queryables and keyexpr
//! aliases. Without that, a token would be visible only to whichever peers
//! happened to be connected at declare time — which for upstream's own
//! `z_liveliness.c` (declare, then sleep) is frequently none of them.
//!
//! ## Dropping a token UNDECLARES it, and that is not incidental
//!
//! pico's `z_liveliness_token_drop` runs `_z_liveliness_token_clear`, which
//! calls `_z_undeclare_liveliness_token`
//! (`vendor/zenoh-pico/src/api/liveliness.c:35-43`) — so a token going out of
//! scope is what tells subscribers the resource is gone. Upstream's
//! `z_liveliness.c` relies on it: it never calls
//! `z_liveliness_undeclare_token`, it just drops. A drop that only freed
//! memory would leave every subscriber believing the token is still alive,
//! which is the exact failure the plane exists to prevent.

use std::ffi::c_void;
use std::sync::Arc;

use wz_runtime_tokio::declare::LivelinessSampleKind;
use wz_runtime_tokio::session::LivelinessSubscriberOptions;

use crate::abi::{handle_ref, z_loaned_keyexpr_t};
use crate::faces::{SharedSession, TokenId};
use crate::ffi::{guard_val, guarded};
use crate::keyexpr::keyexpr_str;
use crate::pubsub::{
    z_moved_closure_sample_t, z_owned_closure_sample_t, z_owned_subscriber_t, CClosure,
    SubscriberState, Z_SAMPLE_KIND_DELETE, Z_SAMPLE_KIND_PUT,
};
use crate::result::{ZResult, Z_ERR_GENERIC, Z_ERR_INVALID, Z_ERR_NULL, Z_OK};
use crate::session::{session_state, z_loaned_session_t};

/// pico `z_liveliness_token_options_t` — a single `uint8_t __dummy`
/// (`api/liveliness.h:45-47`), 1 B measured. Carried for layout only; pico's
/// own default just zeroes it.
#[repr(C)]
pub struct z_liveliness_token_options_t {
    pub __dummy: u8,
}

/// pico `z_liveliness_subscriber_options_t` — `{ bool history }`
/// (`api/liveliness.h:89-91`), 1 B measured. `history` requests the peer's
/// CURRENT-state replay at declare time, which wz carries as
/// [`LivelinessSubscriberOptions::history`].
#[repr(C)]
pub struct z_liveliness_subscriber_options_t {
    pub history: bool,
}

/// Owned liveliness token (pico `z_owned_liveliness_token_t`, 24 B measured).
/// Handle in slot 0, zero-padded to pico's size — the same model every other
/// owned handle type in [`crate::abi`] uses.
#[repr(C)]
pub struct z_owned_liveliness_token_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 2],
}

/// Loaned liveliness token (pico `z_loaned_liveliness_token_t`), same layout.
#[repr(C)]
pub struct z_loaned_liveliness_token_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 2],
}

/// Moved owned token (pico `z_moved_liveliness_token_t`).
#[repr(C)]
pub struct z_moved_liveliness_token_t {
    pub(crate) _this: z_owned_liveliness_token_t,
}

impl z_owned_liveliness_token_t {
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [std::ptr::null_mut(); 2],
        }
    }
}

/// Behind a `z_owned_liveliness_token_t` handle: the registry entry to retract.
///
/// Dropping this UNDECLARES on every face, which is what makes
/// [`z_liveliness_token_drop`] notify subscribers (pico's contract, above). The
/// retraction lives in `Drop` rather than in the export so that both the
/// explicit `z_liveliness_undeclare_token` and the implicit `z_drop` take the
/// identical path — the two must not be able to diverge.
pub(crate) struct TokenState {
    shared: Arc<SharedSession>,
    id: TokenId,
}

impl Drop for TokenState {
    fn drop(&mut self) {
        self.shared.undeclare_liveliness_token(self.id);
    }
}

/// Default token options (pico `z_liveliness_token_options_default`).
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_token_options_default(
    options: *mut z_liveliness_token_options_t,
) -> ZResult {
    guarded(|| {
        if options.is_null() {
            return Z_ERR_NULL;
        }
        (*options).__dummy = 0;
        Z_OK
    })
}

/// Default liveliness-subscriber options (pico
/// `z_liveliness_subscriber_options_default`). `history = false` — future
/// events only, which is pico's default and wz's.
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_subscriber_options_default(
    options: *mut z_liveliness_subscriber_options_t,
) -> ZResult {
    guarded(|| {
        if options.is_null() {
            return Z_ERR_NULL;
        }
        (*options).history = false;
        Z_OK
    })
}

/// Declare a liveliness token (pico `z_liveliness_declare_token`).
///
/// Subscribers on an intersecting keyexpr see a PUT when the token appears and
/// a DELETE when it goes away; the DELETE half is [`z_liveliness_token_drop`].
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_declare_token(
    zs: *const z_loaned_session_t,
    token: *mut z_owned_liveliness_token_t,
    keyexpr: *const z_loaned_keyexpr_t,
    _options: *const z_liveliness_token_options_t,
) -> ZResult {
    guarded(|| {
        if token.is_null() {
            return Z_ERR_NULL;
        }
        let state = match session_state(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k.to_owned(),
            None => return Z_ERR_INVALID,
        };
        let Some(id) = state.shared.declare_liveliness_token(ke) else {
            return Z_ERR_GENERIC;
        };
        let boxed = Box::new(TokenState {
            shared: state.shared.clone(),
            id,
        });
        *token = z_owned_liveliness_token_t {
            handle: Box::into_raw(boxed) as *mut c_void,
            _pad: [std::ptr::null_mut(); 2],
        };
        Z_OK
    })
}

/// Retract a liveliness token, notifying subscribers (pico
/// `z_liveliness_undeclare_token`). Consumes the moved value.
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_undeclare_token(
    token: *mut z_moved_liveliness_token_t,
) -> ZResult {
    guarded(|| {
        if token.is_null() {
            return Z_OK;
        }
        let handle = (*token)._this.handle;
        if !handle.is_null() {
            // The retraction is `TokenState::drop`, so this is the same path
            // `z_liveliness_token_drop` takes — deliberately, so an explicit
            // undeclare and an implicit one cannot drift apart.
            drop(Box::from_raw(handle as *mut TokenState));
            (*token)._this = z_owned_liveliness_token_t::null_value();
        }
        Z_OK
    })
}

/// Zero an owned token in place (pico `z_internal_liveliness_token_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_liveliness_token_null(obj: *mut z_owned_liveliness_token_t) {
    if !obj.is_null() {
        *obj = z_owned_liveliness_token_t::null_value();
    }
}

/// `true` iff the owned token holds a live declaration (pico
/// `z_internal_liveliness_token_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_liveliness_token_check(
    obj: *const z_owned_liveliness_token_t,
) -> bool {
    guard_val(false, || !obj.is_null() && !(*obj).handle.is_null())
}

/// Borrow a token (pico `z_liveliness_token_loan`).
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_token_loan(
    obj: *const z_owned_liveliness_token_t,
) -> *const z_loaned_liveliness_token_t {
    obj as *const z_loaned_liveliness_token_t
}

/// Borrow a token mutably (pico `z_liveliness_token_loan_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_token_loan_mut(
    obj: *mut z_owned_liveliness_token_t,
) -> *mut z_loaned_liveliness_token_t {
    obj as *mut z_loaned_liveliness_token_t
}

/// Move-cast (pico `z_liveliness_token_move`).
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_token_move(
    obj: *mut z_owned_liveliness_token_t,
) -> *mut z_moved_liveliness_token_t {
    obj as *mut z_moved_liveliness_token_t
}

/// Take the value out of `src` into `dst` (pico `z_liveliness_token_take`).
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_token_take(
    dst: *mut z_owned_liveliness_token_t,
    src: *mut z_moved_liveliness_token_t,
) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst).handle = (*src)._this.handle;
    (*dst)._pad = (*src)._this._pad;
    (*src)._this = z_owned_liveliness_token_t::null_value();
}

/// Drop a liveliness token (pico `z_liveliness_token_drop`).
///
/// This UNDECLARES — see the module docs. Upstream's `z_liveliness.c` never
/// calls the explicit undeclare, so a drop that only freed memory would leave
/// every subscriber believing the token is still alive.
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_token_drop(obj: *mut z_moved_liveliness_token_t) {
    let _ = z_liveliness_undeclare_token(obj);
}

/// Declare a subscriber on liveliness tokens intersecting `keyexpr` (pico
/// `z_liveliness_declare_subscriber`). Consumes the moved closure.
///
/// The callback receives an ordinary `z_loaned_sample_t`, as pico's does: a
/// token appearing is a PUT and one going away is a DELETE, both with an EMPTY
/// payload. That mapping is not this crate's invention — wz's own
/// [`LivelinessSampleKind`] documents the same Put/Delete correspondence, and
/// upstream's `z_sub_liveliness.c` switches on `z_sample_kind` to print
/// "Alive"/"Dropped".
#[no_mangle]
pub unsafe extern "C" fn z_liveliness_declare_subscriber(
    zs: *const z_loaned_session_t,
    sub: *mut z_owned_subscriber_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut z_liveliness_subscriber_options_t,
) -> ZResult {
    guarded(|| {
        if sub.is_null() || callback.is_null() {
            return Z_ERR_NULL;
        }
        // Consume the moved closure FIRST (consume-on-all-paths), so every
        // early return below still runs the C `drop(context)`.
        let owned = &mut (*callback)._this;
        let cclosure = CClosure::new(owned.context, owned.call, owned.drop);
        *owned = z_owned_closure_sample_t::null_value();

        let state = match session_state(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        let ke = match keyexpr_str(keyexpr) {
            Some(k) => k.to_owned(),
            None => return Z_ERR_INVALID,
        };
        // A NULL options pointer is pico's "defaults", not an error.
        let history = if options.is_null() {
            false
        } else {
            (*options).history
        };
        // `LivelinessSubscriberOptions` is `#[non_exhaustive]`, so it is built
        // from its default and then narrowed — which is also the shape that
        // survives upstream adding a field.
        let mut opts = LivelinessSubscriberOptions::default();
        opts.history = history;
        let id = state
            .shared
            .declare_liveliness_subscriber(ke, opts, Arc::new(cclosure));
        let boxed = Box::new(SubscriberState {
            shared: state.shared.clone(),
            id,
        });
        *sub = z_owned_subscriber_t {
            handle: Box::into_raw(boxed) as *mut c_void,
            _pad: [std::ptr::null_mut(); 3],
        };
        Z_OK
    })
}

/// The pico sample kind for a wz liveliness event.
pub(crate) fn liveliness_kind_of(kind: LivelinessSampleKind) -> crate::pubsub::z_sample_kind_t {
    match kind {
        LivelinessSampleKind::Put => Z_SAMPLE_KIND_PUT,
        LivelinessSampleKind::Delete => Z_SAMPLE_KIND_DELETE,
    }
}

/// Read the boxed token behind a loaned handle — the accessor shape every other
/// handle type in this crate uses.
#[allow(dead_code)]
pub(crate) unsafe fn token_state<'a>(
    ptr: *const z_loaned_liveliness_token_t,
) -> Option<&'a TokenState> {
    handle_ref::<z_loaned_liveliness_token_t, TokenState>(ptr)
}
