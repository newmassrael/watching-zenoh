// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_open`, the session ownership family, and the config -> role mapping.
//!
//! The drive machinery is NOT here: it is
//! [`wz_capi_core::drive`](wz_capi_core::drive), shared with the zenoh-pico ABI.
//! This module is only the shim — read the config, pick a role, hand it to the
//! core, and map the core's neutral error onto zenoh-c's codes.

use std::ffi::c_void;

use wz_capi_core::drive::{open_blocking, CapiTlsConfig, OpenError, SessionState};
use wz_runtime_tokio::session_glue::WhatAmI;

use crate::abi::{
    z_loaned_session_t, z_moved_config_t, z_moved_session_t, z_owned_session_t, Handle,
};
use crate::config::{config_state, ConfigState, CONNECT_KEY, LISTEN_KEY, MODE_KEY};
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_EINVAL, Z_ENETWORK, Z_ENULL, Z_OK};

/// Read the [`SessionState`] behind a loaned session.
///
/// # Safety
/// `zs` must be null, or a valid loaned session whose handle slot holds a live
/// `Box::into_raw::<SessionState>` pointer (what [`z_open`] installs).
pub(crate) unsafe fn session_state<'a>(zs: *const z_loaned_session_t) -> Option<&'a SessionState> {
    if zs.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*zs).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: as above — a live `Box<SessionState>` this crate leaked.
    Some(unsafe { &*(handle as *const SessionState) })
}

/// zenoh-c's `mode` values map onto wz roles. Default CLIENT, matching zenoh's
/// own default when the key is absent.
fn dial_whatami(cfg: &ConfigState) -> WhatAmI {
    match cfg.first(MODE_KEY) {
        Some("peer") => WhatAmI::Peer,
        Some("router") => WhatAmI::Router,
        _ => WhatAmI::Client,
    }
}

/// Construct and open a session, consuming the moved config (zenoh-c `z_open`).
///
/// # Safety
/// `this_` must be valid and writable; `config` must be a valid moved config.
/// `_options` is accepted for ABI compatibility and ignored — zenoh-c's
/// `z_open_options_t` is a single `uint8_t _dummy` at this version.
#[no_mangle]
pub unsafe extern "C" fn z_open(
    this_: *mut z_owned_session_t,
    config: *mut z_moved_config_t,
    _options: *const c_void,
) -> ZResult {
    guarded(|| {
        if this_.is_null() || config.is_null() {
            return Z_ENULL;
        }
        // The gravestone contract, and zenoh-c states it explicitly: on failure
        // "the session will be in its gravestone state". Written BEFORE any
        // fallible work so it holds on every error path.
        unsafe { *this_ = z_owned_session_t::null_value() };

        // z_open CONSUMES the config: reclaim it and null the source, so a
        // defensive later `z_config_drop` is a safe no-op.
        let loaned = unsafe { &raw mut (*config)._this } as *mut crate::abi::z_loaned_config_t;
        let Some(cfg) = (unsafe { config_state(loaned) }) else {
            return Z_ENULL;
        };
        let connect = cfg.first(CONNECT_KEY).map(str::to_owned);
        let listen = cfg.first(LISTEN_KEY).map(str::to_owned);
        let whatami = dial_whatami(cfg);
        let handle = unsafe { (*config)._this.handle };
        // SAFETY: a live `Box<ConfigState>` this crate leaked; consumed here.
        drop(unsafe { Box::from_raw(handle as *mut ConfigState) });
        unsafe { (*config)._this = crate::abi::z_owned_config_t::null_value() };

        // A config with neither endpoint is a scouting open, which this slice
        // does not implement. Refused rather than silently opening a session
        // that reaches nothing.
        if connect.is_none() && listen.is_none() {
            return Z_EINVAL;
        }
        // Both is zenoh's dual-role peer; the core drives one role per session,
        // so refuse rather than silently dropping the listener.
        if connect.is_some() && listen.is_some() {
            return Z_EINVAL;
        }

        // R311y534 — `CapiTlsConfig::default()` is the cert-free tcp/udp/ws open,
        // which is every open this ABI currently parses: zenoh-c's config is a
        // JSON5 document whose `transport/link/tls` block this slice does not
        // read yet. The pico shim resolves its own numeric TLS keys and passes a
        // populated one; when this ABI grows the JSON path it fills the same
        // struct, which is why the parameter is typed rather than a pair of
        // `None`s that only ever meant "no quic cert".
        match open_blocking(connect, listen, CapiTlsConfig::default(), whatami) {
            Ok(state) => {
                let h = Box::into_raw(Box::new(state)) as Handle;
                unsafe { *this_ = z_owned_session_t::from_handle(h) };
                Z_OK
            }
            // The core reports a NEUTRAL failure; zenoh-c's vocabulary for "the
            // session could not be established" is Z_ENETWORK.
            Err(OpenError::DriveFailed) => Z_ENETWORK,
        }
    })
}

/// Close a session (zenoh-c `z_close`): stop the drive loop and join its thread.
/// Does not free the owned struct — that is [`z_session_drop`].
///
/// # Safety
/// `session` must be null or a valid loaned session.
#[no_mangle]
pub unsafe extern "C" fn z_close(
    session: *mut z_loaned_session_t,
    _options: *mut c_void,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated.
        match unsafe { session_state(session) } {
            Some(state) => {
                state.close();
                Z_OK
            }
            None => Z_ENULL,
        }
    })
}

/// `true` iff the owned session holds a live handle (zenoh-c
/// `z_internal_session_check`).
///
/// # Safety
/// `this_` must be null or a valid owned session.
#[no_mangle]
pub unsafe extern "C" fn z_internal_session_check(this_: *const z_owned_session_t) -> bool {
    guard_val(false, || {
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned session (zenoh-c `z_internal_session_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned session.
#[no_mangle]
pub unsafe extern "C" fn z_internal_session_null(this_: *mut z_owned_session_t) {
    if !this_.is_null() {
        unsafe { *this_ = z_owned_session_t::null_value() };
    }
}

/// Borrow a session immutably (zenoh-c `z_session_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned session.
#[no_mangle]
pub unsafe extern "C" fn z_session_loan(
    this_: *const z_owned_session_t,
) -> *const z_loaned_session_t {
    this_ as *const z_loaned_session_t
}

/// Borrow a session mutably (zenoh-c `z_session_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned session.
#[no_mangle]
pub unsafe extern "C" fn z_session_loan_mut(
    this_: *mut z_owned_session_t,
) -> *mut z_loaned_session_t {
    this_ as *mut z_loaned_session_t
}

/// Drop an owned session (zenoh-c `z_session_drop`): closes if not already, then
/// frees the [`SessionState`].
///
/// # Safety
/// `this_` must be null or a valid moved session whose handle is live.
#[no_mangle]
pub unsafe extern "C" fn z_session_drop(this_: *mut z_moved_session_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SessionState::drop runs close() (idempotent).
            // SAFETY: a live `Box<SessionState>` this crate leaked.
            drop(unsafe { Box::from_raw(handle as *mut SessionState) });
            unsafe { (*this_)._this = z_owned_session_t::null_value() };
        }
        Z_OK
    });
}

/// zenoh-c's `z_open_options_t` (`zenoh_commons.h:883-885`) — a placeholder.
///
/// Declared rather than taken as `void*` so a C program using the documented
/// shape compiles, and so the footprint gate can measure it.
#[repr(C)]
pub struct z_open_options_t {
    /// Upstream's own name for the placeholder byte.
    pub _dummy: u8,
}

/// zenoh-c's `z_close_options_t` (`zenoh_commons.h:473-491`).
///
/// FEATURE-DEPENDENT, like the publisher options: `Z_FEATURE_UNSTABLE_API`
/// replaces the placeholder byte with a close timeout and a concurrent-close
/// handle out-pointer.
#[repr(C)]
pub struct z_close_options_t {
    /// The close timeout in milliseconds; 0 means upstream's default of 10 s.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub internal_timeout_ms: u32,
    /// An optional out-pointer for a concurrent-close handle. wz closes
    /// synchronously, so a non-null request here is ACCEPTED and the handle is
    /// left untouched — a named divergence rather than a silent one, and the
    /// shape a caller who never sets it cannot observe.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub internal_out_concurrent: *mut c_void,
    /// Upstream's placeholder on the no-unstable arm.
    #[cfg(feature = "zenoh-c-no-unstable-api")]
    pub _dummy: u8,
}

/// Upstream's defaults for `z_open_options_t` (zenoh-c `z_open_options_default`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_open_options_default(this_: *mut z_open_options_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_open_options_t { _dummy: 0 } };
    }
}

/// Upstream's defaults for `z_close_options_t` (zenoh-c
/// `z_close_options_default`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_close_options_default(this_: *mut z_close_options_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = z_close_options_t {
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            internal_timeout_ms: 0,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            internal_out_concurrent: std::ptr::null_mut(),
            #[cfg(feature = "zenoh-c-no-unstable-api")]
            _dummy: 0,
        }
    };
}

// --- R311y568: the CONCURRENT-CLOSE handle family ---------------------------

/// zenoh-c `zc_owned_concurrent_close_handle_t` — 16 bytes at align 8, MEASURED
/// against the unstable oracle's header (it is declared on that arm only, which
/// is why the whole family is unstable-gated here as upstream gates it).
///
/// ## wz closes SYNCHRONOUSLY, so this handle is always a gravestone
///
/// [`z_close_options_t::internal_out_concurrent`] already records the divergence:
/// wz's close runs to completion inside `z_close`, so there is no separate task
/// to control and the out-param is left untouched. The four functions below are
/// therefore the operations on a handle that is never non-null.
///
/// That is not a stub. Upstream's contract for an uninitialised handle is that
/// `zc_internal_concurrent_close_handle_check` reads `false`, `_wait` has nothing
/// to wait for, and `_drop` is a no-op — which is exactly what a C program that
/// never set the option gets from upstream too, and exactly what it gets here
/// whether or not it set it. Their absence, by contrast, was a LINK error for any
/// program that named them.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[repr(C)]
pub struct zc_owned_concurrent_close_handle_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [u8; 8],
}

/// Moved concurrent-close handle (zenoh-c `zc_moved_concurrent_close_handle_t`).
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[repr(C)]
pub struct zc_moved_concurrent_close_handle_t {
    pub(crate) _this: zc_owned_concurrent_close_handle_t,
}

#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
const _: () = {
    assert!(std::mem::size_of::<zc_owned_concurrent_close_handle_t>() == 16);
    assert!(std::mem::align_of::<zc_owned_concurrent_close_handle_t>() == 8);
    assert!(std::mem::size_of::<zc_moved_concurrent_close_handle_t>() == 16);
};

#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
impl zc_owned_concurrent_close_handle_t {
    /// The gravestone value — the only value wz ever produces.
    pub(crate) fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [0u8; 8],
        }
    }
}

/// Wait for a concurrent close to finish (zenoh-c
/// `zc_concurrent_close_handle_wait`).
///
/// `Z_OK` on a gravestone, which is the honest answer rather than a convenient
/// one: wz's `z_close` has ALREADY completed by the time it returns, so "the
/// close this handle refers to has finished" is true. Reporting an error would
/// tell a C program its session failed to close when it did.
///
/// # Safety
/// `handle` must be null or a valid moved concurrent-close handle.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn zc_concurrent_close_handle_wait(
    handle: *mut zc_moved_concurrent_close_handle_t,
) -> crate::result::ZResult {
    // SAFETY: the caller's contract, delegated — the handle is consumed either
    // way, as a `zc_moved_*` parameter must be.
    unsafe { zc_concurrent_close_handle_drop(handle) };
    crate::result::Z_OK
}

/// Free a concurrent-close handle (zenoh-c `zc_concurrent_close_handle_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved concurrent-close handle.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn zc_concurrent_close_handle_drop(
    this_: *mut zc_moved_concurrent_close_handle_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract. Gravestoned on every path, so a
        // defensive second drop is a no-op.
        unsafe { (*this_)._this = zc_owned_concurrent_close_handle_t::null_value() };
    }
}

/// `true` iff the handle refers to a live concurrent close (zenoh-c
/// `zc_internal_concurrent_close_handle_check`).
///
/// Always `false` here — see the type's docs.
///
/// # Safety
/// `this_` must be null or a valid owned concurrent-close handle.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn zc_internal_concurrent_close_handle_check(
    this_: *const zc_owned_concurrent_close_handle_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero a concurrent-close handle (zenoh-c
/// `zc_internal_concurrent_close_handle_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned concurrent-close handle.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn zc_internal_concurrent_close_handle_null(
    this_: *mut zc_owned_concurrent_close_handle_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = zc_owned_concurrent_close_handle_t::null_value() };
    }
}

/// The last error this thread recorded, as a view string (zenoh-c
/// `zc_get_last_error`).
///
/// wz records none: every entry point in this crate reports its verdict through
/// its `z_result_t` return, and [`crate::ffi`] maps even a panic onto
/// `Z_EINVAL` rather than stashing a message. So this writes the EMPTY view,
/// which is upstream's own answer when nothing has failed.
///
/// The divergence is that a wz caller learns nothing MORE from this than the
/// return code already told them — never something different, and never a stale
/// message from an unrelated call, which is the failure mode a thread-local
/// error string has.
///
/// UNSTABLE-gated, because upstream gates it (`zenoh_commons.h:5774`).
///
/// # Safety
/// `out` must be null or valid and writable.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn zc_get_last_error(out: *mut crate::abi::z_view_string_t) {
    if !out.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *out = crate::abi::z_view_string_t::null_value() };
    }
}

/// `true` iff the session has been closed (zenoh-c `z_session_is_closed`).
///
/// R311y564 — the accessor existed on `SessionState` from the day the drive
/// loop was written, and its doc comment named this very export; only the
/// `#[no_mangle]` wrapper was missing, so a C program asking the question did
/// not link. A null or gravestoned handle reads as CLOSED, which is the safe
/// direction: there is no live session behind it.
///
/// # Safety
/// `session` must be null or a valid loaned session.
#[no_mangle]
pub unsafe extern "C" fn z_session_is_closed(session: *const z_loaned_session_t) -> bool {
    guard_val(true, || {
        // SAFETY: the caller's contract, delegated.
        unsafe { session_state(session) }.map_or(true, SessionState::is_closed)
    })
}
