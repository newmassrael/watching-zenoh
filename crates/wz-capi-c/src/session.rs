// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_open`, the session ownership family, and the config -> role mapping.
//!
//! The drive machinery is NOT here: it is
//! [`wz_capi_core::drive`](wz_capi_core::drive), shared with the zenoh-pico ABI.
//! This module is only the shim — read the config, pick a role, hand it to the
//! core, and map the core's neutral error onto zenoh-c's codes.

use std::ffi::c_void;

use wz_capi_core::drive::{open_blocking, OpenError, SessionState};
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

        match open_blocking(connect, listen, None, None, whatami) {
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
