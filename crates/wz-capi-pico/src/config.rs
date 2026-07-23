// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `z_config_*` / `zp_config_insert` — the pico key/value session config.
//!
//! pico's config is an int-keyed string map; the keys wz Round 1 consumes are
//! `Z_CONFIG_MODE_KEY = 0x40` (`"client"` / `"peer"`),
//! `Z_CONFIG_CONNECT_KEY = 0x41` (a dial endpoint like `tcp/127.0.0.1:7447`)
//! and `Z_CONFIG_LISTEN_KEY = 0x42` (a listen endpoint). `z_open` reads these
//! to pick the dial vs accept role. Values verified against
//! `~/zenoh-pico/include/zenoh-pico/config.h.in:84-103`.

use std::collections::BTreeMap;
use std::ffi::{c_char, c_void, CStr};

use crate::abi::{
    handle_ref, impl_value_ownership, z_loaned_config_t, z_moved_config_t, z_owned_config_t,
};
use crate::ffi::guarded;
use crate::result::{ZResult, Z_ERR_INVALID, Z_ERR_NULL, Z_OK};

/// pico `Z_CONFIG_MODE_KEY` (config.h.in:84).
pub const Z_CONFIG_MODE_KEY: u8 = 0x40;
/// pico `Z_CONFIG_CONNECT_KEY` (config.h.in:95).
pub const Z_CONFIG_CONNECT_KEY: u8 = 0x41;
/// pico `Z_CONFIG_LISTEN_KEY` (config.h.in:103).
pub const Z_CONFIG_LISTEN_KEY: u8 = 0x42;
/// pico `Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY` (config.h.in:168) — the private-key PEM
/// FILE PATH a cert-bearing listener presents. R311y406: value mirrors zenoh-pico's
/// native key. The name is zenoh's tls-block key, which zenoh reuses for quic;
/// wz-capi-pico wires it into the QUIC acceptor (it ships `transport-link-quic`, not a
/// tls acceptor), so today it keys a `quic/` listen.
pub const Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY: u8 = 0x4D;
/// pico `Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY` (config.h.in:170) — the cert-chain PEM
/// FILE PATH a cert-bearing listener presents (the peer of
/// [`Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY`]). R311y406, value mirrors zenoh-pico's.
pub const Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY: u8 = 0x4F;

/// The boxed payload behind a `z_owned_config_t` handle.
#[derive(Clone, Default)]
pub(crate) struct ConfigState {
    pub(crate) entries: BTreeMap<u8, String>,
}

impl ConfigState {
    #[inline]
    pub(crate) fn get(&self, key: u8) -> Option<&str> {
        self.entries.get(&key).map(String::as_str)
    }
}

/// Free-fn for the ownership macro.
///
/// # Safety
/// `h` must be a live `Box::into_raw::<ConfigState>` pointer.
unsafe fn free_config(h: *mut c_void) {
    drop(Box::from_raw(h as *mut ConfigState));
}

impl_value_ownership!(
    z_owned_config_t,
    z_loaned_config_t,
    z_moved_config_t,
    free_config,
    z_internal_config_null,
    z_internal_config_check,
    z_config_loan,
    z_config_loan_mut,
    z_config_move,
    z_config_take,
    z_config_drop,
    z_config_take_from_loaned
);

/// Initialise an empty default config (pico `z_config_default`).
#[no_mangle]
pub unsafe extern "C" fn z_config_default(config: *mut z_owned_config_t) -> ZResult {
    guarded(|| {
        if config.is_null() {
            return Z_ERR_NULL;
        }
        let boxed = Box::new(ConfigState::default());
        *config = z_owned_config_t {
            handle: Box::into_raw(boxed) as *mut c_void,
            _pad: [std::ptr::null_mut(); 3],
        };
        Z_OK
    })
}

/// Insert a string value under an int key (pico `zp_config_insert`).
#[no_mangle]
pub unsafe extern "C" fn zp_config_insert(
    config: *mut z_loaned_config_t,
    key: u8,
    value: *const c_char,
) -> ZResult {
    guarded(|| {
        if config.is_null() || value.is_null() {
            return Z_ERR_NULL;
        }
        let handle = (*config).handle;
        if handle.is_null() {
            return Z_ERR_NULL;
        }
        let state = &mut *(handle as *mut ConfigState);
        let val = match CStr::from_ptr(value).to_str() {
            Ok(s) => s.to_owned(),
            Err(_) => return Z_ERR_INVALID,
        };
        state.entries.insert(key, val);
        Z_OK
    })
}

/// Deep-copy a config (pico `z_config_clone`).
#[no_mangle]
pub unsafe extern "C" fn z_config_clone(
    dst: *mut z_owned_config_t,
    src: *const z_loaned_config_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        let cloned = match handle_ref::<z_loaned_config_t, ConfigState>(src) {
            Some(state) => state.clone(),
            None => return Z_ERR_NULL,
        };
        *dst = z_owned_config_t {
            handle: Box::into_raw(Box::new(cloned)) as *mut c_void,
            _pad: [std::ptr::null_mut(); 3],
        };
        Z_OK
    })
}
