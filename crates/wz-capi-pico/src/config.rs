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

// --- the rest of pico's TLS key block (R311y534) ---------------------------
//
// The two constants above were added when the QUIC acceptor needed a cert, and
// they are two of TWELVE (`config.h.in:166-177`). The other ten are what the
// upstream `z_pub_tls.c` / `z_sub_tls.c` examples actually set, and the shape of
// what was missing is worth stating: every certificate value comes in a PATH
// form AND a `*_BASE64` inline form, and the stock examples default to the
// INLINE one — their CA, cert and key are base64 blobs compiled into the
// program, used unless `-C`/`-P`/`-Q`/`-R`/`-S` overrides them. So a shim that
// reads only the path forms reads none of the values a stock run supplies.
//
// The BASE64 halves decode to exactly the bytes the path halves would have read
// out of a file, so both forms resolve to the same PEM bytes at `z_open` and
// nothing downstream can tell them apart.

/// pico `Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_KEY` (config.h.in:166) — FILE PATH of the
/// trust bundle a `tls/...` dial verifies the peer's server cert against.
pub const Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_KEY: u8 = 0x4B;
/// pico `Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_BASE64_KEY` (config.h.in:167) — the same
/// trust bundle, base64-wrapped inline. What the stock examples use by default.
pub const Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_BASE64_KEY: u8 = 0x4C;
/// pico `Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_BASE64_KEY` (config.h.in:169) — inline form
/// of [`Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY`].
pub const Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_BASE64_KEY: u8 = 0x4E;
/// pico `Z_CONFIG_TLS_LISTEN_CERTIFICATE_BASE64_KEY` (config.h.in:171) — inline form
/// of [`Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY`].
pub const Z_CONFIG_TLS_LISTEN_CERTIFICATE_BASE64_KEY: u8 = 0x50;
/// pico `Z_CONFIG_TLS_ENABLE_MTLS_KEY` (config.h.in:172) — `"true"` turns on MUTUAL
/// TLS: the dialer presents a client cert, and a listener requires one.
pub const Z_CONFIG_TLS_ENABLE_MTLS_KEY: u8 = 0x51;
/// pico `Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_KEY` (config.h.in:173) — FILE PATH of the
/// private key an mTLS DIALER presents.
pub const Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_KEY: u8 = 0x52;
/// pico `Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_BASE64_KEY` (config.h.in:174) — inline form
/// of [`Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_KEY`].
pub const Z_CONFIG_TLS_CONNECT_PRIVATE_KEY_BASE64_KEY: u8 = 0x53;
/// pico `Z_CONFIG_TLS_CONNECT_CERTIFICATE_KEY` (config.h.in:175) — FILE PATH of the
/// cert chain an mTLS DIALER presents.
pub const Z_CONFIG_TLS_CONNECT_CERTIFICATE_KEY: u8 = 0x54;
/// pico `Z_CONFIG_TLS_CONNECT_CERTIFICATE_BASE64_KEY` (config.h.in:176) — inline form
/// of [`Z_CONFIG_TLS_CONNECT_CERTIFICATE_KEY`].
pub const Z_CONFIG_TLS_CONNECT_CERTIFICATE_BASE64_KEY: u8 = 0x55;
/// pico `Z_CONFIG_TLS_VERIFY_NAME_ON_CONNECT_KEY` (config.h.in:177) — `"true"`
/// requires the peer cert's SAN to match the dialed host. pico's DEFAULT is
/// `false`, and the stock examples depend on it: they dial a numeric
/// `tls/127.0.0.1:<port>` while their bundled cert names `localhost`.
pub const Z_CONFIG_TLS_VERIFY_NAME_ON_CONNECT_KEY: u8 = 0x56;

/// The boxed payload behind a `z_owned_config_t` handle.
#[derive(Clone, Default)]
pub(crate) struct ConfigState {
    pub(crate) entries: BTreeMap<u8, String>,
}

impl ConfigState {
    #[inline]
    pub(crate) fn get(&self, key: u8) -> Option<&str> {
        self.entries
            .get(&key)
            .map(|v| v.strip_suffix('\0').unwrap_or(v.as_str()))
    }

    /// Record `value` under `key`, NUL-TERMINATED in the map (R311y559).
    ///
    /// The terminator is stored rather than appended per read because
    /// [`zp_config_get`] hands the C side a `const char *` INTO this storage —
    /// upstream's contract is a borrow of the config, not a rendered copy — and
    /// a borrow can only be NUL-terminated if the stored bytes are. Every
    /// reader goes through [`Self::get`], which strips it, so the terminator is
    /// invisible to the Rust side.
    pub(crate) fn insert(&mut self, key: u8, value: &str) {
        let mut owned = String::with_capacity(value.len() + 1);
        owned.push_str(value);
        owned.push('\0');
        self.entries.insert(key, owned);
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
            Ok(s) => s,
            Err(_) => return Z_ERR_INVALID,
        };
        state.insert(key, val);
        Z_OK
    })
}

/// Read a config value by int key (pico `zp_config_get`), or NULL when unset.
///
/// R311y559 — a symbol the census found missing. The returned pointer borrows
/// the config's OWN storage, which is upstream's contract and is why the value
/// is not rendered into a temporary: a caller holds it for as long as it holds
/// the config. `ConfigState::entries` owns `String`s that are never rewritten
/// in place (`zp_config_insert` replaces the map entry), so the borrow is
/// stable for the entry's life.
///
/// The stored bytes carry the terminator, which is what makes the borrow a
/// valid C string; see [`ConfigState::insert`].
///
/// # Safety
/// `config` must be null or a live loaned config; the result must not outlive
/// it.
#[no_mangle]
pub unsafe extern "C" fn zp_config_get(config: *const z_loaned_config_t, key: u8) -> *const c_char {
    crate::ffi::guard_val(std::ptr::null(), || {
        if config.is_null() {
            return std::ptr::null();
        }
        let handle = (*config).handle;
        if handle.is_null() {
            return std::ptr::null();
        }
        let state = &*(handle as *const ConfigState);
        match state.entries.get(&key) {
            // The map's values are stored NUL-terminated (see the insert path),
            // so the pointer is a valid C string.
            Some(value) => value.as_ptr() as *const c_char,
            None => std::ptr::null(),
        }
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
