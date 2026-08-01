// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The zenoh-c config surface `z_put.c` drives: default, from-file, and the
//! json5 key insert.
//!
//! ## What a config is here
//!
//! zenoh-c's `z_owned_config_t` is a 1960-byte INLINE struct the C side
//! stack-allocates. wz stores a handle to a [`ConfigState`] in its leading
//! pointer slot and zero-pads the rest — the C side never reads inside, it only
//! hands the struct back through `z_loan_mut` / `z_move`.
//!
//! ## The json5 values this slice understands, and the ones it refuses
//!
//! `zc_config_insert_json5` takes a json5 VALUE, and upstream's `parse_args.h`
//! passes exactly three shapes: a quoted string (`"client"`), a list of quoted
//! strings (`["tcp/127.0.0.1:7447"]`), and the bare literal `false`. This slice
//! parses those three and REFUSES anything else with
//! [`Z_EPARSE`](crate::result::Z_EPARSE) rather than storing it unparsed.
//!
//! Refusing is the load-bearing half. A config engine that silently accepted a
//! nested object would let a program believe it had configured something wz never
//! read — which is the failure mode that makes a "drop-in" claim hollow. A full
//! json5 engine is a later slice; what it must not do in the meantime is pretend.

use std::collections::BTreeMap;
use std::ffi::{c_char, CStr};

use crate::abi::{z_loaned_config_t, z_moved_config_t, z_owned_config_t, Handle};
use crate::ffi::guarded;
use crate::result::{ZResult, Z_EIO, Z_ENULL, Z_EPARSE, Z_OK};

/// zenoh-c's `mode` key (`Z_CONFIG_MODE_KEY`, `zenoh_constants.h:23`).
pub(crate) const MODE_KEY: &str = "mode";
/// `connect/endpoints` (`Z_CONFIG_CONNECT_KEY`, `:24`).
pub(crate) const CONNECT_KEY: &str = "connect/endpoints";
/// `listen/endpoints` (`Z_CONFIG_LISTEN_KEY`, `:25`).
pub(crate) const LISTEN_KEY: &str = "listen/endpoints";

/// The key/value store behind an owned config.
///
/// A `BTreeMap<String, Vec<String>>` rather than `String`: every value upstream
/// inserts is either a scalar or a LIST of endpoints, and flattening a list into
/// one string would lose the boundary the open path needs.
#[derive(Debug, Default)]
pub(crate) struct ConfigState {
    entries: BTreeMap<String, Vec<String>>,
}

impl ConfigState {
    /// The first value stored under `key`, if any.
    pub(crate) fn first(&self, key: &str) -> Option<&str> {
        self.entries.get(key).and_then(|v| v.first()).map(|s| &**s)
    }
}

/// Parse one json5 VALUE into the strings it denotes.
///
/// Returns `None` for a shape this slice does not implement — see the module
/// doc for why that is a refusal rather than a passthrough.
fn parse_json5_value(raw: &str) -> Option<Vec<String>> {
    let text = raw.trim();
    if text.is_empty() {
        return None;
    }
    // A bare literal: `false` / `true` / a number. Stored verbatim; the open path
    // reads only the keys it knows.
    if !text.starts_with('[') && !text.starts_with('"') && !text.starts_with('\'') {
        return if text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            Some(vec![text.to_owned()])
        } else {
            None
        };
    }
    // A quoted scalar.
    if let Some(inner) = unquote(text) {
        return Some(vec![inner]);
    }
    // A list of quoted scalars.
    let body = text.strip_prefix('[')?.strip_suffix(']')?.trim();
    if body.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for item in body.split(',') {
        out.push(unquote(item.trim())?);
    }
    Some(out)
}

/// Strip one matching pair of `"` or `'`, or `None` if `text` is not quoted.
fn unquote(text: &str) -> Option<String> {
    let mut chars = text.chars();
    let open = chars.next()?;
    if open != '"' && open != '\'' {
        return None;
    }
    let rest = text.get(1..)?;
    let inner = rest.strip_suffix(open)?;
    // A quote inside would mean escaping rules this slice does not implement;
    // refuse rather than mis-split.
    if inner.contains(open) {
        return None;
    }
    Some(inner.to_owned())
}

/// Install a fresh [`ConfigState`] into `out`, returning its handle slot.
fn install(out: *mut z_owned_config_t, state: ConfigState) -> Handle {
    let handle = Box::into_raw(Box::new(state)) as Handle;
    // SAFETY: the caller checked `out` for null before calling.
    unsafe { *out = z_owned_config_t::from_handle(handle) };
    handle
}

/// Borrow the state behind a loaned config.
///
/// # Safety
/// `cfg` must be null or a valid loaned config whose handle slot holds a live
/// `Box::into_raw::<ConfigState>` pointer.
pub(crate) unsafe fn config_state<'a>(cfg: *mut z_loaned_config_t) -> Option<&'a mut ConfigState> {
    if cfg.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*cfg).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: as above — a live `Box<ConfigState>` leaked as a raw pointer.
    Some(unsafe { &mut *(handle as *mut ConfigState) })
}

/// Construct the default configuration (zenoh-c `z_config_default`).
///
/// # Safety
/// `this_` must be a valid, writable `z_owned_config_t`.
#[no_mangle]
pub unsafe extern "C" fn z_config_default(this_: *mut z_owned_config_t) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        install(this_, ConfigState::default());
        Z_OK
    })
}

/// Read a configuration from a json5 FILE (zenoh-c `zc_config_from_file`).
///
/// This slice reads the file so a missing or unreadable path is reported as
/// [`Z_EIO`] exactly as upstream would, and then applies the same value parser
/// the insert path uses to any `key: value` lines it recognises. A file using
/// json5 nesting is REFUSED, not partially applied — see the module doc.
///
/// # Safety
/// `this_` must be valid and writable; `path` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn zc_config_from_file(
    this_: *mut z_owned_config_t,
    path: *const c_char,
) -> ZResult {
    guarded(|| {
        if this_.is_null() || path.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract — NUL-terminated, valid for the call.
        let Ok(path) = (unsafe { CStr::from_ptr(path) }).to_str() else {
            return Z_EPARSE;
        };
        let Ok(text) = std::fs::read_to_string(path) else {
            // The out-param is left in its gravestone state so a caller that
            // ignores the code cannot open a session on a config that was never
            // read.
            unsafe { *this_ = z_owned_config_t::null_value() };
            return Z_EIO;
        };
        let mut state = ConfigState::default();
        for line in text.lines() {
            let line = line.trim().trim_end_matches(',');
            if line.is_empty() || line.starts_with("//") || line == "{" || line == "}" {
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                return Z_EPARSE;
            };
            let key = key.trim().trim_matches(['"', '\'']).to_owned();
            let Some(values) = parse_json5_value(value) else {
                return Z_EPARSE;
            };
            state.entries.insert(key, values);
        }
        install(this_, state);
        Z_OK
    })
}

/// Insert a json5 value at `key` (zenoh-c `zc_config_insert_json5`).
///
/// # Safety
/// `this_` must be a valid loaned config; `key` and `value` must be
/// NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn zc_config_insert_json5(
    this_: *mut z_loaned_config_t,
    key: *const c_char,
    value: *const c_char,
) -> ZResult {
    guarded(|| {
        if this_.is_null() || key.is_null() || value.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract for all three pointers.
        let (Ok(key), Ok(value)) = (
            unsafe { CStr::from_ptr(key) }.to_str(),
            unsafe { CStr::from_ptr(value) }.to_str(),
        ) else {
            return Z_EPARSE;
        };
        let Some(state) = (unsafe { config_state(this_) }) else {
            return Z_ENULL;
        };
        let Some(values) = parse_json5_value(value) else {
            return Z_EPARSE;
        };
        state.entries.insert(key.to_owned(), values);
        Z_OK
    })
}

/// Borrow a config mutably (zenoh-c `z_config_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned config.
#[no_mangle]
pub unsafe extern "C" fn z_config_loan_mut(this_: *mut z_owned_config_t) -> *mut z_loaned_config_t {
    this_ as *mut z_loaned_config_t
}

/// Borrow a config immutably (zenoh-c `z_config_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned config.
#[no_mangle]
pub unsafe extern "C" fn z_config_loan(this_: *const z_owned_config_t) -> *const z_loaned_config_t {
    this_ as *const z_loaned_config_t
}

/// Free a config and reset it to its gravestone state (zenoh-c
/// `z_config_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved config whose handle is live.
#[no_mangle]
pub unsafe extern "C" fn z_config_drop(this_: *mut z_moved_config_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_)._this.handle };
    if !handle.is_null() {
        // SAFETY: a live `Box<ConfigState>` this crate leaked.
        drop(unsafe { Box::from_raw(handle as *mut ConfigState) });
        unsafe { (*this_)._this = z_owned_config_t::null_value() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quoted_scalar_parses_to_one_value() {
        assert_eq!(parse_json5_value("\"client\""), Some(vec!["client".into()]));
        assert_eq!(parse_json5_value("  'peer' "), Some(vec!["peer".into()]));
    }

    #[test]
    fn an_endpoint_list_keeps_its_items_separate() {
        // The shape upstream's parse_args.h builds for connect/listen.
        assert_eq!(
            parse_json5_value("[\"tcp/127.0.0.1:7447\",\"tcp/127.0.0.1:7448\"]"),
            Some(vec![
                "tcp/127.0.0.1:7447".into(),
                "tcp/127.0.0.1:7448".into()
            ])
        );
        assert_eq!(parse_json5_value("[]"), Some(Vec::new()));
    }

    #[test]
    fn a_bare_literal_is_kept_verbatim() {
        // `scouting/multicast/enabled` is inserted as the bare word `false`.
        assert_eq!(parse_json5_value("false"), Some(vec!["false".into()]));
    }

    /// The REFUSAL is the load-bearing half: a shape this slice cannot honour
    /// must not be stored, or a program believes it configured something wz never
    /// reads.
    #[test]
    fn an_unimplemented_shape_is_refused_rather_than_stored() {
        for raw in [
            "{nested: 1}",
            "[\"unterminated",
            "[\"a\", bare]",
            "\"unbalanced'",
            "",
        ] {
            assert_eq!(parse_json5_value(raw), None, "must refuse {raw:?}");
        }
    }
}
