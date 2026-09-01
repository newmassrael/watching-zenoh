// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The zenoh-c config surface `z_put.c` drives: default, from-file, and the
//! json5 key insert.
//!
//! ## What a config is here
//!
//! zenoh-c's `z_owned_config_t` is an INLINE struct the C side stack-allocates
//! — by far the largest of them, and its size is a pure function of upstream's
//! `Config`, so it moves whenever that type does (1.5.0 -> 1.10.0 moved it).
//! The number lives once, in [`crate::abi`]. wz stores a handle to a
//! [`ConfigState`] in its leading
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
/// `scouting/multicast/address` (`Z_CONFIG_MULTICAST_IPV4_ADDRESS_KEY`, `:30`) —
/// the group `z_scout` beacons onto.
pub(crate) const MULTICAST_LOCATOR_KEY: &str = "scouting/multicast/address";
/// `scouting/timeout` (`Z_CONFIG_SCOUTING_TIMEOUT_KEY`, `:32`).
pub(crate) const SCOUTING_TIMEOUT_KEY: &str = "scouting/timeout";
/// `id` — the session zid. NOT in `zenoh_constants.h`'s `Z_CONFIG_*` list (it is
/// a plain json5 field of zenoh's own config schema), which is why it is spelled
/// out here rather than cited to a `#define` that does not exist.
pub(crate) const SESSION_ZID_KEY: &str = "id";

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

    /// Store `values` under `key`, replacing whatever was there.
    fn insert(&mut self, key: String, values: Vec<String>) {
        self.entries.insert(key, values);
    }

    /// Render one key's value back in the json5 form the insert path accepts,
    /// or `None` when the key is absent.
    ///
    /// The round trip is the contract: a scalar renders bare and a list renders
    /// bracketed with quoted elements, so `get` of an inserted value re-inserts
    /// identically. A renderer that could not be re-parsed would make the pair
    /// of exports lossy in a way only a caller would notice.
    fn render(&self, key: &str) -> Option<String> {
        let values = self.entries.get(key)?;
        Some(render_values(values))
    }

    /// Render every entry as a json5 object.
    fn render_all(&self) -> String {
        let body: Vec<String> = self
            .entries
            .iter()
            .map(|(key, values)| format!("  \"{key}\": {}", render_values(values)))
            .collect();
        format!("{{\n{}\n}}", body.join(",\n"))
    }

    /// An independent copy — the config is a plain value, so this is a clone.
    fn deep_copy(&self) -> Self {
        Self {
            entries: self.entries.clone(),
        }
    }
}

/// Render a stored value list in the json5 form [`parse_json5_value`] accepts.
///
/// A single entry that parsed from a bare literal renders bare; anything else
/// renders as a quoted string or a bracketed list. The one-entry case cannot
/// distinguish "was a bare literal" from "was a quoted scalar" after the fact,
/// so it renders bare when the text is literal-shaped and quoted otherwise —
/// which re-parses to the same value either way.
fn render_values(values: &[String]) -> String {
    let is_bare = |text: &str| {
        text == "true"
            || text == "false"
            || (!text.is_empty()
                && text
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c == '+'))
    };
    match values {
        [one] if is_bare(one) => one.clone(),
        [one] => format!("\"{one}\""),
        many => {
            let items: Vec<String> = many.iter().map(|v| format!("\"{v}\"")).collect();
            format!("[{}]", items.join(", "))
        }
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
    // An OBJECT value, stored VERBATIM. R311y573 — found by running an upstream
    // program rather than by reading: `zc_config_insert_json5(cfg,
    // "timestamping", "{\"enabled\":{...}}")` is what `ze_publication_cache`
    // requires of its session, upstream accepts it, and this parser returned
    // `None` for it, i.e. `Z_EPARSE`. Upstream's config takes ANY JSON5 value at
    // ANY path; this parser exists to give wz's own open path a list of strings
    // for the handful of keys it reads, and it must not become a whitelist of
    // the SHAPES a caller may store. The bare-literal branch below already
    // stores verbatim on exactly that reasoning; an object is the same case with
    // a delimiter.
    //
    // The brace scan is QUOTE-AWARE, so a `}` inside a string does not close the
    // object early. A value whose braces do not balance is still rejected —
    // accepting it would turn a malformed insert into a silent success.
    if text.starts_with('{') {
        return if braces_balance(text) {
            Some(vec![text.to_owned()])
        } else {
            None
        };
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

/// Whether `text` is a brace-balanced object, ignoring braces inside strings.
///
/// Deliberately NOT a JSON5 parser: wz's open path reads a handful of known
/// keys and stores everything else verbatim, so the only question this has to
/// answer is whether the caller handed over a complete value or a truncated one.
fn braces_balance(text: &str) -> bool {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in text.chars() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    quote.is_none() && depth == 0
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

// --- R311y564: the rest of upstream's config surface ------------------------

/// Read a configuration from json5 TEXT (zenoh-c `zc_config_from_str`).
///
/// The same line-oriented parser [`zc_config_from_file`] applies, over a string
/// the caller already has. Sharing the parser is the point: a config that opens
/// a session when read from a file and refuses when read from a string would be
/// a difference no caller could predict.
///
/// # Safety
/// `this_` must be valid and writable; `s` must be null or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn zc_config_from_str(
    this_: *mut z_owned_config_t,
    s: *const c_char,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_config_t::null_value() };
        if s.is_null() {
            return Z_ENULL;
        }
        // SAFETY: as above.
        let Ok(text) = (unsafe { CStr::from_ptr(s) }).to_str() else {
            return Z_EPARSE;
        };
        // SAFETY: `this_` is valid and currently a gravestone.
        unsafe { install_parsed(this_, text) }
    })
}

/// The counted form of [`zc_config_from_str`] (zenoh-c `zc_config_from_substr`).
///
/// # Safety
/// `this_` must be valid and writable; `s` must be null or point at `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn zc_config_from_substr(
    this_: *mut z_owned_config_t,
    s: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_config_t::null_value() };
        if s.is_null() {
            return Z_ENULL;
        }
        // SAFETY: as above — `len` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(s.cast::<u8>(), len) };
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Z_EPARSE;
        };
        // SAFETY: `this_` is valid and currently a gravestone.
        unsafe { install_parsed(this_, text) }
    })
}

/// The counted form of [`zc_config_from_file`] (zenoh-c
/// `zc_config_from_file_substr`).
///
/// # Safety
/// `this_` must be valid and writable; `path` must be null or point at `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn zc_config_from_file_substr(
    this_: *mut z_owned_config_t,
    path: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_config_t::null_value() };
        if path.is_null() {
            return Z_ENULL;
        }
        // SAFETY: as above — `len` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(path.cast::<u8>(), len) };
        let Ok(path) = std::str::from_utf8(bytes) else {
            return Z_EPARSE;
        };
        let Ok(owned) = std::ffi::CString::new(path) else {
            return Z_EPARSE;
        };
        // SAFETY: `owned` is a live NUL-terminated string.
        unsafe { zc_config_from_file(this_, owned.as_ptr()) }
    })
}

/// The DEFAULT configuration read from the environment (zenoh-c
/// `zc_config_from_env`).
///
/// Upstream reads `ZENOH_CONFIG`, and falls back to the default configuration
/// when it is unset. Both halves are reproduced: an unset variable is not an
/// error, and a path that does not read IS.
///
/// # Safety
/// `this_` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn zc_config_from_env(this_: *mut z_owned_config_t) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        match std::env::var("ZENOH_CONFIG") {
            Ok(path) if !path.is_empty() => {
                let Ok(owned) = std::ffi::CString::new(path) else {
                    // SAFETY: the caller's contract.
                    unsafe { *this_ = z_owned_config_t::null_value() };
                    return Z_EPARSE;
                };
                // SAFETY: `owned` is a live NUL-terminated string.
                unsafe { zc_config_from_file(this_, owned.as_ptr()) }
            }
            // SAFETY: the caller's contract.
            _ => unsafe { z_config_default(this_) },
        }
    })
}

/// Parse `text` into a fresh state and install it, or leave the gravestone.
///
/// # Safety
/// `this_` must be valid, writable, and currently a gravestone.
unsafe fn install_parsed(this_: *mut z_owned_config_t, text: &str) -> ZResult {
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
        state.insert(key, values);
    }
    install(this_, state);
    Z_OK
}

/// Read one config value back as a string (zenoh-c `zc_config_get_from_str`).
///
/// The rendering is json5-ish and MATCHES what the insert path accepts, so a
/// `get` of an inserted value round-trips: a scalar renders bare and a list
/// renders bracketed with quoted elements.
///
/// # Safety
/// `this_` must be null or a valid loaned config; `key` must be null or
/// NUL-terminated; `out_value_string` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn zc_config_get_from_str(
    this_: *const z_loaned_config_t,
    key: *const c_char,
    out_value_string: *mut crate::abi::z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if out_value_string.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *out_value_string = crate::string::null_string() };
        if key.is_null() {
            return Z_ENULL;
        }
        // SAFETY: as above.
        let Ok(key) = (unsafe { CStr::from_ptr(key) }).to_str() else {
            return Z_EPARSE;
        };
        // SAFETY: as above.
        unsafe { get_into(this_, key, out_value_string) }
    })
}

/// The counted-key form of [`zc_config_get_from_str`] (zenoh-c
/// `zc_config_get_from_substr`).
///
/// # Safety
/// `this_` must be null or a valid loaned config; `key` must be null or point
/// at `key_len` readable bytes; `out_value_string` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn zc_config_get_from_substr(
    this_: *const z_loaned_config_t,
    key: *const c_char,
    key_len: usize,
    out_value_string: *mut crate::abi::z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if out_value_string.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *out_value_string = crate::string::null_string() };
        if key.is_null() {
            return Z_ENULL;
        }
        // SAFETY: as above — `key_len` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(key.cast::<u8>(), key_len) };
        let Ok(key) = std::str::from_utf8(bytes) else {
            return Z_EPARSE;
        };
        // SAFETY: as above.
        unsafe { get_into(this_, key, out_value_string) }
    })
}

/// The shared body of the two `get` entry points.
///
/// # Safety
/// `this_` must be null or a valid loaned config; `out` must be valid, writable
/// and currently a gravestone.
unsafe fn get_into(
    this_: *const z_loaned_config_t,
    key: &str,
    out: *mut crate::abi::z_owned_string_t,
) -> ZResult {
    // SAFETY: the caller's contract. The cast drops `const`, which is sound
    // because `config_state` only reads here — upstream types the get path
    // `const` and the insert path mutable over the same handle.
    let Some(state) = (unsafe { config_state(this_ as *mut z_loaned_config_t) }) else {
        return Z_ENULL;
    };
    let Some(rendered) = state.render(key) else {
        // Upstream distinguishes "no such key" from a bad argument; this is the
        // former, and the out-param stays a gravestone.
        return Z_EPARSE;
    };
    // SAFETY: the caller's contract.
    unsafe { *out = crate::string::owned_string_from(rendered.as_bytes()) };
    Z_OK
}

/// The counted form of [`zc_config_insert_json5`] (zenoh-c
/// `zc_config_insert_json5_from_substr`).
///
/// # Safety
/// `this_` must be null or a valid loaned config; `key` / `value` must be null
/// or point at `key_len` / `value_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn zc_config_insert_json5_from_substr(
    this_: *mut z_loaned_config_t,
    key: *const c_char,
    key_len: usize,
    value: *const c_char,
    value_len: usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() || key.is_null() || value.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract — the two counted buffers.
        let (key_bytes, value_bytes) = unsafe {
            (
                std::slice::from_raw_parts(key.cast::<u8>(), key_len),
                std::slice::from_raw_parts(value.cast::<u8>(), value_len),
            )
        };
        let (Ok(key), Ok(value)) = (
            std::str::from_utf8(key_bytes),
            std::str::from_utf8(value_bytes),
        ) else {
            return Z_EPARSE;
        };
        // SAFETY: the caller's contract for the handle.
        let Some(state) = (unsafe { config_state(this_) }) else {
            return Z_ENULL;
        };
        let Some(values) = parse_json5_value(value) else {
            return Z_EPARSE;
        };
        state.insert(key.to_owned(), values);
        Z_OK
    })
}

/// Render the whole configuration as json5 (zenoh-c `zc_config_to_string`).
///
/// # Safety
/// `config` must be null or a valid loaned config; `out_config_string` must be
/// valid and writable.
#[no_mangle]
pub unsafe extern "C" fn zc_config_to_string(
    config: *const z_loaned_config_t,
    out_config_string: *mut crate::abi::z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if out_config_string.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *out_config_string = crate::string::null_string() };
        // SAFETY: as above; see `get_into` for the `const` cast.
        let Some(state) = (unsafe { config_state(config as *mut z_loaned_config_t) }) else {
            return Z_ENULL;
        };
        // SAFETY: the caller's contract.
        unsafe {
            *out_config_string = crate::string::owned_string_from(state.render_all().as_bytes())
        };
        Z_OK
    })
}

/// Deep-copy a configuration (zenoh-c `z_config_clone`).
///
/// # Safety
/// `dst` must be valid and writable; `this_` must be null or a valid loaned
/// config.
#[no_mangle]
pub unsafe extern "C" fn z_config_clone(
    dst: *mut z_owned_config_t,
    this_: *const z_loaned_config_t,
) {
    crate::ffi::guard_val((), || {
        if dst.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *dst = z_owned_config_t::null_value() };
        // SAFETY: as above; see `get_into` for the `const` cast.
        let Some(state) = (unsafe { config_state(this_ as *mut z_loaned_config_t) }) else {
            return;
        };
        install(dst, state.deep_copy());
    });
}

/// `true` iff the owned config holds a state (zenoh-c
/// `z_internal_config_check`).
///
/// # Safety
/// `this_` must be null or a valid owned config.
#[no_mangle]
pub unsafe extern "C" fn z_internal_config_check(this_: *const z_owned_config_t) -> bool {
    crate::ffi::guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Gravestone an owned config (zenoh-c `z_internal_config_null`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_config_null(this_: *mut z_owned_config_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_config_t::null_value() };
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
    ///
    /// R311y573 MOVED `{nested: 1}` OUT of this list, and the move is a
    /// correction rather than a relaxation. The list encoded "an object is a
    /// shape this slice cannot honour"; upstream accepts an object at any config
    /// path, `ze_publication_cache` REQUIRES one (`timestamping`), and refusing
    /// it made a whole upstream family unusable on wz — measured by running the
    /// probe, not argued. A balanced object now stores VERBATIM, which is what
    /// the bare-literal branch beside it has always done; an UNBALANCED one is
    /// still refused, and that case is what keeps this test discriminating.
    #[test]
    fn an_unimplemented_shape_is_refused_rather_than_stored() {
        for raw in [
            "{unbalanced: 1",
            "nested: 1}",
            "{\"quote: \"still open\"",
            "[\"unterminated",
            "[\"a\", bare]",
            "\"unbalanced'",
            "",
        ] {
            assert_eq!(parse_json5_value(raw), None, "must refuse {raw:?}");
        }
    }

    /// R311y573 — a BALANCED object is stored verbatim, braces and all. wz's
    /// open path reads the handful of keys it knows and ignores the rest, so the
    /// parser's job is to tell a complete value from a truncated one, never to
    /// whitelist the shapes a caller may store.
    #[test]
    fn a_balanced_object_is_stored_verbatim() {
        for raw in [
            "{nested: 1}",
            "{\"enabled\":{\"router\":true,\"peer\":true,\"client\":true}}",
            // A brace INSIDE a string must not close the object early.
            "{\"body\":\"}\"}",
        ] {
            assert_eq!(
                parse_json5_value(raw),
                Some(vec![raw.to_owned()]),
                "must store {raw:?} verbatim"
            );
        }
    }
}
