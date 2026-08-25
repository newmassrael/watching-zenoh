// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `z_view_keyexpr_*` + `z_keyexpr_as_view_string` — the keyexpr view type.
//!
//! pico `z_view_keyexpr_t` is a VIEW: it aliases the caller's `const char*`
//! (no allocation, no drop). Round 1 reproduces that borrow: the view stores
//! `{ start, len }` into the caller's NUL-terminated string, which the caller
//! must keep alive while the keyexpr is used (the pico contract). `z_put` /
//! `z_declare_*` read the borrowed UTF-8 back via [`keyexpr_str`].

use std::ffi::{c_char, c_void, CStr};

use crate::abi::{
    view_bytes, z_loaned_keyexpr_t, z_loaned_string_t, z_moved_keyexpr_t, z_owned_keyexpr_t,
    z_view_keyexpr_t, z_view_string_t,
};
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_ERR_GENERIC, Z_ERR_INVALID, Z_ERR_NULL, Z_OK};
use crate::session::{session_state, z_loaned_session_t};

/// Resolve a loaned keyexpr to its borrowed UTF-8 string, or `None` if null /
/// not valid UTF-8.
///
/// Branchless across the view / declared arms by construction: both keep the
/// literal at slots 0/1 (see [`z_loaned_keyexpr_t`]).
///
/// # Safety
/// `ke` must be a live `z_loaned_keyexpr_t` pointer (or null).
pub(crate) unsafe fn keyexpr_str<'a>(ke: *const z_loaned_keyexpr_t) -> Option<&'a str> {
    if ke.is_null() {
        return None;
    }
    let bytes = view_bytes((*ke)._start, (*ke)._len)?;
    std::str::from_utf8(bytes).ok()
}

/// The wire alias id a `z_declare_keyexpr` bound to this keyexpr, or `None`
/// when it is an undeclared view.
///
/// The publish path consults this to choose between an aliased Push (the
/// bandwidth-efficient shape a declaration exists to enable) and a literal
/// one. `0` is the "absent" encoding and is sound as such: the wire reserves
/// it, so it can never name a real declaration.
///
/// # Safety
/// `ke` must be a live `z_loaned_keyexpr_t` pointer (or null).
pub(crate) unsafe fn keyexpr_mapping(ke: *const z_loaned_keyexpr_t) -> Option<u64> {
    if ke.is_null() {
        return None;
    }
    match (*ke)._mapping {
        0 => None,
        id => Some(id as u64),
    }
}

/// Build a view keyexpr borrowing the caller's C string (pico
/// `z_view_keyexpr_from_str`). The keyexpr must be valid UTF-8; the caller
/// keeps `name` alive for the view's lifetime.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_from_str(
    keyexpr: *mut z_view_keyexpr_t,
    name: *const c_char,
) -> ZResult {
    guarded(|| {
        if keyexpr.is_null() || name.is_null() {
            return Z_ERR_NULL;
        }
        let cstr = CStr::from_ptr(name);
        // Validate UTF-8 up front; the borrowed bytes are read as `&str` later.
        if cstr.to_str().is_err() {
            return Z_ERR_INVALID;
        }
        let bytes = cstr.to_bytes();
        *keyexpr = z_view_keyexpr_t {
            _start: bytes.as_ptr(),
            _len: bytes.len(),
            _pad: [0usize; 4],
        };
        Z_OK
    })
}

/// Build a view keyexpr WITHOUT validating it (pico
/// `z_view_keyexpr_from_str_unchecked`).
///
/// Returns `void`, not a result — that is pico's signature, and it is the whole
/// point of the "unchecked" variant: the caller asserts the string is already a
/// canon keyexpr, so there is no failure to report. wz's checked
/// [`z_view_keyexpr_from_str`] validates UTF-8 and rejects; this one records the
/// borrow as given.
///
/// wz still refuses to build a view over a NULL pointer or non-UTF-8 bytes, and
/// leaves the view EMPTY in that case rather than storing a pointer it cannot
/// later read as `&str`. That is narrower than pico, which would store the
/// bytes and misbehave later, and it is deliberate: with no error channel, an
/// empty keyexpr surfaces at the next publish instead of as undefined
/// behaviour inside the library.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_from_str_unchecked(
    keyexpr: *mut z_view_keyexpr_t,
    name: *const c_char,
) {
    let _ = guarded(|| {
        if keyexpr.is_null() {
            return Z_ERR_NULL;
        }
        if name.is_null() || CStr::from_ptr(name).to_str().is_err() {
            z_view_keyexpr_empty(keyexpr);
            return Z_ERR_INVALID;
        }
        let bytes = CStr::from_ptr(name).to_bytes();
        *keyexpr = z_view_keyexpr_t {
            _start: bytes.as_ptr(),
            _len: bytes.len(),
            _pad: [0usize; 4],
        };
        Z_OK
    });
}

/// Build a view keyexpr borrowing `len` bytes of the caller's buffer (pico
/// `z_view_keyexpr_from_substr`).
///
/// The substring form exists because a keyexpr is frequently a SLICE of a
/// larger buffer a program already holds — `z_querier.c` builds
/// `demo/example/**` and then re-views a prefix of it — and copying to
/// NUL-terminate would defeat the whole point of a borrowing view.
///
/// UTF-8 is validated over exactly those `len` bytes, matching the checked
/// [`z_view_keyexpr_from_str`]: a view this crate stores must be readable as
/// `&str` at every later publish.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_from_substr(
    keyexpr: *mut z_view_keyexpr_t,
    name: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        if keyexpr.is_null() || name.is_null() {
            return Z_ERR_NULL;
        }
        let bytes = std::slice::from_raw_parts(name.cast::<u8>(), len);
        if std::str::from_utf8(bytes).is_err() {
            return Z_ERR_INVALID;
        }
        *keyexpr = z_view_keyexpr_t {
            _start: bytes.as_ptr(),
            _len: len,
            _pad: [0usize; 4],
        };
        Z_OK
    })
}

/// Build a view keyexpr over `len` bytes WITHOUT validating it (pico
/// `z_view_keyexpr_from_substr_unchecked`). Same no-error-channel contract as
/// [`z_view_keyexpr_from_str_unchecked`], including leaving the view EMPTY
/// rather than storing bytes this crate could not later read as `&str`.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_from_substr_unchecked(
    keyexpr: *mut z_view_keyexpr_t,
    name: *const c_char,
    len: usize,
) {
    let _ = guarded(|| {
        if keyexpr.is_null() {
            return Z_ERR_NULL;
        }
        if name.is_null() {
            z_view_keyexpr_empty(keyexpr);
            return Z_ERR_INVALID;
        }
        let bytes = std::slice::from_raw_parts(name.cast::<u8>(), len);
        if std::str::from_utf8(bytes).is_err() {
            z_view_keyexpr_empty(keyexpr);
            return Z_ERR_INVALID;
        }
        *keyexpr = z_view_keyexpr_t {
            _start: bytes.as_ptr(),
            _len: len,
            _pad: [0usize; 4],
        };
        Z_OK
    });
}

/// `true` iff the view keyexpr is empty (pico `z_view_keyexpr_is_empty`).
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_is_empty(keyexpr: *const z_view_keyexpr_t) -> bool {
    guard_val(true, || keyexpr.is_null() || (*keyexpr)._len == 0)
}

/// Borrow a view keyexpr immutably (pico `z_view_keyexpr_loan`).
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_loan(
    keyexpr: *const z_view_keyexpr_t,
) -> *const z_loaned_keyexpr_t {
    keyexpr as *const z_loaned_keyexpr_t
}

/// Borrow a view keyexpr mutably (pico `z_view_keyexpr_loan_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_loan_mut(
    keyexpr: *mut z_view_keyexpr_t,
) -> *mut z_loaned_keyexpr_t {
    keyexpr as *mut z_loaned_keyexpr_t
}

/// Reset a view keyexpr to empty (pico `z_view_keyexpr_empty`).
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_empty(keyexpr: *mut z_view_keyexpr_t) {
    if !keyexpr.is_null() {
        *keyexpr = z_view_keyexpr_t {
            _start: std::ptr::null(),
            _len: 0,
            _pad: [0usize; 4],
        };
    }
}

/// Expose a loaned keyexpr as a borrowed view string (pico
/// `z_keyexpr_as_view_string`). The string view aliases the keyexpr's bytes.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_as_view_string(
    keyexpr: *const z_loaned_keyexpr_t,
    string: *mut z_view_string_t,
) -> ZResult {
    guarded(|| {
        if keyexpr.is_null() || string.is_null() {
            return Z_ERR_NULL;
        }
        *string = z_view_string_t {
            _start: (*keyexpr)._start,
            _len: (*keyexpr)._len,
            _pad: [0usize; 2],
        };
        Z_OK
    })
}

/// Borrow a view string (pico `z_view_string_loan`). The loaned form is a
/// `{ start, len }` borrow, read by `z_string_data` / `z_string_len`.
#[no_mangle]
pub unsafe extern "C" fn z_view_string_loan(
    string: *const z_view_string_t,
) -> *const z_loaned_string_t {
    string as *const z_loaned_string_t
}

// --- declared keyexpr (the `z_declare_keyexpr` family) ---------------------

/// Behind a `z_owned_keyexpr_t` handle: the OWNED literal.
///
/// Owned, not borrowed, and that is the difference between this and the view
/// type. pico's `z_declare_keyexpr` produces a value that outlives the string
/// the caller built it from — upstream's `z_put.c` declares from `argv`-backed
/// storage and keeps the owned keyexpr past it — so a borrow here would be a
/// dangling read waiting for a caller that frees first.
///
/// `z_owned_keyexpr_t::_start` points into this `String`'s HEAP buffer, which
/// is stable when the `Box` moves (the same distinction `crate::bytes`
/// documents for `StringState`).
pub(crate) struct DeclaredKeyexpr {
    literal: String,
}

/// Declare a keyexpr, binding it to a numerical id on every connected peer
/// (pico `z_declare_keyexpr`).
///
/// The id is announced on every live face and REPLAYED onto faces that connect
/// later (`SharedSession::declare_keyexpr` / `face_up`), so a program that
/// declares before its first peer — which upstream's `z_put.c` does whenever it
/// wins the race — still publishes aliased to that peer.
///
/// Returns `Z_ERR_GENERIC` when the wire's `u16` alias space is exhausted.
/// Refusing beats wrapping: a reused id would silently re-point a peer's live
/// alias at a different keyexpr.
#[no_mangle]
pub unsafe extern "C" fn z_declare_keyexpr(
    zs: *const z_loaned_session_t,
    declared: *mut z_owned_keyexpr_t,
    keyexpr: *const z_loaned_keyexpr_t,
) -> ZResult {
    guarded(|| {
        if declared.is_null() {
            return Z_ERR_NULL;
        }
        let state = match session_state(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        let literal = match keyexpr_str(keyexpr) {
            Some(k) => k.to_owned(),
            None => return Z_ERR_INVALID,
        };
        let Some(mapping) = state.shared.declare_keyexpr(literal.clone()) else {
            return Z_ERR_GENERIC;
        };
        let boxed = Box::new(DeclaredKeyexpr { literal });
        // Read the heap pointer BEFORE the box is consumed by `into_raw`, and
        // note it survives that: `String`'s buffer does not move with the box.
        let start = boxed.literal.as_ptr();
        let len = boxed.literal.len();
        *declared = z_owned_keyexpr_t {
            _start: start,
            _len: len,
            _handle: Box::into_raw(boxed) as *mut c_void,
            _mapping: mapping as usize,
            _pad: [0usize; 2],
        };
        Z_OK
    })
}

/// Retract a keyexpr declaration (pico `z_undeclare_keyexpr`). Consumes the
/// moved value on every path, including the error paths — pico's
/// `z_move` contract.
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_keyexpr(
    zs: *const z_loaned_session_t,
    keyexpr: *mut z_moved_keyexpr_t,
) -> ZResult {
    guarded(|| {
        if keyexpr.is_null() {
            return Z_ERR_NULL;
        }
        // Take the value out first so the owned literal is freed and the
        // caller's struct nulled whether or not the session resolves.
        let mapping = (*keyexpr)._this._mapping;
        let handle = (*keyexpr)._this._handle;
        (*keyexpr)._this = z_owned_keyexpr_t::null_value();
        if !handle.is_null() {
            drop(Box::from_raw(handle as *mut DeclaredKeyexpr));
        }
        let state = match session_state(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        if mapping != 0 {
            state.shared.undeclare_keyexpr(mapping as u64);
        }
        Z_OK
    })
}

/// Zero an owned keyexpr in place (pico `z_internal_keyexpr_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_keyexpr_null(obj: *mut z_owned_keyexpr_t) {
    if !obj.is_null() {
        *obj = z_owned_keyexpr_t::null_value();
    }
}

/// `true` iff the owned keyexpr holds a live declaration (pico
/// `z_internal_keyexpr_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_keyexpr_check(obj: *const z_owned_keyexpr_t) -> bool {
    guard_val(false, || !obj.is_null() && !(*obj)._handle.is_null())
}

/// Borrow a declared keyexpr (pico `z_keyexpr_loan`). The owned and loaned
/// layouts share their first four slots, so this is a reinterpretation — the
/// same shape `z_view_keyexpr_loan` has.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_loan(
    obj: *const z_owned_keyexpr_t,
) -> *const z_loaned_keyexpr_t {
    obj as *const z_loaned_keyexpr_t
}

/// Borrow a declared keyexpr mutably (pico `z_keyexpr_loan_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_loan_mut(
    obj: *mut z_owned_keyexpr_t,
) -> *mut z_loaned_keyexpr_t {
    obj as *mut z_loaned_keyexpr_t
}

/// Move-cast (pico `z_keyexpr_move`) — a pure reinterpretation; the consuming
/// callee nulls the source.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_move(obj: *mut z_owned_keyexpr_t) -> *mut z_moved_keyexpr_t {
    obj as *mut z_moved_keyexpr_t
}

/// Take the value out of `src` into `dst`, leaving `src` null (pico
/// `z_keyexpr_take`).
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_take(dst: *mut z_owned_keyexpr_t, src: *mut z_moved_keyexpr_t) {
    if dst.is_null() || src.is_null() {
        return;
    }
    std::ptr::copy_nonoverlapping(&(*src)._this, dst, 1);
    (*src)._this = z_owned_keyexpr_t::null_value();
}

/// Drop a declared keyexpr (pico `z_keyexpr_drop`).
///
/// Frees the LOCAL value only; it does NOT retract the declaration from peers.
/// That asymmetry is pico's, not an omission: the retraction is what
/// [`z_undeclare_keyexpr`] is for, and it needs a session this signature does
/// not take. A drop that silently retracted would also break the `z_move`
/// contract in the other direction — the C side would lose a live alias by
/// letting a value go out of scope.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_drop(obj: *mut z_moved_keyexpr_t) {
    let _ = guarded(|| {
        if obj.is_null() {
            return Z_OK;
        }
        let handle = (*obj)._this._handle;
        if !handle.is_null() {
            drop(Box::from_raw(handle as *mut DeclaredKeyexpr));
        }
        (*obj)._this = z_owned_keyexpr_t::null_value();
        Z_OK
    });
}

// --- R311y559: the keyexpr ALGEBRA + the owned constructors -----------------
//
// Every export below is a symbol the real `libzenohpico.so` defines and this
// cdylib did not (`wz-integration-tests/tests/pico_abi_symbol_census.rs`).
//
// None of them re-derives keyexpr semantics. Canonization routes through
// `wz_runtime_tokio::keyexpr_canon::canonize_keyexpr` and the set relations
// through `wz_runtime_tokio::keyexpr_match`, which are the SSOTs the wire path
// and the R300 outbound gate already use — a second reading of the grammar
// here would be a copy that drifts from the one the wire obeys, and the
// drift would be invisible to every test that reads only this copy.

/// pico `z_keyexpr_intersection_level_t` (`api/constants.h:112-117`).
pub type z_keyexpr_intersection_level_t = std::ffi::c_int;
/// The two key expressions do not intersect.
pub const Z_KEYEXPR_INTERSECTION_LEVEL_DISJOINT: z_keyexpr_intersection_level_t = 0;
/// They intersect: some key expression is included by both.
pub const Z_KEYEXPR_INTERSECTION_LEVEL_INTERSECTS: z_keyexpr_intersection_level_t = 1;
/// The left one is a superset of the right one.
pub const Z_KEYEXPR_INTERSECTION_LEVEL_INCLUDES: z_keyexpr_intersection_level_t = 2;
/// They are equal.
pub const Z_KEYEXPR_INTERSECTION_LEVEL_EQUALS: z_keyexpr_intersection_level_t = 3;

/// Store an owned keyexpr over `literal`, replacing whatever `dst` held.
///
/// The `_start` slot points into the boxed `String`'s HEAP buffer, which is
/// what makes the borrow survive the box moving — the distinction
/// [`DeclaredKeyexpr`] documents. `_mapping` is 0, the wire's reserved
/// "no declaration" value: these constructors build a LITERAL keyexpr, not a
/// declared alias.
unsafe fn store_owned_keyexpr(dst: *mut z_owned_keyexpr_t, literal: String) {
    let boxed = Box::new(DeclaredKeyexpr { literal });
    let start = boxed.literal.as_ptr();
    let len = boxed.literal.len();
    *dst = z_owned_keyexpr_t {
        _start: start,
        _len: len,
        _handle: Box::into_raw(boxed) as *mut c_void,
        _mapping: 0,
        _pad: [0usize; 2],
    };
}

/// Build an owned keyexpr from a NUL-terminated string (pico
/// `z_keyexpr_from_str`), REJECTING a non-canon input.
///
/// Rejecting rather than repairing is upstream's split: the `_autocanonize`
/// siblings exist precisely because this one does not canonize. A constructor
/// that silently canonized would make `z_keyexpr_from_str("a//b")` succeed
/// where upstream fails, and the program would never learn its keyexpr was
/// malformed.
///
/// # Safety
/// `keyexpr` must be valid and writable; `name` must be null or a valid
/// NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_from_str(
    keyexpr: *mut z_owned_keyexpr_t,
    name: *const c_char,
) -> ZResult {
    let len = if name.is_null() {
        0
    } else {
        CStr::from_ptr(name).to_bytes().len()
    };
    z_keyexpr_from_substr(keyexpr, name, len)
}

/// Build an owned keyexpr from an explicitly-sized substring (pico
/// `z_keyexpr_from_substr`), rejecting a non-canon input.
///
/// # Safety
/// `keyexpr` must be valid and writable; `name` must be null or point at `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_from_substr(
    keyexpr: *mut z_owned_keyexpr_t,
    name: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        let Some(text) = owned_keyexpr_input(keyexpr, name, len) else {
            return Z_ERR_NULL;
        };
        // The canon CHECK, not the canon transform: equality with the canonical
        // form is exactly `_z_keyexpr_is_canon` returning OK.
        match wz_runtime_tokio::keyexpr_canon::canonize_keyexpr(&text) {
            Ok(canon) if canon.as_str() == text => {
                store_owned_keyexpr(keyexpr, text);
                Z_OK
            }
            _ => Z_ERR_INVALID,
        }
    })
}

/// Build an owned keyexpr from a NUL-terminated string, CANONIZING it first
/// (pico `z_keyexpr_from_str_autocanonize`).
///
/// # Safety
/// As [`z_keyexpr_from_str`].
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_from_str_autocanonize(
    keyexpr: *mut z_owned_keyexpr_t,
    name: *const c_char,
) -> ZResult {
    guarded(|| {
        let len = if name.is_null() {
            0
        } else {
            CStr::from_ptr(name).to_bytes().len()
        };
        let Some(text) = owned_keyexpr_input(keyexpr, name, len) else {
            return Z_ERR_NULL;
        };
        match wz_runtime_tokio::keyexpr_canon::canonize_keyexpr(&text) {
            Ok(canon) => {
                store_owned_keyexpr(keyexpr, canon.as_str().to_owned());
                Z_OK
            }
            Err(_) => Z_ERR_INVALID,
        }
    })
}

/// Build an owned keyexpr from a substring, canonizing it and writing the
/// canonical LENGTH back through `len` (pico
/// `z_keyexpr_from_substr_autocanonize`).
///
/// `len` is in/out, which is upstream's signature and not an accident:
/// canonization only ever SHRINKS a keyexpr (`$*` collapses, `*` after `**` is
/// absorbed), so the caller needs the new length to keep its own view in step.
///
/// # Safety
/// `keyexpr` must be valid and writable; `name` must be null or point at
/// `*len` readable bytes; `len` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_from_substr_autocanonize(
    keyexpr: *mut z_owned_keyexpr_t,
    name: *const c_char,
    len: *mut usize,
) -> ZResult {
    guarded(|| {
        if len.is_null() {
            return Z_ERR_NULL;
        }
        let Some(text) = owned_keyexpr_input(keyexpr, name, *len) else {
            return Z_ERR_NULL;
        };
        match wz_runtime_tokio::keyexpr_canon::canonize_keyexpr(&text) {
            Ok(canon) => {
                *len = canon.as_str().len();
                store_owned_keyexpr(keyexpr, canon.as_str().to_owned());
                Z_OK
            }
            Err(_) => Z_ERR_INVALID,
        }
    })
}

/// Null `keyexpr` and read `name[..len]` as UTF-8, or `None` on any bad input.
///
/// Shared by the four owned constructors so the "null the destination FIRST"
/// discipline cannot drift between them: a constructor that failed without
/// nulling would leave the caller's stack value looking live.
unsafe fn owned_keyexpr_input(
    keyexpr: *mut z_owned_keyexpr_t,
    name: *const c_char,
    len: usize,
) -> Option<String> {
    if keyexpr.is_null() {
        return None;
    }
    *keyexpr = z_owned_keyexpr_t::null_value();
    if name.is_null() {
        return None;
    }
    let bytes = std::slice::from_raw_parts(name as *const u8, len);
    std::str::from_utf8(bytes).ok().map(str::to_owned)
}

/// Deep-copy a keyexpr into an owned one (pico `z_keyexpr_clone`).
///
/// The clone is a LITERAL keyexpr even when the source is a declared alias:
/// `_mapping` is not copied. That is deliberate and it is the safe direction —
/// an alias id belongs to the session that declared it and to the peers that
/// were told about it, so a clone carrying the id would publish aliased on a
/// keyexpr whose declaration it does not own a reference to. The literal is
/// what every peer can resolve.
///
/// # Safety
/// `dst` must be valid and writable; `src` must be null or a live loaned
/// keyexpr.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_clone(
    dst: *mut z_owned_keyexpr_t,
    src: *const z_loaned_keyexpr_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        *dst = z_owned_keyexpr_t::null_value();
        match keyexpr_str(src) {
            Some(text) => {
                store_owned_keyexpr(dst, text.to_owned());
                Z_OK
            }
            None => Z_ERR_NULL,
        }
    })
}

/// Adopt a loaned keyexpr into an owned one (pico
/// `z_keyexpr_take_from_loaned`).
///
/// COPIES rather than moving, and empties the source. A loaned keyexpr is a
/// `{ start, len }` borrow with no transferable handle — the same reason
/// [`crate::bytes::z_string_take_from_loaned`] copies.
///
/// # Safety
/// `dst` must be valid and writable; `src` must be null or a live loaned
/// keyexpr.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_take_from_loaned(
    dst: *mut z_owned_keyexpr_t,
    src: *mut z_loaned_keyexpr_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        let rc = z_keyexpr_clone(dst, src as *const z_loaned_keyexpr_t);
        if rc == Z_OK {
            (*src)._start = std::ptr::null();
            (*src)._len = 0;
        }
        rc
    })
}

/// Append `right[..len]` to `left` and canonize (pico `z_keyexpr_concat`).
///
/// Concatenation is TEXTUAL, with no separator inserted — upstream appends the
/// bytes as given, so `concat("a/b", "c")` is `a/bc` and a caller wanting a new
/// chunk passes `"/c"`. The result is canonized because the join of two canon
/// keyexprs need not be canon (`"a/**" + "/*"` is not).
///
/// # Safety
/// `key` must be valid and writable; `left` must be null or a live loaned
/// keyexpr; `right` must be null or point at `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_concat(
    key: *mut z_owned_keyexpr_t,
    left: *const z_loaned_keyexpr_t,
    right: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        if key.is_null() {
            return Z_ERR_NULL;
        }
        *key = z_owned_keyexpr_t::null_value();
        let Some(head) = keyexpr_str(left) else {
            return Z_ERR_NULL;
        };
        let tail: &str = if right.is_null() || len == 0 {
            ""
        } else {
            match std::str::from_utf8(std::slice::from_raw_parts(right as *const u8, len)) {
                Ok(t) => t,
                Err(_) => return Z_ERR_INVALID,
            }
        };
        let joined = format!("{head}{tail}");
        match wz_runtime_tokio::keyexpr_canon::canonize_keyexpr(&joined) {
            Ok(canon) => {
                store_owned_keyexpr(key, canon.as_str().to_owned());
                Z_OK
            }
            Err(_) => Z_ERR_INVALID,
        }
    })
}

/// Join two keyexprs with a `/` and canonize (pico `z_keyexpr_join`).
///
/// # Safety
/// `key` must be valid and writable; `left` / `right` must be null or live
/// loaned keyexprs.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_join(
    key: *mut z_owned_keyexpr_t,
    left: *const z_loaned_keyexpr_t,
    right: *const z_loaned_keyexpr_t,
) -> ZResult {
    guarded(|| {
        if key.is_null() {
            return Z_ERR_NULL;
        }
        *key = z_owned_keyexpr_t::null_value();
        let (Some(l), Some(r)) = (keyexpr_str(left), keyexpr_str(right)) else {
            return Z_ERR_NULL;
        };
        let joined = format!("{l}/{r}");
        match wz_runtime_tokio::keyexpr_canon::canonize_keyexpr(&joined) {
            Ok(canon) => {
                store_owned_keyexpr(key, canon.as_str().to_owned());
                Z_OK
            }
            Err(_) => Z_ERR_INVALID,
        }
    })
}

/// Whether two keyexprs denote the same set (pico `z_keyexpr_equals`).
///
/// STRING equality on the canon forms, which is what upstream's
/// `_z_declared_keyexpr_equals` reduces to — a canon keyexpr is a normal form,
/// so two canon strings denote the same set iff they are the same string.
///
/// # Safety
/// `l` / `r` must be null or live loaned keyexprs.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_equals(
    l: *const z_loaned_keyexpr_t,
    r: *const z_loaned_keyexpr_t,
) -> bool {
    guard_val(false, || match (keyexpr_str(l), keyexpr_str(r)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    })
}

/// Whether `l`'s set CONTAINS `r`'s (pico `z_keyexpr_includes`).
///
/// # Safety
/// As [`z_keyexpr_equals`].
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_includes(
    l: *const z_loaned_keyexpr_t,
    r: *const z_loaned_keyexpr_t,
) -> bool {
    guard_val(false, || match (keyexpr_str(l), keyexpr_str(r)) {
        (Some(a), Some(b)) => {
            let a_chunks: Vec<&str> = a.split('/').collect();
            let b_chunks: Vec<&str> = b.split('/').collect();
            wz_runtime_tokio::keyexpr_match::keyexpr_includes_patterns(&a_chunks, &b_chunks)
        }
        _ => false,
    })
}

/// Whether the two sets share a member (pico `z_keyexpr_intersects`).
///
/// # Safety
/// As [`z_keyexpr_equals`].
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_intersects(
    l: *const z_loaned_keyexpr_t,
    r: *const z_loaned_keyexpr_t,
) -> bool {
    guard_val(false, || match (keyexpr_str(l), keyexpr_str(r)) {
        (Some(a), Some(b)) => {
            let a_chunks: Vec<&str> = a.split('/').collect();
            let b_chunks: Vec<&str> = b.split('/').collect();
            wz_runtime_tokio::keyexpr_match::keyexpr_intersect_patterns(&a_chunks, &b_chunks)
        }
        _ => false,
    })
}

/// The STRONGEST relation that holds between two keyexprs (pico
/// `z_keyexpr_relation_to`).
///
/// The order is upstream's own cascade (`api.c:186-195`) and it is ordered
/// strongest-first on purpose: equal keyexprs also include and intersect, so
/// testing `intersects` first would report the weakest true answer for every
/// input.
///
/// # Safety
/// As [`z_keyexpr_equals`].
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_relation_to(
    left: *const z_loaned_keyexpr_t,
    right: *const z_loaned_keyexpr_t,
) -> z_keyexpr_intersection_level_t {
    guard_val(Z_KEYEXPR_INTERSECTION_LEVEL_DISJOINT, || {
        if z_keyexpr_equals(left, right) {
            Z_KEYEXPR_INTERSECTION_LEVEL_EQUALS
        } else if z_keyexpr_includes(left, right) {
            Z_KEYEXPR_INTERSECTION_LEVEL_INCLUDES
        } else if z_keyexpr_intersects(left, right) {
            Z_KEYEXPR_INTERSECTION_LEVEL_INTERSECTS
        } else {
            Z_KEYEXPR_INTERSECTION_LEVEL_DISJOINT
        }
    })
}

/// Whether `start[..len]` is already canonical (pico `z_keyexpr_is_canon`).
///
/// `Z_OK` for canon, an error otherwise — pico returns a `z_result_t` rather
/// than a bool here, and a caller writes `if (z_keyexpr_is_canon(s, n) == 0)`.
///
/// # Safety
/// `start` must be null or point at `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_is_canon(start: *const c_char, len: usize) -> ZResult {
    guarded(|| {
        if start.is_null() {
            return Z_ERR_NULL;
        }
        let Ok(text) = std::str::from_utf8(std::slice::from_raw_parts(start as *const u8, len))
        else {
            return Z_ERR_INVALID;
        };
        match wz_runtime_tokio::keyexpr_canon::canonize_keyexpr(text) {
            Ok(canon) if canon.as_str() == text => Z_OK,
            _ => Z_ERR_INVALID,
        }
    })
}

/// Canonize `start[..*len]` IN PLACE, writing the new length back (pico
/// `z_keyexpr_canonize`).
///
/// In place is safe because canonization never grows a keyexpr — every rule
/// (`$*` -> `*`, `$*$*` -> `$*`, dropping a `*` after `**`) removes bytes or
/// keeps the count. The buffer is NOT NUL-terminated here; that is
/// [`z_keyexpr_canonize_null_terminated`]'s job, and the split is upstream's.
///
/// # Safety
/// `start` must be null or point at `*len` readable AND writable bytes; `len`
/// must be null or valid and writable.
/// wz's typed canon error as pico's `zp_keyexpr_canon_status_t`
/// (`api/constants.h:90-100`).
///
/// R311y564 — this export used to flatten every failure onto `Z_ERR_INVALID`
/// (-1), which is not a member of that enum at all: -1 is
/// `Z_KEYEXPR_CANON_LONE_DOLLAR_STAR`, a SUCCESS-shaped status describing a
/// keyexpr that merely needs rewriting. So a C program checking why its keyexpr
/// was refused was told "it contains a `$*` chunk" for an empty chunk, a stray
/// `?`, or an unbound `$`.
///
/// The mapping already existed — `layer3_keyexpr_canon.rs` has carried it since
/// R221 to compare wz's Rust canonizer against pico's status codes — so this is
/// the same table finally reaching the C ABI. Found by the dlopen differential
/// in `pico_pure_function_oracle.rs`, which compares the two libraries' EXPORTS
/// rather than wz's Rust function.
fn pico_canon_status(err: &wz_runtime_tokio::keyexpr_canon::KeyexprCanonError) -> ZResult {
    use wz_runtime_tokio::keyexpr_canon::KeyexprCanonError as E;
    match err {
        E::EmptyChunk => -4,
        E::StarsInChunk => -5,
        E::DollarAfterDollarOrStar => -6,
        E::ContainsSharpOrQmark => -7,
        E::ContainsUnboundDollar => -8,
        // A wz-side no-alloc-only variant with no pico mirror; on the AP
        // backing this crate runs on it is never produced, and a generic
        // failure is the honest answer rather than a status pico defines.
        E::ExceedsCapacity => Z_ERR_GENERIC,
    }
}

#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_canonize(start: *mut c_char, len: *mut usize) -> ZResult {
    guarded(|| {
        if start.is_null() || len.is_null() {
            return Z_ERR_NULL;
        }
        let Ok(text) = std::str::from_utf8(std::slice::from_raw_parts(start as *const u8, *len))
        else {
            return Z_ERR_INVALID;
        };
        let canon = match wz_runtime_tokio::keyexpr_canon::canonize_keyexpr(text) {
            Ok(c) => c,
            Err(err) => return pico_canon_status(&err),
        };
        let bytes = canon.as_str().as_bytes();
        debug_assert!(
            bytes.len() <= *len,
            "canonization grew a keyexpr, which the in-place contract forbids"
        );
        if bytes.len() > *len {
            return Z_ERR_GENERIC;
        }
        std::ptr::copy(bytes.as_ptr(), start as *mut u8, bytes.len());
        *len = bytes.len();
        Z_OK
    })
}

/// Canonize a NUL-terminated buffer in place, re-terminating it (pico
/// `z_keyexpr_canonize_null_terminated`).
///
/// # Safety
/// `start` must be null or a valid NUL-terminated, WRITABLE buffer.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_canonize_null_terminated(start: *mut c_char) -> ZResult {
    guarded(|| {
        if start.is_null() {
            return Z_ERR_NULL;
        }
        let mut len = CStr::from_ptr(start).to_bytes().len();
        let rc = z_keyexpr_canonize(start, &mut len);
        if rc == Z_OK {
            *start.add(len) = 0;
        }
        rc
    })
}

/// Point a view keyexpr at a NUL-terminated string, canonizing it IN PLACE
/// first (pico `z_view_keyexpr_from_str_autocanonize`).
///
/// `name` is `char *`, not `const char *`, in upstream's signature — the
/// canonization mutates the CALLER's buffer, and the view then borrows it.
/// That is why this cannot be a wrapper over the const constructor.
///
/// # Safety
/// `keyexpr` must be valid and writable; `name` must be null or a valid
/// NUL-terminated, WRITABLE buffer that outlives the view.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_from_str_autocanonize(
    keyexpr: *mut z_view_keyexpr_t,
    name: *mut c_char,
) -> ZResult {
    guarded(|| {
        if keyexpr.is_null() {
            return Z_ERR_NULL;
        }
        z_view_keyexpr_empty(keyexpr);
        let rc = z_keyexpr_canonize_null_terminated(name);
        if rc != Z_OK {
            return rc;
        }
        z_view_keyexpr_from_str(keyexpr, name)
    })
}

/// Point a view keyexpr at an explicitly-sized substring, canonizing it in
/// place and writing the new length back (pico
/// `z_view_keyexpr_from_substr_autocanonize`).
///
/// # Safety
/// `keyexpr` must be valid and writable; `name` must be null or point at
/// `*len` readable AND writable bytes that outlive the view; `len` must be
/// null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_from_substr_autocanonize(
    keyexpr: *mut z_view_keyexpr_t,
    name: *mut c_char,
    len: *mut usize,
) -> ZResult {
    guarded(|| {
        if keyexpr.is_null() || len.is_null() {
            return Z_ERR_NULL;
        }
        z_view_keyexpr_empty(keyexpr);
        let rc = z_keyexpr_canonize(name, len);
        if rc != Z_OK {
            return rc;
        }
        z_view_keyexpr_from_substr(keyexpr, name, *len)
    })
}
