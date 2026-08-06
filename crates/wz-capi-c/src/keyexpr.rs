// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The VIEW keyexpr — a keyexpr that borrows the caller's string.
//!
//! zenoh-c's `z_view_keyexpr_from_str` ALIASES the `const char*` it is given
//! rather than copying it, and upstream's `z_put.c` relies on that: the string it
//! passes is `args.keyexpr`, which outlives the put. wz stores an owned copy
//! behind the handle instead, which is a strict superset of the contract (a
//! caller whose string dies early is served correctly here and would be a
//! use-after-free upstream) and costs one allocation per view.
//!
//! The divergence is recorded rather than hidden because it is observable in one
//! direction: a program that mutates its buffer AFTER constructing the view and
//! expects the put to see the new bytes gets the OLD bytes here. Upstream's
//! examples do not do that, and a copy is the safe direction to differ in.

use std::ffi::{c_char, CStr};

use crate::abi::{
    z_loaned_keyexpr_t, z_moved_keyexpr_t, z_owned_keyexpr_t, z_view_keyexpr_t, Handle,
};
use crate::ffi::guarded;
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_EPARSE, Z_OK};

/// The owned copy behind a keyexpr handle — view, owned or declared.
///
/// One state type for all three shapes, because they differ in OWNERSHIP rather
/// than in content: a view is never freed by this crate's drop path, an owned
/// keyexpr is, and a declared one additionally carries the wire alias its
/// `z_declare_keyexpr` bound.
pub(crate) struct KeyexprState {
    pub(crate) keyexpr: String,
    /// The wire alias id a [`z_declare_keyexpr`] bound to this keyexpr, or
    /// `None` for an undeclared view.
    ///
    /// The publish path consults it to choose between an aliased Push — the
    /// bandwidth saving a declaration exists to enable — and a literal one.
    pub(crate) mapping: Option<u64>,
}

impl KeyexprState {
    /// An UNDECLARED keyexpr: a literal with no wire alias behind it.
    pub(crate) fn new(keyexpr: String) -> Self {
        Self {
            keyexpr,
            mapping: None,
        }
    }
}

/// R311y568 — the keyexpr a DECLARATION was made under, plus the loaned view its
/// accessor hands back.
///
/// `z_subscriber_keyexpr` / `z_queryable_keyexpr` / `z_querier_keyexpr` all
/// answer the same question — "what did I declare?" — and all three need the
/// same two things: the state, and a `z_loaned_keyexpr_t` VALUE whose address
/// they can return. Writing that pair into three declaration-state structs
/// would be three copies of the bind discipline
/// ([`crate::sample::SampleMarshal::bind`]'s: never bind before the final
/// address), which is the shape that gets one of them wrong.
///
/// Held by value inside a BOXED declaration state, so the address it hands out
/// lives exactly as long as the declaration — which is upstream's contract for
/// these accessors (the borrow is valid while the subscriber / queryable /
/// querier is).
pub(crate) struct DeclaredKeyexpr {
    state: KeyexprState,
    loaned: z_loaned_keyexpr_t,
}

impl DeclaredKeyexpr {
    /// Build it UNBOUND. [`Self::bind`] must run once the owner is boxed.
    pub(crate) fn new(keyexpr: String) -> Self {
        Self {
            state: KeyexprState::new(keyexpr),
            loaned: z_loaned_keyexpr_t::null_value(),
        }
    }

    /// Aim the cached view at this value's own state. MUST run only once the
    /// owner sits at its FINAL address.
    pub(crate) fn bind(&mut self) {
        self.loaned = z_loaned_keyexpr_t::from_handle(
            &self.state as *const KeyexprState as *mut std::ffi::c_void,
        );
    }

    /// The keyexpr LITERAL, for the wire paths that publish against it.
    ///
    /// One holder rather than two: a declaration that kept its own `String`
    /// beside this value could answer the accessor with a keyexpr it does not
    /// actually use.
    pub(crate) fn literal(&self) -> &str {
        &self.state.keyexpr
    }

    /// The borrowed keyexpr an accessor returns, or NULL if [`Self::bind`] has
    /// not run — a null rather than a dangling pointer, so a missed bind is a
    /// visible NULL instead of a use-after-free.
    pub(crate) fn as_loaned(&self) -> *const z_loaned_keyexpr_t {
        if self.loaned.handle.is_null() {
            return std::ptr::null();
        }
        &self.loaned as *const z_loaned_keyexpr_t
    }
}

/// Read the keyexpr behind a loaned handle.
///
/// # Safety
/// `ke` must be null or a valid loaned keyexpr whose handle is live.
pub(crate) unsafe fn keyexpr_str<'a>(ke: *const z_loaned_keyexpr_t) -> Option<&'a str> {
    if ke.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*ke).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<KeyexprState>` this crate leaked.
    Some(&unsafe { &*(handle as *const KeyexprState) }.keyexpr)
}

/// Construct a view keyexpr from a NUL-terminated string (zenoh-c
/// `z_view_keyexpr_from_str`).
///
/// # Safety
/// `this_` must be valid and writable; `expr` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_from_str(
    this_: *mut z_view_keyexpr_t,
    expr: *const c_char,
) -> ZResult {
    guarded(|| {
        if this_.is_null() || expr.is_null() {
            return Z_ENULL;
        }
        // Always initialise the out-param before any fallible work, so a caller
        // that ignores the code sees a gravestone rather than a stale stack value.
        unsafe { *this_ = z_view_keyexpr_t::null_value() };
        // SAFETY: the caller's contract.
        let Ok(text) = (unsafe { CStr::from_ptr(expr) }).to_str() else {
            return Z_EINVAL;
        };
        // R311y564 — the CHECKED constructor REFUSES a non-canonical keyexpr,
        // which is what upstream does: the real `libzenohc.so` answers -1 for
        // `home/**/*/x` and for `home/$*/x` as well as for `home//x`. The
        // `_unchecked` sibling exists precisely because this one refuses, so
        // accepting everything here made the pair meaningless.
        if let Err(code) = require_canonical(text) {
            return code;
        }
        let handle = Box::into_raw(Box::new(KeyexprState::new(text.to_owned()))) as Handle;
        unsafe { *this_ = z_view_keyexpr_t::from_handle(handle) };
        Z_OK
    })
}

/// Borrow a view keyexpr (zenoh-c `z_view_keyexpr_loan`).
///
/// # Safety
/// `this_` must be null or a valid view keyexpr.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_loan(
    this_: *const z_view_keyexpr_t,
) -> *const z_loaned_keyexpr_t {
    this_ as *const z_loaned_keyexpr_t
}

/// Construct a view keyexpr WITHOUT canonicity validation (zenoh-c
/// `z_view_keyexpr_from_str_unchecked`).
///
/// Upstream returns `void`: the whole point of the export is that the caller has
/// asserted the string is already canonical, so there is no verdict to report.
/// `z_pong.c` uses it for its compile-time literal.
///
/// wz still refuses a NULL or non-UTF-8 pointer, because those are not "skipped
/// validation" but an unreadable argument — there is no keyexpr to alias at all.
/// The out-param is left in its gravestone state on that path, which is what a
/// caller's later `z_loan` reads as invalid.
///
/// # Safety
/// `this_` must be null or valid and writable; `s` must be null or
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_from_str_unchecked(
    this_: *mut z_view_keyexpr_t,
    s: *const c_char,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe { *this_ = z_view_keyexpr_t::null_value() };
    if s.is_null() {
        return;
    }
    // SAFETY: as above. NOT delegated to the checked constructor any more:
    // since R311y564 that one REFUSES a non-canonical keyexpr, and the whole
    // contract of this export is that the caller has already asserted
    // canonicity and wants no verdict.
    let Ok(text) = (unsafe { CStr::from_ptr(s) }).to_str() else {
        return;
    };
    let handle = Box::into_raw(Box::new(KeyexprState::new(text.to_owned()))) as Handle;
    // SAFETY: the slot was gravestoned above.
    unsafe { *this_ = z_view_keyexpr_t::from_handle(handle) };
}

/// Construct a view keyexpr from a pointer plus LENGTH (zenoh-c
/// `z_view_keyexpr_from_substr`).
///
/// The length form rather than the NUL-terminated one, which `z_get.c` uses to
/// take a keyexpr out of the middle of a `keyexpr?parameters` selector its own
/// argument parser split — so the source bytes are NOT terminated at `len` and
/// reading them as a C string would swallow the parameters.
///
/// # Safety
/// `this_` must be valid and writable; `expr` must be null or point at `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_from_substr(
    this_: *mut z_view_keyexpr_t,
    expr: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() || expr.is_null() {
            return Z_ENULL;
        }
        // The gravestone before any fallible work.
        unsafe { *this_ = z_view_keyexpr_t::null_value() };
        // SAFETY: the caller's contract — `len` readable bytes at `expr`.
        let bytes = unsafe { std::slice::from_raw_parts(expr as *const u8, len) };
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Z_EINVAL;
        };
        if let Err(code) = require_canonical(text) {
            return code;
        }
        let handle = Box::into_raw(Box::new(KeyexprState::new(text.to_owned()))) as Handle;
        unsafe { *this_ = z_view_keyexpr_t::from_handle(handle) };
        Z_OK
    })
}

/// `true` iff the two keyexprs INTERSECT (zenoh-c `z_keyexpr_intersects`).
///
/// Intersection, not inclusion and not equality: `z_storage.c` uses it to decide
/// which of its stored keys a wildcard query covers, so `demo/**` must intersect
/// `demo/a` in BOTH argument orders. Routed through the one matching SSOT
/// ([`wz_runtime_tokio::keyexpr_match`]) that the reply gate uses, rather than
/// re-derived.
///
/// # Safety
/// `left` and `right` must be null or valid loaned keyexprs.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_intersects(
    left: *const z_loaned_keyexpr_t,
    right: *const z_loaned_keyexpr_t,
) -> bool {
    crate::ffi::guard_val(false, || {
        // SAFETY: the caller's contract, delegated.
        let (Some(a), Some(b)) = (unsafe { keyexpr_str(left) }, unsafe { keyexpr_str(right) })
        else {
            return false;
        };
        let a_chunks: Vec<&str> = a.split('/').collect();
        let b_chunks: Vec<&str> = b.split('/').collect();
        wz_runtime_tokio::keyexpr_match::keyexpr_intersect_patterns(&a_chunks, &b_chunks)
    })
}

// --- the OWNED keyexpr family (R311y564) ------------------------------------
//
// Everything below produces or consumes a `z_owned_keyexpr_t`. It shares
// `KeyexprState` with the view family above, so `keyexpr_str` reads all three
// shapes; what differs is that a drop here FREES.

/// Build an owned keyexpr around `text`, writing it into `slot`.
///
/// # Safety
/// `slot` must be valid and writable.
unsafe fn install_owned(slot: *mut z_owned_keyexpr_t, text: String) {
    let handle = Box::into_raw(Box::new(KeyexprState::new(text))) as Handle;
    // SAFETY: the caller's contract.
    unsafe { *slot = z_owned_keyexpr_t::from_handle(handle) };
}

/// Read `len` bytes at `s` as UTF-8, or `None` for a null pointer / bad UTF-8.
///
/// # Safety
/// `s` must be null, or point at `len` readable bytes.
unsafe fn substr(s: *const c_char, len: usize) -> Option<&'static str> {
    if s.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let bytes = unsafe { std::slice::from_raw_parts(s as *const u8, len) };
    std::str::from_utf8(bytes).ok()
}

/// Canonize `text` in the ZENOH-C dialect, mapping wz's typed error onto the
/// code the real library returns.
///
/// Two facts here were MEASURED against `libzenohc.so` rather than chosen.
/// (1) The dialect: zenoh-c and zenoh-pico produce different canonical forms
/// for a `$*` inside a wild run, so this crate cannot use the default
/// (pico) one — see
/// [`KeyexprDialect`](wz_runtime_tokio::keyexpr_canon::KeyexprDialect).
/// (2) The code: upstream answers `-1` for EVERY canon failure — empty chunk,
/// reserved character, bare star mid-chunk — where wz's typed errors would
/// naturally have mapped onto distinct ones. A drop-in that returned `-2`
/// would break a caller comparing against `Z_EINVAL`.
fn canonize(text: &str) -> Result<String, ZResult> {
    wz_runtime_tokio::keyexpr_canon::canonize_keyexpr_in(
        text,
        wz_runtime_tokio::keyexpr_canon::KeyexprDialect::ZenohC,
    )
    .map(|canon| canon.as_str().to_owned())
    .map_err(|_| Z_EINVAL)
}

/// Construct an owned keyexpr from a NUL-terminated string (zenoh-c
/// `z_keyexpr_from_str`).
///
/// # Safety
/// `this_` must be valid and writable; `expr` must be null or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_from_str(
    this_: *mut z_owned_keyexpr_t,
    expr: *const c_char,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // The gravestone before any fallible work.
        unsafe { *this_ = z_owned_keyexpr_t::null_value() };
        if expr.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let Ok(text) = (unsafe { CStr::from_ptr(expr) }).to_str() else {
            return Z_EINVAL;
        };
        if let Err(code) = require_canonical(text) {
            return code;
        }
        // SAFETY: `this_` is valid and currently a gravestone.
        unsafe { install_owned(this_, text.to_owned()) };
        Z_OK
    })
}

/// Construct an owned keyexpr from a counted string (zenoh-c
/// `z_keyexpr_from_substr`).
///
/// # Safety
/// `this_` must be valid and writable; `expr` must be null or point at `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_from_substr(
    this_: *mut z_owned_keyexpr_t,
    expr: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        unsafe { *this_ = z_owned_keyexpr_t::null_value() };
        // SAFETY: the caller's contract.
        let Some(text) = (unsafe { substr(expr, len) }) else {
            return if expr.is_null() { Z_ENULL } else { Z_EINVAL };
        };
        if let Err(code) = require_canonical(text) {
            return code;
        }
        // SAFETY: as above.
        unsafe { install_owned(this_, text.to_owned()) };
        Z_OK
    })
}

/// Construct an owned keyexpr, CANONIZING the caller's buffer in place
/// (zenoh-c `z_keyexpr_from_str_autocanonize`).
///
/// The buffer is rewritten because upstream rewrites it: its `expr` is `char*`,
/// not `const char*`, and the canonical form is never longer than the input, so
/// the shortening is written back and the string re-terminated.
///
/// # Safety
/// `this_` must be valid and writable; `expr` must be null or a valid,
/// WRITABLE NUL-terminated buffer.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_from_str_autocanonize(
    this_: *mut z_owned_keyexpr_t,
    expr: *mut c_char,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        unsafe { *this_ = z_owned_keyexpr_t::null_value() };
        if expr.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let Ok(text) = (unsafe { CStr::from_ptr(expr) }).to_str() else {
            return Z_EINVAL;
        };
        match canonize(text) {
            // SAFETY: `this_` is valid and currently a gravestone.
            Ok(canon) => {
                unsafe { install_owned(this_, canon) };
                Z_OK
            }
            Err(code) => code,
        }
    })
}

/// The counted form of [`z_keyexpr_from_str_autocanonize`] (zenoh-c
/// `z_keyexpr_from_substr_autocanonize`).
///
/// `len` is IN-OUT: the caller passes the input length and reads back the
/// canonical one.
///
/// # Safety
/// `this_` must be valid and writable; `start` must be null or point at `*len`
/// readable and writable bytes; `len` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_from_substr_autocanonize(
    this_: *mut z_owned_keyexpr_t,
    start: *mut c_char,
    len: *mut usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        unsafe { *this_ = z_owned_keyexpr_t::null_value() };
        if len.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract. The caller's BUFFER is deliberately
        // left alone — measured: the real `libzenohc.so` returns the canonical
        // form in the owned value and leaves `start` / `*len` untouched, and
        // only the VIEW autocanonize rewrites in place (it has to, because the
        // view aliases that buffer).
        let Some(text) = (unsafe { substr(start, *len) }) else {
            return if start.is_null() { Z_ENULL } else { Z_EINVAL };
        };
        match canonize(text) {
            // SAFETY: `this_` is valid and currently a gravestone.
            Ok(canon) => {
                unsafe { install_owned(this_, canon) };
                Z_OK
            }
            Err(code) => code,
        }
    })
}

/// `Ok` iff `text` is a non-empty, CANONICAL keyexpr.
///
/// The verdict is "canonizing it changes nothing", not a second grammar walk:
/// one implementation of the grammar means the constructors and
/// [`z_keyexpr_is_canon`] cannot disagree about what they accept.
fn require_canonical(text: &str) -> Result<(), ZResult> {
    if text.is_empty() {
        return Err(Z_EINVAL);
    }
    match canonize(text) {
        Ok(canon) if canon == text => Ok(()),
        Ok(_) => Err(Z_EINVAL),
        Err(code) => Err(code),
    }
}

/// Canonize a keyexpr IN PLACE (zenoh-c `z_keyexpr_canonize`).
///
/// `len` is in-out. The rewrite is safe in place because canonization only ever
/// REMOVES chunks (`**/*` -> `**`) or shortens them (`$*$*` -> `$*`) — it never
/// grows — which is the same property upstream relies on for the `char*`
/// signature.
///
/// # Safety
/// `start` must be null or point at `*len` readable and writable bytes; `len`
/// must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_canonize(start: *mut c_char, len: *mut usize) -> ZResult {
    guarded(|| {
        if start.is_null() || len.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let Some(text) = (unsafe { substr(start, *len) }) else {
            return Z_EPARSE;
        };
        let canon = match canonize(text) {
            Ok(canon) => canon,
            Err(code) => return code,
        };
        debug_assert!(canon.len() <= text.len(), "canonization must not grow");
        // SAFETY: `canon.len() <= *len`, so the copy stays inside the caller's
        // buffer; the two regions may overlap, hence `copy` rather than
        // `copy_nonoverlapping`.
        unsafe {
            std::ptr::copy(canon.as_ptr(), start as *mut u8, canon.len());
            *len = canon.len();
        }
        Z_OK
    })
}

/// The NUL-terminated form of [`z_keyexpr_canonize`] (zenoh-c
/// `z_keyexpr_canonize_null_terminated`).
///
/// Re-terminates the buffer at the canonical length, so the caller's `char*`
/// stays a valid C string.
///
/// # Safety
/// `start` must be null or a valid, WRITABLE NUL-terminated buffer.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_canonize_null_terminated(start: *mut c_char) -> ZResult {
    guarded(|| {
        if start.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let mut len = unsafe { CStr::from_ptr(start) }.to_bytes().len();
        // SAFETY: as above — `len` bytes are readable and writable.
        let code = unsafe { z_keyexpr_canonize(start, &mut len) };
        if code == Z_OK {
            // SAFETY: `len` is the canonical length, which is <= the original,
            // so the terminator lands inside the caller's buffer.
            unsafe { *start.add(len) = 0 };
        }
        code
    })
}

/// `Z_OK` iff `start[..len]` is already canonical (zenoh-c `z_keyexpr_is_canon`).
///
/// A RESULT rather than a bool, which is upstream's shape: the non-zero value
/// distinguishes "not canonical" from "not a keyexpr at all".
///
/// # Safety
/// `start` must be null or point at `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_is_canon(start: *const c_char, len: usize) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract.
        let Some(text) = (unsafe { substr(start, len) }) else {
            return if start.is_null() { Z_ENULL } else { Z_EPARSE };
        };
        match canonize(text) {
            Ok(canon) if canon == text => Z_OK,
            // A VALID but non-canonical keyexpr and an ungrammatical one both
            // answer `-1` upstream; measured, and the reason `canonize` maps
            // every typed error onto the same code.
            Ok(_) => Z_EINVAL,
            Err(code) => code,
        }
    })
}

/// String equality of two keyexprs (zenoh-c `z_keyexpr_equals`).
///
/// Equality, NOT intersection and NOT inclusion — `demo/**` equals only
/// `demo/**`. The three relations are separate exports because a caller
/// choosing between them is choosing between different answers.
///
/// # Safety
/// Both arguments must be null or valid loaned keyexprs.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_equals(
    left: *const z_loaned_keyexpr_t,
    right: *const z_loaned_keyexpr_t,
) -> bool {
    crate::ffi::guard_val(false, || {
        // SAFETY: the caller's contract.
        let (Some(a), Some(b)) = (unsafe { keyexpr_str(left) }, unsafe { keyexpr_str(right) })
        else {
            return false;
        };
        a == b
    })
}

/// `true` iff every key `right` matches is also matched by `left` (zenoh-c
/// `z_keyexpr_includes`).
///
/// Routed through the same matching SSOT as [`z_keyexpr_intersects`], so
/// inclusion and intersection cannot disagree about the grammar.
///
/// # Safety
/// Both arguments must be null or valid loaned keyexprs.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_includes(
    left: *const z_loaned_keyexpr_t,
    right: *const z_loaned_keyexpr_t,
) -> bool {
    crate::ffi::guard_val(false, || {
        // SAFETY: the caller's contract.
        let (Some(a), Some(b)) = (unsafe { keyexpr_str(left) }, unsafe { keyexpr_str(right) })
        else {
            return false;
        };
        let a_chunks: Vec<&str> = a.split('/').collect();
        let b_chunks: Vec<&str> = b.split('/').collect();
        wz_runtime_tokio::keyexpr_match::keyexpr_includes_patterns(&a_chunks, &b_chunks)
    })
}

/// `Z_KEYEXPR_INTERSECTION_LEVEL_DISJOINT` = 0 — no key matches both.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
pub const Z_KEYEXPR_INTERSECTION_LEVEL_DISJOINT: std::ffi::c_int = 0;
/// `Z_KEYEXPR_INTERSECTION_LEVEL_INTERSECTS` = 1 — some key matches both.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
pub const Z_KEYEXPR_INTERSECTION_LEVEL_INTERSECTS: std::ffi::c_int = 1;
/// `Z_KEYEXPR_INTERSECTION_LEVEL_INCLUDES` = 2 — every key matching the right
/// also matches the left.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
pub const Z_KEYEXPR_INTERSECTION_LEVEL_INCLUDES: std::ffi::c_int = 2;
/// `Z_KEYEXPR_INTERSECTION_LEVEL_EQUALS` = 3 — the two accept the same keys.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
pub const Z_KEYEXPR_INTERSECTION_LEVEL_EQUALS: std::ffi::c_int = 3;

/// The strongest set relation that holds between two keyexprs (zenoh-c
/// `z_keyexpr_relation_to`).
///
/// R311y568. The three predicates this crate already exports —
/// [`z_keyexpr_intersects`], [`z_keyexpr_includes`], [`z_keyexpr_equals`] —
/// answer the same question one bit at a time; this collapses them into
/// upstream's four-level ladder, which is what a router-shaped C program
/// switches on.
///
/// Routed through those SAME three rather than re-deriving the relation, so the
/// ladder and the predicates cannot disagree: a pair this reports as `EQUALS`
/// is exactly a pair `z_keyexpr_equals` accepts. The ladder is checked from the
/// STRONGEST end down, because the levels nest — equal implies includes implies
/// intersects — and reporting the first level that holds from the weak end would
/// answer `INTERSECTS` for an equal pair.
///
/// UNSTABLE-gated, because upstream gates it: `zenoh_commons.h:3697` wraps the
/// declaration in `#if defined(Z_FEATURE_UNSTABLE_API)`, so the published
/// archive neither declares nor defines it. Exporting it unconditionally — which
/// this did for the length of one damage probe — makes wz's surface a SUPERSET
/// of the reference's on that arm, and the drop-in census cannot see that: it
/// measures reference-minus-wz and is blind by construction to the other
/// direction. R311y568 added the reverse assertion for exactly this.
///
/// # Safety
/// `left` and `right` must be null or valid loaned keyexprs.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_relation_to(
    left: *const z_loaned_keyexpr_t,
    right: *const z_loaned_keyexpr_t,
) -> std::ffi::c_int {
    crate::ffi::guard_val(Z_KEYEXPR_INTERSECTION_LEVEL_DISJOINT, || {
        // SAFETY: the caller's contract, delegated to the three predicates.
        unsafe {
            if z_keyexpr_equals(left, right) {
                Z_KEYEXPR_INTERSECTION_LEVEL_EQUALS
            } else if z_keyexpr_includes(left, right) {
                Z_KEYEXPR_INTERSECTION_LEVEL_INCLUDES
            } else if z_keyexpr_intersects(left, right) {
                Z_KEYEXPR_INTERSECTION_LEVEL_INTERSECTS
            } else {
                Z_KEYEXPR_INTERSECTION_LEVEL_DISJOINT
            }
        }
    })
}

/// Concatenate `left` with the raw bytes `right` (zenoh-c `z_keyexpr_concat`).
///
/// NO separator is inserted — that is what distinguishes this from
/// [`z_keyexpr_join`], and it is why `demo/` + `example` is the caller's job to
/// spell. The result is canonized, so a concatenation that produces a
/// non-canonical form is corrected rather than accepted; one that produces an
/// ungrammatical form is `Z_EPARSE`.
///
/// # Safety
/// `this_` must be valid and writable; `left` must be null or a valid loaned
/// keyexpr; `right_start` must be null or point at `right_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_concat(
    this_: *mut z_owned_keyexpr_t,
    left: *const z_loaned_keyexpr_t,
    right_start: *const c_char,
    right_len: usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        unsafe { *this_ = z_owned_keyexpr_t::null_value() };
        // SAFETY: the caller's contract.
        let (Some(a), Some(b)) = (unsafe { keyexpr_str(left) }, unsafe {
            substr(right_start, right_len)
        }) else {
            return Z_ENULL;
        };
        match canonize(&format!("{a}{b}")) {
            // SAFETY: `this_` is valid and currently a gravestone.
            Ok(text) => {
                unsafe { install_owned(this_, text) };
                Z_OK
            }
            Err(code) => code,
        }
    })
}

/// Join two keyexprs with a `/` (zenoh-c `z_keyexpr_join`).
///
/// # Safety
/// `this_` must be valid and writable; both keyexprs must be null or valid
/// loaned keyexprs.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_join(
    this_: *mut z_owned_keyexpr_t,
    left: *const z_loaned_keyexpr_t,
    right: *const z_loaned_keyexpr_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        unsafe { *this_ = z_owned_keyexpr_t::null_value() };
        // SAFETY: the caller's contract.
        let (Some(a), Some(b)) = (unsafe { keyexpr_str(left) }, unsafe { keyexpr_str(right) })
        else {
            return Z_ENULL;
        };
        match canonize(&format!("{a}/{b}")) {
            // SAFETY: `this_` is valid and currently a gravestone.
            Ok(text) => {
                unsafe { install_owned(this_, text) };
                Z_OK
            }
            Err(code) => code,
        }
    })
}

/// Deep-copy a keyexpr into an owned one (zenoh-c `z_keyexpr_clone`).
///
/// A COPY, not a handle share: the source may be a view over a caller's buffer
/// or a declared keyexpr the caller undeclares first, and either would leave the
/// clone dangling. The alias mapping is deliberately NOT carried across — a
/// declaration belongs to the value it was made on, and a clone that inherited
/// the id would keep publishing aliased after the original was undeclared.
///
/// # Safety
/// `dst` must be valid and writable; `this_` must be null or a valid loaned
/// keyexpr.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_clone(
    dst: *mut z_owned_keyexpr_t,
    this_: *const z_loaned_keyexpr_t,
) {
    crate::ffi::guard_val((), || {
        if dst.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *dst = z_owned_keyexpr_t::null_value() };
        // SAFETY: as above.
        let Some(text) = (unsafe { keyexpr_str(this_) }) else {
            return;
        };
        // SAFETY: `dst` is valid and currently a gravestone.
        unsafe { install_owned(dst, text.to_owned()) };
    });
}

/// Borrow an owned keyexpr (zenoh-c `z_keyexpr_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned keyexpr.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_loan(
    this_: *const z_owned_keyexpr_t,
) -> *const z_loaned_keyexpr_t {
    this_ as *const z_loaned_keyexpr_t
}

/// Free an owned keyexpr (zenoh-c `z_keyexpr_drop`).
///
/// Frees the state and gravestones the caller's slot. This does NOT retract a
/// declaration — [`z_undeclare_keyexpr`] is the session-aware path and is what a
/// program that declared must call, exactly as upstream splits them.
///
/// # Safety
/// `this_` must be null or a valid, writable moved keyexpr.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_drop(this_: *mut z_moved_keyexpr_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_)._this.handle };
    unsafe { (*this_)._this = z_owned_keyexpr_t::null_value() };
    if !handle.is_null() {
        // SAFETY: every owned keyexpr's handle is a `Box::into_raw`.
        drop(unsafe { Box::from_raw(handle as *mut KeyexprState) });
    }
}

/// `true` iff the owned keyexpr holds a value (zenoh-c
/// `z_internal_keyexpr_check`).
///
/// # Safety
/// `this_` must be null or a valid owned keyexpr.
#[no_mangle]
pub unsafe extern "C" fn z_internal_keyexpr_check(this_: *const z_owned_keyexpr_t) -> bool {
    crate::ffi::guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned keyexpr (zenoh-c `z_internal_keyexpr_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned keyexpr.
#[no_mangle]
pub unsafe extern "C" fn z_internal_keyexpr_null(this_: *mut z_owned_keyexpr_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_keyexpr_t::null_value() };
    }
}

/// Gravestone a view keyexpr (zenoh-c `z_view_keyexpr_empty`).
///
/// # Safety
/// `this_` must be null or a valid, writable view keyexpr.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_empty(this_: *mut z_view_keyexpr_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_view_keyexpr_t::null_value() };
    }
}

/// `true` iff the view keyexpr is the gravestone (zenoh-c
/// `z_view_keyexpr_is_empty`).
///
/// # Safety
/// `this_` must be null or a valid view keyexpr.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_is_empty(this_: *const z_view_keyexpr_t) -> bool {
    crate::ffi::guard_val(true, || {
        // SAFETY: the caller's contract.
        this_.is_null() || unsafe { (*this_).handle }.is_null()
    })
}

/// Construct a view keyexpr, canonizing the caller's buffer in place (zenoh-c
/// `z_view_keyexpr_from_str_autocanonize`).
///
/// # Safety
/// `this_` must be valid and writable; `expr` must be null or a valid, WRITABLE
/// NUL-terminated buffer.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_from_str_autocanonize(
    this_: *mut z_view_keyexpr_t,
    expr: *mut c_char,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        unsafe { *this_ = z_view_keyexpr_t::null_value() };
        // SAFETY: the caller's contract.
        let code = unsafe { z_keyexpr_canonize_null_terminated(expr) };
        if code != Z_OK {
            return code;
        }
        // SAFETY: still NUL-terminated after the in-place rewrite.
        unsafe { z_view_keyexpr_from_str(this_, expr) }
    })
}

/// The counted form of [`z_view_keyexpr_from_str_autocanonize`] (zenoh-c
/// `z_view_keyexpr_from_substr_autocanonize`).
///
/// # Safety
/// `this_` must be valid and writable; `start` must be null or point at `*len`
/// readable and writable bytes; `len` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_from_substr_autocanonize(
    this_: *mut z_view_keyexpr_t,
    start: *mut c_char,
    len: *mut usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        unsafe { *this_ = z_view_keyexpr_t::null_value() };
        if len.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let code = unsafe { z_keyexpr_canonize(start, len) };
        if code != Z_OK {
            return code;
        }
        // SAFETY: `*len` now holds the canonical length.
        unsafe { z_view_keyexpr_from_substr(this_, start, *len) }
    })
}

/// The counted, UNVALIDATED view constructor (zenoh-c
/// `z_view_keyexpr_from_substr_unchecked`).
///
/// Upstream returns `void` — the caller has asserted canonicity, so there is no
/// verdict to report. See [`z_view_keyexpr_from_str_unchecked`] for why an
/// unreadable pointer still leaves a gravestone rather than a half-built view.
///
/// # Safety
/// `this_` must be null or valid and writable; `start` must be null or point at
/// `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_from_substr_unchecked(
    this_: *mut z_view_keyexpr_t,
    start: *const c_char,
    len: usize,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe { *this_ = z_view_keyexpr_t::null_value() };
    // SAFETY: as above — see the NUL-terminated sibling for why this does not
    // delegate to the checked constructor.
    let Some(text) = (unsafe { substr(start, len) }) else {
        return;
    };
    let handle = Box::into_raw(Box::new(KeyexprState::new(text.to_owned()))) as Handle;
    // SAFETY: the slot was gravestoned above.
    unsafe { *this_ = z_view_keyexpr_t::from_handle(handle) };
}

/// The wire alias a [`z_declare_keyexpr`] bound to this keyexpr, or `None` for
/// an undeclared view.
///
/// # Safety
/// `ke` must be null or a valid loaned keyexpr whose handle is live.
pub(crate) unsafe fn keyexpr_mapping(ke: *const z_loaned_keyexpr_t) -> Option<u64> {
    if ke.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*ke).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `KeyexprState` this crate leaked.
    unsafe { &*(handle as *const KeyexprState) }.mapping
}

/// Declare a keyexpr, binding it to a numerical id on every connected peer
/// (zenoh-c `z_declare_keyexpr`).
///
/// The id is announced on every live face and REPLAYED onto faces that connect
/// later (`SharedSession::declare_keyexpr` / `face_up`), so a program that
/// declares before its first peer still publishes aliased to that peer.
///
/// Returns `Z_EINVAL` when the wire's `u16` alias space is exhausted. Refusing
/// beats wrapping: a reused id would silently re-point a peer's live alias at a
/// different keyexpr.
///
/// # Safety
/// `session` must be a valid loaned session; `declared_key_expr` must be valid
/// and writable; `key_expr` must be null or a valid loaned keyexpr.
#[no_mangle]
pub unsafe extern "C" fn z_declare_keyexpr(
    session: *const crate::abi::z_loaned_session_t,
    declared_key_expr: *mut z_owned_keyexpr_t,
    key_expr: *const z_loaned_keyexpr_t,
) -> ZResult {
    guarded(|| {
        if declared_key_expr.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *declared_key_expr = z_owned_keyexpr_t::null_value() };
        // SAFETY: as above.
        let (Some(state), Some(literal)) =
            (unsafe { crate::session::session_state(session) }, unsafe {
                keyexpr_str(key_expr)
            })
        else {
            return Z_ENULL;
        };
        let literal = literal.to_owned();
        let Some(mapping) = state.shared.declare_keyexpr(literal.clone()) else {
            return Z_EINVAL;
        };
        let handle = Box::into_raw(Box::new(KeyexprState {
            keyexpr: literal,
            mapping: Some(mapping),
        })) as Handle;
        // SAFETY: the slot was gravestoned above.
        unsafe { *declared_key_expr = z_owned_keyexpr_t::from_handle(handle) };
        Z_OK
    })
}

/// Retract a keyexpr declaration (zenoh-c `z_undeclare_keyexpr`).
///
/// Consumes the moved value on EVERY path including the error ones — the state
/// is freed and the caller's slot gravestoned before the session is even
/// resolved, so a program that undeclares against a dead session still ends up
/// with a value it may safely drop again.
///
/// # Safety
/// `session` must be a valid loaned session; `key_expr` must be null or a
/// valid, writable moved keyexpr.
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_keyexpr(
    session: *const crate::abi::z_loaned_session_t,
    key_expr: *mut z_moved_keyexpr_t,
) -> ZResult {
    guarded(|| {
        if key_expr.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*key_expr)._this.handle };
        unsafe { (*key_expr)._this = z_owned_keyexpr_t::null_value() };
        let mapping = if handle.is_null() {
            None
        } else {
            // SAFETY: every owned keyexpr's handle is a `Box::into_raw`.
            let boxed = unsafe { Box::from_raw(handle as *mut KeyexprState) };
            boxed.mapping
        };
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { crate::session::session_state(session) }) else {
            return Z_ENULL;
        };
        if let Some(mapping) = mapping {
            state.shared.undeclare_keyexpr(mapping);
        }
        Z_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The substring constructor stops at `len` rather than at a NUL — the
    /// property `z_get.c` depends on when it points at the middle of a
    /// `keyexpr?parameters` selector.
    #[test]
    fn the_substr_constructor_stops_at_the_length_not_at_a_nul() {
        let selector = c"demo/example/**?value=1";
        let mut view = z_view_keyexpr_t::null_value();
        // SAFETY: `selector` is a live C string and `view` a live local.
        unsafe {
            assert_eq!(
                z_view_keyexpr_from_substr(&mut view, selector.as_ptr(), 15),
                Z_OK
            );
            let loaned = z_view_keyexpr_loan(&view);
            assert_eq!(
                keyexpr_str(loaned),
                Some("demo/example/**"),
                "the constructor read past its length into the parameters"
            );
        }
    }

    /// Intersection is SYMMETRIC and is not equality — the two properties
    /// `z_storage.c`'s wildcard get rests on.
    #[test]
    fn keyexpr_intersection_is_symmetric_and_is_not_equality() {
        let mut wild = z_view_keyexpr_t::null_value();
        let mut concrete = z_view_keyexpr_t::null_value();
        let mut other = z_view_keyexpr_t::null_value();
        // SAFETY: live locals and live C strings.
        unsafe {
            assert_eq!(
                z_view_keyexpr_from_str(&mut wild, c"demo/**".as_ptr()),
                Z_OK
            );
            assert_eq!(
                z_view_keyexpr_from_str(&mut concrete, c"demo/a/b".as_ptr()),
                Z_OK
            );
            assert_eq!(
                z_view_keyexpr_from_str(&mut other, c"other/a".as_ptr()),
                Z_OK
            );
            let (w, c, o) = (
                z_view_keyexpr_loan(&wild),
                z_view_keyexpr_loan(&concrete),
                z_view_keyexpr_loan(&other),
            );
            assert!(z_keyexpr_intersects(w, c));
            assert!(z_keyexpr_intersects(c, w), "intersection must be symmetric");
            assert!(!z_keyexpr_intersects(w, o));
            assert!(!z_keyexpr_intersects(std::ptr::null(), c));
            assert!(!z_keyexpr_intersects(c, std::ptr::null()));
        }
    }
}
