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
use std::sync::{Arc, Weak};

use wz_capi_core::faces::{SharedSession, WireKey};
use wz_runtime_tokio::session::RetractionKey;
use wz_runtime_tokio::session_glue::WhatAmI;

use crate::abi::{
    view_bytes, z_loaned_keyexpr_t, z_loaned_string_t, z_moved_keyexpr_t, z_owned_keyexpr_t,
    z_view_keyexpr_t, z_view_string_t,
};
use crate::ffi::{guard_val, guarded};
use crate::result::{
    ZResult, Z_ERR_GENERIC, Z_ERR_INVALID, Z_ERR_KEYEXPR_DECLARED_ON_ANOTHER_SESSION, Z_ERR_NULL,
    Z_OK,
};
use crate::session::{session_state, z_loaned_session_t};
use crate::write_filter::PicoSession;

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

/// The [`DeclaredKeyexpr`] behind a loaned keyexpr, or `None` for a view.
///
/// Only the owned keyexprs this crate builds, and the loans its entities hand
/// out over their own keys, put anything in slot 2; a view leaves it null.
///
/// # Safety
/// `ke` must be a live `z_loaned_keyexpr_t` pointer (or null).
pub(crate) unsafe fn declared_of<'a>(ke: *const z_loaned_keyexpr_t) -> Option<&'a DeclaredKeyexpr> {
    if ke.is_null() || (*ke)._handle.is_null() {
        return None;
    }
    Some(&*((*ke)._handle as *const DeclaredKeyexpr))
}

/// How `ke` goes on `shared`'s wire: its own declaration's id and the rest of
/// the key when the declaration is this session's, the literal otherwise.
///
/// pico `_z_declared_keyexpr_alias_to_wire`
/// (`vendor/zenoh-pico/src/session/keyexpr.c`), which every message that names
/// a caller's key goes through. `None` when `ke` is null or not UTF-8.
///
/// # Safety
/// `ke` must be a live `z_loaned_keyexpr_t` pointer (or null).
pub(crate) unsafe fn wire_key_of(
    ke: *const z_loaned_keyexpr_t,
    shared: &Arc<SharedSession>,
) -> Option<WireKey> {
    keyexpr_str(ke)?;
    Some(match declared_of(ke) {
        Some(declared) => declared.wire(shared),
        None => WireKey::literal(),
    })
}

/// pico `_z_keyexpr_wire_declaration_t` behind its refcount: ONE keyexpr
/// declaration on ONE session, retracted when the last key holding it lets go.
///
/// Shared by every key that names it — the owned keyexpr `z_declare_keyexpr`
/// returns, its clones, the keys `z_keyexpr_concat` / `z_keyexpr_join` build on
/// it, and an entity declared on it — exactly as pico shares the
/// `_z_keyexpr_wire_declaration_rc_t`. Its `Drop` is pico's
/// `_z_keyexpr_wire_declaration_clear`, which undeclares
/// (`vendor/zenoh-pico/src/session/keyexpr.c` @
/// `void _z_keyexpr_wire_declaration_clear(`).
///
/// The session is held WEAKLY, as pico holds `_z_session_weak_t`: a key that
/// outlives its session must not keep the session alive, and retracting on a
/// session that is gone is moot.
pub(crate) struct WireDeclaration {
    session: Weak<SharedSession>,
    id: u64,
    /// How many bytes of the key the declaration covers — pico's `_prefix_len`.
    prefix_len: usize,
}

impl Drop for WireDeclaration {
    /// Let go of this declaration's hold on the key. The key itself goes only
    /// when no other declaration of the same key holds it: pico's resource table
    /// counts its holders, and a second declaration of a key it already has is
    /// the same id with one more (see [`SharedSession::acquire_keyexpr`]).
    fn drop(&mut self) {
        if let Some(session) = self.session.upgrade() {
            session.release_keyexpr(self.id);
        }
    }
}

/// Behind a `z_owned_keyexpr_t` handle, and held by every entity for its own
/// key: the OWNED literal plus the declaration that covers a prefix of it, if
/// any — pico's `_z_declared_keyexpr_t` (`{ _declaration, _inner }`).
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
    declaration: Option<Arc<WireDeclaration>>,
}

impl DeclaredKeyexpr {
    /// A key with no declaration.
    pub(crate) fn literal_only(literal: String) -> Self {
        Self {
            literal,
            declaration: None,
        }
    }

    /// The literal key.
    pub(crate) fn literal(&self) -> &str {
        &self.literal
    }

    /// A borrow of this key in the loaned layout, carrying the declaration so a
    /// caller that publishes on it aliases as pico's `z_publisher_keyexpr` loan
    /// does. Valid while `self` stays at its address.
    pub(crate) fn loaned(&self) -> z_loaned_keyexpr_t {
        z_loaned_keyexpr_t {
            _start: self.literal.as_ptr(),
            _len: self.literal.len(),
            _handle: self as *const Self as *mut c_void,
            _mapping: 0,
        }
    }

    /// Another key sharing this one's literal and declaration — pico
    /// `_z_declared_keyexpr_copy`, which clones the refcount.
    pub(crate) fn share(&self) -> Self {
        Self {
            literal: self.literal.clone(),
            declaration: self.declaration.clone(),
        }
    }

    /// A new literal that keeps this key's declaration — pico's
    /// `_z_declared_keyexpr_concat` / `_join`, which clone the left side's
    /// refcount onto the result.
    ///
    /// Kept only while the new literal still begins with the declared prefix.
    /// pico's concat appends raw bytes, so there it always does; wz canonizes
    /// the joined text, which can in principle rewrite the seam, and a
    /// declaration naming bytes the key no longer starts with would put the
    /// wrong key on the wire.
    pub(crate) fn extended(&self, literal: String) -> Self {
        let declaration = self.declaration.clone().filter(|d| {
            literal.get(..d.prefix_len).is_some()
                && literal.get(..d.prefix_len) == self.literal.get(..d.prefix_len)
        });
        Self {
            literal,
            declaration,
        }
    }

    fn declared_on(&self, shared: &Arc<SharedSession>) -> Option<&Arc<WireDeclaration>> {
        self.declaration
            .as_ref()
            .filter(|d| std::ptr::eq(d.session.as_ptr(), Arc::as_ptr(shared)))
    }

    /// pico `_z_declared_keyexpr_alias_to_wire`: the declaration's id and the
    /// remainder of the key when the declaration is `shared`'s, the literal
    /// otherwise.
    ///
    /// An aliased key KEEPS its declaration: whatever records it — a registry
    /// entry replayed onto later faces — holds the id declared for as long as
    /// it names it.
    pub(crate) fn wire(&self, shared: &Arc<SharedSession>) -> WireKey {
        // Every constructor keeps the declared prefix at the front of the
        // literal (see `extended`), so the remainder always exists; the `get`
        // turns a broken invariant into the literal rather than a panic.
        match self
            .declared_on(shared)
            .and_then(|d| Some((d, self.literal.get(d.prefix_len..)?)))
        {
            Some((d, rest)) => {
                let anchor: Arc<dyn Send + Sync> = d.clone();
                WireKey::aliased(d.id, (!rest.is_empty()).then(|| rest.to_owned())).keeping(anchor)
            }
            None => WireKey::literal(),
        }
    }

    /// What an entity held on this key names when it retracts itself, or `None`
    /// when it retracts by id alone.
    ///
    /// pico names the entity's OWN key in every mode but client (`vendor/zenoh-pico/src/net/primitives.c`
    /// @ `_z_wireexpr_t expr = _z_declared_keyexpr_alias_to_wire(&_Z_RC_IN_VAL(&s)->_key, zn);`),
    /// and that key is the one this is called on: for a subscriber it is not
    /// the key the subscription was announced on, which is the caller's.
    pub(crate) fn retraction_naming(&self, session: &PicoSession) -> Option<RetractionKey> {
        self.retraction_naming_in(session.mode, &session.shared)
    }

    /// [`Self::retraction_naming`] for a caller that holds the two facts it
    /// reads — the role and the registry — without a whole [`PicoSession`]: one
    /// that has to hold the registry WEAKLY, because the registry holds it.
    pub(crate) fn retraction_naming_in(
        &self,
        mode: WhatAmI,
        shared: &Arc<SharedSession>,
    ) -> Option<RetractionKey> {
        if mode == WhatAmI::Client {
            return None;
        }
        let wire = self.wire(shared);
        Some(if wire.mapping_id == 0 {
            RetractionKey {
                mapping_id: 0,
                suffix: self.literal.clone(),
            }
        } else {
            RetractionKey {
                mapping_id: wire.mapping_id,
                suffix: wire.suffix.unwrap_or_default(),
            }
        })
    }

    /// pico `_z_declared_keyexpr_declare`: a key whose declaration covers ALL
    /// of it on `shared`, sharing the caller's when it already does.
    pub(crate) fn declare(
        shared: &Arc<SharedSession>,
        literal: &str,
        existing: Option<&DeclaredKeyexpr>,
    ) -> Result<Self, ZResult> {
        Self::declare_up_to(shared, literal, existing, literal.len())
    }

    /// pico `_z_declared_keyexpr_declare_non_wild_prefix`: the same, covering
    /// only the part of the key before its first wild chunk.
    pub(crate) fn declare_non_wild_prefix(
        shared: &Arc<SharedSession>,
        literal: &str,
        existing: Option<&DeclaredKeyexpr>,
    ) -> Result<Self, ZResult> {
        Self::declare_up_to(shared, literal, existing, non_wild_prefix_len(literal))
    }

    fn declare_up_to(
        shared: &Arc<SharedSession>,
        literal: &str,
        existing: Option<&DeclaredKeyexpr>,
        prefix_len: usize,
    ) -> Result<Self, ZResult> {
        // Already optimized on THIS session to exactly this prefix: share it
        // (pico's `_z_declared_keyexpr_is_fully_optimized` /
        // `_is_non_wild_prefix_optimized` arm).
        if let Some(existing) = existing {
            if existing
                .declared_on(shared)
                .is_some_and(|d| d.prefix_len == prefix_len)
            {
                return Ok(existing.share());
            }
        }
        // pico `_z_keyexpr_declare_prefix`: an empty prefix declares nothing.
        // Its multicast skip has no counterpart here — this ABI's sessions are
        // unicast.
        if prefix_len == 0 {
            return Ok(Self::literal_only(literal.to_owned()));
        }
        let Some(id) = shared.acquire_keyexpr(literal[..prefix_len].to_owned()) else {
            return Err(Z_ERR_GENERIC);
        };
        Ok(Self {
            literal: literal.to_owned(),
            declaration: Some(Arc::new(WireDeclaration {
                session: Arc::downgrade(shared),
                id,
                prefix_len,
            })),
        })
    }
}

/// pico `_z_keyexpr_non_wild_prefix_len`: the length up to the `/` before the
/// first `*`, the whole key when there is none, 0 when the key opens wild.
fn non_wild_prefix_len(literal: &str) -> usize {
    let bytes = literal.as_bytes();
    let Some(star) = bytes.iter().position(|&b| b == b'*') else {
        return bytes.len();
    };
    bytes[..star].iter().rposition(|&b| b == b'/').unwrap_or(0)
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

/// Declare a keyexpr, binding it to a numerical id on every connected peer
/// (pico `z_declare_keyexpr`, which is `_z_declared_keyexpr_declare` on the
/// caller's key).
///
/// The id is announced on every live face and REPLAYED onto faces that connect
/// later (`SharedSession::declare_keyexpr` / `face_up`), so a program that
/// declares before its first peer — which upstream's `z_put.c` does whenever it
/// wins the race — still publishes aliased to that peer. A key that already
/// carries a whole-key declaration on this session shares it rather than
/// declaring again, as upstream's does.
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
        let Some(literal) = keyexpr_str(keyexpr) else {
            return Z_ERR_INVALID;
        };
        match DeclaredKeyexpr::declare(&state.shared, literal, declared_of(keyexpr)) {
            Ok(key) => {
                store_owned_keyexpr(declared, key);
                Z_OK
            }
            Err(rc) => rc,
        }
    })
}

/// Retract a keyexpr declaration (pico `z_undeclare_keyexpr`). Consumes the
/// moved value on every path, including the error paths — pico's `z_move`
/// contract.
///
/// Upstream's three answers, in its order: `Z_ERR_INVALID` for a key that
/// carries no declaration, `Z_ERR_KEYEXPR_DECLARED_ON_ANOTHER_SESSION` for one
/// another session made, and otherwise the retraction — which happens only when
/// this key is the LAST holder (`strong_count == 1`), because an entity
/// declared on the same key shares the declaration and still needs it. Here
/// that last-holder rule is the refcount's own: dropping the key retracts
/// exactly when nothing else holds the declaration.
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_keyexpr(
    zs: *const z_loaned_session_t,
    keyexpr: *mut z_moved_keyexpr_t,
) -> ZResult {
    guarded(|| {
        if keyexpr.is_null() {
            return Z_ERR_NULL;
        }
        // Take the value out first so the owned key is released and the
        // caller's struct nulled whether or not the session resolves.
        let handle = (*keyexpr)._this._handle;
        (*keyexpr)._this = z_owned_keyexpr_t::null_value();
        if handle.is_null() {
            return Z_ERR_INVALID;
        }
        let key = Box::from_raw(handle as *mut DeclaredKeyexpr);
        let Some(state) = session_state(zs) else {
            return Z_ERR_NULL;
        };
        if key.declaration.is_none() {
            Z_ERR_INVALID
        } else if key.declared_on(&state.shared).is_none() {
            Z_ERR_KEYEXPR_DECLARED_ON_ANOTHER_SESSION
        } else {
            Z_OK
        }
        // `key` drops here, retracting the declaration if it was the last
        // holder.
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
/// R2959 — this RETRACTS the declaration when the dropped key was its last
/// holder. The doc here used to say the opposite, that a drop frees the local
/// value only and retraction is `z_undeclare_keyexpr`'s alone; zenoh-pico
/// 1.10.1 does not work that way. Its key holds the declaration through a
/// refcount whose clear undeclares
/// (`vendor/zenoh-pico/src/session/keyexpr.c` @
/// `void _z_keyexpr_wire_declaration_clear(`), and a publisher dropped by a
/// real pico program retracts its key's declaration on the wire, measured by
/// `pico_keyexpr_declaration_twice_and_diff.rs`. The session the retraction
/// needs is the one the declaration holds, not an argument.
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

/// Store `key` as an owned keyexpr, replacing whatever `dst` held.
///
/// The `_start` slot points into the boxed `String`'s HEAP buffer, which is
/// what makes the borrow survive the box moving — the distinction
/// [`DeclaredKeyexpr`] documents. The declaration, if any, rides in the box;
/// `_mapping` stays 0 because nothing reads it any more — a key's wire form is
/// asked of the key ([`wire_key_of`]), which is the only place that can tell a
/// whole-key declaration from a prefix one.
unsafe fn store_owned_keyexpr(dst: *mut z_owned_keyexpr_t, key: DeclaredKeyexpr) {
    let boxed = Box::new(key);
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
                store_owned_keyexpr(keyexpr, DeclaredKeyexpr::literal_only(text));
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
                store_owned_keyexpr(
                    keyexpr,
                    DeclaredKeyexpr::literal_only(canon.as_str().to_owned()),
                );
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
                store_owned_keyexpr(
                    keyexpr,
                    DeclaredKeyexpr::literal_only(canon.as_str().to_owned()),
                );
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

/// Copy a keyexpr into an owned one (pico `z_keyexpr_clone`, which is
/// `_z_declared_keyexpr_copy`).
///
/// R2959 — the clone SHARES the source's declaration. This used to make every
/// clone a literal, on the argument that a clone carrying the id would publish
/// on a declaration it held no reference to. The declaration is refcounted now
/// (`WireDeclaration`), so the clone holds exactly such a reference, and a
/// literal clone is no longer the safe direction but a divergence: upstream's
/// copy clones the refcount (`vendor/zenoh-pico/src/session/keyexpr.c` @
/// `dst->_declaration = _z_keyexpr_wire_declaration_rc_clone(&src->_declaration);`).
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
        let Some(text) = keyexpr_str(src) else {
            return Z_ERR_NULL;
        };
        let key = match declared_of(src) {
            Some(declared) => declared.share(),
            None => DeclaredKeyexpr::literal_only(text.to_owned()),
        };
        store_owned_keyexpr(dst, key);
        Z_OK
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
                store_owned_keyexpr(key, extended_from(left, canon.as_str()));
                Z_OK
            }
            Err(_) => Z_ERR_INVALID,
        }
    })
}

/// The result of extending `left` to `literal`: `left`'s declaration kept when
/// `left` is a declared key (pico `_z_declared_keyexpr_concat` / `_join`), a
/// plain literal otherwise.
///
/// # Safety
/// `left` must be null or a live loaned keyexpr.
unsafe fn extended_from(left: *const z_loaned_keyexpr_t, literal: &str) -> DeclaredKeyexpr {
    match declared_of(left) {
        Some(declared) => declared.extended(literal.to_owned()),
        None => DeclaredKeyexpr::literal_only(literal.to_owned()),
    }
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
                store_owned_keyexpr(key, extended_from(left, canon.as_str()));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Arc<SharedSession> {
        Arc::new(
            SharedSession::new(
                wz_runtime_tokio::runtime_impl::TokioTime::new(),
                vec![0x5a; 16],
            )
            .expect("test host entropy"),
        )
    }

    /// R2959 — pico's `_z_keyexpr_non_wild_prefix_len`, case by case: up to the
    /// `/` before the first `*`, the whole key without one, nothing when the
    /// key opens wild.
    #[test]
    fn the_non_wild_prefix_stops_at_the_chunk_before_the_first_star() {
        assert_eq!(non_wild_prefix_len("demo/kd/sub/**"), "demo/kd/sub".len());
        assert_eq!(non_wild_prefix_len("demo/kd/qbl/*/x"), "demo/kd/qbl".len());
        assert_eq!(non_wild_prefix_len("demo/kd/pub"), "demo/kd/pub".len());
        assert_eq!(non_wild_prefix_len("**"), 0);
        assert_eq!(non_wild_prefix_len("a/b$*/c"), "a".len());
    }

    /// R2959 — a declaration is retracted when its LAST holder lets go, and not
    /// before: an entity sharing the key keeps it declared after the key the
    /// program declared is dropped. This is pico's refcount, and the reason
    /// `z_keyexpr_drop` now retracts.
    ///
    /// Control: making `share` copy the literal alone (no declaration) reds the
    /// second assertion — the entity would declare a second id.
    #[test]
    fn a_declaration_lives_as_long_as_its_last_holder() {
        let shared = session();
        let program = DeclaredKeyexpr::declare(&shared, "demo/kd/decl", None).expect("declared");
        assert_eq!(shared.keyexpr_declarations().len(), 1);
        let entity = DeclaredKeyexpr::declare(&shared, "demo/kd/decl", Some(&program))
            .expect("an already-declared key is shared, not redeclared");
        assert_eq!(
            shared.keyexpr_declarations().len(),
            1,
            "a fully optimized key shares its declaration"
        );
        drop(program);
        assert_eq!(
            shared.keyexpr_declarations().len(),
            1,
            "the entity still holds the declaration"
        );
        drop(entity);
        assert!(shared.keyexpr_declarations().is_empty());
    }

    /// R2959 — the wire form: the declaration's id plus the remainder of the
    /// key, and the literal on a session that did not make the declaration.
    #[test]
    fn a_prefix_declaration_names_the_rest_of_the_key_as_suffix() {
        let shared = session();
        let key = DeclaredKeyexpr::declare_non_wild_prefix(&shared, "demo/kd/qbl/*/x", None)
            .expect("declared");
        let declarations = shared.keyexpr_declarations();
        assert_eq!(declarations.len(), 1);
        assert_eq!(declarations[0].1, "demo/kd/qbl");
        let wire = key.wire(&shared);
        assert_eq!(wire.mapping_id, declarations[0].0);
        assert_eq!(wire.suffix.as_deref(), Some("/*/x"));

        let other = session();
        assert_eq!(
            key.wire(&other).mapping_id,
            0,
            "another session's id is not ours"
        );
    }
}
