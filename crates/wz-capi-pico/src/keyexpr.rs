// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `z_view_keyexpr_*` + `z_keyexpr_as_view_string` — the keyexpr view type.
//!
//! pico `z_view_keyexpr_t` is a VIEW: it aliases the caller's `const char*`
//! (no allocation, no drop). Round 1 reproduces that borrow: the view stores
//! `{ start, len }` into the caller's NUL-terminated string, which the caller
//! must keep alive while the keyexpr is used (the pico contract). `z_put` /
//! `z_declare_*` read the borrowed UTF-8 back via `keyexpr_str`.

use alloc::sync::{Arc, Weak};
use core::ffi::{c_char, c_void, CStr};
use core::mem::ManuallyDrop;

use crate::prelude::*;

use wz_capi_port::{HeldKey, KeyAsk, KeyHold, KeyNotHeld, WireKey};
use wz_session_core::declare_form::RetractionKey;
use wz_session_core::keyexpr_canon::KeyexprCanonError;
use wz_session_core::WhatAmI;

use crate::abi::{
    view_bytes, z_loaned_keyexpr_t, z_loaned_string_t, z_moved_keyexpr_t, z_owned_keyexpr_t,
    z_view_keyexpr_t, z_view_string_t,
};
use crate::ffi::{guard_val, guarded};
use crate::result::{
    ZResult, Z_EINVAL, Z_ERR_GENERIC, Z_ERR_INVALID, Z_ERR_KEYEXPR_DECLARED_ON_ANOTHER_SESSION,
    Z_ERR_NULL, Z_OK,
};
use crate::session::{engine_of, engine_ref, session_handle, z_loaned_session_t, Engine};

/// Whether `key` is no longer than the longest key a row of a session's tables stores: the
/// capacity the build gives the row (`MAX_KEYEXPR_BYTES`), which no session's limits raise. A key
/// past it is a value this build cannot take, refused with `Z_EINVAL`, never cut short; a session
/// that states a lower bound refuses the key again when it is declared on it.
fn fits(key: &str) -> bool {
    key.len() <= row_capacity::<{ wz_session_core::caps::MAX_KEYEXPR_BYTES }>()
}

/// The bytes a key row of `N` bytes holds.
const fn row_capacity<const N: usize>() -> usize {
    N
}

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
    core::str::from_utf8(bytes).ok()
}

/// The key a declaration or a get names, read where the caller holds it: `Z_ERR_INVALID` when it
/// is null or not UTF-8, and when it is not one a zenoh-pico peer takes (not canon, or pico-unsafe),
/// the outbound gate wz's own session applies per face. Judged here, before anything is declared or
/// asked, because a session declares and asks per face at its best, and would swallow a refusal of
/// one face. One body every such door calls, so the gate and its code are not copied into each.
///
/// # Safety
/// As [`keyexpr_str`].
#[inline(never)]
pub(crate) unsafe fn outbound_keyexpr<'a>(
    ke: *const z_loaned_keyexpr_t,
) -> Result<&'a str, ZResult> {
    let key = keyexpr_str(ke).ok_or(Z_ERR_INVALID)?;
    wz_session_core::keyexpr_canon::check_outbound_keyexpr_pico_safe(key)
        .map_err(|_| Z_ERR_INVALID)?;
    Ok(key)
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
/// a caller's key goes through. Every caller has read the key's text first
/// ([`keyexpr_str`]), which refuses a null or non-UTF-8 key, so the text is not
/// read again here: only the declaration is.
///
/// # Safety
/// `ke` must be a live `z_loaned_keyexpr_t` pointer (or null).
pub(crate) unsafe fn wire_key_of(ke: *const z_loaned_keyexpr_t, shared: &Engine) -> WireKey {
    match declared_of(ke) {
        Some(declared) => declared.wire(shared),
        None => WireKey::literal(),
    }
}

/// pico `_z_keyexpr_wire_declaration_t`: ONE keyexpr declaration on ONE session, held by every
/// key that names it — the owned keyexpr `z_declare_keyexpr` returns, its clones, the keys
/// `z_keyexpr_concat` / `z_keyexpr_join` build on it, and an entity declared on it — and retracted
/// when the last lets go, as pico's refcount does (`vendor/zenoh-pico/src/session/keyexpr.c` @
/// `void _z_keyexpr_wire_declaration_clear(`).
///
/// Each holder keeps one hold of the engine's own count of the declaration's holders
/// ([`KeyHold`]): a copy takes one more and a drop lets its own go, so the count has one owner and
/// a holder keeps nothing on the heap. The session is held WEAKLY, as pico holds
/// `_z_session_weak_t`: a key that outlives its session does not keep it alive, and a hold on a
/// session that is gone lets go of nothing.
#[derive(Clone)]
pub(crate) struct WireDeclaration {
    hold: KeyHold,
    /// How many bytes of the key the declaration covers — pico's `_prefix_len`.
    prefix_len: usize,
}

/// A key's text as an object of this ABI keeps it: a block of its session's key arena when the
/// session keeps one, which a key of the same text anywhere in the session shares, or a copy of its
/// own: a key made with no session, for an engine that keeps no key arena, or for a closed
/// session.
///
/// Its text is read from the handle with no branch and no lock. Holding, sharing and letting go of
/// it are one out-of-line body each for every object that keeps a key, and each reaches the
/// engine through its one door for keys ([`SessionKeys::key`](wz_capi_port::SessionKeys::key)).
pub(crate) struct KeyText {
    /// Taken only by the drop.
    key: ManuallyDrop<HeldKey>,
    /// The engine whose key arena holds `key`, kept for as long as it does; `None` for a copy
    /// of its own.
    engine: Option<Arc<Engine>>,
}

impl KeyText {
    /// `text` as a copy of its own.
    pub(crate) fn owned(text: &str) -> Self {
        Self {
            key: ManuallyDrop::new(HeldKey::own(text)),
            engine: None,
        }
    }

    /// `text` kept for an object of `shared`'s session: in its key arena when it keeps one, and
    /// refused as zenoh-pico refuses what its heap cannot hold (`_Z_ERR_SYSTEM_OUT_OF_MEMORY`) when
    /// the arena has no room, or with `Z_EINVAL` when it is longer than the session's
    /// `MAX_KEYEXPR_BYTES`; a copy of its own for a session with no key arena or a closed one,
    /// which keeps nothing more.
    #[inline(never)]
    pub(crate) fn of_session(shared: &Arc<Engine>, text: &str) -> Result<Self, ZResult> {
        let refused = match shared.key_arena().map(|keys| keys.key(KeyAsk::Hold(text))) {
            Some(Ok(Some(key))) => {
                return Ok(Self {
                    key: ManuallyDrop::new(key),
                    engine: Some(shared.clone()),
                })
            }
            Some(Err(why)) => refusal_of(why),
            _ => None,
        };
        match refused {
            Some(code) => Err(code),
            None => Ok(Self::owned(text)),
        }
    }

    /// The key.
    pub(crate) fn as_str(&self) -> &str {
        self.key.as_str()
    }

    /// Another holder of the same text: one more holder of the block for a key of the arena, a
    /// copy for one of its own.
    #[inline(never)]
    pub(crate) fn share(&self) -> Self {
        if let Some(engine) = &self.engine {
            // An engine that keeps no key arena made no key of one; a copy reads the same.
            if let Some(Ok(Some(key))) = engine
                .key_arena()
                .map(|keys| keys.key(KeyAsk::Share(&self.key)))
            {
                return Self {
                    key: ManuallyDrop::new(key),
                    engine: Some(engine.clone()),
                };
            }
        }
        Self::owned(self.as_str())
    }

    /// Whether the text is a block of the session's key arena.
    #[cfg(test)]
    fn is_session(&self) -> bool {
        self.engine.is_some()
    }
}

impl Drop for KeyText {
    #[inline(never)]
    fn drop(&mut self) {
        // SAFETY: the key is taken here, once, and the field is not read again.
        let key = unsafe { ManuallyDrop::take(&mut self.key) };
        match self.engine.take() {
            Some(engine) => {
                if let Some(keys) = engine.key_arena() {
                    let _ = keys.key(KeyAsk::Release(key));
                }
            }
            // SAFETY: with no engine the key is a copy of its own (`Self::owned`), freed here once.
            None => unsafe { key.free_own() },
        }
    }
}

/// The code a key the session kept no room for is refused with, as zenoh-pico refuses what its heap
/// cannot hold; `None` for a closed session, whose object keeps a copy of its own as it keeps
/// nothing more.
fn refusal_of(why: KeyNotHeld) -> Option<ZResult> {
    match why {
        KeyNotHeld::TooLong => Some(Z_EINVAL),
        KeyNotHeld::NoRoom => Some(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY),
        KeyNotHeld::Closed => None,
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
/// `z_owned_keyexpr_t::_start` points at the key's text where it is kept, a block
/// of the session's key arena or a `String`'s heap buffer, either of which is
/// stable when the `Box` moves (the same distinction `crate::bytes` documents for
/// `StringState`).
pub(crate) struct DeclaredKeyexpr {
    literal: KeyText,
    declaration: Option<WireDeclaration>,
}

impl DeclaredKeyexpr {
    /// A key with no declaration.
    pub(crate) fn literal_only(literal: &str) -> Self {
        Self {
            literal: KeyText::owned(literal),
            declaration: None,
        }
    }

    /// The literal key.
    pub(crate) fn literal(&self) -> &str {
        self.literal.as_str()
    }

    /// Another holder of the declaration that covers a prefix of the key, if any, without the
    /// key's text: what keeps the declaration on the session for something that names the key by
    /// it.
    pub(crate) fn declaration_hold(&self) -> Option<WireDeclaration> {
        self.declaration.clone()
    }

    /// Another holder of the literal key's text, without the declaration.
    pub(crate) fn share_text(&self) -> KeyText {
        self.literal.share()
    }

    /// A borrow of this key in the loaned layout, carrying the declaration so a
    /// caller that publishes on it aliases as pico's `z_publisher_keyexpr` loan
    /// does. Valid while `self` stays at its address.
    pub(crate) fn loaned(&self) -> z_loaned_keyexpr_t {
        z_loaned_keyexpr_t {
            _start: self.literal().as_ptr(),
            _len: self.literal().len(),
            _handle: self as *const Self as *mut c_void,
            _mapping: 0,
        }
    }

    /// Another key sharing this one's literal and declaration — pico
    /// `_z_declared_keyexpr_copy`, which clones the refcount.
    pub(crate) fn share(&self) -> Self {
        Self {
            literal: self.literal.share(),
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
    pub(crate) fn extended(&self, literal: &str) -> Self {
        let declaration = self.declaration.clone().filter(|d| {
            literal.get(..d.prefix_len).is_some()
                && literal.get(..d.prefix_len) == self.literal().get(..d.prefix_len)
        });
        Self {
            literal: KeyText::owned(literal),
            declaration,
        }
    }

    fn declared_on(&self, shared: &Engine) -> Option<&WireDeclaration> {
        self.declaration
            .as_ref()
            // By ADDRESS: both are fat pointers to one engine, and their vtable halves are
            // not guaranteed to be one copy, so comparing them whole could say a session is
            // not itself.
            .filter(|d| d.hold.is_on((shared as *const Engine).cast::<()>()))
    }

    /// pico `_z_declared_keyexpr_alias_to_wire`: the declaration's id and the
    /// remainder of the key when the declaration is `shared`'s, the literal
    /// otherwise.
    ///
    /// An aliased key KEEPS its declaration: whatever records it — a registry
    /// entry replayed onto later faces — holds the id declared for as long as
    /// it names it.
    pub(crate) fn wire(&self, shared: &Engine) -> WireKey {
        // Every constructor keeps the declared prefix at the front of the
        // literal (see `extended`), so the remainder always exists; the `get`
        // turns a broken invariant into the literal rather than a panic.
        match self
            .declared_on(shared)
            .and_then(|d| Some((d, self.literal().get(d.prefix_len..)?)))
        {
            Some((d, rest)) => WireKey::aliased(
                d.hold.mapping_id(),
                (!rest.is_empty()).then(|| rest.to_owned()),
            )
            .holding(d.hold.clone()),
            None => WireKey::literal(),
        }
    }

    /// What an entity held on this key names when it retracts itself, or `None`
    /// when it retracts by id alone, on a session whose role is `mode` and whose
    /// registry is `shared`: the two facts it reads, which a door has in the
    /// session's handle and a composite that holds the registry WEAKLY has apart.
    ///
    /// pico names the entity's OWN key in every mode but client (`vendor/zenoh-pico/src/net/primitives.c`
    /// @ `_z_wireexpr_t expr = _z_declared_keyexpr_alias_to_wire(&_Z_RC_IN_VAL(&s)->_key, zn);`),
    /// and that key is the one this is called on: for a subscriber it is not
    /// the key the subscription was announced on, which is the caller's.
    pub(crate) fn retraction_naming_in(
        &self,
        mode: WhatAmI,
        shared: &Engine,
    ) -> Option<RetractionKey> {
        if mode == WhatAmI::Client {
            return None;
        }
        Some(self.retraction_key(shared))
    }

    /// This key as a retraction names it: its declaration and the rest of the key, or the
    /// literal when nothing covers it. A token's retraction names it in every mode
    /// (`vendor/zenoh-pico/src/net/liveliness.c` @
    /// `_z_declaration_t declaration = _z_make_undecl_token(id, &wireexpr);`).
    pub(crate) fn retraction_key(&self, shared: &Engine) -> RetractionKey {
        let wire = self.wire(shared);
        if wire.mapping_id == 0 {
            RetractionKey {
                mapping_id: 0,
                suffix: self.literal().to_owned(),
            }
        } else {
            RetractionKey {
                mapping_id: wire.mapping_id,
                suffix: wire.suffix.unwrap_or_default(),
            }
        }
    }

    /// pico `_z_declared_keyexpr_declare`: a key whose declaration covers ALL
    /// of it on `shared`, sharing the caller's when it already does.
    pub(crate) fn declare(
        shared: &Arc<Engine>,
        literal: &str,
        existing: Option<&DeclaredKeyexpr>,
    ) -> Result<Self, ZResult> {
        Self::declare_up_to(shared, literal, existing, literal)
    }

    /// pico `_z_declared_keyexpr_declare_non_wild_prefix`: the same, covering
    /// only the part of the key before its first wild chunk.
    pub(crate) fn declare_non_wild_prefix(
        shared: &Arc<Engine>,
        literal: &str,
        existing: Option<&DeclaredKeyexpr>,
    ) -> Result<Self, ZResult> {
        Self::declare_up_to(shared, literal, existing, non_wild_prefix(literal))
    }

    /// `literal` declared on `shared` up to `prefix`, a prefix of it (the whole key or its
    /// non-wild prefix), named as text so that no length is cut out of the key by index.
    fn declare_up_to(
        shared: &Arc<Engine>,
        literal: &str,
        existing: Option<&DeclaredKeyexpr>,
        prefix: &str,
    ) -> Result<Self, ZResult> {
        let prefix_len = prefix.len();
        // A key the session's tables cannot hold is refused before anything is declared.
        if !fits(literal) {
            return Err(Z_EINVAL);
        }
        // Already optimized on THIS session to exactly this prefix: share it
        // (pico's `_z_declared_keyexpr_is_fully_optimized` /
        // `_is_non_wild_prefix_optimized` arm).
        if let Some(existing) = existing {
            if existing
                .declared_on(Arc::as_ref(shared))
                .is_some_and(|d| d.prefix_len == prefix_len)
            {
                return Ok(existing.share());
            }
        }
        // The key is kept before anything is declared, so one the session's key arena has no room
        // for is refused having sent nothing; a declaration that covers it whole finds its block
        // and shares it.
        let text = KeyText::of_session(shared, literal)?;
        // pico `_z_keyexpr_declare_prefix`: an empty prefix declares nothing.
        // Its multicast skip has no counterpart here — this ABI's sessions are
        // unicast.
        if prefix_len == 0 {
            return Ok(Self {
                literal: text,
                declaration: None,
            });
        }
        // A refused declaration sent nothing, and answers pico's code for its cause; the key goes
        // back with `text`.
        let id = shared.acquire_keyexpr(prefix).map_err(|refused| {
            crate::result::refusal_code(refused, crate::result::Door::Keyexpr)
        })?;
        Ok(Self {
            literal: text,
            declaration: Some(WireDeclaration {
                hold: KeyHold::taken(engine_hold_of(shared), id),
                prefix_len,
            }),
        })
    }
}

/// The session `shared` as a key's hold names it: weakly, through the engine's door for keys.
fn engine_hold_of(shared: &Arc<Engine>) -> Weak<dyn wz_capi_port::SessionEngine> {
    // The engine's own type named, so the downgrade is of it and the coercion to the door's
    // object follows it, on an engine of a concrete type and on the door's object alike.
    Arc::<Engine>::downgrade(shared)
}

/// pico `_z_keyexpr_non_wild_prefix_len`, as the prefix itself: the key up to the `/` before
/// the first `*`, the whole key when there is none, empty when the key opens wild.
///
/// The prefix ends at an ASCII byte or at the key's end, both boundaries of the text, so `get`
/// always answers it; taking it by `get` rather than by index leaves the declaration no path
/// to the formatter of a failed slice.
fn non_wild_prefix(literal: &str) -> &str {
    let bytes = literal.as_bytes();
    let len = match bytes.iter().position(|&b| b == b'*') {
        Some(star) => bytes
            .get(..star)
            .and_then(|head| head.iter().rposition(|&b| b == b'/'))
            .unwrap_or(0),
        None => bytes.len(),
    };
    literal.get(..len).unwrap_or_default()
}

/// Whether `text` is a key expression in canon form, as pico's
/// `_z_keyexpr_is_canon` answers it: valid, and already what canonizing it
/// would produce. The one judgement behind [`z_keyexpr_is_canon`], the two
/// checked view constructors and the checked owned constructor.
fn is_pico_canon(text: &str) -> bool {
    // Judged without writing the canonical form, so a view of a key allocates nothing.
    wz_session_core::keyexpr_canon::is_canon(
        text,
        wz_session_core::keyexpr_canon::KeyexprDialect::Pico,
    )
}

/// Build a view keyexpr borrowing the caller's C string (pico
/// `z_view_keyexpr_from_str`). The keyexpr must be valid UTF-8 and in canon
/// form; the caller keeps `name` alive for the view's lifetime.
///
/// A text that is not canon is refused with `Z_EINVAL`, as pico's documented
/// contract says ("This function will fail if the string is not in canon
/// form", `vendor/zenoh-pico/include/zenoh-pico/api/primitives.h` @
/// `z_result_t z_view_keyexpr_from_str(`) and its body does
/// (`vendor/zenoh-pico/src/api/api.c` @
/// `if (_z_keyexpr_is_canon(name, len) != Z_KEYEXPR_CANON_SUCCESS) {`). Before
/// it, `a//b` and `a/b/` were viewed, declared and published under where pico
/// refuses them at this call.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_from_str(
    keyexpr: *mut z_view_keyexpr_t,
    name: *const c_char,
) -> ZResult {
    // pico's is the substring form over the string's length, and so is this one, so the two
    // judge a text through one body.
    z_view_keyexpr_from_substr(keyexpr, name, c_str_len(name))
}

/// The length of the C string at `name`, `0` for a null one: what each `_from_str` door of a key
/// hands its substring form.
///
/// # Safety
/// `name` must be null or a valid NUL-terminated string.
unsafe fn c_str_len(name: *const c_char) -> usize {
    if name.is_null() {
        0
    } else {
        CStr::from_ptr(name).to_bytes().len()
    }
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
    z_view_keyexpr_from_substr_unchecked(keyexpr, name, c_str_len(name));
}

/// Build a view keyexpr borrowing `len` bytes of the caller's buffer (pico
/// `z_view_keyexpr_from_substr`).
///
/// The substring form exists because a keyexpr is frequently a SLICE of a
/// larger buffer a program already holds — `z_querier.c` builds
/// `demo/example/**` and then re-views a prefix of it — and copying to
/// NUL-terminate would defeat the whole point of a borrowing view.
///
/// UTF-8 and canon form are validated over exactly those `len` bytes, matching
/// the checked [`z_view_keyexpr_from_str`] (which pico implements as this
/// function): a view this crate stores must be readable as `&str` at every
/// later publish, and a text that is not canon is refused with `Z_EINVAL`.
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
        let bytes = core::slice::from_raw_parts(name.cast::<u8>(), len);
        let Ok(text) = core::str::from_utf8(bytes) else {
            return Z_ERR_INVALID;
        };
        if !is_pico_canon(text) {
            return Z_EINVAL;
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
        let bytes = core::slice::from_raw_parts(name.cast::<u8>(), len);
        if core::str::from_utf8(bytes).is_err() {
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
            _start: core::ptr::null(),
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
/// Returns `_Z_ERR_SYSTEM_OUT_OF_MEMORY` when the session holds no more declarations:
/// its table of them is at the `MAX_DECLARED_KEYEXPRS` it opened under, or the wire's
/// alias space is exhausted. Refusing beats wrapping: a reused id would silently
/// re-point a peer's live alias at a different keyexpr.
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
        let state = match session_handle(zs) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        let Some(literal) = keyexpr_str(keyexpr) else {
            return Z_ERR_INVALID;
        };
        // The key's place is taken before it is declared, so a full pool refuses the key and
        // nothing is declared.
        let Some(slot) = crate::object_slot::Slot::take(crate::object_slot::Kind::Keyexpr) else {
            return crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY;
        };
        match DeclaredKeyexpr::declare(&engine_of(state), literal, declared_of(keyexpr)) {
            Ok(key) => {
                owned_keyexpr_at(declared, slot.fill(key));
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
        // Its place goes back as `key` drops, wherever it lies.
        let Some(key) = crate::object_slot::Placed::from_raw(handle as *mut DeclaredKeyexpr) else {
            return Z_ERR_INVALID;
        };
        let Some(state) = session_handle(zs) else {
            return Z_ERR_NULL;
        };
        if key.declaration.is_none() {
            Z_ERR_INVALID
        } else if key.declared_on(engine_ref(state)).is_none() {
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
    core::ptr::copy_nonoverlapping(&(*src)._this, dst, 1);
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
            // A declared key's place is a pool's, another's the heap's: `release` gives it back to
            // whichever it lies in.
            crate::object_slot::release(handle as *mut DeclaredKeyexpr);
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
// `wz_session_core::keyexpr_canon`'s one walk and the set relations
// through `wz_session_core::keyexpr_match`, which are the SSOTs the wire path
// and the R300 outbound gate already use — a second reading of the grammar
// here would be a copy that drifts from the one the wire obeys, and the
// drift would be invisible to every test that reads only this copy.

/// pico `z_keyexpr_intersection_level_t` (`api/constants.h:112-117`).
pub type z_keyexpr_intersection_level_t = core::ffi::c_int;
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
    owned_keyexpr_at(dst, Box::into_raw(Box::new(key)));
}

/// Write into `dst` the owned keyexpr whose key lies at `key`, a place of its own: a pool's slot
/// for a key the program declared (`z_declare_keyexpr`), the heap's for the rest.
///
/// # Safety
/// `dst` is valid and writable; `key` is a live key a [`crate::object_slot::Slot`] was filled
/// with or a `Box` made, which `dst` then owns.
unsafe fn owned_keyexpr_at(dst: *mut z_owned_keyexpr_t, key: *mut DeclaredKeyexpr) {
    let literal = (*key).literal();
    *dst = z_owned_keyexpr_t {
        _start: literal.as_ptr(),
        _len: literal.len(),
        _handle: key as *mut c_void,
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
    z_keyexpr_from_substr(keyexpr, name, c_str_len(name))
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
        if !is_pico_canon(text) {
            return Z_ERR_INVALID;
        }
        if !fits(text) {
            return Z_EINVAL;
        }
        store_owned_keyexpr(keyexpr, DeclaredKeyexpr::literal_only(text));
        Z_OK
    })
}

/// Build an owned keyexpr from a NUL-terminated string, CANONIZING it first
/// (pico `z_keyexpr_from_str_autocanonize`): the substring form over the string's
/// length, as pico's is.
///
/// # Safety
/// As [`z_keyexpr_from_str`].
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_from_str_autocanonize(
    keyexpr: *mut z_owned_keyexpr_t,
    name: *const c_char,
) -> ZResult {
    let mut len = c_str_len(name);
    z_keyexpr_from_substr_autocanonize(keyexpr, name, &mut len)
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
        // The form is written where the key's text is made from, as long as the bound: a text of
        // any length is read, and only a form past the bound is refused.
        let mut form = [0u8; wz_session_core::caps::MAX_KEYEXPR_BYTES];
        match wz_session_core::keyexpr_canon::canonize_into(
            text,
            &mut form,
            wz_session_core::keyexpr_canon::KeyexprDialect::Pico,
        ) {
            Ok(written) => {
                // The form of UTF-8 is UTF-8 (`canonize_into`).
                let Some(canon) = form
                    .get(..written)
                    .and_then(|bytes| core::str::from_utf8(bytes).ok())
                else {
                    return Z_ERR_INVALID;
                };
                *len = written;
                store_owned_keyexpr(keyexpr, DeclaredKeyexpr::literal_only(canon));
                Z_OK
            }
            Err(KeyexprCanonError::ExceedsCapacity) => Z_EINVAL,
            Err(_) => Z_ERR_INVALID,
        }
    })
}

/// Null `keyexpr` and read `name[..len]` as UTF-8 where it lies, or `None` on any bad
/// input. The owned key is made from it once, where it is stored, so nothing is copied to read it.
///
/// Shared by the owned constructors so the "null the destination FIRST"
/// discipline cannot drift between them: a constructor that failed without
/// nulling would leave the caller's stack value looking live.
///
/// # Safety
/// `keyexpr` must be null or valid and writable; `name` must be null or point at `len`
/// readable bytes, which outlive the answer.
unsafe fn owned_keyexpr_input<'a>(
    keyexpr: *mut z_owned_keyexpr_t,
    name: *const c_char,
    len: usize,
) -> Option<&'a str> {
    if keyexpr.is_null() {
        return None;
    }
    *keyexpr = z_owned_keyexpr_t::null_value();
    if name.is_null() {
        return None;
    }
    let bytes = core::slice::from_raw_parts(name as *const u8, len);
    core::str::from_utf8(bytes).ok()
}

/// Copy a keyexpr into an owned one (pico `z_keyexpr_clone`, which is
/// `_z_declared_keyexpr_copy`).
///
/// R2959 — the clone SHARES the source's declaration. This used to make every
/// clone a literal, on the argument that a clone carrying the id would publish
/// on a declaration it held no reference to. The declaration is held now
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
            None => DeclaredKeyexpr::literal_only(text),
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
            (*src)._start = core::ptr::null();
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
            match core::str::from_utf8(core::slice::from_raw_parts(right as *const u8, len)) {
                Ok(t) => t,
                Err(_) => return Z_ERR_INVALID,
            }
        };
        store_joined(key, left, &[head.as_bytes(), tail.as_bytes()])
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
        Some(declared) => declared.extended(literal),
        None => DeclaredKeyexpr::literal_only(literal),
    }
}

/// The body `z_keyexpr_concat` and `z_keyexpr_join` share, out of line so neither export holds a
/// copy of it: the text `parts` make, read in order where each lies, canonized into a buffer of
/// the bound and stored in `key` keeping `left`'s declaration ([`extended_from`]). The bound every
/// key of this build is held to is held to the form and not to the text, as pico keeps only the
/// form: a long text whose form is short is a key, and a form past the bound is refused with
/// `Z_EINVAL`. The join takes no allocation and no copy of its text.
///
/// # Safety
/// `key` must be valid and writable; `left` must be null or a live loaned keyexpr.
#[inline(never)]
unsafe fn store_joined(
    key: *mut z_owned_keyexpr_t,
    left: *const z_loaned_keyexpr_t,
    parts: &[&[u8]],
) -> ZResult {
    let mut form = [0u8; wz_session_core::caps::MAX_KEYEXPR_BYTES];
    let written = match wz_session_core::keyexpr_canon::canonize_parts_into(
        parts,
        &mut form,
        wz_session_core::keyexpr_canon::KeyexprDialect::Pico,
    ) {
        Ok(written) => written,
        Err(KeyexprCanonError::ExceedsCapacity) => return Z_EINVAL,
        Err(_) => return Z_ERR_INVALID,
    };
    // The parts are whole `str` values, and the form of UTF-8 is UTF-8.
    let Some(canon) = form
        .get(..written)
        .and_then(|bytes| core::str::from_utf8(bytes).ok())
    else {
        return Z_ERR_INVALID;
    };
    store_owned_keyexpr(key, extended_from(left, canon));
    Z_OK
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
        store_joined(key, left, &[l.as_bytes(), b"/".as_slice(), r.as_bytes()])
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
    guard_val(false, || keyexpr_pair(l, r).is_some_and(|(a, b)| a == b))
}

/// The texts of two loaned keyexprs, or `None` when either is null or not UTF-8: what each door
/// that compares two keys reads, through one body.
///
/// # Safety
/// `l` / `r` must be null or live loaned keyexprs.
#[inline(never)]
unsafe fn keyexpr_pair<'a>(
    l: *const z_loaned_keyexpr_t,
    r: *const z_loaned_keyexpr_t,
) -> Option<(&'a str, &'a str)> {
    Some((keyexpr_str(l)?, keyexpr_str(r)?))
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
    guard_val(false, || {
        keyexpr_pair(l, r)
            .is_some_and(|(a, b)| wz_session_core::keyexpr_match::keyexpr_includes(a, b))
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
    guard_val(false, || {
        keyexpr_pair(l, r)
            .is_some_and(|(a, b)| wz_session_core::keyexpr_match::keyexpr_intersects(a, b))
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
        // The two texts are read once, and the cascade asks of them.
        let Some((a, b)) = keyexpr_pair(left, right) else {
            return Z_KEYEXPR_INTERSECTION_LEVEL_DISJOINT;
        };
        if a == b {
            Z_KEYEXPR_INTERSECTION_LEVEL_EQUALS
        } else if wz_session_core::keyexpr_match::keyexpr_includes(a, b) {
            Z_KEYEXPR_INTERSECTION_LEVEL_INCLUDES
        } else if wz_session_core::keyexpr_match::keyexpr_intersects(a, b) {
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
        let Ok(text) = core::str::from_utf8(core::slice::from_raw_parts(start as *const u8, len))
        else {
            return Z_ERR_INVALID;
        };
        if is_pico_canon(text) {
            Z_OK
        } else {
            Z_ERR_INVALID
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
fn pico_canon_status(err: &wz_session_core::keyexpr_canon::KeyexprCanonError) -> ZResult {
    use wz_session_core::keyexpr_canon::KeyexprCanonError as E;
    match err {
        E::EmptyChunk => -4,
        E::StarsInChunk => -5,
        E::DollarAfterDollarOrStar => -6,
        E::ContainsSharpOrQmark => -7,
        E::ContainsUnboundDollar => -8,
        // A form past a buffer it is written into, which pico, bounding no key, has no status
        // for: a generic failure is the honest answer rather than one it defines. The in-place
        // canonizer, which bounds nothing, never answers it.
        E::ExceedsCapacity => Z_ERR_GENERIC,
    }
}

#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_canonize(start: *mut c_char, len: *mut usize) -> ZResult {
    guarded(|| {
        if start.is_null() || len.is_null() {
            return Z_ERR_NULL;
        }
        let text = core::slice::from_raw_parts_mut(start as *mut u8, *len);
        if core::str::from_utf8(text).is_err() {
            return Z_ERR_INVALID;
        }
        // Over the caller's own bytes, as pico canonizes them, of any length: the form never
        // grows, so it takes no buffer and no bound.
        match wz_session_core::keyexpr_canon::canonize_in_place(
            text,
            wz_session_core::keyexpr_canon::KeyexprDialect::Pico,
        ) {
            Ok(written) => {
                *len = written;
                Z_OK
            }
            Err(err) => pico_canon_status(&err),
        }
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
mod door_reading_tests {
    use super::*;

    /// A view over `text`, made without the checks, so a test can hand a door a key the
    /// checked constructors refuse.
    fn unchecked(text: &core::ffi::CStr) -> z_view_keyexpr_t {
        let mut view = z_view_keyexpr_t {
            _start: core::ptr::null(),
            _len: 0,
            _pad: [0usize; 4],
        };
        // SAFETY: a live view of this frame and a C string that outlives it.
        unsafe { z_view_keyexpr_from_str_unchecked(&mut view, text.as_ptr()) };
        view
    }

    /// The key a declaration or a get names is read through one gate: a canon key is read where
    /// it lies, and no key, an empty one and one with an empty chunk are `Z_ERR_INVALID`.
    #[test]
    fn the_outbound_gate_reads_a_canon_key_and_refuses_the_rest() {
        let canon = unchecked(c"demo/a/**");
        let empty_chunk = unchecked(c"demo//a");
        // SAFETY: views of this frame, and a null pointer.
        unsafe {
            let read = outbound_keyexpr(z_view_keyexpr_loan(&canon)).expect("a canon key");
            assert_eq!(read, "demo/a/**");
            assert_eq!(read.as_ptr(), canon._start, "read where the view holds it");
            assert_eq!(
                outbound_keyexpr(z_view_keyexpr_loan(&empty_chunk)),
                Err(Z_ERR_INVALID)
            );
            assert_eq!(outbound_keyexpr(core::ptr::null()), Err(Z_ERR_INVALID));
        }
    }

    /// The C string forms of the view constructors judge a text as their substring forms do:
    /// a canon key is viewed whole, one that is not canon is `Z_EINVAL`, no text is `Z_ERR_NULL`
    /// for the checked form and an empty view for the unchecked one.
    #[test]
    fn the_string_views_judge_as_the_substring_views() {
        let mut view = unchecked(c"x");
        // SAFETY: a live view of this frame, and C strings that outlive it.
        unsafe {
            assert_eq!(z_view_keyexpr_from_str(&mut view, c"a/b".as_ptr()), Z_OK);
            assert_eq!(view._len, 3);
            assert_eq!(
                z_view_keyexpr_from_str(&mut view, c"a//b".as_ptr()),
                Z_EINVAL
            );
            assert_eq!(
                z_view_keyexpr_from_str(&mut view, core::ptr::null()),
                Z_ERR_NULL
            );
            z_view_keyexpr_from_str_unchecked(&mut view, core::ptr::null());
            assert!(z_view_keyexpr_is_empty(&view));
        }
    }

    /// Two keys are compared through one reading of both: equal, including, intersecting and
    /// disjoint keys each have their relation, and a key that is absent relates to nothing.
    #[test]
    fn two_keys_are_read_once_and_related_strongest_first() {
        let ab = unchecked(c"a/b");
        let any = unchecked(c"a/**");
        let star_c = unchecked(c"a/*/c");
        let b_star = unchecked(c"a/b/*");
        let other = unchecked(c"z");
        let relation = |l: &z_view_keyexpr_t, r: &z_view_keyexpr_t| {
            // SAFETY: views of this frame.
            unsafe { z_keyexpr_relation_to(z_view_keyexpr_loan(l), z_view_keyexpr_loan(r)) }
        };
        assert_eq!(relation(&ab, &ab), Z_KEYEXPR_INTERSECTION_LEVEL_EQUALS);
        assert_eq!(relation(&any, &ab), Z_KEYEXPR_INTERSECTION_LEVEL_INCLUDES);
        assert_eq!(
            relation(&star_c, &b_star),
            Z_KEYEXPR_INTERSECTION_LEVEL_INTERSECTS
        );
        assert_eq!(relation(&ab, &other), Z_KEYEXPR_INTERSECTION_LEVEL_DISJOINT);
        // SAFETY: a view of this frame and a null pointer.
        unsafe {
            let ab = z_view_keyexpr_loan(&ab);
            assert_eq!(
                z_keyexpr_relation_to(ab, core::ptr::null()),
                Z_KEYEXPR_INTERSECTION_LEVEL_DISJOINT
            );
            assert!(z_keyexpr_equals(ab, ab));
            assert!(!z_keyexpr_equals(ab, core::ptr::null()));
            assert!(z_keyexpr_includes(z_view_keyexpr_loan(&any), ab));
            assert!(!z_keyexpr_includes(ab, z_view_keyexpr_loan(&any)));
            assert!(z_keyexpr_intersects(
                z_view_keyexpr_loan(&star_c),
                z_view_keyexpr_loan(&b_star)
            ));
            assert!(!z_keyexpr_intersects(ab, z_view_keyexpr_loan(&other)));
        }
    }
}

// Their engine is the tokio engine's face registry, which a cooperative build does not have.
#[cfg(all(test, feature = "engine-tokio"))]
mod tests {
    use super::*;

    fn session() -> Arc<Engine> {
        Arc::new(
            wz_capi_core::faces::SharedSession::new(
                wz_capi_core::runtime::runtime_impl::TokioTime::new(),
                [0x5a; 16].into(),
                wz_session_core::policy::SessionPolicy::defaults(),
            )
            .expect("test host entropy"),
        )
        .as_engine()
    }

    /// The checked view constructors refuse what pico refuses: a text that is
    /// not in canon form (an empty chunk inside, at the end or at the start, a
    /// spelling canonizing would change) is `Z_EINVAL` from both, and a canon
    /// one, wildcards included, is viewed. The substring form judges exactly its
    /// `len` bytes, so a canon prefix of a text that is not canon is viewed.
    #[test]
    fn the_checked_views_refuse_a_text_not_in_canon_form() {
        let view = |text: &str| unsafe {
            let c = alloc::ffi::CString::new(text).unwrap();
            let mut out: z_view_keyexpr_t = core::mem::zeroed();
            z_view_keyexpr_from_str(&mut out, c.as_ptr())
        };
        let view_substr = |text: &str, len: usize| unsafe {
            let mut out: z_view_keyexpr_t = core::mem::zeroed();
            z_view_keyexpr_from_substr(&mut out, text.as_ptr().cast(), len)
        };
        for refused in [
            "zenoh//test",
            "zenoh/test/",
            "/zenoh/test",
            "a/**/*",
            "a/$*",
        ] {
            assert_eq!(view(refused), Z_EINVAL, "{refused} is not canon");
            assert_eq!(
                view_substr(refused, refused.len()),
                Z_EINVAL,
                "{refused} is not canon"
            );
        }
        for viewed in ["zenoh/test", "zenoh/test/*", "a/*/**", "demo/$*x"] {
            assert_eq!(view(viewed), Z_OK, "{viewed} is canon");
            assert_eq!(view_substr(viewed, viewed.len()), Z_OK, "{viewed} is canon");
        }
        assert_eq!(view_substr("zenoh/test/", "zenoh/test".len()), Z_OK);
    }

    /// R2959 — pico's `_z_keyexpr_non_wild_prefix_len`, case by case: up to the
    /// `/` before the first `*`, the whole key without one, nothing when the
    /// key opens wild.
    #[test]
    fn the_non_wild_prefix_stops_at_the_chunk_before_the_first_star() {
        assert_eq!(non_wild_prefix("demo/kd/sub/**"), "demo/kd/sub");
        assert_eq!(non_wild_prefix("demo/kd/qbl/*/x"), "demo/kd/qbl");
        assert_eq!(non_wild_prefix("demo/kd/pub"), "demo/kd/pub");
        assert_eq!(non_wild_prefix("**"), "");
        assert_eq!(non_wild_prefix("a/b$*/c"), "a");
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
        let wire = key.wire(Arc::as_ref(&shared));
        assert_eq!(wire.mapping_id, declarations[0].0);
        assert_eq!(wire.suffix.as_deref(), Some("/*/x"));

        let other = session();
        assert_eq!(
            key.wire(&*other).mapping_id,
            0,
            "another session's id is not ours"
        );
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::non_wild_prefix;

    /// The non-wild prefix is cut at the `/` before the first `*` whatever the chunks before
    /// it hold, multi-byte characters included, and is the whole key or nothing at the two ends.
    #[test]
    fn the_non_wild_prefix_is_cut_at_a_boundary_of_the_text() {
        assert_eq!(
            non_wild_prefix("d\u{e9}mo/\u{d55c}/sub/**"),
            "d\u{e9}mo/\u{d55c}/sub"
        );
        assert_eq!(non_wild_prefix("\u{d55c}/*"), "\u{d55c}");
        assert_eq!(non_wild_prefix("\u{d55c}\u{ae00}"), "\u{d55c}\u{ae00}");
        assert_eq!(non_wild_prefix("*/a"), "");
        assert_eq!(non_wild_prefix("a*/b"), "");
        assert_eq!(non_wild_prefix(""), "");
    }
}

#[cfg(test)]
mod bound_tests {
    //! The longest key a session's tables hold bounds every key this ABI makes: one past it is a
    //! value the build cannot take, refused with `Z_EINVAL` and nothing left behind.
    use super::*;
    use wz_session_core::caps::MAX_KEYEXPR_BYTES;

    /// A canon key of exactly `len` bytes: chunks of `a` under `/`, never ending in one.
    fn key_of(len: usize) -> String {
        let mut key = String::with_capacity(len);
        while key.len() < len {
            key.push(if key.len() % 8 == 7 && key.len() + 1 < len {
                '/'
            } else {
                'a'
            });
        }
        key
    }

    /// An owned key made from `text`, and the code its constructor answered.
    unsafe fn owned(text: &str) -> (ZResult, z_owned_keyexpr_t) {
        let mut key = z_owned_keyexpr_t::null_value();
        let rc = z_keyexpr_from_substr(&mut key, text.as_ptr() as *const c_char, text.len());
        (rc, key)
    }

    /// A key of the bound itself is taken; one byte past it is refused and the destination is
    /// left null.
    #[test]
    fn a_key_one_byte_past_the_bound_is_refused() {
        unsafe {
            let (at, mut key) = owned(&key_of(MAX_KEYEXPR_BYTES));
            assert_eq!(at, Z_OK, "a key of the bound itself is taken");
            z_keyexpr_drop(z_keyexpr_move(&mut key));
            let (past, refused) = owned(&key_of(MAX_KEYEXPR_BYTES + 1));
            assert_eq!(past, Z_EINVAL);
            assert!(
                !z_internal_keyexpr_check(&refused),
                "nothing is left behind"
            );
        }
    }

    /// A join that lands on the bound is made; one byte more is refused, as is a concatenation
    /// that would pass it, each leaving its destination null.
    #[test]
    fn a_join_that_would_pass_the_bound_is_refused() {
        let half = MAX_KEYEXPR_BYTES / 2;
        unsafe {
            let (rc_left, mut left) = owned(&key_of(half));
            let (rc_right, mut right) = owned(&key_of(MAX_KEYEXPR_BYTES - half - 1));
            let (rc_wider, mut wider) = owned(&key_of(MAX_KEYEXPR_BYTES - half));
            assert_eq!((rc_left, rc_right, rc_wider), (Z_OK, Z_OK, Z_OK));

            let mut joined = z_owned_keyexpr_t::null_value();
            assert_eq!(
                z_keyexpr_join(&mut joined, z_keyexpr_loan(&left), z_keyexpr_loan(&right)),
                Z_OK,
                "left, the separator and right are the bound exactly"
            );
            z_keyexpr_drop(z_keyexpr_move(&mut joined));

            let mut past = z_owned_keyexpr_t::null_value();
            assert_eq!(
                z_keyexpr_join(&mut past, z_keyexpr_loan(&left), z_keyexpr_loan(&wider)),
                Z_EINVAL
            );
            assert!(!z_internal_keyexpr_check(&past), "nothing is left behind");

            let (rc_full, mut full) = owned(&key_of(MAX_KEYEXPR_BYTES));
            assert_eq!(rc_full, Z_OK);
            let tail = "/b";
            let mut concat = z_owned_keyexpr_t::null_value();
            assert_eq!(
                z_keyexpr_concat(
                    &mut concat,
                    z_keyexpr_loan(&full),
                    tail.as_ptr() as *const c_char,
                    tail.len(),
                ),
                Z_EINVAL
            );
            assert!(!z_internal_keyexpr_check(&concat), "nothing is left behind");

            for key in [&mut left, &mut right, &mut wider, &mut full] {
                z_keyexpr_drop(z_keyexpr_move(key));
            }
        }
    }

    /// A concatenation is held to the bound once it is canonized, not before: a text past the bound
    /// whose form is under it is a key, the lone `$*` chunk canonized, and a form past the bound is
    /// refused with the destination left null. Turned red by a bound judged on the text.
    #[test]
    fn a_concatenation_is_held_to_the_bound_once_it_is_canonized() {
        unsafe {
            let (rc, mut left) = owned(&key_of(MAX_KEYEXPR_BYTES - 10));
            assert_eq!(rc, Z_OK);
            let long = "/$*$*$*$*$*$*";
            assert!(MAX_KEYEXPR_BYTES - 10 + long.len() > MAX_KEYEXPR_BYTES);
            let mut concat = z_owned_keyexpr_t::null_value();
            assert_eq!(
                z_keyexpr_concat(
                    &mut concat,
                    z_keyexpr_loan(&left),
                    long.as_ptr() as *const c_char,
                    long.len(),
                ),
                Z_OK
            );
            let made = keyexpr_str(z_keyexpr_loan(&concat)).expect("a key");
            assert_eq!(made.len(), MAX_KEYEXPR_BYTES - 10 + 2);
            assert!(made.ends_with("/*"), "the lone `$*` chunk is canonized");
            z_keyexpr_drop(z_keyexpr_move(&mut concat));

            // A suffix longer than two keys of the bound is read where it lies, whatever its
            // length: only its form is held to the bound.
            let (rc, mut short) = owned("a");
            assert_eq!(rc, Z_OK);
            let longer = "/**".repeat(3 * MAX_KEYEXPR_BYTES);
            assert_eq!(
                z_keyexpr_concat(
                    &mut concat,
                    z_keyexpr_loan(&short),
                    longer.as_ptr() as *const c_char,
                    longer.len(),
                ),
                Z_OK
            );
            assert_eq!(keyexpr_str(z_keyexpr_loan(&concat)), Some("a/**"));
            z_keyexpr_drop(z_keyexpr_move(&mut concat));
            z_keyexpr_drop(z_keyexpr_move(&mut short));

            let (rc, mut full) = owned(&key_of(MAX_KEYEXPR_BYTES - 1));
            assert_eq!(rc, Z_OK);
            let past = "/b";
            assert_eq!(
                z_keyexpr_concat(
                    &mut concat,
                    z_keyexpr_loan(&full),
                    past.as_ptr() as *const c_char,
                    past.len(),
                ),
                Z_EINVAL
            );
            assert!(!z_internal_keyexpr_check(&concat), "nothing is left behind");
            z_keyexpr_drop(z_keyexpr_move(&mut full));
            z_keyexpr_drop(z_keyexpr_move(&mut left));
        }
    }

    /// The canonizing doors read a text of any length and hold only its form to the bound, as
    /// pico keeps only the form: a text past the bound whose form is under it is a key, its
    /// form's length written back, and is canonized over itself; a form past the bound is refused
    /// by the owned constructor with `Z_EINVAL`, the destination null and no length written back,
    /// and canonized in place, which bounds nothing. Turned red by a bound judged on the text.
    #[test]
    fn the_canonizing_doors_hold_the_form_to_the_bound_and_not_the_text() {
        let stem = key_of(MAX_KEYEXPR_BYTES - 10);
        let long = format!("{stem}/**/**/**/**");
        assert!(long.len() > MAX_KEYEXPR_BYTES);
        let form = format!("{stem}/**");
        let past = key_of(MAX_KEYEXPR_BYTES + 1);
        unsafe {
            let mut len = long.len();
            let mut key = z_owned_keyexpr_t::null_value();
            assert_eq!(
                z_keyexpr_from_substr_autocanonize(
                    &mut key,
                    long.as_ptr() as *const c_char,
                    &mut len
                ),
                Z_OK
            );
            assert_eq!(len, form.len(), "the form's length is written back");
            assert_eq!(keyexpr_str(z_keyexpr_loan(&key)), Some(form.as_str()));
            z_keyexpr_drop(z_keyexpr_move(&mut key));
            let mut text = long.clone().into_bytes();
            let mut len = text.len();
            assert_eq!(
                z_keyexpr_canonize(text.as_mut_ptr() as *mut c_char, &mut len),
                Z_OK
            );
            assert_eq!(&text[..len], form.as_bytes());

            let mut len = past.len();
            assert_eq!(
                z_keyexpr_from_substr_autocanonize(
                    &mut key,
                    past.as_ptr() as *const c_char,
                    &mut len
                ),
                Z_EINVAL
            );
            assert!(!z_internal_keyexpr_check(&key), "nothing is left behind");
            assert_eq!(len, past.len(), "no length is written back");
            let mut text = past.clone().into_bytes();
            let mut len = text.len();
            assert_eq!(
                z_keyexpr_canonize(text.as_mut_ptr() as *mut c_char, &mut len),
                Z_OK
            );
            assert_eq!(
                &text[..len],
                past.as_bytes(),
                "a canon text is its own form"
            );
        }
    }

    /// The string form of the canonizing constructor is the substring form over the string's
    /// length: both canonize alike, the substring form writes the canonical length back, and a
    /// null string is refused with the destination left null.
    #[test]
    fn both_canonizing_constructors_canonize_alike() {
        unsafe {
            let mut by_str = z_owned_keyexpr_t::null_value();
            assert_eq!(
                z_keyexpr_from_str_autocanonize(&mut by_str, c"demo/$*/x".as_ptr()),
                Z_OK
            );
            let text = "demo/$*/x";
            let mut len = text.len();
            let mut by_substr = z_owned_keyexpr_t::null_value();
            assert_eq!(
                z_keyexpr_from_substr_autocanonize(
                    &mut by_substr,
                    text.as_ptr() as *const c_char,
                    &mut len,
                ),
                Z_OK
            );
            assert_eq!(
                len,
                "demo/*/x".len(),
                "the canonical length is written back"
            );
            assert_eq!(keyexpr_str(z_keyexpr_loan(&by_str)), Some("demo/*/x"));
            assert_eq!(keyexpr_str(z_keyexpr_loan(&by_substr)), Some("demo/*/x"));
            let mut none = z_owned_keyexpr_t::null_value();
            assert_eq!(
                z_keyexpr_from_str_autocanonize(&mut none, core::ptr::null()),
                Z_ERR_NULL
            );
            assert!(!z_internal_keyexpr_check(&none));
            z_keyexpr_drop(z_keyexpr_move(&mut by_str));
            z_keyexpr_drop(z_keyexpr_move(&mut by_substr));
        }
    }
}

#[cfg(test)]
mod key_text_tests {
    //! How a key the session's key arena kept no room for is refused.
    use super::*;

    /// A key past the session's bound is a value it cannot take, one the arena has no room for is
    /// out of memory, and a closed session's object keeps a copy of its own.
    #[test]
    fn a_key_the_arena_refuses_answers_picos_code() {
        assert_eq!(refusal_of(KeyNotHeld::TooLong), Some(Z_EINVAL));
        assert_eq!(
            refusal_of(KeyNotHeld::NoRoom),
            Some(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY)
        );
        assert_eq!(refusal_of(KeyNotHeld::Closed), None);
    }

    /// A key made with no session is a copy of its own, read and shared as one.
    #[test]
    fn a_key_with_no_session_is_a_copy_of_its_own() {
        let key = DeclaredKeyexpr::literal_only("demo/own/key");
        assert!(!key.literal.is_session());
        let shared = key.share();
        assert!(!shared.literal.is_session());
        assert_ne!(
            shared.literal().as_ptr(),
            key.literal().as_ptr(),
            "the share is a copy of its own"
        );
        drop(key);
        assert_eq!(shared.literal(), "demo/own/key");
        let loaned = shared.loaned();
        assert_eq!(loaned._start, shared.literal().as_ptr());
        assert_eq!(loaned._len, shared.literal().len());
    }
}

// The cooperative engine, which keeps a key arena: a session the build opens as `z_open` opens it,
// listening on the loopback, its engine the build's own `Engine`. The room a test needs is made by
// filling the session's arena, as a program's own keys fill it, not by a smaller arena.
#[cfg(all(test, not(feature = "engine-tokio"), feature = "peer"))]
mod arena_key_tests {
    use super::*;
    use crate::session::{
        listening_on_loopback, z_close, z_owned_session_t, z_session_drop, z_session_loan,
        z_session_loan_mut, z_session_move,
    };
    use wz_capi_port::SessionKeys;

    /// A session that listens on a port of the loopback, opened as a program opens one, and the
    /// engine it runs on.
    fn listening() -> (z_owned_session_t, Arc<Engine>) {
        let session = listening_on_loopback();
        // SAFETY: the session is live and owned by this frame.
        let handle = unsafe { session_handle(z_session_loan(&session)) };
        let engine = engine_of(handle.expect("an open session has its handle"));
        (session, engine)
    }

    /// Close and let go of a session [`listening`] opened.
    fn close(mut session: z_owned_session_t) {
        // SAFETY: the session is live and owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }

    /// The session's key arena, which the cooperative engine always keeps.
    fn keys(engine: &Arc<Engine>) -> &dyn SessionKeys {
        engine
            .key_arena()
            .expect("the cooperative engine keeps a key arena")
    }

    /// `text` held in the session's key arena, or why not.
    fn hold(engine: &Arc<Engine>, text: &str) -> Result<HeldKey, KeyNotHeld> {
        keys(engine)
            .key(KeyAsk::Hold(text))
            .map(|key| key.expect("a hold answers its key"))
    }

    /// Let go of `key`.
    fn release(engine: &Arc<Engine>, key: HeldKey) {
        assert!(matches!(keys(engine).key(KeyAsk::Release(key)), Ok(None)));
    }

    /// Keys of `len` bytes, each a text of its own and so a block of its own (a text the arena
    /// keeps already is that block shared), held until the arena has no room for one more.
    fn fill_with(engine: &Arc<Engine>, len: usize) -> Vec<HeldKey> {
        let mut held = Vec::new();
        loop {
            match hold(engine, &format!("{:0>len$}", held.len())) {
                Ok(key) => held.push(key),
                Err(why) => {
                    assert_eq!(
                        why,
                        KeyNotHeld::NoRoom,
                        "only the arena's room ends the fill"
                    );
                    return held;
                }
            }
        }
    }

    /// Fill the key arena with keys of `len` bytes, and what is left past them with keys of one
    /// byte, the shortest block, until no key at all has room; then give back the `room` keys of
    /// `len` bytes held last. The arena is left with the room of `room` such keys and none for any
    /// other: a key no longer than `len` takes one of those blocks or is refused.
    fn fill_leaving(engine: &Arc<Engine>, len: usize, room: usize) -> Vec<HeldKey> {
        let mut held = fill_with(engine, len);
        assert!(
            held.len() >= room,
            "the arena holds {room} keys of {len} bytes"
        );
        let shortest = fill_with(engine, 1);
        for key in held.split_off(held.len() - room) {
            release(engine, key);
        }
        held.extend(shortest);
        held
    }

    /// Give back every key [`fill_leaving`] held.
    fn give_back(engine: &Arc<Engine>, held: Vec<HeldKey>) {
        for key in held {
            release(engine, key);
        }
    }

    /// Whether the session's key arena has room for one more key of `len` bytes, asked and let go.
    fn room_for(engine: &Arc<Engine>, len: usize) -> bool {
        match hold(engine, &"k".repeat(len)) {
            Ok(key) => {
                release(engine, key);
                true
            }
            Err(_) => false,
        }
    }

    /// A key the session declares whole and the declaration's own row keep one block between them,
    /// the row finding the key's text in the arena, so with room for two such keys one is left
    /// after it. Its share reads
    /// it after the first holder is gone.
    #[test]
    fn a_whole_declaration_and_its_key_take_one_block() {
        let (session, engine) = listening();
        let held = fill_leaving(&engine, 10, 2);
        let key = DeclaredKeyexpr::declare(&engine, "demo/pk/a1", None).expect("declared");
        assert!(key.literal.is_session());
        assert_eq!(key.literal(), "demo/pk/a1");
        assert!(room_for(&engine, 10), "one block is left");
        let shared = key.share();
        drop(key);
        assert_eq!(shared.literal(), "demo/pk/a1", "the share reads the key");
        let second = DeclaredKeyexpr::declare(&engine, "demo/pk/b2", None).expect("the last block");
        assert!(!room_for(&engine, 10), "the two blocks are taken");
        drop((shared, second));
        assert!(room_for(&engine, 10), "and given back with their holders");
        give_back(&engine, held);
        close(session);
    }

    /// A declaration stays as long as any key holds it, each holder one hold of the engine's own
    /// count: a share and a wire key outlive the key they were made from, and the last holder let
    /// go retracts it. Turned red by a copy that takes no hold of its own, which lets the
    /// declaration go with the first holder.
    #[test]
    fn a_declaration_lasts_as_long_as_its_last_holder() {
        let (session, engine) = listening();
        let declared = |engine: &Arc<Engine>| {
            engine
                .keyexpr_declarations()
                .iter()
                .any(|(_, key)| key == "demo/hold/a")
        };
        let key = DeclaredKeyexpr::declare(&engine, "demo/hold/a", None).expect("declared");
        assert!(declared(&engine));
        let shared = key.share();
        let wire = key.wire(Arc::as_ref(&engine));
        assert_ne!(wire.mapping_id, 0, "the wire names the declaration");
        drop(key);
        assert!(declared(&engine), "the share holds it");
        drop(shared);
        assert!(declared(&engine), "the wire key holds it");
        drop(wire);
        assert!(!declared(&engine), "the last holder retracts it");
        close(session);
    }

    /// A key declared by its prefix is kept before anything is declared: with room for the key
    /// and not for the prefix's row, the declaration is refused with pico's out of memory and the
    /// key's block goes back.
    #[test]
    fn a_prefix_declaration_the_arena_cannot_hold_leaves_nothing() {
        let (session, engine) = listening();
        let held = fill_leaving(&engine, 10, 1);
        assert_eq!(
            DeclaredKeyexpr::declare_non_wild_prefix(&engine, "demo/pk/**", None).err(),
            Some(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY)
        );
        assert!(engine.keyexpr_declarations().is_empty(), "nothing declared");
        assert!(room_for(&engine, 10), "the key's block went back");
        give_back(&engine, held);
        close(session);
    }

    /// Keys declared and let go of, many times past the room the arena has left, each take the
    /// block the one before gave back.
    #[test]
    fn declarations_past_the_arena_take_the_blocks_given_back() {
        let (session, engine) = listening();
        let held = fill_leaving(&engine, 10, 1);
        for round in 0..10 {
            let text = format!("demo/pk/c{round}");
            let key = DeclaredKeyexpr::declare(&engine, &text, None).expect("the block given back");
            assert_eq!(key.literal(), text);
        }
        assert!(engine.keyexpr_declarations().is_empty());
        assert!(room_for(&engine, 10));
        give_back(&engine, held);
        close(session);
    }

    /// A key past the session's `MAX_KEYEXPR_BYTES` is a value it cannot take; after the close a
    /// key is a copy of its own, and one held from before still reads.
    #[test]
    fn a_key_too_long_is_invalid_and_a_closed_sessions_key_is_a_copy() {
        let (mut session, engine) = listening();
        let longest = wz_session_core::caps::MAX_KEYEXPR_BYTES;
        assert_eq!(
            KeyText::of_session(&engine, &"k".repeat(longest + 1)).err(),
            Some(Z_EINVAL)
        );
        let held = KeyText::of_session(&engine, "demo/a").expect("a short key");
        assert!(held.is_session());
        // SAFETY: the session is live and owned here.
        let closed = unsafe { z_close(z_session_loan_mut(&mut session), core::ptr::null()) };
        assert_eq!(closed, Z_OK);
        let copy = KeyText::of_session(&engine, "demo/b").expect("a copy of its own");
        assert!(!copy.is_session());
        assert_eq!(held.share().as_str(), "demo/a");
        close(session);
    }
}
