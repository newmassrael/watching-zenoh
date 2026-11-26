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

use core::ffi::{c_char, c_void, CStr};
use core::mem::ManuallyDrop;

use crate::prelude::*;

use wz_capi_port::{HeldKey, KeyAsk, KeyHold, KeyNotHeld, KeyView, OwnKey, SessionKeys, WireKey};
use wz_session_core::declare_form::RetractionKey;
use wz_session_core::keyexpr_canon::{
    canonize_parts_as, CanonKey, KeyexprCanonError, KeyexprDialect, PartsForm, PartsRefusal,
};
use wz_session_core::WhatAmI;

use crate::abi::{
    c_str_len, view_bytes, z_loaned_keyexpr_t, z_loaned_string_t, z_moved_keyexpr_t,
    z_owned_keyexpr_t, z_view_keyexpr_t, z_view_string_t,
};
use crate::ffi::{guard_val, guarded};
use crate::result::{
    ZResult, Z_EINVAL, Z_ERR_GENERIC, Z_ERR_INVALID, Z_ERR_KEYEXPR_DECLARED_ON_ANOTHER_SESSION,
    Z_ERR_NULL, Z_OK,
};
use crate::session::{engine_held, engine_ref, session_handle, z_loaned_session_t, Engine};

/// Whether `key` is no longer than the longest key a row of a session's tables stores: the
/// capacity the build gives the row (`MAX_KEYEXPR_BYTES`), which no session's limits raise. A key
/// past it is one this build has no room for, refused as zenoh-pico refuses a key its heap cannot
/// hold (`_Z_ERR_SYSTEM_OUT_OF_MEMORY`, `vendor/zenoh-pico/src/session/keyexpr.c` @
/// `return _z_string_check(&dst->_keyexpr) ? _Z_RES_OK : _Z_ERR_SYSTEM_OUT_OF_MEMORY;`), never cut
/// short; a session that states a lower bound refuses the key again when it is declared on it.
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
/// Both arms keep the literal at slots 0/1 (see [`z_loaned_keyexpr_t`]). A view's text is the
/// caller's and is checked, unless a checked constructor marked the view ([`PROVEN_CANON`]); a key that names the object keeping it (slot 3) lies in that object's
/// text, or in the text the session's record of an entity keeps, either of which was a `str` when
/// it was kept, and is read as it is.
///
/// Out of line: every door that names a key reads it here, and each copy inlined carried the
/// UTF-8 check of its own.
///
/// # Safety
/// `ke` must be a live `z_loaned_keyexpr_t` pointer (or null).
#[inline(never)]
pub(crate) unsafe fn keyexpr_str<'a>(ke: *const z_loaned_keyexpr_t) -> Option<&'a str> {
    if ke.is_null() {
        return None;
    }
    let bytes = view_bytes((*ke)._start, (*ke)._len)?;
    // One test for both: a view a checked constructor marked was read as UTF-8 where it was made.
    if ((*ke)._state as usize | ((*ke)._handle & PROVEN_CANON)) == 0 {
        return crate::abi::text_of(bytes);
    }
    // SAFETY: slots 0/1 of a key that names its object are that object's text, a `str` it keeps
    // unchanged while the key is lent; those of a marked view were read as UTF-8 when it was made,
    // and the caller keeps them unchanged while the view stands (the view's contract).
    Some(unsafe { core::str::from_utf8_unchecked(bytes) })
}

/// The key a declaration or a get names, read where the caller holds it: `Z_ERR_INVALID` when it
/// is null or not UTF-8, and otherwise refused as [`outbound_key`] refuses it, unless the
/// constructor that made it proved both of what that judges ([`PROVEN`]), which is read and not
/// judged again. Judged here, before
/// anything is declared or asked, because a session declares and asks per face at its best, and
/// would swallow a refusal of one face. One body every such door calls, so the gate and its codes
/// are not copied into each.
///
/// # Safety
/// As [`keyexpr_str`].
#[inline(never)]
pub(crate) unsafe fn outbound_keyexpr<'a>(
    ke: *const z_loaned_keyexpr_t,
) -> Result<&'a str, ZResult> {
    let key = keyexpr_str(ke).ok_or(Z_ERR_INVALID)?;
    if proof_of(ke) != PROVEN {
        outbound_key(key)?;
    }
    Ok(key)
}

/// The bit slot 2 of a key's loan carries when the checked constructor that made the key found its
/// text admitted by [`canon_key`]: in canon form and within the build's bound.
const PROVEN_CANON: usize = 0b01;

/// The bit slot 2 of a key's loan carries besides when the outbound gate for a zenoh-pico peer
/// admitted the text too, so [`outbound_key`] would admit it whole.
const PROVEN_PICO_SAFE: usize = 0b10;

/// Both marks: a key the checked constructors proved all that [`outbound_key`] judges.
const PROVEN: usize = PROVEN_CANON | PROVEN_PICO_SAFE;

// Slot 2 of an owned key and of a record's loan is the address of a declaration's count, whose
// alignment leaves the bits of the mark clear; a view's slot 2 holds the mark alone.
const _: () =
    assert!(core::mem::align_of::<wz_session_core::session_tables::KeyexprCount>() > PROVEN);

/// What a checked constructor proves of `text`, a text it found in canon form, as slot 2 of the
/// key's loan keeps it: nothing for a text past the build's bound, which [`canon_key`] refuses;
/// [`PROVEN_CANON`] otherwise, with [`PROVEN_PICO_SAFE`] when the pico-safe gate admits it.
/// Judged where the key is made, as zenoh-pico judges its checked view once where it is made, so
/// an operation on the key does not walk it again. Out of line: every checked constructor marks
/// its key through it.
#[inline(never)]
fn proof_of_canon(text: &str) -> usize {
    if !fits(text) {
        return 0;
    }
    match wz_session_core::keyexpr_canon::check_outbound_keyexpr_pico_safe(text) {
        Ok(()) => PROVEN,
        Err(_) => PROVEN_CANON,
    }
}

/// What slot 2 of `ke`'s loan says the constructor proved of its key ([`proof_of_canon`]); no
/// mark for null, a view made unchecked, a zeroed one and a key lent from a record.
///
/// # Safety
/// `ke` must be a live `z_loaned_keyexpr_t` pointer (or null).
unsafe fn proof_of(ke: *const z_loaned_keyexpr_t) -> usize {
    if ke.is_null() {
        0
    } else {
        (*ke)._handle & PROVEN
    }
}

/// The judgement of a key a declaration or a get names: refused as [`canon_key`] refuses it, and
/// then `Z_ERR_INVALID` for a key in canon form that a zenoh-pico peer's canonizer aborts on, the
/// outbound gate wz's own session applies per face.
pub(crate) fn outbound_key(key: &str) -> Result<(), ZResult> {
    canon_key(key)?;
    wz_session_core::keyexpr_canon::check_outbound_keyexpr_pico_safe(key).map_err(|_| Z_ERR_INVALID)
}

/// The one judgement of a caller's key text that every door making, declaring or sending a key
/// goes through: `Z_EINVAL` for a text not in canon form, the code the checked view constructor
/// answers (`vendor/zenoh-pico/src/api/api.c` @
/// `if (_z_keyexpr_is_canon(name, len) != Z_KEYEXPR_CANON_SUCCESS) {`), and
/// `_Z_ERR_SYSTEM_OUT_OF_MEMORY` for one longer than the longest key the build holds ([`fits`]).
///
/// A text not in canon form is refused, neither passed on nor rewritten, as upstream zenoh refuses
/// one wherever a key is made of text (`commons/zenoh-keyexpr/src/key_expr/borrowed.rs` @
/// `fn try_from(value: &'a str) -> Result<Self, Self::Error> {`). zenoh-pico checks only its view
/// constructor and copies the text of its owned one as given; wz does not follow that gap. A
/// program whose text needs rewriting asks an `_autocanonize` door, or the join, which rewrite it as
/// both originals do.
///
/// The key it takes is handed back judged, so a door that keeps the judgement with the text judges
/// it once.
#[inline(never)]
pub(crate) fn canon_key(text: &str) -> Result<CanonKey<'_>, ZResult> {
    // The bound first: whether a text past it is judged canon depends on the profile's scratch.
    if !fits(text) {
        Err(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY)
    } else {
        CanonKey::judge(text, KeyexprDialect::Pico).ok_or(Z_EINVAL)
    }
}

/// What slot 3 of a loan names.
enum LentKey<'a> {
    /// Nothing: a view of the caller's text.
    View,
    /// A key this crate keeps, with the declaration that covers a prefix of it.
    Kept(&'a DeclaredKeyexpr),
    /// An entity's key as the session's record of it keeps it ([`record_loan`]): the session the
    /// entity is on, and the declaration the record holds that the key begins with.
    Record(&'a crate::session::EngineHold, Option<OwnKey>),
}

/// What a key lent from the session's record of an entity names besides its text, in slot 3 of
/// its loan ([`record_loan`]): the session the entity is on and the declaration the record holds
/// that the key begins with. Every kind of entity lends its key in this one shape, so a loan is
/// read the same whatever lent it. It lies in the entity's state, beside the session handle it
/// names, both at their address while the state stands.
pub(crate) struct RecordKey {
    session: *const crate::session::EngineHold,
    own: Option<OwnKey>,
}

impl RecordKey {
    /// No key lent yet.
    pub(crate) const UNLENT: Self = Self {
        session: core::ptr::null(),
        own: None,
    };

    /// The key `session`'s record lends with `own`, `session` named where it lies in the
    /// entity's state.
    pub(crate) fn lent(session: &crate::session::EngineHold, own: Option<OwnKey>) -> Self {
        Self { session, own }
    }

    /// The declaration the key was lent with, which a queryable's test reads where its state keeps
    /// it, the queryable's door keeping no other.
    #[cfg(all(
        test,
        feature = "queryable",
        feature = "peer",
        not(feature = "engine-tokio")
    ))]
    pub(crate) fn own(&self) -> Option<OwnKey> {
        self.own
    }
}

/// The bit slot 3 of a key lent from the session's record carries ([`record_loan`]), the
/// [`RecordKey`] lying at the address without it. A kept key's address never carries it: both
/// are aligned past it.
const RECORD_TAG: usize = 1;

const _: () = assert!(
    core::mem::align_of::<DeclaredKeyexpr>() > RECORD_TAG
        && core::mem::align_of::<RecordKey>() > RECORD_TAG
);

/// What slot 3 of `ke` names.
///
/// # Safety
/// `ke` must be a live `z_loaned_keyexpr_t` pointer (or null).
unsafe fn lent_of<'a>(ke: *const z_loaned_keyexpr_t) -> LentKey<'a> {
    if ke.is_null() || (*ke)._state.is_null() {
        return LentKey::View;
    }
    let state = (*ke)._state;
    if (state as usize) & RECORD_TAG == 0 {
        // SAFETY: an untagged slot 3 is a kept key, live while the loan is (the caller's).
        return LentKey::Kept(unsafe { &*(state as *const DeclaredKeyexpr) });
    }
    // SAFETY: a tagged slot 3 is the record's key the tag was added to (`record_loan`), which
    // stands in its entity's state while the loan does (the caller's).
    let record = unsafe {
        &*state
            .cast::<u8>()
            .wrapping_sub(RECORD_TAG)
            .cast::<RecordKey>()
    };
    // SAFETY: a lent record names the session handle beside it in the same state
    // ([`RecordKey::lent`]), which stands as long.
    LentKey::Record(unsafe { &*record.session }, record.own)
}

/// The loan of `view`, the key the session's record of an entity keeps: its text where the record
/// keeps it, the address of the count of the declaration it names in slot 2, and `record`,
/// tagged, in slot 3, which names the session and the declaration a key made of the loan holds.
/// Valid while `record` stays at its address and the entity stands.
pub(crate) fn record_loan(view: KeyView, record: &RecordKey) -> z_loaned_keyexpr_t {
    z_loaned_keyexpr_t {
        _start: view.start,
        _len: view.len,
        _handle: record.own.map_or(0, |own| own.row_address()),
        _state: (record as *const RecordKey)
            .cast::<u8>()
            .wrapping_add(RECORD_TAG)
            .cast_mut()
            .cast::<c_void>(),
    }
}

/// The [`DeclaredKeyexpr`] behind a loaned keyexpr, or `None` for a view and for a key lent from
/// the session's record of a subscription, whose declaration a key declared on it asks of the
/// session again and finds held.
///
/// Only the owned keyexprs this crate builds, and the loans its entities hand
/// out over their own keys, put anything in slot 3; a view leaves it null.
///
/// # Safety
/// `ke` must be a live `z_loaned_keyexpr_t` pointer (or null).
pub(crate) unsafe fn declared_of<'a>(ke: *const z_loaned_keyexpr_t) -> Option<&'a DeclaredKeyexpr> {
    match lent_of(ke) {
        LentKey::Kept(declared) => Some(declared),
        LentKey::View | LentKey::Record(..) => None,
    }
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
/// The wire key holds nothing: a message sent once records nothing, and an entity the session
/// records holds the declaration in the session's own count from its record on. The rest of the
/// key is named by its length, read against the key's text that goes with it
/// ([`WireKey::names_in`]).
///
/// Out of line: a put or a delete, a get and a subscriber's announce each name the caller's key
/// here, and each copy inlined carried the read of every kind of loan.
///
/// # Safety
/// `ke` must be a live `z_loaned_keyexpr_t` pointer (or null).
#[inline(never)]
pub(crate) unsafe fn wire_key_of(ke: *const z_loaned_keyexpr_t, shared: &Engine) -> WireKey {
    match lent_of(ke) {
        LentKey::Kept(declared) => declared.wire(shared),
        LentKey::Record(session, own) => record_wire(session, own, (*ke)._len, shared),
        LentKey::View => WireKey::literal(),
    }
}

/// How a key of `len` bytes lent from the session's record of an entity on `session` goes on
/// `shared`'s wire: the id of `own`, the declaration the record holds, and the rest of the key,
/// when the entity is `shared`'s; the literal otherwise. Read off the loan: no row, no lock.
pub(crate) fn record_wire(
    session: &crate::session::EngineHold,
    own: Option<OwnKey>,
    len: usize,
    shared: &Engine,
) -> WireKey {
    let on = core::ptr::addr_eq(
        crate::session::EngineHold::as_ref(session) as *const Engine,
        shared as *const Engine,
    );
    match own
        .filter(|_| on)
        .and_then(|own| Some((own, len.checked_sub(own.prefix_len)?)))
    {
        Some((own, rest)) => WireKey::aliased_tail(own.mapping, rest).at_row(Some(own.row)),
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
/// ([`KeyHold`]): a copy takes one more and a drop gives its own back, so the count has one owner
/// and a holder keeps nothing on the heap. The session is held WEAKLY, as pico holds
/// `_z_session_weak_t`: a key that outlives its session does not keep it alive, and a hold on a
/// session that is gone gives nothing back. This object of the program's is what names the
/// session; what the session records holds the declaration in its count itself, by no key.
pub(crate) struct WireDeclaration {
    /// The session the declaration was made on. Let go of only by the drop, so a holder's drop
    /// glue is the one call to it.
    session: ManuallyDrop<crate::session::EngineHandle>,
    /// Taken only by the drop.
    hold: ManuallyDrop<KeyHold>,
    /// How many bytes of the key the declaration covers — pico's `_prefix_len`.
    prefix_len: usize,
}

impl WireDeclaration {
    /// One more holder of `own`, the declaration the session's record of an entity holds, taken
    /// at its row of `shared`: refused as [`Self::share`] is when its count holds as many holders
    /// as it can.
    fn lent(shared: &crate::session::EngineHold, own: OwnKey) -> Result<Self, ZResult> {
        let named = own.named_hold();
        let held = Self::held(shared, &named, own.prefix_len);
        // The record's own hold: it gives it back itself, so naming it gives nothing back.
        named.outlived_its_session();
        held
    }

    /// One more holder of the declaration `hold` names, taken of `shared`, the session it is on,
    /// covering `prefix_len` bytes of the key: refused with pico's code for a count past its bound
    /// (`vendor/zenoh-pico/src/collections/refcount.c` @ `_Z_ERROR_RETURN(_Z_ERR_OVERFLOW);`) when
    /// the count holds as many holders as it can, as a copy that held nothing would name a
    /// declaration its last counted holder's going retracts. Out of line: a copy of a kept key and
    /// a copy of an entity's lent key each carried the count's share.
    #[inline(never)]
    fn held(
        shared: &crate::session::EngineHold,
        hold: &KeyHold,
        prefix_len: usize,
    ) -> Result<Self, ZResult> {
        let hold = hold
            .share(crate::session::EngineHold::as_ref(shared))
            .ok_or(crate::result::Z_ERR_OVERFLOW)?;
        Ok(Self::taken(shared, hold, prefix_len))
    }

    /// The hold the caller took of `shared`, covering `prefix_len` bytes of the key.
    fn taken(shared: &crate::session::EngineHold, hold: KeyHold, prefix_len: usize) -> Self {
        Self {
            session: ManuallyDrop::new(crate::session::EngineHold::downgrade(shared)),
            hold: ManuallyDrop::new(hold),
            prefix_len,
        }
    }

    /// The declaration's id.
    fn mapping_id(&self) -> wz_session_core::wire_id::ExprId {
        self.hold.mapping_id()
    }

    /// Whether the declaration was made on `shared`, by ADDRESS: on the tokio engine both are
    /// fat pointers to one engine, and their vtable halves are not guaranteed to be one copy, so
    /// comparing them whole could say a session is not itself.
    fn is_on(&self, shared: &Engine) -> bool {
        #[cfg(feature = "engine-tokio")]
        {
            core::ptr::addr_eq(self.session.as_ptr(), shared as *const Engine)
        }
        // The cooperative engine's handle names its row, which the engine knows.
        #[cfg(not(feature = "engine-tokio"))]
        {
            self.session.is_of(shared)
        }
    }
}

impl WireDeclaration {
    /// Another holder of the declaration, as pico's `_z_keyexpr_wire_declaration_rc_clone` is: one
    /// more of the session's count of its holders. Refused with pico's code for a count past its
    /// bound (`vendor/zenoh-pico/src/collections/refcount.c` @
    /// `_Z_ERROR_RETURN(_Z_ERR_OVERFLOW);`) when the count holds as many as it can: a copy that held
    /// nothing would name a declaration its last counted holder's going retracts.
    fn share(&self) -> Result<Self, ZResult> {
        match self.session.upgrade() {
            Some(engine) => Self::held(&engine, &self.hold, self.prefix_len),
            // A session that is gone counts nothing: the copy gives nothing back either.
            None => Ok(Self {
                // A copy where the session is held by a handle that is `Copy`, a count where by
                // an `Arc`.
                session: Clone::clone(&self.session),
                hold: ManuallyDrop::new(self.hold.unheld()),
                prefix_len: self.prefix_len,
            }),
        }
    }
}

/// The declaration a key made of another holds one more hold of, when the new key still begins with
/// the bytes it covers ([`DeclaredKeyexpr::kept_with`]).
enum Covering<'a> {
    /// A kept key's declaration ([`WireDeclaration::share`]).
    Kept(&'a WireDeclaration),
    /// The declaration the session's record of an entity on `shared` holds
    /// ([`WireDeclaration::lent`]).
    Lent(&'a crate::session::EngineHold, OwnKey),
}

impl Covering<'_> {
    /// How many bytes of the key the declaration covers.
    fn prefix_len(&self) -> usize {
        match self {
            Self::Kept(declaration) => declaration.prefix_len,
            Self::Lent(_, own) => own.prefix_len,
        }
    }
}

impl Drop for WireDeclaration {
    // Out of line, as `KeyText`'s drop is: every drop of a declared key reaches it, and each copy
    // inlined would carry the session's upgrade, the release of the hold and the weak count.
    #[inline(never)]
    fn drop(&mut self) {
        // SAFETY: the hold is taken here, once, and the field is not read again.
        let hold = unsafe { ManuallyDrop::take(&mut self.hold) };
        match self.session.upgrade() {
            Some(engine) => hold.release(crate::session::EngineHold::as_ref(&engine)),
            None => hold.outlived_its_session(),
        }
        // SAFETY: the session is let go of here, once, after its last read.
        unsafe { ManuallyDrop::drop(&mut self.session) };
    }
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
    /// of its own. Let go of only by the drop, so a holder's drop glue is the one call to it.
    engine: ManuallyDrop<Option<crate::session::EngineHold>>,
}

impl KeyText {
    /// `text` as a copy of its own; refused as zenoh-pico refuses what its heap cannot hold
    /// (`_Z_ERR_SYSTEM_OUT_OF_MEMORY`) when the heap refuses the copy.
    pub(crate) fn owned(text: &str) -> Result<Self, ZResult> {
        let key = HeldKey::own(text).ok_or(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY)?;
        Ok(Self {
            key: ManuallyDrop::new(key),
            engine: ManuallyDrop::new(None),
        })
    }

    /// `text` kept for an object of `shared`'s session: in its key arena when it keeps one, and
    /// refused as zenoh-pico refuses what its heap cannot hold (`_Z_ERR_SYSTEM_OUT_OF_MEMORY`) when
    /// the arena has no room or the key is longer than the session's
    /// `MAX_KEYEXPR_BYTES`; a copy of its own for a session with no key arena or a closed one,
    /// which keeps nothing more.
    pub(crate) fn of_session(
        shared: &crate::session::EngineHold,
        text: &str,
    ) -> Result<Self, ZResult> {
        Self::kept(shared, KeyAsk::Hold(text), text)
    }

    /// `text` kept as `ask` asks of `engine`'s key arena, held or shared: a block of it, refused
    /// as [`refusal_of`] answers why the arena kept none, and a copy of its own when the session
    /// keeps no arena or is closed. One body for holding and sharing, which differ only in the ask.
    #[inline(never)]
    fn kept(
        engine: &crate::session::EngineHold,
        ask: KeyAsk<'_>,
        text: &str,
    ) -> Result<Self, ZResult> {
        let refused = match key_arena(engine).map(|keys| SessionKeys::key(keys, ask)) {
            Some(Ok(Some(key))) => {
                return Ok(Self {
                    key: ManuallyDrop::new(key),
                    engine: ManuallyDrop::new(Some(engine.clone())),
                })
            }
            Some(Err(why)) => refusal_of(why),
            _ => None,
        };
        match refused {
            Some(code) => Err(code),
            None => Self::owned(text),
        }
    }

    /// The key.
    pub(crate) fn as_str(&self) -> &str {
        self.key.as_str()
    }

    /// `text` kept for an object of `engine`'s session ([`Self::of_session`]), or a copy of its own
    /// for an object of none ([`Self::owned`]); refused as those refuse it.
    fn kept_for(engine: Option<&crate::session::EngineHold>, text: &str) -> Result<Self, ZResult> {
        match engine {
            Some(engine) => Self::of_session(engine, text),
            None => Self::owned(text),
        }
    }

    /// The session whose key arena holds the text, `None` for a copy of its own.
    fn engine(&self) -> Option<&crate::session::EngineHold> {
        (*self.engine).as_ref()
    }

    /// Another holder of the same text: one more holder of the block for a key of the arena, a
    /// copy for one of its own, refused as [`Self::owned`] refuses it.
    pub(crate) fn share(&self) -> Result<Self, ZResult> {
        match &*self.engine {
            // An engine that keeps no key arena made no key of one, and a closed session shares
            // none: a copy reads the same. A share is only counted, so the arena refuses none.
            Some(engine) => Self::kept(engine, KeyAsk::Share(&self.key), self.as_str()),
            None => Self::owned(self.as_str()),
        }
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
        // SAFETY: the engine is taken here, once, and the field is not read again.
        match unsafe { ManuallyDrop::take(&mut self.engine) } {
            Some(engine) => {
                if let Some(keys) = key_arena(&engine) {
                    let _ = SessionKeys::key(keys, KeyAsk::Release(key));
                }
            }
            // SAFETY: with no engine the key is a copy of its own (`Self::owned`), freed here once.
            None => unsafe { key.free_own() },
        }
    }
}

/// The key arena of `engine`'s session: the cooperative engine always keeps one and is reached as
/// its own type, so a key's hold, share and release are calls resolved when the build is made.
///
/// Both arms take the hold a holder keeps ([`EngineHold`](crate::session::EngineHold)): on the tokio engine `Engine` is a trait object, and an
/// `&crate::session::EngineHold` handed where an `&Engine` is asked would be unsized, not dereferenced.
#[cfg(not(feature = "engine-tokio"))]
fn key_arena(engine: &crate::session::EngineHold) -> Option<&Engine> {
    Some(crate::session::EngineHold::as_ref(engine))
}

/// The key arena of the session behind the port, when its engine keeps one.
#[cfg(feature = "engine-tokio")]
fn key_arena(engine: &crate::session::EngineHold) -> Option<&dyn SessionKeys> {
    engine.key_arena()
}

/// The code a key the session kept no room for is refused with, as zenoh-pico refuses what its heap
/// cannot hold; `None` for a closed session, whose object keeps a copy of its own as it keeps
/// nothing more.
fn refusal_of(why: KeyNotHeld) -> Option<ZResult> {
    match why {
        // A key past the bound is one the arena has no room for, as a key past pico's heap is.
        KeyNotHeld::TooLong | KeyNotHeld::NoRoom => Some(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY),
        KeyNotHeld::Closed => None,
    }
}

/// Behind a `z_owned_keyexpr_t` handle, and kept by a composite that names its entities' keys
/// itself (an advanced entity's carriers): the OWNED literal plus the declaration that covers a
/// prefix of it, if any — pico's `_z_declared_keyexpr_t` (`{ _declaration, _inner }`). An entity
/// the session records keeps none: the record keeps its key ([`EntityKey`]).
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
    pub(crate) fn literal_only(literal: &str) -> Result<Self, ZResult> {
        Ok(Self {
            literal: KeyText::owned(literal)?,
            declaration: None,
        })
    }

    /// A key with no declaration, its text kept for an object of `shared`'s session
    /// ([`KeyText::of_session`]): a block of the session's key arena when it keeps one, so a share
    /// of it is one more holder of the block and not a copy. Refused as that is.
    #[cfg(any(
        feature = "advanced",
        all(test, not(feature = "engine-tokio"), feature = "peer")
    ))]
    pub(crate) fn literal_of_session(
        shared: &crate::session::EngineHold,
        literal: &str,
    ) -> Result<Self, ZResult> {
        Ok(Self {
            literal: KeyText::of_session(shared, literal)?,
            declaration: None,
        })
    }

    /// `literal` kept for an object of `shared`'s session ([`KeyText::of_session`]), holding `own`,
    /// the declaration the session's record of an entity holds for its key `named`, while
    /// `literal` still begins with the bytes of `named` it covers, as [`Self::extended`] keeps
    /// one. The hold is one more of the declaration's count, taken at its row
    /// ([`WireDeclaration::lent`]). Refused as the text and the hold are.
    #[cfg(feature = "advanced")]
    pub(crate) fn of_record(
        shared: &crate::session::EngineHold,
        own: Option<OwnKey>,
        named: &str,
        literal: &str,
    ) -> Result<Self, ZResult> {
        Self::kept_with(
            Some(shared),
            named,
            literal,
            own.map(|own| Covering::Lent(shared, own)),
        )
    }

    /// `literal` kept for an object of `engine`'s session, or as a copy of its own for none
    /// ([`KeyText::kept_for`]), holding the declaration `covering` names while `literal` still
    /// begins with the bytes of `named` it covers: one more holder of a kept key's declaration
    /// ([`WireDeclaration::share`]) or of the one the session's record of an entity holds
    /// ([`WireDeclaration::lent`]). Refused as the text and the hold are.
    ///
    /// Out of line: a copy and a concatenation of every kind of loan, and an advanced entity's
    /// keys, end here, and each carried its own copy of the text's keeping and the hold's share.
    #[inline(never)]
    fn kept_with(
        engine: Option<&crate::session::EngineHold>,
        named: &str,
        literal: &str,
        covering: Option<Covering<'_>>,
    ) -> Result<Self, ZResult> {
        // The text is kept first: a refusal then has no hold of the declaration to let go of.
        let text = KeyText::kept_for(engine, literal)?;
        let declaration = covering
            .filter(|covering| {
                let prefix_len = covering.prefix_len();
                literal.get(..prefix_len).is_some()
                    && literal.get(..prefix_len) == named.get(..prefix_len)
            })
            .map(|covering| match covering {
                Covering::Kept(declaration) => declaration.share(),
                Covering::Lent(shared, own) => WireDeclaration::lent(shared, own),
            })
            .transpose()?;
        Ok(Self {
            literal: text,
            declaration,
        })
    }

    /// The literal key.
    pub(crate) fn literal(&self) -> &str {
        self.literal.as_str()
    }

    /// The address of the row of the declaration that covers a prefix of the key, where the
    /// session's table keeps it in place, `0` for none: slot 2 of the key's loan.
    pub(crate) fn row_address(&self) -> usize {
        self.declaration
            .as_ref()
            .map_or(0, |d| d.hold.row_address())
    }

    /// Another key sharing this one's literal and declaration — pico
    /// `_z_declared_keyexpr_copy`, which clones the refcount; refused, making nothing, as the
    /// literal's share is, or when the declaration's count holds as many holders as it can
    /// ([`WireDeclaration::share`]). Out of line: the clone door and a declaration asked again
    /// each carried its own copy of the two shares and their refusal.
    #[inline(never)]
    pub(crate) fn share(&self) -> Result<Self, ZResult> {
        // The text is kept first: a refusal then has no hold of the declaration to let go of.
        let literal = self.literal.share()?;
        let declaration = self
            .declaration
            .as_ref()
            .map(WireDeclaration::share)
            .transpose()?;
        Ok(Self {
            literal,
            declaration,
        })
    }

    /// A new literal that keeps this key's declaration — pico's
    /// `_z_declared_keyexpr_concat` / `_join`, which clone the left side's
    /// refcount onto the result.
    ///
    /// Kept only while the new literal still begins with the declared prefix.
    /// A concatenation is taken only as it is, so there it always does; a join
    /// canonizes the joined text, as pico's does, which can in principle
    /// rewrite the seam, and a declaration naming bytes the key no longer
    /// starts with would put the wrong key on the wire.
    ///
    /// The new literal is kept where this key's is ([`KeyText::kept_for`]), and refused as that
    /// refuses it.
    pub(crate) fn extended(&self, literal: &str) -> Result<Self, ZResult> {
        // The key's own text, as a copy names it (`z_keyexpr_clone`): one more holder of the
        // text and of the declaration, which a share is.
        if core::ptr::eq(literal, self.literal()) {
            return self.share();
        }
        Self::kept_with(
            self.literal.engine(),
            self.literal(),
            literal,
            self.declaration.as_ref().map(Covering::Kept),
        )
    }

    fn declared_on(&self, shared: &Engine) -> Option<&WireDeclaration> {
        self.declaration.as_ref().filter(|d| d.is_on(shared))
    }

    /// pico `_z_declared_keyexpr_alias_to_wire`: the declaration's id and the
    /// remainder of the key when the declaration is `shared`'s, the literal
    /// otherwise.
    ///
    /// It holds nothing: for a message sent once, or a record that keeps this key itself. The
    /// remainder is named by its length, read against this key's literal, which every engine
    /// call takes beside the wire key ([`WireKey::names_in`]), so naming it copies nothing.
    ///
    /// The id and the length of the declared key are the hold's own, which no retraction
    /// changes, so naming the key reads no row, takes no lock of the session and reads the text
    /// for no boundary.
    pub(crate) fn wire(&self, shared: &Engine) -> WireKey {
        let rest = self
            .declared_on(shared)
            .and_then(|d| Some((d, self.literal().len().checked_sub(d.prefix_len)?)));
        match rest {
            Some((d, rest)) => WireKey::aliased_tail(d.mapping_id(), rest).at_row(d.hold.row()),
            None => WireKey::literal(),
        }
    }

    /// The declaration's id and the remainder of the key, borrowed from this key, when the
    /// declaration is `shared`'s: what [`Self::wire`] names, for a holder that keeps this key
    /// and lends the remainder from it.
    #[cfg(feature = "advanced")]
    pub(crate) fn aliased_parts(
        &self,
        shared: &Engine,
    ) -> Option<(wz_session_core::wire_id::ExprId, &str)> {
        self.declared_rest(shared)
            .map(|(d, rest)| (d.mapping_id(), rest))
    }

    /// The declaration that is `shared`'s and the remainder of the key past it. One body out of
    /// line: an advanced entity's form reads it for the key it is announced on and for the key its
    /// retraction names.
    #[cfg(feature = "advanced")]
    #[inline(never)]
    fn declared_rest(&self, shared: &Engine) -> Option<(&WireDeclaration, &str)> {
        // Every constructor keeps the declared prefix at the front of the
        // literal (see `extended`), so the remainder always exists; the `get`
        // turns a broken invariant into the literal rather than a panic.
        self.declared_on(shared)
            .and_then(|d| Some((d, self.literal().get(d.prefix_len..)?)))
    }

    /// What an entity held on this key names when it retracts itself, or `None`
    /// when it retracts by id alone, on a session whose role is `mode` and whose
    /// registry is `shared`: the two facts it reads, which a door has in the
    /// session's handle and a composite that holds the registry WEAKLY has apart.
    ///
    /// pico names the entity's OWN key in every mode but client (`vendor/zenoh-pico/src/net/primitives.c`
    /// @ `_z_wireexpr_t expr = _z_declared_keyexpr_alias_to_wire(&_Z_RC_IN_VAL(&s)->_key, zn);`),
    /// and that key is the one this is called on: for a subscriber it is not
    /// the key the subscription was announced on, which is the caller's. Its declaration and the
    /// rest of the key, or the literal when nothing covers it.
    #[cfg(feature = "advanced")]
    pub(crate) fn retraction_naming_in(
        &self,
        mode: WhatAmI,
        shared: &Engine,
    ) -> Option<RetractionKey> {
        if mode == WhatAmI::Client {
            return None;
        }
        Some(match self.declared_rest(shared) {
            Some((d, rest)) => RetractionKey::declared(d.mapping_id(), rest),
            None => RetractionKey::literal(),
        })
    }

    /// pico `_z_declared_keyexpr_declare`: a key whose declaration covers ALL
    /// of it on `shared`, sharing the caller's when it already does.
    pub(crate) fn declare(
        shared: &crate::session::EngineHold,
        literal: &str,
        existing: Option<&DeclaredKeyexpr>,
    ) -> Result<Self, ZResult> {
        Self::declare_up_to(shared, literal, existing, literal)
    }

    /// pico `_z_declared_keyexpr_declare_non_wild_prefix`: the same, covering
    /// only the part of the key before its first wild chunk.
    #[cfg(any(
        feature = "advanced",
        all(test, not(feature = "engine-tokio"), feature = "peer")
    ))]
    pub(crate) fn declare_non_wild_prefix(
        shared: &crate::session::EngineHold,
        literal: &str,
        existing: Option<&DeclaredKeyexpr>,
    ) -> Result<Self, ZResult> {
        Self::declare_up_to(shared, literal, existing, non_wild_prefix(literal))
    }

    /// `literal` declared on `shared` up to `prefix`, a prefix of it (the whole key or its
    /// non-wild prefix), named as text so that no length is cut out of the key by index.
    fn declare_up_to(
        shared: &crate::session::EngineHold,
        literal: &str,
        existing: Option<&DeclaredKeyexpr>,
        prefix: &str,
    ) -> Result<Self, ZResult> {
        let prefix_len = prefix.len();
        // A key the session's tables cannot hold is refused before anything is declared.
        if !fits(literal) {
            return Err(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY);
        }
        // Already optimized on THIS session to exactly this prefix: share it
        // (pico's `_z_declared_keyexpr_is_fully_optimized` /
        // `_is_non_wild_prefix_optimized` arm).
        if let Some(existing) = existing {
            if existing
                .declared_on(crate::session::EngineHold::as_ref(shared))
                .is_some_and(|d| d.prefix_len == prefix_len)
            {
                return existing.share();
            }
        }
        // The key is kept before anything is declared, so one the session's key arena has no room
        // for is refused having sent nothing; a declaration that covers it whole finds its block
        // and shares it.
        let text = KeyText::of_session(shared, literal)?;
        // The declaration an entity's door makes, its hold kept by this key from here on; a refused
        // one sent nothing, and the key goes back with `text`.
        let declaration = EntityKey::up_to(shared, literal, None, prefix)?
            .into_held()
            .map(|(hold, prefix_len)| WireDeclaration::taken(shared, hold, prefix_len));
        Ok(Self {
            literal: text,
            declaration,
        })
    }
}

/// The declaration a door holds of an entity's own key while it declares the entity: pico's
/// `_z_declared_keyexpr_declare` / `_declare_non_wild_prefix` of the entity's `_key`, whose copy
/// pico's entity keeps. Here the session's record of the entity is that copy: it keeps the key in
/// its row and takes its own hold of the declaration the wire and the retraction name, so the door
/// keeps no text of the key, and its hold goes with this once the record stands or the entity is
/// refused.
///
/// The key is the caller's, read where it lies for the call.
pub(crate) struct EntityKey<'a> {
    engine: &'a crate::session::EngineHold,
    literal: &'a str,
    /// The declaration's id, `0` when no declaration covers the key.
    mapping: wz_session_core::wire_id::ExprId,
    /// The row the declaration lies in.
    row: Option<wz_session_core::session_tables::KeyexprHandle>,
    /// How many bytes of the key the declaration covers.
    prefix_len: usize,
    /// The door's own hold of the declaration, given back by the drop; `None` when the caller's
    /// key holds it on this session for the call, or nothing is declared.
    taken: Option<KeyHold>,
}

impl<'a> EntityKey<'a> {
    /// pico `_z_declared_keyexpr_declare`: a declaration of the whole key on `engine`, the caller's
    /// `existing` one when it is that declaration on this session already.
    pub(crate) fn whole(
        engine: &'a crate::session::EngineHold,
        literal: &'a str,
        existing: Option<&DeclaredKeyexpr>,
    ) -> Result<Self, ZResult> {
        Self::up_to(engine, literal, existing, literal)
    }

    /// pico `_z_declared_keyexpr_declare_non_wild_prefix`: the same, covering only the part of
    /// the key before its first wild chunk.
    pub(crate) fn non_wild_prefix(
        engine: &'a crate::session::EngineHold,
        literal: &'a str,
        existing: Option<&DeclaredKeyexpr>,
    ) -> Result<Self, ZResult> {
        Self::up_to(engine, literal, existing, non_wild_prefix(literal))
    }

    /// `literal` declared on `engine` up to `prefix`, a prefix of it. Refused, holding nothing,
    /// as [`DeclaredKeyexpr::declare`] refuses a key the session's tables cannot hold and a
    /// declaration the session refuses. Out of line: the program's declarations
    /// ([`DeclaredKeyexpr::declare`]) and the publisher's and the querier's, the subscriber's, the
    /// liveliness subscriber's and token's and the queryable's each carried a copy of it.
    #[inline(never)]
    fn up_to(
        engine: &'a crate::session::EngineHold,
        literal: &'a str,
        existing: Option<&DeclaredKeyexpr>,
        prefix: &str,
    ) -> Result<Self, ZResult> {
        if !fits(literal) {
            return Err(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY);
        }
        let prefix_len = prefix.len();
        let unheld = |mapping, row| Self {
            engine,
            literal,
            mapping,
            row,
            prefix_len,
            taken: None,
        };
        // pico `_z_keyexpr_declare_prefix`: an empty prefix declares nothing.
        if prefix_len == 0 {
            return Ok(unheld(0, None));
        }
        // Already declared on THIS session to exactly this prefix: the caller's key holds it
        // through the call, and the record takes its own hold (pico's
        // `_z_declared_keyexpr_is_fully_optimized` / `_is_non_wild_prefix_optimized` arm).
        if let Some(d) = existing
            .and_then(|existing| existing.declared_on(crate::session::EngineHold::as_ref(engine)))
            .filter(|d| d.prefix_len == prefix_len)
        {
            return Ok(unheld(d.mapping_id(), d.hold.row()));
        }
        // A refused declaration sent nothing, and answers pico's code for its cause.
        let hold = engine.acquire_keyexpr(prefix).map_err(|refused| {
            crate::refusal::refusal_code(refused, crate::refusal::Door::Keyexpr)
        })?;
        Ok(Self {
            engine,
            literal,
            mapping: hold.mapping_id(),
            row: hold.row(),
            prefix_len,
            taken: Some(hold),
        })
    }

    /// The door's hold of the declaration and how many bytes of the key it covers, kept by the
    /// caller from here on; `None` when the door holds none.
    fn into_held(mut self) -> Option<(KeyHold, usize)> {
        let prefix_len = self.prefix_len;
        self.taken.take().map(|hold| (hold, prefix_len))
    }

    /// pico `_z_declared_keyexpr_alias_to_wire`: the declaration's id and the rest of the key, the
    /// literal when nothing covers it. It holds nothing, and names the rest by its length, read
    /// against the key's text ([`WireKey::names_in`]).
    pub(crate) fn wire(&self) -> WireKey {
        match self.literal.len().checked_sub(self.prefix_len) {
            Some(rest) if self.mapping != 0 => {
                WireKey::aliased_tail(self.mapping, rest).at_row(self.row)
            }
            _ => WireKey::literal(),
        }
    }

    /// The id of the declaration, `0` for none: what an entity announced on another key states
    /// as its own key's declaration, which the session's record of it holds
    /// (`WireKey::with_own`).
    pub(crate) fn declaration_id(&self) -> wz_session_core::wire_id::ExprId {
        self.mapping
    }

    /// This key as a retraction names it: its declaration and the rest of the key, or the
    /// literal when nothing covers it. A token's retraction names it in every mode
    /// (`vendor/zenoh-pico/src/net/liveliness.c` @
    /// `_z_declaration_t declaration = _z_make_undecl_token(id, &wireexpr);`).
    pub(crate) fn retraction_key(&self) -> RetractionKey {
        match self.literal.get(self.prefix_len..) {
            Some(rest) if self.mapping != 0 => RetractionKey::declared(self.mapping, rest),
            _ => RetractionKey::literal(),
        }
    }

    /// What an entity on this key names when it retracts itself on a session whose role is
    /// `mode`, or `None` when it retracts by id alone. pico names the entity's OWN key in every
    /// mode but client (`vendor/zenoh-pico/src/net/primitives.c` @
    /// `_z_wireexpr_t expr = _z_declared_keyexpr_alias_to_wire(&_Z_RC_IN_VAL(&s)->_key, zn);`):
    /// for a subscriber that is not the key the subscription was announced on, which is the
    /// caller's.
    pub(crate) fn retraction_naming_in(&self, mode: WhatAmI) -> Option<RetractionKey> {
        (mode != WhatAmI::Client).then(|| self.retraction_key())
    }
}

impl Drop for EntityKey<'_> {
    // Out of line: every door that declares an entity lets its hold go here, and each copy inlined
    // carried the give-back at the row and the session's.
    #[inline(never)]
    fn drop(&mut self) {
        if let Some(hold) = self.taken.take() {
            hold.release(crate::session::EngineHold::as_ref(self.engine));
        }
    }
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
///
/// Out of line: the `_from_str` door and both autocanonizing view doors end in this one, and
/// each held the reading and the judgement of its own.
#[no_mangle]
#[inline(never)]
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
        let Some(text) = crate::abi::text_of(bytes) else {
            return Z_ERR_INVALID;
        };
        if !is_pico_canon(text) {
            return Z_EINVAL;
        }
        *keyexpr = z_view_keyexpr_t {
            _start: bytes.as_ptr(),
            _len: len,
            _pad: [proof_of_canon(text), 0, 0, 0],
        };
        Z_OK
    })
}

/// Build a view keyexpr over `len` bytes WITHOUT validating it (pico
/// `z_view_keyexpr_from_substr_unchecked`). Same no-error-channel contract as
/// [`z_view_keyexpr_from_str_unchecked`], including leaving the view EMPTY
/// rather than storing bytes this crate could not later read as `&str`.
///
/// Out of line: the `_from_str` door ends in this one, and held a copy of its own.
#[no_mangle]
#[inline(never)]
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
        if crate::abi::text_of(bytes).is_none() {
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
    guard_val(|| keyexpr.is_null() || (*keyexpr)._len == 0)
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
///
/// A key not in canon form, which only an unchecked view can hold, is refused with `Z_EINVAL`
/// before anything is declared; zenoh-pico declares whatever text the key holds.
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
        let literal = match outbound_keyexpr(keyexpr) {
            Ok(key) => key,
            Err(code) => return code,
        };
        // The key's place is taken before it is declared, so a full pool refuses the key and
        // nothing is declared.
        let Some(slot) = crate::object_slot::Slot::take(crate::object_slot::Kind::Keyexpr) else {
            return crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY;
        };
        match DeclaredKeyexpr::declare(engine_held(state), literal, declared_of(keyexpr)) {
            Ok(key) => {
                // The literal passed the whole outbound gate above.
                owned_keyexpr_at(declared, slot.fill(key), PROVEN);
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
        let handle = (*keyexpr)._this._state;
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

// A key's handle is its fourth word, not its first: null and take are the shared bodies over its
// size, while check and drop read the handle where it lies.
crate::abi::impl_type_facts!(z_owned_keyexpr_t, None);

/// Zero an owned keyexpr in place (pico `z_internal_keyexpr_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_keyexpr_null(obj: *mut z_owned_keyexpr_t) {
    crate::abi::obj_null(obj.cast(), <z_owned_keyexpr_t>::facts());
}

/// `true` iff the owned keyexpr holds a live declaration (pico
/// `z_internal_keyexpr_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_keyexpr_check(obj: *const z_owned_keyexpr_t) -> bool {
    !obj.is_null() && !(*obj)._state.is_null()
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
    crate::abi::obj_move(dst.cast(), src.cast(), <z_owned_keyexpr_t>::facts());
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
        let handle = (*obj)._this._state;
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
/// [`DeclaredKeyexpr`] documents. The declaration, if any, rides in the box, and
/// `_handle` names its row ([`DeclaredKeyexpr::row_address`]); a key's wire form is
/// asked of the key ([`wire_key_of`]), which is the only place that can tell a
/// whole-key declaration from a prefix one.
/// `Z_OK`; `_Z_ERR_SYSTEM_OUT_OF_MEMORY`, `dst` as it was and `key` let go of, when the heap
/// refuses the key's box.
///
/// Out of line: the clone, the owned constructor and the canonizing body each carried their own
/// copy of the box, its move into place and the drop of a key the heap refused.
#[inline(never)]
unsafe fn store_owned_keyexpr(
    dst: *mut z_owned_keyexpr_t,
    key: DeclaredKeyexpr,
    proof: usize,
) -> ZResult {
    match crate::bytes::try_box(key) {
        Ok(key) => {
            owned_keyexpr_at(dst, Box::into_raw(key), proof);
            Z_OK
        }
        Err(no_room) => no_room.code(),
    }
}

/// Write into `dst` the owned keyexpr whose key lies at `key`, a place of its own: a pool's slot
/// for a key the program declared (`z_declare_keyexpr`), the heap's for the rest; `proof` is
/// what its constructor proved of the text ([`proof_of_canon`]), `0` for nothing.
///
/// # Safety
/// `dst` is valid and writable; `key` is a live key a [`crate::object_slot::Slot`] was filled
/// with or a `Box` made, which `dst` then owns.
unsafe fn owned_keyexpr_at(dst: *mut z_owned_keyexpr_t, key: *mut DeclaredKeyexpr, proof: usize) {
    let literal = (*key).literal();
    *dst = z_owned_keyexpr_t {
        _start: literal.as_ptr(),
        _len: literal.len(),
        _handle: (*key).row_address() | proof,
        _state: key as *mut c_void,
        _pad: [0usize; 2],
    };
}

/// Build an owned keyexpr from a NUL-terminated string (pico
/// `z_keyexpr_from_str`), REJECTING a non-canon input with `Z_EINVAL`, as the
/// checked view constructor rejects it.
///
/// Rejecting rather than repairing is upstream's split: the `_autocanonize`
/// siblings exist precisely because this one does not canonize. A constructor
/// that silently canonized would make `z_keyexpr_from_str("a//b")` succeed
/// where upstream fails, and the program would never learn its keyexpr was
/// malformed. zenoh-pico's copies the text unjudged
/// (`vendor/zenoh-pico/src/api/api.c` @
/// `return _z_declared_keyexpr_from_substr(&key->_val, name, len);`), unlike its
/// own view constructor; that gap is not followed.
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
/// `z_keyexpr_from_substr`), rejecting a non-canon input as
/// [`z_keyexpr_from_str`] does.
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
        if let Err(code) = canon_key(text) {
            return code;
        }
        match DeclaredKeyexpr::literal_only(text) {
            Ok(key) => store_owned_keyexpr(keyexpr, key, proof_of_canon(text)),
            Err(code) => code,
        }
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
///
/// Out of line: the `_from_str` door ends in this one, and held a copy of its own.
#[no_mangle]
#[inline(never)]
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
        // The text is the one part of a join with nothing on its left, so it is canonized, held
        // to the bound and stored by the body the joins use, as a literal. pico copies the text and
        // canonizes the copy (`vendor/zenoh-pico/src/api/api.c` @
        // `z_keyexpr_canonize((char *)_z_string_data(&key->_val._inner._keyexpr),`), answering
        // its canonize status.
        match store_canonized(
            keyexpr,
            core::ptr::null(),
            &[text.as_bytes()],
            PartsForm::Canonized,
        ) {
            Ok(written) => {
                *len = written;
                Z_OK
            }
            Err(code) => code,
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
    crate::abi::text_of(core::slice::from_raw_parts(name.cast::<u8>(), len))
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
// Out of line: `z_keyexpr_take_from_loaned` is a clone that empties its source, and carried a
// copy of this body.
#[inline(never)]
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
        // A copy is the key extended by nothing. One its declaration's count or the heap has no
        // room for is refused, and `dst` stays null.
        // The copy's text is the source's, so it keeps what was proven of it.
        match extended_from(src, text) {
            Ok(key) => store_owned_keyexpr(dst, key, proof_of(src)),
            Err(code) => code,
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
            (*src)._start = core::ptr::null();
            (*src)._len = 0;
        }
        rc
    })
}

/// Append `right[..len]` to `left` (pico `z_keyexpr_concat`).
///
/// Concatenation is TEXTUAL, with no separator inserted — upstream appends the
/// bytes as given, so `concat("a/b", "c")` is `a/bc` and a caller wanting a new
/// chunk passes `"/c"`. Nothing is rewritten: a `*` meeting a `*` at the seam is
/// refused with `Z_EINVAL`, as both originals refuse it
/// (`vendor/zenoh-pico/src/session/keyexpr.c` @
/// `if (left_data[left_len - 1] == '*' && len > 0 && right[0] == '*') {`), and so is a
/// result not in canon form (`"a/**" + "/*"`), as upstream zenoh refuses it
/// (`zenoh/src/api/key_expr.rs` @
/// `key_expr: OwnedKeyExpr::try_from(format!("{self}{s}"))?,`). zenoh-pico keeps such a
/// result as it is; wz does not follow that gap.
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
            match crate::abi::text_of(core::slice::from_raw_parts(right.cast::<u8>(), len)) {
                Some(t) => t,
                None => return Z_ERR_INVALID,
            }
        };
        if head.ends_with('*') && tail.starts_with('*') {
            return Z_EINVAL;
        }
        store_canonized(
            key,
            left,
            &[head.as_bytes(), tail.as_bytes()],
            PartsForm::AsGiven,
        )
        .err()
        .unwrap_or(Z_OK)
    })
}

/// The result of extending `left` to `literal`: `left`'s declaration kept when
/// `left` is a declared key (pico `_z_declared_keyexpr_concat` / `_join`), a
/// plain literal otherwise. Refused as [`DeclaredKeyexpr::extended`] refuses.
///
/// Out of line: the clone door and the canonizing body both end here, and each carried its own
/// read of the kinds of a loan, so each kind is one call of [`DeclaredKeyexpr::kept_with`].
///
/// # Safety
/// `left` must be null or a live loaned keyexpr.
#[inline(never)]
unsafe fn extended_from(
    left: *const z_loaned_keyexpr_t,
    literal: &str,
) -> Result<DeclaredKeyexpr, ZResult> {
    match lent_of(left) {
        LentKey::Kept(declared) => declared.extended(literal),
        LentKey::Record(session, own) => DeclaredKeyexpr::kept_with(
            Some(session),
            keyexpr_str(left).unwrap_or_default(),
            literal,
            own.map(|own| Covering::Lent(session, own)),
        ),
        LentKey::View => DeclaredKeyexpr::kept_with(None, "", literal, None),
    }
}

/// The body `z_keyexpr_concat`, `z_keyexpr_join` and the owned canonizing constructor share, out
/// of line so no export holds a copy of it: the key the text `parts` make, taken as `form` says
/// by [`canonize_parts_as`] into a buffer of the bound, stored in `key` keeping `left`'s
/// declaration ([`extended_from`]), a literal for a null `left`. The bound is held to the form
/// and not to the text, as pico keeps only the form: a form past the bound is refused as a key past
/// pico's heap is (`_Z_ERR_SYSTEM_OUT_OF_MEMORY`, [`fits`]). A text no canonizing makes a key of
/// is answered with pico's canonize status for the cause under [`PartsForm::Canonized`], as its
/// join and its canonizing constructor answer (`vendor/zenoh-pico/src/session/keyexpr.c` @
/// `_Z_CLEAN_RETURN_IF_ERR(_z_keyexpr_canonize((char *)key->_keyexpr._slice.start, &key->_keyexpr._slice.len),`),
/// and every refusal under [`PartsForm::AsGiven`] with pico's `_Z_ERR_INVALID` (`Z_EINVAL`), the
/// one refusal its concatenation has (`vendor/zenoh-pico/src/session/keyexpr.c` @
/// `_Z_ERROR_RETURN(_Z_ERR_INVALID);`). The form's length on success; `key` is left as it was on
/// a refusal.
///
/// # Safety
/// `key` must be valid and writable; `left` must be null or a live loaned keyexpr.
#[inline(never)]
unsafe fn store_canonized(
    key: *mut z_owned_keyexpr_t,
    left: *const z_loaned_keyexpr_t,
    parts: &[&[u8]],
    form: PartsForm,
) -> Result<usize, ZResult> {
    // Left unfilled: the walk writes the form from the room's first byte and reads no further than
    // it wrote, and a room of the bound filled first is a write of the whole bound at every call.
    let mut room =
        [core::mem::MaybeUninit::<u8>::uninit(); wz_session_core::caps::MAX_KEYEXPR_BYTES];
    let canon = canonize_parts_as(parts, &mut room, KeyexprDialect::Pico, form).map_err(
        |refusal| match (refusal, form) {
            (PartsRefusal::Canon(KeyexprCanonError::ExceedsCapacity), _) => {
                crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY
            }
            (PartsRefusal::Canon(err), PartsForm::Canonized) => pico_canon_status(&err),
            (PartsRefusal::NotText, _) => Z_ERR_INVALID,
            _ => Z_EINVAL,
        },
    )?;
    match store_owned_keyexpr(key, extended_from(left, canon)?, proof_of_canon(canon)) {
        Z_OK => Ok(canon.len()),
        code => Err(code),
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
        store_canonized(
            key,
            left,
            &[l.as_bytes(), b"/".as_slice(), r.as_bytes()],
            PartsForm::Canonized,
        )
        .err()
        .unwrap_or(Z_OK)
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
    guard_val(|| keyexpr_pair(l, r).is_some_and(|(a, b)| a == b))
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
    guard_val(|| {
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
    guard_val(|| {
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
    guard_val(|| {
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
        let Some(text) = crate::abi::text_of(core::slice::from_raw_parts(start.cast::<u8>(), len))
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

/// Canonize `start[..*len]` IN PLACE, writing the new length back (pico
/// `z_keyexpr_canonize`).
///
/// In place is safe because canonization never grows a keyexpr — every rule
/// (`$*` -> `*`, `$*$*` -> `$*`, dropping a `*` after `**`) removes bytes or
/// keeps the count. The buffer is NOT NUL-terminated here; that is
/// [`z_keyexpr_canonize_null_terminated`]'s job, and the split is upstream's.
///
/// Out of line: the NUL-terminated form and the substring autocanonizing view door canonize
/// through this one, and each held the reading and the status mapping of its own.
///
/// # Safety
/// `start` must be null or point at `*len` readable AND writable bytes; `len`
/// must be null or valid and writable.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn z_keyexpr_canonize(start: *mut c_char, len: *mut usize) -> ZResult {
    guarded(|| {
        if start.is_null() || len.is_null() {
            return Z_ERR_NULL;
        }
        let text = core::slice::from_raw_parts_mut(start.cast::<u8>(), *len);
        if crate::abi::text_of(text).is_none() {
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
    /// it lies; a key not in canon form is `Z_EINVAL`, whether no canonizing makes a key of it
    /// (an empty chunk) or canonizing would rewrite it (a lone `$*` chunk, a `*` after `**`); a
    /// canon key a pico peer's canonizer aborts on, and no key, are `Z_ERR_INVALID`. Turned red by
    /// [`outbound_key`] without [`canon_key`], which passes the keys canonizing would rewrite.
    #[test]
    fn the_outbound_gate_reads_a_canon_key_and_refuses_the_rest() {
        let canon = unchecked(c"demo/a/**");
        let empty_chunk = unchecked(c"demo//a");
        let lone_dollar_star = unchecked(c"demo/$*");
        let star_after_double = unchecked(c"demo/**/*");
        let pico_aborts = unchecked(c"**/c/*");
        // SAFETY: views of this frame, and a null pointer.
        unsafe {
            let read = outbound_keyexpr(z_view_keyexpr_loan(&canon)).expect("a canon key");
            assert_eq!(read, "demo/a/**");
            assert_eq!(read.as_ptr(), canon._start, "read where the view holds it");
            for refused in [&empty_chunk, &lone_dollar_star, &star_after_double] {
                assert_eq!(
                    outbound_keyexpr(z_view_keyexpr_loan(refused)),
                    Err(Z_EINVAL)
                );
            }
            assert_eq!(
                outbound_keyexpr(z_view_keyexpr_loan(&pico_aborts)),
                Err(Z_ERR_INVALID)
            );
            assert_eq!(outbound_keyexpr(core::ptr::null()), Err(Z_ERR_INVALID));
        }
    }

    /// The owned constructors refuse a text not in canon form with `Z_EINVAL`, the code the
    /// checked view constructors answer, and leave the destination null; the same keys in canon
    /// form are made. Turned red by the owned constructor copying the text unjudged, as
    /// zenoh-pico's does, or answering another code than the view's.
    #[test]
    fn the_owned_constructors_refuse_a_text_not_in_canon_form() {
        // SAFETY: owned keys of this frame, each let go of once, and C strings that outlive them.
        unsafe {
            for refused in [
                c"zenoh//test",
                c"zenoh/test/",
                c"/zenoh/test",
                c"a/**/*",
                c"a/$*",
            ] {
                let mut view = unchecked(c"x");
                assert_eq!(
                    z_view_keyexpr_from_str(&mut view, refused.as_ptr()),
                    Z_EINVAL,
                    "{refused:?}: the view refuses it"
                );
                let mut key = z_owned_keyexpr_t::null_value();
                assert_eq!(
                    z_keyexpr_from_str(&mut key, refused.as_ptr()),
                    Z_EINVAL,
                    "{refused:?}"
                );
                assert!(!z_internal_keyexpr_check(&key), "{refused:?}: left null");
                let text = refused.to_bytes();
                assert_eq!(
                    z_keyexpr_from_substr(&mut key, text.as_ptr().cast(), text.len()),
                    Z_EINVAL,
                    "{refused:?}"
                );
                assert!(!z_internal_keyexpr_check(&key), "{refused:?}: left null");
            }
            for made in [c"zenoh/test", c"a/*/**", c"demo/$*x"] {
                let mut key = z_owned_keyexpr_t::null_value();
                assert_eq!(
                    z_keyexpr_from_str(&mut key, made.as_ptr()),
                    Z_OK,
                    "{made:?}"
                );
                assert_eq!(
                    keyexpr_str(z_keyexpr_loan(&key)).map(str::as_bytes),
                    Some(made.to_bytes())
                );
                z_keyexpr_drop(z_keyexpr_move(&mut key));
            }
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

    /// The outbound gate reads a key a checked constructor marked as it lies, and judges every
    /// other key as before: a view of a text not in canon form made unchecked is `Z_EINVAL`, and
    /// a canon key the pico-safe gate refuses is `Z_ERR_INVALID` though its view was made checked.
    /// The mark is what is read: a view marked by hand over a text not in canon form is not walked.
    /// Turned red by [`outbound_keyexpr`] trusting a key with no mark or with the canon mark alone,
    /// or judging a marked one again.
    #[test]
    fn the_outbound_gate_reads_a_marked_key_and_judges_the_rest() {
        let mut marked = unchecked(c"x");
        let mut canon_only = unchecked(c"x");
        let off_canon = unchecked(c"demo//a");
        let mut forged = unchecked(c"demo//a");
        forged._pad[0] = PROVEN;
        // SAFETY: views of this frame, and C strings that outlive them.
        unsafe {
            assert_eq!(
                z_view_keyexpr_from_str(&mut marked, c"demo/a/**".as_ptr()),
                Z_OK
            );
            let read = outbound_keyexpr(z_view_keyexpr_loan(&marked)).expect("a marked key");
            assert_eq!(read, "demo/a/**");
            assert_eq!(read.as_ptr(), marked._start, "read where the view holds it");
            assert_eq!(
                z_view_keyexpr_from_str(&mut canon_only, c"**/c/*".as_ptr()),
                Z_OK
            );
            assert_eq!(
                outbound_keyexpr(z_view_keyexpr_loan(&canon_only)),
                Err(Z_ERR_INVALID)
            );
            assert_eq!(
                outbound_keyexpr(z_view_keyexpr_loan(&off_canon)),
                Err(Z_EINVAL)
            );
            assert_eq!(
                outbound_keyexpr(z_view_keyexpr_loan(&forged)),
                Ok("demo//a"),
                "a marked key is read, not judged"
            );
        }
    }

    /// A checked constructor marks its key with what it proved: a canon key the pico-safe gate
    /// admits carries both marks, a canon key the gate refuses carries the canon mark alone, and
    /// a view made unchecked or emptied carries none; an owned key made checked, joined or copied
    /// carries the marks of its text, and a copy of an unchecked view none. Turned red by a
    /// constructor that leaves the mark out, or by [`proof_of_canon`] setting the pico-safe mark
    /// without its check.
    #[test]
    fn a_checked_constructor_marks_what_it_proved() {
        // SAFETY: views and owned keys of this frame, each owned key let go of once, and C strings
        // that outlive them.
        unsafe {
            let mut view = unchecked(c"x");
            assert_eq!(proof_of(z_view_keyexpr_loan(&view)), 0, "unchecked");
            assert_eq!(
                z_view_keyexpr_from_str(&mut view, c"demo/a/**".as_ptr()),
                Z_OK
            );
            assert_eq!(proof_of(z_view_keyexpr_loan(&view)), PROVEN);
            assert_eq!(z_view_keyexpr_from_str(&mut view, c"**/c/*".as_ptr()), Z_OK);
            assert_eq!(
                proof_of(z_view_keyexpr_loan(&view)),
                PROVEN_CANON,
                "canon, and refused by the pico-safe gate"
            );
            z_view_keyexpr_empty(&mut view);
            assert_eq!(proof_of(z_view_keyexpr_loan(&view)), 0, "emptied");
            let plain = unchecked(c"demo/a");
            assert_eq!(proof_of(z_view_keyexpr_loan(&plain)), 0, "unchecked");

            let mut key = z_owned_keyexpr_t::null_value();
            assert_eq!(z_keyexpr_from_str(&mut key, c"demo/a".as_ptr()), Z_OK);
            assert_eq!(proof_of(z_keyexpr_loan(&key)), PROVEN);
            let mut copy = z_owned_keyexpr_t::null_value();
            assert_eq!(z_keyexpr_clone(&mut copy, z_keyexpr_loan(&key)), Z_OK);
            assert_eq!(proof_of(z_keyexpr_loan(&copy)), PROVEN, "a copy keeps them");
            let mut joined = z_owned_keyexpr_t::null_value();
            assert_eq!(
                z_keyexpr_join(
                    &mut joined,
                    z_keyexpr_loan(&key),
                    z_view_keyexpr_loan(&plain)
                ),
                Z_OK
            );
            assert_eq!(proof_of(z_keyexpr_loan(&joined)), PROVEN);
            let mut unproven = z_owned_keyexpr_t::null_value();
            assert_eq!(
                z_keyexpr_clone(&mut unproven, z_view_keyexpr_loan(&plain)),
                Z_OK
            );
            assert_eq!(
                proof_of(z_keyexpr_loan(&unproven)),
                0,
                "a copy of an unchecked view"
            );
            for mut owned in [key, copy, joined, unproven] {
                z_keyexpr_drop(z_keyexpr_move(&mut owned));
            }
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
    use alloc::sync::Arc;

    /// A registry with no face, read back through its own key table.
    fn session() -> Arc<wz_capi_core::faces::SharedSession> {
        Arc::new(
            wz_capi_core::faces::SharedSession::new(
                wz_capi_core::runtime::runtime_impl::TokioTime::new(),
                [0x5a; 16].into(),
                wz_session_core::policy::SessionPolicy::defaults(),
            )
            .expect("test host entropy"),
        )
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
        let engine = shared.as_engine();
        let program = DeclaredKeyexpr::declare(&engine, "demo/kd/decl", None).expect("declared");
        assert_eq!(shared.keyexpr_declarations().len(), 1);
        let entity = DeclaredKeyexpr::declare(&engine, "demo/kd/decl", Some(&program))
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

    /// A key the program holds gives its declaration back by the row its hold was taken in, not
    /// by its id: a declaration retracted whatever held it, whose id a later declaration takes
    /// again once the ids wrap, is not the one the program's `z_keyexpr_drop` lets go of. The ids
    /// are minted from the last, so they wrap at the next declaration and the id comes again
    /// within as many as it is from 1. Turned red by a hold given back by its id
    /// (`KeyHold::release` or the engine's `release_keyexpr` looking the id up), which retracts
    /// the new declaration.
    #[test]
    fn dropping_a_key_spares_a_declaration_that_took_its_retracted_id_again() {
        let shared = session();
        let engine = shared.as_engine();
        let declared = DeclaredKeyexpr::declare(&engine, "demo/kd/old", None).expect("declared");
        let old = shared.keyexpr_declarations()[0].0;
        let mut key = z_owned_keyexpr_t::null_value();
        // SAFETY: `key` is a live owned key the store writes over.
        unsafe { store_owned_keyexpr(&mut key, declared, 0) };
        // Retracted whatever holds it, as the other ABI's undeclaration of its key does.
        shared.undeclare_keyexpr(old);
        assert!(
            shared.keyexpr_declarations().is_empty(),
            "CONTROL: retracted"
        );
        // The last id, then 1 onward: declarations made and let go of come to the retracted id
        // again.
        shared.expr_ids_from(wz_session_core::wire_id::ExprId::MAX);
        let again = (0..=old)
            .find_map(|_| {
                let hold = shared
                    .acquire_keyexpr("demo/kd/new".to_owned())
                    .expect("an id is free");
                if hold.mapping_id() == old {
                    return Some(hold);
                }
                hold.release(&*shared);
                None
            })
            .expect("the retracted id is minted again");
        // SAFETY: `key` holds the owned key stored above, moved out once here.
        unsafe { z_keyexpr_drop(z_keyexpr_move(&mut key)) };
        assert_eq!(
            shared.keyexpr_declarations(),
            vec![(old, "demo/kd/new".to_owned())],
            "the new declaration stands after the program's key went"
        );
        again.release(&*shared);
        assert!(shared.keyexpr_declarations().is_empty());
    }

    /// A copy of a key whose declaration's count holds as many holders as it can is refused with
    /// pico's code for a count past its bound, and its destination is left null: a copy that held
    /// nothing would name a declaration its last counted holder's going retracts. Turned red by a
    /// `z_keyexpr_clone` that makes the copy anyway (`Z_OK`, or a destination that is not null),
    /// or one that makes it holding nothing (the declaration gone before the copy is dropped).
    #[test]
    fn a_clone_past_the_declarations_count_is_refused_and_left_null() {
        let shared = session();
        let engine = shared.as_engine();
        let declared = DeclaredKeyexpr::declare(&engine, "demo/kd/full", None).expect("declared");
        let mut key = z_owned_keyexpr_t::null_value();
        // SAFETY: `key` is a live owned key the store writes over.
        unsafe { store_owned_keyexpr(&mut key, declared, 0) };
        // The count is filled: the program's key holds one, and each acquire one more until the
        // count refuses.
        let mut holds = Vec::new();
        while let Some(hold) = shared.acquire_keyexpr("demo/kd/full".to_owned()) {
            holds.push(hold);
        }
        assert_eq!(
            holds.len(),
            usize::from(wz_session_core::session_tables::KeyexprHolds::MAX) - 1,
            "CONTROL: the count holds its bound"
        );
        let mut copy = z_owned_keyexpr_t::null_value();
        // SAFETY: `copy` is writable and `key` a live owned key, loaned for the call.
        let refused = unsafe { z_keyexpr_clone(&mut copy, z_keyexpr_loan(&key)) };
        assert_eq!(refused, crate::result::Z_ERR_OVERFLOW);
        // SAFETY: `copy` is a live owned key, null or not.
        assert!(
            !unsafe { z_internal_keyexpr_check(&copy) },
            "the destination is left null"
        );
        holds.pop().expect("a hold").release(&*shared);
        // SAFETY: as above.
        let taken = unsafe { z_keyexpr_clone(&mut copy, z_keyexpr_loan(&key)) };
        assert_eq!(taken, Z_OK, "CONTROL: a count with room takes the copy");
        // SAFETY: both hold the owned keys made above, each moved out once here.
        unsafe {
            z_keyexpr_drop(z_keyexpr_move(&mut key));
            z_keyexpr_drop(z_keyexpr_move(&mut copy));
        }
        for hold in holds {
            hold.release(&*shared);
        }
        assert!(
            shared.keyexpr_declarations().is_empty(),
            "every hold went back"
        );
    }

    /// A copy made through a key's loan names the declaration's row by its address, as the key
    /// does, takes its own hold there, and keeps the declaration after the key it was made from is
    /// dropped; the wire names it by the row's id. Turned red by a loan whose slot 2 is not the
    /// row, by a copy that takes no hold (the declaration gone with the first drop), or by a wire
    /// key that does not read the row's id.
    #[test]
    fn a_copy_made_through_a_loan_holds_the_declaration_at_its_row_past_the_original() {
        let shared = session();
        let engine = shared.as_engine();
        let declared = DeclaredKeyexpr::declare(&engine, "demo/kd/row", None).expect("declared");
        let row = declared.row_address();
        assert_ne!(row, 0, "the session's table names where the row lies");
        let mut key = z_owned_keyexpr_t::null_value();
        // SAFETY: `key` is a live owned key the store writes over.
        assert_eq!(unsafe { store_owned_keyexpr(&mut key, declared, 0) }, Z_OK);
        let mut copy = z_owned_keyexpr_t::null_value();
        // SAFETY: `copy` is writable and `key` a live owned key, loaned for the call.
        assert_eq!(
            unsafe { z_keyexpr_clone(&mut copy, z_keyexpr_loan(&key)) },
            Z_OK
        );
        // SAFETY: both are live owned keys, loaned for the reads.
        let slots = unsafe {
            (
                (*z_keyexpr_loan(&key))._handle,
                (*z_keyexpr_loan(&copy))._handle,
            )
        };
        assert_eq!(slots, (row, row), "both name the one row");
        // SAFETY: `key` holds the owned key stored above, moved out once here.
        unsafe { z_keyexpr_drop(z_keyexpr_move(&mut key)) };
        let declarations = shared.keyexpr_declarations();
        assert_eq!(declarations.len(), 1, "the copy holds the declaration");
        // SAFETY: `copy` is a live owned key, loaned for the call on the session it names.
        let wire = unsafe {
            wire_key_of(
                z_keyexpr_loan(&copy),
                crate::session::EngineHold::as_ref(&engine),
            )
        };
        assert_eq!(wire.mapping_id, declarations[0].0, "named by the row's id");
        drop(wire);
        // SAFETY: `copy` holds the owned key cloned above, moved out once here.
        unsafe { z_keyexpr_drop(z_keyexpr_move(&mut copy)) };
        assert!(
            shared.keyexpr_declarations().is_empty(),
            "the last holder retracts it"
        );
    }

    /// The session keeps its declarations' rows where they were put however many come after
    /// them, past the build's bound, as zenoh-c bounds a session's declarations by nothing but its
    /// heap: a key holding the first row by its address finds it there. Turned red by a table that
    /// moves its rows to grow (the first row's address changes) or one held to the build's bound (a
    /// declaration past it refused).
    #[test]
    fn declarations_past_the_builds_bound_leave_the_first_row_where_it_was() {
        let shared = session();
        let first = shared
            .acquire_keyexpr("demo/kd/0".to_owned())
            .expect("room for a declaration");
        let at = first.row_address();
        assert_ne!(at, 0, "the session names where the row lies");
        let past = wz_session_core::caps::MAX_DECLARED_KEYEXPRS + 1;
        let holds: Vec<_> = (1..=past)
            .map(|n| {
                shared
                    .acquire_keyexpr(alloc::format!("demo/kd/{n}"))
                    .expect("no bound but the heap's")
            })
            .collect();
        assert_eq!(shared.keyexpr_declarations().len(), past + 1);
        let again = shared
            .acquire_keyexpr("demo/kd/0".to_owned())
            .expect("a declaration held once more");
        assert_eq!(again.row_address(), at, "the first row is where it was put");
        again.release(&*shared);
        first.release(&*shared);
        for hold in holds {
            hold.release(&*shared);
        }
        assert!(shared.keyexpr_declarations().is_empty());
    }

    /// R2959 — the wire form: the declaration's id plus the remainder of the
    /// key, and the literal on a session that did not make the declaration.
    ///
    /// Turned red by an entity's key that keeps its hold past the door (the declarations left), or
    /// a wire that names the whole key by the prefix's id.
    #[test]
    fn a_prefix_declaration_names_the_rest_of_the_key_as_suffix() {
        let shared = session();
        let engine = shared.as_engine();
        let text = "demo/kd/qbl/*/x";
        let key = EntityKey::non_wild_prefix(&engine, text, None).expect("declared");
        let declarations = shared.keyexpr_declarations();
        assert_eq!(declarations.len(), 1);
        assert_eq!(declarations[0].1, "demo/kd/qbl");
        assert_eq!(key.declaration_id(), declarations[0].0);
        assert_eq!(key.wire().names_in(text), (declarations[0].0, Some("/*/x")));
        drop(key);
        assert!(
            shared.keyexpr_declarations().is_empty(),
            "the door's hold went with its key"
        );

        let program = DeclaredKeyexpr::declare(&engine, "demo/kd/qbl", None).expect("declared");
        let other = session().as_engine();
        assert_eq!(
            program.wire(&*other).mapping_id,
            0,
            "another session's id is not ours"
        );
    }

    /// An entity's key that opens wild declares nothing and is named whole, on the wire and in
    /// its retraction; a client names no key in a retraction. Turned red by a declaration of an
    /// empty prefix, or a retraction a client names.
    #[test]
    fn an_entity_key_that_opens_wild_is_named_whole() {
        let shared = session();
        let engine = shared.as_engine();
        let text = "**/x";
        let key = EntityKey::non_wild_prefix(&engine, text, None).expect("nothing to declare");
        assert!(shared.keyexpr_declarations().is_empty(), "nothing declared");
        assert_eq!(key.declaration_id(), 0);
        assert!(key.wire().is_literal());
        assert_eq!(key.retraction_key().names(text), (0, text));
        assert!(key.retraction_naming_in(WhatAmI::Client).is_none());
        assert!(key.retraction_naming_in(WhatAmI::Peer).is_some());
    }

    /// What a retraction names is the declaration and the length of the rest of the key, read
    /// against the entity's key, so making it takes no memory; on a session that did not make the
    /// declaration it names the literal.
    ///
    /// # Control
    ///
    /// A retraction that copies the rest of the key reds the count.
    #[cfg(feature = "connectivity")]
    #[test]
    fn a_retraction_names_the_rest_of_its_own_key_and_takes_no_memory() {
        let shared = session();
        let engine = shared.as_engine();
        let text = "demo/kd/ret/**";
        let key = EntityKey::non_wild_prefix(&engine, text, None).expect("declared");
        let declared = shared.keyexpr_declarations()[0].0;
        let mut named = None;
        let taken = crate::connectivity::tests::allocations(|| {
            named = Some(key.retraction_key());
        });
        assert_eq!(taken, 0, "a retraction copies nothing of the key");
        let named = named.expect("the retraction was made");
        assert_eq!(named.names(text), (declared, "/**"));
    }

    /// A wire key names the rest of its key by its length, read against the key's literal, so
    /// making one takes no memory, whether it holds the declaration or not.
    ///
    /// # Control
    ///
    /// A wire key that copies the rest of the key (`WireKey::aliased` over `to_owned`) reds the
    /// count; one whose length is not the rest's reds the `names_in` assertions.
    #[cfg(feature = "connectivity")]
    #[test]
    fn a_wire_key_names_the_rest_of_its_key_and_takes_no_memory() {
        let shared = session();
        let engine = shared.as_engine();
        let text = "demo/kd/wire/*/x";
        let key = EntityKey::non_wild_prefix(&engine, text, None).expect("declared");
        let declared = shared.keyexpr_declarations()[0].0;
        let mut plain = None;
        let taken = crate::connectivity::tests::allocations(|| {
            plain = Some(key.wire());
        });
        assert_eq!(taken, 0, "a wire key copies nothing of the key");
        let plain = plain.expect("the plain key was made");
        assert_eq!(plain.names_in(text), (declared, Some("/*/x")));
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
    //! key the build has no room for, refused as pico's heap refuses one
    //! (`_Z_ERR_SYSTEM_OUT_OF_MEMORY`), with nothing left behind.
    use super::*;
    use crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY;
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
            assert_eq!(past, Z_ERR_SYSTEM_OUT_OF_MEMORY);
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
                Z_ERR_SYSTEM_OUT_OF_MEMORY
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
                Z_ERR_SYSTEM_OUT_OF_MEMORY
            );
            assert!(!z_internal_keyexpr_check(&concat), "nothing is left behind");

            for key in [&mut left, &mut right, &mut wider, &mut full] {
                z_keyexpr_drop(z_keyexpr_move(key));
            }
        }
    }

    /// `left` concatenated with `tail`: the code the door answered and the key it made.
    unsafe fn concat(left: &z_owned_keyexpr_t, tail: &str) -> (ZResult, z_owned_keyexpr_t) {
        let mut key = z_owned_keyexpr_t::null_value();
        let rc = z_keyexpr_concat(
            &mut key,
            z_keyexpr_loan(left),
            tail.as_ptr() as *const c_char,
            tail.len(),
        );
        (rc, key)
    }

    /// A concatenation is taken only as it is: a result in canon form is the key, and one that is
    /// not is refused with `Z_EINVAL` and the destination left null, whether canonizing would
    /// rewrite it (a `*` after `**`, a lone `$*` chunk, a text past the bound whose form is
    /// short) or not; a `*` meeting a `*` at the seam is refused even where the result is canon.
    /// Turned red by a concatenation that canonizes its result, or that drops the seam rule.
    #[test]
    fn a_concatenation_is_taken_only_as_it_is() {
        unsafe {
            let (rc, mut ab) = owned("a/b");
            assert_eq!(rc, Z_OK);
            let (rc, mut made) = concat(&ab, "/c");
            assert_eq!(rc, Z_OK, "CONTROL: a canon result is the key");
            assert_eq!(keyexpr_str(z_keyexpr_loan(&made)), Some("a/b/c"));
            z_keyexpr_drop(z_keyexpr_move(&mut made));

            let (rc, mut wild) = owned("a/**");
            assert_eq!(rc, Z_OK);
            let (rc, refused) = concat(&wild, "/*");
            assert_eq!(rc, Z_EINVAL, "a/**/* is not canon, and is not rewritten");
            assert!(
                !z_internal_keyexpr_check(&refused),
                "nothing is left behind"
            );
            let (rc, refused) = concat(&ab, "/$*");
            assert_eq!(rc, Z_EINVAL, "a lone `$*` chunk is not rewritten");
            assert!(
                !z_internal_keyexpr_check(&refused),
                "nothing is left behind"
            );

            let (rc, mut star) = owned("a/*");
            assert_eq!(rc, Z_OK);
            let (rc, refused) = concat(&star, "*/b");
            assert_eq!(rc, Z_EINVAL, "a `*` meets a `*` at the seam");
            assert!(
                !z_internal_keyexpr_check(&refused),
                "nothing is left behind"
            );
            let (rc, mut made) = concat(&star, "/b");
            assert_eq!(rc, Z_OK, "CONTROL: a `*` before a `/` is no seam of stars");
            assert_eq!(keyexpr_str(z_keyexpr_loan(&made)), Some("a/*/b"));
            z_keyexpr_drop(z_keyexpr_move(&mut made));

            // A suffix longer than two keys of the bound whose form is short is not its own form.
            let (rc, mut short) = owned("a");
            assert_eq!(rc, Z_OK);
            let longer = "/**".repeat(3 * MAX_KEYEXPR_BYTES);
            let (rc, refused) = concat(&short, &longer);
            assert_eq!(rc, Z_EINVAL);
            assert!(
                !z_internal_keyexpr_check(&refused),
                "nothing is left behind"
            );

            for key in [&mut ab, &mut wild, &mut star, &mut short] {
                z_keyexpr_drop(z_keyexpr_move(key));
            }
        }
    }

    /// A concatenation is held to the bound: a canon result past it is refused with
    /// `_Z_ERR_SYSTEM_OUT_OF_MEMORY` and the destination left null.
    #[test]
    fn a_concatenation_past_the_bound_is_refused() {
        unsafe {
            let mut concat = z_owned_keyexpr_t::null_value();
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
                Z_ERR_SYSTEM_OUT_OF_MEMORY
            );
            assert!(!z_internal_keyexpr_check(&concat), "nothing is left behind");
            z_keyexpr_drop(z_keyexpr_move(&mut full));
        }
    }

    /// The one judgement of a key's text answers each cause with its code: a canon key passes, a
    /// text not in canon form is `Z_EINVAL`, and a key past the bound is out of memory in every
    /// profile, as pico refuses what its heap cannot hold. Turned red by a refusal of either cause
    /// folded onto the other's code, or by the bound judged after the form.
    #[test]
    fn the_key_judgement_answers_each_cause_with_its_code() {
        assert_eq!(
            canon_key("demo/a/**").map(CanonKey::as_str),
            Ok("demo/a/**")
        );
        let longest = key_of(MAX_KEYEXPR_BYTES);
        assert_eq!(
            canon_key(&longest).map(CanonKey::as_str),
            Ok(longest.as_str())
        );
        for refused in ["demo//a", "demo/a/", "demo/$*", "demo/**/*", "demo/**/**"] {
            assert_eq!(canon_key(refused), Err(Z_EINVAL), "{refused}");
        }
        assert_eq!(
            canon_key(&key_of(MAX_KEYEXPR_BYTES + 1)),
            Err(Z_ERR_SYSTEM_OUT_OF_MEMORY)
        );
    }

    /// The canonizing doors read a text of any length and hold only its form to the bound, as
    /// pico keeps only the form: a text past the bound whose form is under it is a key, its
    /// form's length written back, and is canonized over itself; a form past the bound is refused
    /// by the owned constructor with `_Z_ERR_SYSTEM_OUT_OF_MEMORY`, the destination null and no
    /// length written back, and canonized in place, which bounds nothing. Turned red by a bound judged on the text.
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
                Z_ERR_SYSTEM_OUT_OF_MEMORY
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

    /// Each text no canonizing makes a key of, with the status zenoh-pico's canonize answers for
    /// it (`vendor/zenoh-pico/include/zenoh-pico/api/constants.h` @
    /// `Z_KEYEXPR_CANON_EMPTY_CHUNK = -4,` to `Z_KEYEXPR_CANON_CONTAINS_UNBOUND_DOLLAR = -8`).
    const REFUSED: [(&str, ZResult); 5] = [
        ("home//temp", -4),
        ("home/foo*bar", -5),
        ("home/$$", -6),
        ("home/foo#bar", -7),
        ("home/foo$bar", -8),
    ];

    /// Every door that canonizes answers a text no canonizing makes a key of with zenoh-pico's
    /// code: the owned canonizing constructor, the join and the in-place canonize with pico's
    /// canonize status for the cause, as pico's do; the concatenation, which in pico canonizes
    /// nothing and refuses only with `_Z_ERR_INVALID`, with that code (`Z_EINVAL`). Each leaves
    /// its destination null. Turned red by a refusal of any cause folded onto one code, or by the
    /// concatenation answering a canonize status pico's never answers.
    #[test]
    fn every_canon_refusal_answers_picos_code() {
        unsafe {
            let (rc, mut home) = owned("home");
            assert_eq!(rc, Z_OK);
            for (text, status) in REFUSED {
                let mut len = text.len();
                let mut key = z_owned_keyexpr_t::null_value();
                assert_eq!(
                    z_keyexpr_from_substr_autocanonize(
                        &mut key,
                        text.as_ptr() as *const c_char,
                        &mut len,
                    ),
                    status,
                    "autocanonize {text}"
                );
                assert!(
                    !z_internal_keyexpr_check(&key),
                    "{text}: nothing is left behind"
                );

                let mut bytes = text.as_bytes().to_vec();
                let mut len = bytes.len();
                assert_eq!(
                    z_keyexpr_canonize(bytes.as_mut_ptr() as *mut c_char, &mut len),
                    status,
                    "canonize {text}"
                );

                let tail = text
                    .strip_prefix("home")
                    .expect("each text opens with home");
                assert_eq!(
                    z_keyexpr_concat(
                        &mut key,
                        z_keyexpr_loan(&home),
                        tail.as_ptr() as *const c_char,
                        tail.len(),
                    ),
                    Z_EINVAL,
                    "concat {text}"
                );
                assert!(
                    !z_internal_keyexpr_check(&key),
                    "{text}: nothing is left behind"
                );

                let right = text
                    .strip_prefix("home/")
                    .expect("each text opens with home/");
                let cright = alloc::ffi::CString::new(right).expect("no NUL");
                let mut view = z_view_keyexpr_t {
                    _start: core::ptr::null(),
                    _len: 0,
                    _pad: [0usize; 4],
                };
                z_view_keyexpr_from_str_unchecked(&mut view, cright.as_ptr());
                assert_eq!(
                    z_keyexpr_join(&mut key, z_keyexpr_loan(&home), z_view_keyexpr_loan(&view)),
                    status,
                    "join {text}"
                );
                assert!(
                    !z_internal_keyexpr_check(&key),
                    "{text}: nothing is left behind"
                );
            }
            z_keyexpr_drop(z_keyexpr_move(&mut home));
        }
    }

    /// The owned canonizing constructor writes no length back on a refusal, and the key it makes
    /// names no declaration. Turned red by a length written back on a refusal.
    #[test]
    fn the_owned_canonizing_constructor_writes_back_only_what_it_made() {
        unsafe {
            for (text, status) in REFUSED {
                let mut len = text.len();
                let mut key = z_owned_keyexpr_t::null_value();
                assert_eq!(
                    z_keyexpr_from_substr_autocanonize(
                        &mut key,
                        text.as_ptr() as *const c_char,
                        &mut len,
                    ),
                    status,
                    "{text}"
                );
                assert!(
                    !z_internal_keyexpr_check(&key),
                    "{text}: nothing is left behind"
                );
                assert_eq!(len, text.len(), "{text}: no length is written back");
            }
            let text = "demo/**/**";
            let mut len = text.len();
            let mut key = z_owned_keyexpr_t::null_value();
            assert_eq!(
                z_keyexpr_from_substr_autocanonize(
                    &mut key,
                    text.as_ptr() as *const c_char,
                    &mut len
                ),
                Z_OK
            );
            assert_eq!(len, "demo/**".len());
            let made = declared_of(z_keyexpr_loan(&key)).expect("an owned key has its handle");
            assert_eq!(made.literal(), "demo/**");
            assert!(made.declaration.is_none(), "a literal names no declaration");
            z_keyexpr_drop(z_keyexpr_move(&mut key));
        }
    }
}

#[cfg(test)]
mod key_text_tests {
    //! How a key the session's key arena kept no room for is refused.
    use super::*;

    /// A key past the session's bound and one the arena has no room for are both out of memory, as
    /// a key past pico's heap is, and a closed session's object keeps a copy of its own.
    #[test]
    fn a_key_the_arena_refuses_answers_picos_code() {
        assert_eq!(
            refusal_of(KeyNotHeld::TooLong),
            Some(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY)
        );
        assert_eq!(
            refusal_of(KeyNotHeld::NoRoom),
            Some(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY)
        );
        assert_eq!(refusal_of(KeyNotHeld::Closed), None);
    }

    /// A key made with no session is a copy of its own, read and shared as one.
    #[test]
    fn a_key_with_no_session_is_a_copy_of_its_own() {
        let key = DeclaredKeyexpr::literal_only("demo/own/key").expect("the test's heap");
        assert!(!key.literal.is_session());
        let shared = key.share().expect("a share");
        assert!(!shared.literal.is_session());
        assert_ne!(
            shared.literal().as_ptr(),
            key.literal().as_ptr(),
            "the share is a copy of its own"
        );
        drop(key);
        assert_eq!(shared.literal(), "demo/own/key");
    }
}

// The cooperative engine, which keeps a key arena: a session the build opens as `z_open` opens it,
// listening on the loopback, its engine the build's own `Engine`. The room a test needs is made by
// filling the session's arena, as a program's own keys fill it, not by a smaller arena.
#[cfg(all(test, not(feature = "engine-tokio"), feature = "peer"))]
mod arena_key_tests {
    use super::*;
    use crate::session::{
        engine_held, listening_on_loopback, z_close, z_owned_session_t, z_session_drop,
        z_session_loan, z_session_loan_mut, z_session_move,
    };

    /// A session that listens on a port of the loopback, opened as a program opens one, and the
    /// engine it runs on.
    fn listening() -> (z_owned_session_t, crate::session::EngineHold) {
        let session = listening_on_loopback();
        // SAFETY: the session is live and owned by this frame.
        let handle = unsafe { session_handle(z_session_loan(&session)) };
        let engine = engine_held(handle.expect("an open session has its handle")).clone();
        (session, engine)
    }

    /// Close and let go of a session [`listening`] opened.
    fn close(mut session: z_owned_session_t) {
        // SAFETY: the session is live and owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }

    /// The session's key arena, which the cooperative engine always keeps.
    fn keys(engine: &crate::session::EngineHold) -> &dyn SessionKeys {
        super::key_arena(engine).expect("the cooperative engine keeps a key arena")
    }

    /// The arena a key of an object is held in is the engine's own, reached as its type and not
    /// through the port's object.
    #[test]
    fn the_key_arena_is_the_engine_itself() {
        let (session, engine) = listening();
        let arena: *const Engine = super::key_arena(&engine).expect("the engine keeps a key arena");
        assert!(core::ptr::eq(
            arena,
            crate::session::EngineHold::as_ptr(&engine)
        ));
        drop(engine);
        close(session);
    }

    /// `text` held in the session's key arena, or why not.
    fn hold(engine: &crate::session::EngineHold, text: &str) -> Result<HeldKey, KeyNotHeld> {
        keys(engine)
            .key(KeyAsk::Hold(text))
            .map(|key| key.expect("a hold answers its key"))
    }

    /// Let go of `key`.
    fn release(engine: &crate::session::EngineHold, key: HeldKey) {
        assert!(matches!(keys(engine).key(KeyAsk::Release(key)), Ok(None)));
    }

    /// Keys of `len` bytes, each a text of its own and so a block of its own (a text the arena
    /// keeps already is that block shared), held until the arena has no room for one more.
    fn fill_with(engine: &crate::session::EngineHold, len: usize) -> Vec<HeldKey> {
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
    fn fill_leaving(engine: &crate::session::EngineHold, len: usize, room: usize) -> Vec<HeldKey> {
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
    fn give_back(engine: &crate::session::EngineHold, held: Vec<HeldKey>) {
        for key in held {
            release(engine, key);
        }
    }

    /// Whether the session's key arena has room for one more key of `len` bytes, asked and let go.
    fn room_for(engine: &crate::session::EngineHold, len: usize) -> bool {
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
        let shared = key.share().expect("a share");
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
    /// count: a share outlives the key it was made from, the last holder let go retracts it, and a
    /// wire key made from it holds nothing. Turned red by a copy that takes no hold of its own,
    /// which lets the declaration go with the first holder, or by a wire key that takes one (the
    /// block still taken once the last key is dropped).
    #[test]
    fn a_declaration_lasts_as_long_as_its_last_holder() {
        let (session, engine) = listening();
        // The arena keeps room for one key of the declared one's length, which the declaration
        // takes: whether its block is back says whether the declaration is.
        let text = "demo/hold/a";
        let held = fill_leaving(&engine, text.len(), 1);
        let key = DeclaredKeyexpr::declare(&engine, text, None).expect("declared");
        assert!(
            !room_for(&engine, text.len()),
            "the declaration takes the last block"
        );
        let shared = key.share().expect("a share");
        let wire = key.wire(crate::session::EngineHold::as_ref(&engine));
        assert_ne!(wire.mapping_id, 0, "the wire names the declaration");
        drop(key);
        assert!(!room_for(&engine, text.len()), "the share holds it");
        drop(shared);
        assert!(
            room_for(&engine, text.len()),
            "the last holder retracts it and its key's block goes back; the wire key held nothing"
        );
        drop(wire);
        give_back(&engine, held);
        close(session);
    }

    /// A key's loan names its declaration's row by the row's address, as a copy made through the
    /// loan does; the copy takes its own hold there and keeps the declaration after the key it was
    /// made from is dropped, and the wire names it by the row's id. Turned red by a loan whose
    /// slot 2 is not the row, by a copy that takes no hold (the declaration's block back after the
    /// first drop), or by a wire key that does not read the row's id.
    #[test]
    fn a_keys_loan_names_its_row_and_a_copy_holds_it_past_the_original() {
        let (session, engine) = listening();
        let text = "demo/row/a";
        let held = fill_leaving(&engine, text.len(), 1);
        let declared = DeclaredKeyexpr::declare(&engine, text, None).expect("declared");
        let id = declared
            .wire(crate::session::EngineHold::as_ref(&engine))
            .mapping_id;
        let row = declared.row_address();
        assert_ne!(row, 0, "a declared key names its row");
        let mut key = z_owned_keyexpr_t::null_value();
        // SAFETY: `key` is a live owned key the store writes over.
        assert_eq!(unsafe { store_owned_keyexpr(&mut key, declared, 0) }, Z_OK);
        let mut copy = z_owned_keyexpr_t::null_value();
        // SAFETY: `copy` is writable and `key` a live owned key, loaned for the call.
        assert_eq!(
            unsafe { z_keyexpr_clone(&mut copy, z_keyexpr_loan(&key)) },
            Z_OK
        );
        // SAFETY: both are live owned keys, loaned for the reads.
        let slots = unsafe {
            (
                (*z_keyexpr_loan(&key))._handle,
                (*z_keyexpr_loan(&copy))._handle,
            )
        };
        assert_eq!(slots, (row, row), "both name the one row");
        // SAFETY: `key` holds the owned key stored above, moved out once here.
        unsafe { z_keyexpr_drop(z_keyexpr_move(&mut key)) };
        assert!(!room_for(&engine, text.len()), "the copy holds it");
        // SAFETY: `copy` is a live owned key, loaned for the call on the session it names.
        let wire = unsafe {
            wire_key_of(
                z_keyexpr_loan(&copy),
                crate::session::EngineHold::as_ref(&engine),
            )
        };
        assert_eq!(wire.mapping_id, id, "named by the row's id");
        drop(wire);
        // SAFETY: `copy` holds the owned key cloned above, moved out once here.
        unsafe { z_keyexpr_drop(z_keyexpr_move(&mut copy)) };
        assert!(
            room_for(&engine, text.len()),
            "the last holder retracts it and its key's block goes back"
        );
        give_back(&engine, held);
        close(session);
    }

    /// A declared key holds its session's engine through its text and names it through its
    /// declaration: its drop gives the text's hold back, the declaration reaches the session while
    /// it is open and nothing once it is closed, and a key dropped after the close lets go of the
    /// engine all the same. Turned red by a drop that keeps the text's hold, or by a close that
    /// leaves the session reached.
    #[test]
    fn a_declared_key_names_its_session_until_the_close_and_lets_its_engine_go() {
        use crate::session::EngineHold;
        let (session, engine) = listening();
        let before = EngineHold::holders(&engine);
        let key = DeclaredKeyexpr::declare(&engine, "demo/counts/a", None).expect("declared");
        assert!(key.literal.is_session());
        assert!(
            EngineHold::holders(&engine) > before,
            "the text holds the engine"
        );
        drop(key);
        assert_eq!(
            EngineHold::holders(&engine),
            before,
            "the drop gave it back"
        );
        let key = DeclaredKeyexpr::declare(&engine, "demo/counts/a", None).expect("declared");
        let named = EngineHold::downgrade(&engine);
        assert!(named.upgrade().is_some(), "open, the session is reached");
        close(session);
        assert!(
            named.upgrade().is_none(),
            "closed, it is reached by nothing"
        );
        drop(key);
        assert_eq!(
            EngineHold::holders(&engine),
            1,
            "the key let go of the engine its text held"
        );
    }

    /// A key named for a message sent once holds nothing: the declaration goes with the last key
    /// that holds it while the named one still stands, and is dropped giving nothing back. Turned
    /// red by a named key that takes a hold, which keeps the declaration past its last holder.
    #[test]
    fn a_wire_key_holds_no_declaration() {
        let (session, engine) = listening();
        let text = "demo/hold/named";
        let held = fill_leaving(&engine, text.len(), 1);
        let key = DeclaredKeyexpr::declare(&engine, text, None).expect("declared");
        let named = key.wire(crate::session::EngineHold::as_ref(&engine));
        assert_ne!(named.mapping_id, 0, "the key names the declaration");
        drop(key);
        assert!(
            room_for(&engine, text.len()),
            "the named key held nothing, so the declaration went with the key"
        );
        drop(named);
        give_back(&engine, held);
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
        assert!(
            room_for(&engine, 10),
            "nothing was declared, and the key's block went back"
        );
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
        assert!(
            room_for(&engine, 10),
            "every declaration went, and its block with it"
        );
        give_back(&engine, held);
        close(session);
    }

    /// A key with no declaration kept for the session's own object is a block of its key arena, and
    /// a share of it another holder of the block, so neither copies the text; a key past the
    /// session's `MAX_KEYEXPR_BYTES` is refused. Turned red by keeping it as a copy of its own.
    #[test]
    fn a_literal_of_the_session_is_a_block_and_so_is_its_share() {
        let (session, engine) = listening();
        let key = DeclaredKeyexpr::literal_of_session(&engine, "demo/adv/base").expect("room");
        assert!(key.literal.is_session(), "the text is a block of the arena");
        assert!(
            key.wire(crate::session::EngineHold::as_ref(&engine))
                .is_literal(),
            "nothing is declared"
        );
        let shared = key.share().expect("a share");
        assert!(shared.literal.is_session(), "a share holds the block");
        assert_eq!(shared.literal(), "demo/adv/base");
        let longest = wz_session_core::caps::MAX_KEYEXPR_BYTES;
        assert_eq!(
            DeclaredKeyexpr::literal_of_session(&engine, &"k".repeat(longest + 1)).err(),
            Some(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY)
        );
        drop((key, shared));
        close(session);
    }

    /// A key extended from a key of the session's arena (a concatenation, a join, an advanced
    /// subscriber's carriers) is a block of the same arena and keeps the declaration its literal
    /// still begins with; one too long for the session is refused.
    ///
    /// # Control
    ///
    /// Extending into a copy of its own reds the first assertion.
    #[test]
    fn an_extended_key_is_a_block_of_the_session() {
        let (session, engine) = listening();
        let base =
            DeclaredKeyexpr::declare_non_wild_prefix(&engine, "demo/ext/**", None).expect("room");
        let extended = base.extended("demo/ext/**/x").expect("room");
        assert!(
            extended.literal.is_session(),
            "the text is a block of the arena"
        );
        assert_eq!(extended.literal(), "demo/ext/**/x");
        assert!(
            !extended
                .wire(crate::session::EngineHold::as_ref(&engine))
                .is_literal(),
            "the declared prefix still begins the key"
        );
        let longest = wz_session_core::caps::MAX_KEYEXPR_BYTES;
        assert_eq!(
            base.extended(&"k".repeat(longest + 1)).err(),
            Some(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY)
        );
        drop((base, extended));
        close(session);
    }

    /// A key extended to its own text, as a copy of it is, is one more holder of its block and of
    /// its declaration. Turned red by an extension that drops the declaration (the count, the row)
    /// or keeps the text anywhere but the key's block.
    #[test]
    fn a_key_extended_to_its_own_text_is_a_share() {
        use wz_session_core::session_tables::KeyexprCount;

        let (session, engine) = listening();
        let key = DeclaredKeyexpr::declare(&engine, "demo/ext/own", None).expect("room");
        // SAFETY: the declaration's row stands while `key` holds it, to the end of the test.
        let count = unsafe { &*(key.row_address() as *const KeyexprCount) };
        let holds = count.holds();
        let copy = key.extended(key.literal()).expect("a share");
        assert!(copy.literal.is_session());
        assert_eq!(
            copy.literal().as_ptr(),
            key.literal().as_ptr(),
            "the key's block"
        );
        assert_eq!(
            copy.row_address(),
            key.row_address(),
            "at the declaration's row"
        );
        assert_eq!(
            Some(count.holds()),
            holds.checked_add(1),
            "the copy holds the declaration"
        );
        drop(copy);
        assert_eq!(count.holds(), holds, "the copy gave its hold back");
        drop(key);
        close(session);
    }

    /// An entity's key a door declares keeps no text of its own in the session's key arena, holds
    /// the declaration while the door has it and gives it back with its drop, and takes no hold of
    /// the caller's key when that is the declaration already; a key past the session's bound is
    /// refused.
    ///
    /// Turned red by a door's key that keeps a block of the arena beside its declaration's row
    /// (the first declaration, refused), one that takes a hold of the caller's declaration (the
    /// count), or one that keeps its hold past its drop (the room after it).
    #[test]
    fn an_entity_key_keeps_no_text_and_holds_only_while_the_door_does() {
        use wz_session_core::session_tables::KeyexprCount;

        let (session, engine) = listening();
        let held = fill_leaving(&engine, 10, 1);
        let key = EntityKey::non_wild_prefix(&engine, "demo/ek/**", None)
            .expect("the prefix's row takes the one block");
        assert!(!room_for(&engine, 10), "the prefix's row holds the block");
        drop(key);
        assert!(
            room_for(&engine, 10),
            "the declaration went with the door's key"
        );

        let program = DeclaredKeyexpr::declare(&engine, "demo/ek", None).expect("the block");
        // SAFETY: the declaration's row stands while `program` holds it, to the end of the test.
        let count = unsafe { &*(program.row_address() as *const KeyexprCount) };
        let holds = count.holds();
        let entity = EntityKey::non_wild_prefix(&engine, "demo/ek/**", Some(&program))
            .expect("the caller's declaration");
        assert_eq!(count.holds(), holds, "no hold of the caller's declaration");
        assert_eq!(
            entity.declaration_id(),
            program
                .wire(crate::session::EngineHold::as_ref(&engine))
                .mapping_id
        );
        drop(entity);
        assert_eq!(count.holds(), holds, "and none given back");

        let longest = wz_session_core::caps::MAX_KEYEXPR_BYTES;
        assert_eq!(
            EntityKey::whole(&engine, &"k".repeat(longest + 1), None).err(),
            Some(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY)
        );
        drop(program);
        give_back(&engine, held);
        close(session);
    }

    /// A key past the session's `MAX_KEYEXPR_BYTES` is one it has no room for; after the close a
    /// key is a copy of its own, and one held from before still reads.
    #[test]
    fn a_key_too_long_has_no_room_and_a_closed_sessions_key_is_a_copy() {
        let (mut session, engine) = listening();
        let longest = wz_session_core::caps::MAX_KEYEXPR_BYTES;
        assert_eq!(
            KeyText::of_session(&engine, &"k".repeat(longest + 1)).err(),
            Some(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY)
        );
        let held = KeyText::of_session(&engine, "demo/a").expect("a short key");
        assert!(held.is_session());
        // SAFETY: the session is live and owned here.
        let closed = unsafe { z_close(z_session_loan_mut(&mut session), core::ptr::null()) };
        assert_eq!(closed, Z_OK);
        let copy = KeyText::of_session(&engine, "demo/b").expect("a copy of its own");
        assert!(!copy.is_session());
        assert_eq!(held.share().expect("a share").as_str(), "demo/a");
        close(session);
    }
}
