// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The ENCODING plane — pico's `z_owned_encoding_t`, the `id;schema` string
//! form, and the wire projection wz already carries as
//! [`wz_session_core::sample::EncodingHint`].
//!
//! ## Why the id table is transcribed, and why that is safe here
//!
//! `Z_FEATURE_ENCODING_VALUES` is **1** in the CMake-generated `config.h` these
//! programs compile against, so pico's `z_encoding_from_str` is not a
//! store-the-whole-string operation: it splits on the FIRST `;`, looks the
//! prefix up in a 53-entry table, and stores `(id, schema)`; `z_encoding_to_string`
//! renders that back as `prefix[;schema]`. An implementation that stored the
//! whole string as a schema would round-trip through ITSELF perfectly and put a
//! different id on the wire — invisible to any wz-authored test, and visible to
//! every peer.
//!
//! So the table below is transcribed from `src/api/encoding.c:89`, and it is
//! transcribed **under an oracle**: `tests/pico_pure_function_oracle.rs` walks
//! every id and every table string through BOTH this library and the real
//! `libzenohpico.so`, comparing `z_encoding_to_string` and the
//! `from_str -> to_string` round trip. A transcription checked against upstream's
//! compiled code is a measurement; one checked against itself is not.
//!
//! ## The id lives PACKED, because that is what wz already had
//!
//! [`EncodingHint::packed_id`](wz_session_core::sample::EncodingHint::packed_id) is the WIRE
//! word — `(id << 1) | has_schema` — and this module keeps encodings in exactly that shape rather than unpacking to a
//! `(u16, Option<String>)` pair. Two reasons, and the second is the load-bearing
//! one: the sample accessors hand a decoded `EncodingHint` straight through, so
//! an unpacked intermediate would be a second representation to keep in step;
//! and a schema-present flag that disagreed with the schema actually stored is
//! unrepresentable when the flag is derived at pack time.
//!
//! A received message's encoding is not copied into a hint: its state keeps the packed word and
//! reads the schema where the message holds it ([`EncodingState::lent`]), and a copy is made only
//! where a program keeps the sample, the reply or the query.

use core::ffi::{c_char, c_void, CStr};

use wz_session_core::sample::{BoundedEncoding, EncodingRef};

use crate::abi::{handle_ref, impl_handle_ownership7, z_owned_string_t};
use crate::bytes::{store_owned_string, ByteBuf, NoRoom};
use crate::ffi::guarded;
use crate::object_slot::{Kind, Placed, Slot};
use crate::result::{ZResult, Z_ERR_NULL, Z_ERR_SYSTEM_OUT_OF_MEMORY, Z_OK};

/// pico's `ENCODING_VALUES_ID_TO_STR` (`src/api/encoding.c:89`), 53 entries,
/// index = encoding id.
///
/// R311y545 — the table itself moved out of this crate, and it lives in
/// [`wz_codecs::encoding_ids`] since R311y617, which is where
/// an ABI-neutral wire fact belongs: `wz-capi-c`'s `z_encoding_*` constants
/// need the SAME ids, and two transcriptions of one wire table drift in a way
/// neither crate's own tests can see. This stays as a re-export so the
/// cross-impl oracle keeps naming the constant it always named — and so it
/// keeps gating the SSOT rather than a copy of it.
///
/// `pub` deliberately, and NOT part of the C ABI: it is a Rust constant so the
/// cross-impl test can feed entry `i` to the REAL pico and assert pico assigns
/// it id `i`. That is the only non-circular way to check the order — a
/// `from_str -> to_string` round trip reads the same table in both directions,
/// so it is invariant under ANY permutation, which a damage probe demonstrated
/// by swapping two entries and staying green. See
/// `wz-integration-tests/tests/pico_pure_function_oracle.rs::encoding_ids_agree_with_the_real_pico_library`
/// — R311y618 corrected the crate this path names: it said `tests/` of THIS
/// crate, where the oracle has never lived, and a reader following it found
/// nothing. The oracle needs the real `libzenohpico.so`, so it can only live
/// where the interop harness does.
pub use wz_codecs::encoding_ids::ENCODING_ID_TO_STR;

/// pico's `_Z_ENCODING_ID_DEFAULT` — `zenoh/bytes`, id 0. Re-exported from the
/// same SSOT as the table it indexes.
use wz_codecs::encoding_ids::ENCODING_ID_DEFAULT;

/// Behind a loaned encoding: the packed wire word and where the schema lies. The handle of an owned
/// encoding points at the state of its [`HeldEncoding`], or for an encoding of no schema at the
/// state of its well-known constant ([`constant_of`]); a sample's, a reply's or a query's at the
/// one its marshal holds.
pub(crate) struct EncodingState {
    packed_id: u32,
    schema: Schema,
}

/// Where an encoding's schema lies.
enum Schema {
    /// The encoding carries none.
    Absent,
    /// Bytes another holds: a received message's, read for as long as the marshal that holds this
    /// state does ([`EncodingState::lent`]), or the room of the held encoding this state is part
    /// of, which never moves while it lives.
    Lent { start: *const u8, len: usize },
    /// A copy of its own in a block of the payloads' area, where a kept value's other bytes lie:
    /// what a sample, a reply or a query kept past its callback holds, whose message's bytes it may
    /// outlive. It takes no encoding of the pool, whose count is the program's own encodings.
    Kept(ByteBuf),
}

// SAFETY: a lent schema is its holder's, valid and unchanged for as long as the state lives
// (`EncodingState::lent`), and nothing writes through the pointer, so it is shared between threads
// as the holder's own borrow would be; a kept one is a block of the payloads' area this state alone
// holds, and the pools are reached under the port's lock.
unsafe impl Send for Schema {}
unsafe impl Sync for Schema {}

impl EncodingState {
    /// A well-known encoding: its id, no schema.
    const fn constant(id: u16) -> Self {
        Self {
            // The wire word is `(id << 1) | has_schema`, and a constant never carries a schema, so
            // bit 0 is clear by construction rather than by a second field agreeing with the first.
            packed_id: (id as u32) << 1,
            schema: Schema::Absent,
        }
    }

    /// The encoding a received message carried, its schema read where the message holds it, as
    /// zenoh-pico hands its callback the encoding its receive decoded: nothing is copied for it.
    ///
    /// # Safety
    /// The state is dropped before the borrow of `schema` ends.
    pub(crate) unsafe fn lent(packed_id: u32, schema: Option<&[u8]>) -> Self {
        Self {
            packed_id,
            schema: match schema {
                Some(schema) => Schema::Lent {
                    start: schema.as_ptr(),
                    len: schema.len(),
                },
                None => Schema::Absent,
            },
        }
    }

    /// The encoding as its readers see it.
    pub(crate) fn view(&self) -> EncodingRef<'_> {
        match &self.schema {
            Schema::Absent => EncodingRef {
                packed_id: self.packed_id,
                schema: None,
            },
            // SAFETY: a lent schema outlives the state that holds it (`Self::lent`), and a slice's
            // start is never null.
            Schema::Lent { start, len } => EncodingRef {
                packed_id: self.packed_id,
                schema: Some(unsafe { core::slice::from_raw_parts(*start, *len) }),
            },
            Schema::Kept(bytes) => EncodingRef {
                packed_id: self.packed_id,
                schema: Some(bytes.as_slice()),
            },
        }
    }

    /// A state of its own with the same encoding: what a sample, a reply or a query kept past its
    /// callback holds. A schema is copied into a block of the payloads' area, as the kept value's
    /// payload and attachment are, refused with [`NoRoom`] when the area has none free; an
    /// encoding of no schema takes none.
    pub(crate) fn kept(&self) -> Result<Self, NoRoom> {
        let view = self.view();
        let schema = match view.schema {
            None => Schema::Absent,
            Some(schema) => Schema::Kept(ByteBuf::copy_of(schema)?),
        };
        Ok(Self {
            packed_id: view.packed_id,
            schema,
        })
    }
}

/// An encoding a program holds (`z_owned_encoding_t`), in a slot of the pool of encodings
/// (`HELD_ENCODINGS`): its state first, which the handle points at, and the room of its schema,
/// [`MAX_ENCODING_SCHEMA_BYTES`](wz_session_core::caps::MAX_ENCODING_SCHEMA_BYTES) bytes, which
/// the state reads. The slot never moves while the encoding lives, so the state's read of its own
/// room stays valid, as zenoh-pico's encoding holds its schema in a string of its own.
#[repr(C)]
pub(crate) struct HeldEncoding {
    state: EncodingState,
    kept: BoundedEncoding,
}

impl HeldEncoding {
    /// The encoding, read where it lies in its slot.
    pub(crate) fn view(&self) -> EncodingRef<'_> {
        self.kept.view()
    }

    /// `encoding` kept in a slot of the pool of encodings; `None` when its schema is longer than
    /// the room a slot has or the pool has no slot free, which every door that makes one answers
    /// with `_Z_ERR_SYSTEM_OUT_OF_MEMORY`, as zenoh-pico answers a schema its heap cannot copy.
    fn place(encoding: EncodingRef<'_>) -> Option<*mut HeldEncoding> {
        let kept = BoundedEncoding::of(encoding).ok()?;
        let slot = Slot::<HeldEncoding>::take(Kind::Encoding)?;
        // SAFETY: `write_at` writes both fields of the slot it is handed.
        Some(unsafe { slot.fill_in_place(|at| Self::write_at(at, kept)) })
    }

    /// Write `kept` at `at` and the state that reads it there.
    ///
    /// # Safety
    /// `at` is the place of a `HeldEncoding` that holds none and does not move while it is held.
    unsafe fn write_at(at: *mut HeldEncoding, kept: BoundedEncoding) {
        core::ptr::addr_of_mut!((*at).kept).write(kept);
        Self::read_own_room(at);
    }

    /// Point the state at `at` at the room beside it, as it now holds.
    ///
    /// # Safety
    /// `at` is a `HeldEncoding` whose room is written, at a place that does not move while it is
    /// held.
    unsafe fn read_own_room(at: *mut HeldEncoding) {
        let view = (*at).kept.view();
        // SAFETY: the caller's: the room lies in the same slot as the state and outlives it.
        core::ptr::addr_of_mut!((*at).state)
            .write(EncodingState::lent(view.packed_id, view.schema));
    }

    /// Replace the schema with `bytes`, the flag of the wire word following it; empty bytes take
    /// the schema away. Refused, the encoding left as it was, when `bytes` is longer than the room.
    ///
    /// # Safety
    /// `at` is a live `HeldEncoding` nothing else reads while this runs.
    unsafe fn set_schema(at: *mut HeldEncoding, bytes: &[u8]) -> Result<(), NoRoom> {
        let has_schema = !bytes.is_empty();
        let kept = BoundedEncoding::of(EncodingRef {
            packed_id: ((*at).kept.view().packed_id & !1) | u32::from(has_schema),
            schema: has_schema.then_some(bytes),
        })
        .map_err(|_| NoRoom)?;
        (*at).kept = kept;
        Self::read_own_room(at);
        Ok(())
    }
}

impl core::fmt::Debug for HeldEncoding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.view(), f)
    }
}

/// The state of the well-known constant `encoding` is, for an encoding of no schema whose id the
/// table names: such an encoding is read from its constant and takes no slot, as zenoh-pico's
/// encoding of no schema allocates nothing.
fn constant_of(encoding: EncodingRef<'_>) -> Option<&'static EncodingState> {
    if encoding.schema.is_some() || encoding.packed_id & 1 != 0 {
        return None;
    }
    let accessor = CONSTANTS.get(usize::try_from(encoding.packed_id >> 1).ok()?)?;
    // SAFETY: a constant's accessor hands out a `'static` view of a `'static` state.
    unsafe { handle_ref::<z_loaned_encoding_t, EncodingState>(accessor()) }
}

/// Whether `state` is a well-known constant's, which no slot holds and nothing lets go.
fn is_constant(state: &EncodingState) -> bool {
    constant_of(state.view()).is_some_and(|constant| core::ptr::eq(constant, state))
}

/// An encoding a program moved into a call, held for as long as its holder holds it: its
/// constant's state, or an encoding of the pool, which is let go with it.
#[derive(Debug)]
pub(crate) enum OwnedEncoding {
    /// A well-known encoding of no schema, which takes no slot.
    Constant(&'static ConstantState),
    /// An encoding of the pool of encodings.
    Held(Placed<HeldEncoding>),
}

/// A well-known constant's state, shown by what it reads.
#[repr(transparent)]
pub(crate) struct ConstantState(EncodingState);

impl core::fmt::Debug for ConstantState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.0.view(), f)
    }
}

// SAFETY: an owned encoding is a constant's state, which nothing writes, or an encoding of the pool
// this value alone holds and reads, whose slot is given back under the port's lock from whichever
// thread lets it go, as every object of the pools is; it is shared and sent as the bytes it reads.
unsafe impl Send for OwnedEncoding {}
unsafe impl Sync for OwnedEncoding {}

impl OwnedEncoding {
    /// The encoding, read where it lies.
    pub(crate) fn view(&self) -> EncodingRef<'_> {
        match self {
            Self::Constant(constant) => constant.0.view(),
            Self::Held(held) => held.view(),
        }
    }
}

/// `encoding` held by value: its constant when it has one, else kept in a slot of the pool of
/// encodings. What a publisher keeps of the encoding it was declared with. `None` when the schema
/// is longer than the room a slot has or the pool has no slot free. Only an advanced publisher
/// keeps a second copy of the encoding its publisher was declared with
/// (`crate::pubsub::PublisherQos::try_clone`).
#[cfg(any(feature = "advanced", test))]
pub(crate) fn hold(encoding: EncodingRef<'_>) -> Option<OwnedEncoding> {
    if let Some(constant) = constant_of(encoding) {
        return Some(OwnedEncoding::Constant(as_constant(constant)));
    }
    let held = HeldEncoding::place(encoding)?;
    // SAFETY: an encoding just placed, which nothing else holds.
    unsafe { Placed::from_raw(held) }.map(OwnedEncoding::Held)
}

/// A constant's state as the transparent type an owned encoding holds it by.
fn as_constant(state: &'static EncodingState) -> &'static ConstantState {
    // SAFETY: `ConstantState` is a transparent wrapper of `EncodingState`.
    unsafe { &*(state as *const EncodingState).cast::<ConstantState>() }
}

/// Owned encoding (pico `z_owned_encoding_t`, 40 B measured).
#[repr(C)]
pub struct z_owned_encoding_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 4],
}

/// Loaned encoding (pico `z_loaned_encoding_t`), same footprint.
#[repr(C)]
pub struct z_loaned_encoding_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 4],
}

/// Moved encoding (pico `z_moved_encoding_t`).
#[repr(C)]
pub struct z_moved_encoding_t {
    pub(crate) _this: z_owned_encoding_t,
}

impl z_owned_encoding_t {
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            handle: core::ptr::null_mut(),
            _pad: [core::ptr::null_mut(); 4],
        }
    }
}

impl z_loaned_encoding_t {
    /// A loaned view not yet pointed at anything: what a marshal holds until it binds the view to
    /// the encoding it keeps in itself, at its final address.
    pub(crate) const fn unbound() -> Self {
        Self {
            handle: core::ptr::null_mut(),
            _pad: [core::ptr::null_mut(); 4],
        }
    }
}

/// # Safety
/// `h` must be a live handle [`store_encoding`] made.
unsafe fn free_encoding(h: *mut c_void) {
    // A constant's state is no slot's and is never let go.
    if is_constant(&*h.cast::<EncodingState>()) {
        return;
    }
    crate::object_slot::release(h.cast::<HeldEncoding>());
}

impl_handle_ownership7!(
    z_owned_encoding_t,
    z_loaned_encoding_t,
    z_moved_encoding_t,
    free_encoding,
    z_internal_encoding_null,
    z_internal_encoding_check,
    z_encoding_loan,
    z_encoding_loan_mut,
    z_encoding_move,
    z_encoding_take,
    z_encoding_drop
);

/// Hand `encoding` to `dst`, which the caller left null: its constant when it has one, else kept
/// in a slot of the pool of encodings. `Z_OK`, or `_Z_ERR_SYSTEM_OUT_OF_MEMORY` with `dst` still
/// null when the schema is longer than the room or the pool has no slot free.
///
/// # Safety
/// `dst` is valid and writable.
pub(crate) unsafe fn store_encoding(
    dst: *mut z_owned_encoding_t,
    encoding: EncodingRef<'_>,
) -> ZResult {
    let handle = match constant_of(encoding) {
        Some(constant) => (constant as *const EncodingState).cast_mut().cast(),
        None => match HeldEncoding::place(encoding) {
            Some(held) => held.cast(),
            None => return Z_ERR_SYSTEM_OUT_OF_MEMORY,
        },
    };
    *dst = z_owned_encoding_t {
        handle,
        _pad: [core::ptr::null_mut(); 4],
    };
    Z_OK
}

/// Read the encoding behind a loaned encoding, where its state keeps it.
pub(crate) unsafe fn encoding_view<'a>(ptr: *const z_loaned_encoding_t) -> Option<EncodingRef<'a>> {
    handle_ref::<z_loaned_encoding_t, EncodingState>(ptr).map(EncodingState::view)
}

/// Consume a moved encoding, handing back the encoding itself and nulling the source so the
/// caller's value cannot be released twice: a put sends it from its own slot, and a publisher keeps
/// it, with nothing copied.
///
/// The moved pointer is typed `*mut c_void` at the call sites that receive it
/// inside an options struct, so this takes the concrete type and the callers
/// cast — keeping the unsafe cast at ONE place rather than at each option
/// struct that carries an encoding slot.
pub(crate) unsafe fn take_moved_encoding(moved: *mut c_void) -> Option<OwnedEncoding> {
    if moved.is_null() {
        return None;
    }
    let slot = moved as *mut *mut c_void;
    let handle = *slot;
    *slot = core::ptr::null_mut();
    // SAFETY: a moved encoding's handle is null or one `store_encoding` made, which the move hands
    // over: a constant's state, or an encoding of the pool.
    let state = handle.cast::<EncodingState>().as_ref()?;
    if is_constant(state) {
        return Some(OwnedEncoding::Constant(as_constant(
            &*handle.cast::<EncodingState>(),
        )));
    }
    Placed::from_raw(handle.cast::<HeldEncoding>()).map(OwnedEncoding::Held)
}

/// [`take_moved_encoding`] for a door whose options still keep the encoding as a hint of their
/// own: the schema is copied out and the encoding let go. The advanced publisher's put is that
/// door.
#[cfg(feature = "advanced")]
pub(crate) unsafe fn take_moved_encoding_copy(
    moved: *mut c_void,
) -> Option<wz_session_core::sample::EncodingHint> {
    take_moved_encoding(moved).map(|held| held.view().to_hint())
}

// --- exports ---------------------------------------------------------------

/// Build an encoding from a NUL-terminated `id;schema` string (pico
/// `z_encoding_from_str`).
#[no_mangle]
pub unsafe extern "C" fn z_encoding_from_str(
    encoding: *mut z_owned_encoding_t,
    s: *const c_char,
) -> ZResult {
    guarded(|| {
        if encoding.is_null() {
            return Z_ERR_NULL;
        }
        // pico nulls the slot first and treats a NULL string as "leave it
        // null", which is a SUCCESS there — an encoding a program never set.
        *encoding = z_owned_encoding_t::null_value();
        if s.is_null() {
            return Z_OK;
        }
        // pico stores the bytes it is handed, UTF-8 or not, and so does this.
        let bytes = CStr::from_ptr(s).to_bytes();
        store_encoding(
            encoding,
            wz_session_core::encoding_hint::ref_from_bytes(bytes),
        )
    })
}

/// Build an encoding from an explicitly-sized `id;schema` substring (pico
/// `z_encoding_from_substr`).
#[no_mangle]
pub unsafe extern "C" fn z_encoding_from_substr(
    encoding: *mut z_owned_encoding_t,
    s: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        if encoding.is_null() {
            return Z_ERR_NULL;
        }
        *encoding = z_owned_encoding_t::null_value();
        if s.is_null() {
            return Z_OK;
        }
        let bytes = core::slice::from_raw_parts(s.cast::<u8>(), len);
        store_encoding(
            encoding,
            wz_session_core::encoding_hint::ref_from_bytes(bytes),
        )
    })
}

/// Render an encoding as `id;schema` (pico `z_encoding_to_string`).
///
/// A NULL / spent encoding renders as the DEFAULT id's string rather than as an
/// empty one: pico's loaned encoding is never null in a program that got here
/// through `z_sample_encoding`, and reporting `zenoh/bytes` is what a
/// default-constructed encoding means.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_to_string(
    encoding: *const z_loaned_encoding_t,
    string: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if string.is_null() {
            return Z_ERR_NULL;
        }
        let rendered = match encoding_view(encoding) {
            Some(view) => {
                wz_session_core::encoding_hint::parts_to_bytes(view.packed_id, view.schema)
            }
            None => ENCODING_ID_TO_STR
                .get(usize::from(ENCODING_ID_DEFAULT))
                .copied()
                .unwrap_or_default()
                .as_bytes()
                .to_vec(),
        };
        store_owned_string(string, &rendered)
    })
}

/// Whether two encodings are the same id AND the same schema (pico
/// `z_encoding_equals`).
#[no_mangle]
pub unsafe extern "C" fn z_encoding_equals(
    left: *const z_loaned_encoding_t,
    right: *const z_loaned_encoding_t,
) -> bool {
    encoding_view(left) == encoding_view(right)
}

/// Replace an encoding's schema from a NUL-terminated string (pico
/// `z_encoding_set_schema_from_str`).
#[no_mangle]
pub unsafe extern "C" fn z_encoding_set_schema_from_str(
    encoding: *mut z_loaned_encoding_t,
    schema: *const c_char,
) -> ZResult {
    let len = if schema.is_null() {
        0
    } else {
        CStr::from_ptr(schema).to_bytes().len()
    };
    z_encoding_set_schema_from_substr(encoding, schema, len)
}

/// Replace an encoding's schema from an explicitly-sized substring (pico
/// `z_encoding_set_schema_from_substr`).
#[no_mangle]
pub unsafe extern "C" fn z_encoding_set_schema_from_substr(
    encoding: *mut z_loaned_encoding_t,
    schema: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        if encoding.is_null() {
            return Z_ERR_NULL;
        }
        // pico copies the bytes it is handed and asks nothing of them
        // (`src/api/encoding.c`, `z_encoding_set_schema_from_substr` ->
        // `_z_string_copy_from_substr`), so a schema that is not UTF-8 is set; one longer than the
        // room is refused as pico refuses a copy its heap cannot hold, the encoding left as it was.
        let bytes: &[u8] = if schema.is_null() || len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(schema.cast::<u8>(), len)
        };
        // A loan a program may write through is its owned encoding itself (`z_encoding_loan_mut`
        // reinterprets the owned struct), so the handle it holds is the owned encoding's.
        let handle = (*encoding).handle;
        let current = handle.cast::<EncodingState>().as_ref();
        if let Some(state) = current.filter(|state| !is_constant(state)) {
            // An encoding of the pool: its state is the first field of its held encoding, which the
            // handle uniquely owns, and the schema is written into its own room.
            let held = (state as *const EncodingState)
                .cast_mut()
                .cast::<HeldEncoding>();
            return match HeldEncoding::set_schema(held, bytes) {
                Ok(()) => Z_OK,
                Err(no_room) => no_room.code(),
            };
        }
        // A constant, or the null encoding pico reads as the default (its setter writes a schema
        // into one), takes the schema into an encoding of its own, written over the loan's handle;
        // the constant it read is no slot's and nothing lets it go.
        let packed_id = match current {
            Some(state) => state.view().packed_id,
            None => u32::from(ENCODING_ID_DEFAULT) << 1,
        };
        let has_schema = !bytes.is_empty();
        let mut owned = z_owned_encoding_t::null_value();
        let code = store_encoding(
            &mut owned,
            EncodingRef {
                packed_id: (packed_id & !1) | u32::from(has_schema),
                schema: has_schema.then_some(bytes),
            },
        );
        if code == Z_OK {
            (*encoding).handle = owned.handle;
        }
        code
    })
}

// --- the well-known constants ----------------------------------------------

/// A loaned encoding view that lives for the whole program.
///
/// `z_loaned_encoding_t` holds a raw pointer, so it is not `Sync` and cannot be
/// a `static` on its own. This newtype carries the argument that makes it safe:
/// the value is written ONCE at compile time, never mutated, and its handle
/// points at a `'static` [`EncodingState`] — so every thread reads the same
/// immutable bytes pointing at the same immutable state.
#[repr(transparent)]
pub(crate) struct StaticLoanedEncoding(z_loaned_encoding_t);

// SAFETY: see the type's docs — immutable after compile time, pointing at a
// `'static`.
unsafe impl Sync for StaticLoanedEncoding {}

/// Build the `'static` loaned view for a `'static` state.
const fn static_view(state: &'static EncodingState) -> StaticLoanedEncoding {
    StaticLoanedEncoding(z_loaned_encoding_t {
        handle: state as *const EncodingState as *mut c_void,
        _pad: [core::ptr::null_mut(); 4],
    })
}

/// Emit one of pico's `ENCODING_CONSTANT_MACRO` entries
/// (`src/api/encoding.c:27-33`): a `'static` state at the given wire id, its
/// `'static` loaned view, and the exported accessor.
///
/// The state and the view are function-scoped statics rather than module-level
/// ones so the macro needs only the pair upstream's own macro needs — the
/// exported name and the id — instead of two invented Rust identifiers per
/// entry. A hand-maintained second name list is a transcription with no oracle,
/// which is the failure class this crate has already paid for once.
///
/// The MIME string is NOT repeated here. It lives once in
/// [`wz_codecs::encoding_ids::ENCODING_ID_TO_STR`], indexed by the same id,
/// so `z_encoding_to_string` on a constant renders through the identical table
/// the wire codec uses. The (name -> id) pairing below is the only transcribed
/// fact, and it is adjudicated against upstream's COMPILED library by
/// `tests/pico_pure_function_oracle.rs::encoding_constants_agree_with_the_real_pico_library`,
/// which walks every accessor in both implementations and compares the rendered
/// string. A wrong id there is a visible mismatch, not a silent one.
macro_rules! encoding_constant {
    ($fname:ident, $id:expr) => {
        /// A well-known encoding constant (pico `ENCODING_CONSTANT_MACRO`).
        ///
        /// The returned pointer is valid for the whole program: it points at a
        /// `'static`, so a caller may hold it past any session, and there is
        /// nothing to release.
        #[no_mangle]
        pub extern "C" fn $fname() -> *const z_loaned_encoding_t {
            static STATE: EncodingState = EncodingState::constant($id);
            static VIEW: StaticLoanedEncoding = static_view(&STATE);
            &VIEW.0 as *const z_loaned_encoding_t
        }
    };
}

/// Every well-known encoding's accessor, emitted with it, at the index of its wire id: what an
/// encoding of no schema is read from instead of a slot of the pool of encodings
/// ([`constant_of`]), as zenoh-pico's encoding of no schema holds no allocation.
macro_rules! encoding_constants {
    ($(($fname:ident, $id:expr)),* $(,)?) => {
        $(encoding_constant!($fname, $id);)*

        /// The accessors, in the order of their ids.
        const CONSTANTS: &[extern "C" fn() -> *const z_loaned_encoding_t] = &[$($fname),*];
    };
}

encoding_constants! {
    (z_encoding_zenoh_bytes, 0),
    (z_encoding_zenoh_string, 1),
    (z_encoding_zenoh_serialized, 2),
    (z_encoding_application_octet_stream, 3),
    (z_encoding_text_plain, 4),
    (z_encoding_application_json, 5),
    (z_encoding_text_json, 6),
    (z_encoding_application_cdr, 7),
    (z_encoding_application_cbor, 8),
    (z_encoding_application_yaml, 9),
    (z_encoding_text_yaml, 10),
    (z_encoding_text_json5, 11),
    (z_encoding_application_python_serialized_object, 12),
    (z_encoding_application_protobuf, 13),
    (z_encoding_application_java_serialized_object, 14),
    (z_encoding_application_openmetrics_text, 15),
    (z_encoding_image_png, 16),
    (z_encoding_image_jpeg, 17),
    (z_encoding_image_gif, 18),
    (z_encoding_image_bmp, 19),
    (z_encoding_image_webp, 20),
    (z_encoding_application_xml, 21),
    (z_encoding_application_x_www_form_urlencoded, 22),
    (z_encoding_text_html, 23),
    (z_encoding_text_xml, 24),
    (z_encoding_text_css, 25),
    (z_encoding_text_javascript, 26),
    (z_encoding_text_markdown, 27),
    (z_encoding_text_csv, 28),
    (z_encoding_application_sql, 29),
    (z_encoding_application_coap_payload, 30),
    (z_encoding_application_json_patch_json, 31),
    (z_encoding_application_json_seq, 32),
    (z_encoding_application_jsonpath, 33),
    (z_encoding_application_jwt, 34),
    (z_encoding_application_mp4, 35),
    (z_encoding_application_soap_xml, 36),
    (z_encoding_application_yang, 37),
    (z_encoding_audio_aac, 38),
    (z_encoding_audio_flac, 39),
    (z_encoding_audio_mp4, 40),
    (z_encoding_audio_ogg, 41),
    (z_encoding_audio_vorbis, 42),
    (z_encoding_video_h261, 43),
    (z_encoding_video_h263, 44),
    (z_encoding_video_h264, 45),
    (z_encoding_video_h265, 46),
    (z_encoding_video_h266, 47),
    (z_encoding_video_mp4, 48),
    (z_encoding_video_ogg, 49),
    (z_encoding_video_raw, 50),
    (z_encoding_video_vp8, 51),
    (z_encoding_video_vp9, 52),
}

/// The encoding a default-constructed value means (pico
/// `z_encoding_loan_default`, `src/api/encoding.c:266`) — literally upstream's
/// own body, `zenoh/bytes`.
#[no_mangle]
pub extern "C" fn z_encoding_loan_default() -> *const z_loaned_encoding_t {
    z_encoding_zenoh_bytes()
}

/// Duplicate an encoding into a fresh owned one (pico `z_encoding_clone`).
///
/// A DEEP copy, unlike the sibling zenoh-c ABI's handle copy. It has to be: the
/// source may be one of the `'static` constants above OR an encoding of the
/// pool a program built with [`z_encoding_from_str`], and
/// [`z_encoding_drop`] gives its slot back. Copying the hint makes those two
/// sources indistinguishable to the caller, which is what upstream's
/// `_z_encoding_copy` does.
///
/// # Safety
/// `dst` must be valid and writable; `this_` must be null or a valid loaned
/// encoding.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_clone(
    dst: *mut z_owned_encoding_t,
    this_: *const z_loaned_encoding_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        *dst = z_owned_encoding_t::null_value();
        match encoding_view(this_) {
            Some(view) => store_encoding(dst, view),
            // A null / spent source clones to a null destination, which is the
            // shape `z_internal_encoding_check` reports as absent. Upstream
            // copies an empty encoding here rather than failing.
            None => Z_OK,
        }
    })
}

/// Adopt a loaned encoding into an owned one, emptying the source (pico
/// `z_encoding_take_from_loaned`).
///
/// Hand-written rather than emitted by
/// `impl_value_ownership` because that
/// macro clears a THREE-slot pad and `z_owned_encoding_t` carries four; a
/// wrong-width clear would leave a stale pointer word in the source the caller
/// is entitled to reuse.
///
/// # Safety
/// `dst` must be valid and writable; `src` must be null or a valid loaned
/// encoding this crate produced.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_take_from_loaned(
    dst: *mut z_owned_encoding_t,
    src: *mut z_loaned_encoding_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        *dst = z_owned_encoding_t {
            handle: (*src).handle,
            _pad: (*src)._pad,
        };
        (*src).handle = core::ptr::null_mut();
        (*src)._pad = [core::ptr::null_mut(); 4];
        Z_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;
    use wz_session_core::sample::EncodingHint;

    /// What `z_encoding_from_str` stores for `s`: its bytes, split as pico's
    /// `_z_encoding_convert_from_substr` splits them.
    fn parsed(s: &str) -> EncodingHint {
        wz_session_core::encoding_hint::hint_from_bytes(s.as_bytes())
    }

    /// What `z_encoding_to_string` hands back for `hint`, read as text.
    fn rendered(hint: &EncodingHint) -> String {
        String::from_utf8(wz_session_core::encoding_hint::hint_to_bytes(hint))
            .expect("a UTF-8 encoding renders as text")
    }

    /// Every constant renders through the SAME table the wire codec uses, so a
    /// constant and a `z_encoding_from_str` of its own string are one value.
    ///
    /// This is the LOCAL half of the claim — it cannot catch a wrong (name ->
    /// id) pairing, because both sides of the comparison read the same table.
    /// The oracle leg in `tests/pico_pure_function_oracle.rs` is what pins the
    /// pairing against upstream's compiled library.
    #[test]
    fn every_constant_round_trips_through_the_id_table() {
        // SAFETY: each accessor returns a `'static` view.
        let cases: [(*const z_loaned_encoding_t, u32); 5] = [
            (z_encoding_zenoh_bytes(), 0),
            (z_encoding_text_plain(), 4),
            (z_encoding_application_json(), 5),
            (z_encoding_application_octet_stream(), 3),
            (z_encoding_video_vp9(), 52),
        ];
        for (view, id) in cases {
            // SAFETY: a `'static` view this module minted.
            let hint = unsafe { encoding_view(view) }.expect("a constant is never absent");
            assert_eq!(hint.packed_id >> 1, id, "wire id");
            assert_eq!(hint.packed_id & 1, 0, "a constant carries no schema");
            let text = rendered(&hint.to_hint());
            assert_eq!(
                text, ENCODING_ID_TO_STR[id as usize],
                "a constant renders as its table entry"
            );
            assert_eq!(
                parsed(&text).packed_id,
                hint.packed_id,
                "and parsing that string back lands on the same id"
            );
        }
    }

    /// `z_encoding_loan_default` is `zenoh/bytes`, and it is the SAME pointer —
    /// upstream's body delegates, so a caller comparing the two by identity (as
    /// `z_encoding_equals` callers do by value) sees agreement either way.
    #[test]
    fn loan_default_is_zenoh_bytes() {
        assert_eq!(z_encoding_loan_default(), z_encoding_zenoh_bytes());
        // SAFETY: two `'static` views.
        assert!(unsafe { z_encoding_equals(z_encoding_loan_default(), z_encoding_zenoh_bytes()) });
    }

    /// A clone of a `'static` constant is an INDEPENDENT owned value: dropping
    /// it must not attempt to free the constant. Pinned by cloning, dropping,
    /// and then reading the constant again — a handle copy would have freed a
    /// `'static` and this would be a use-after-free under any sanitizer.
    #[test]
    fn cloning_a_constant_yields_an_independently_droppable_value() {
        let mut owned = z_owned_encoding_t::null_value();
        // SAFETY: a live local and a `'static` view.
        unsafe {
            assert_eq!(z_encoding_clone(&mut owned, z_encoding_text_plain()), Z_OK);
            assert!(z_internal_encoding_check(&owned));
            let loaned = z_encoding_loan(&owned);
            assert_eq!(
                encoding_view(loaned).expect("cloned").packed_id,
                encoding_view(z_encoding_text_plain())
                    .expect("constant")
                    .packed_id
            );
            z_encoding_drop(z_encoding_move(&mut owned));
            assert!(!z_internal_encoding_check(&owned));
            // The constant is still readable, which a handle copy would have
            // made false.
            assert_eq!(
                encoding_view(z_encoding_text_plain())
                    .expect("the constant survived its clone's drop")
                    .packed_id
                    >> 1,
                4
            );
        }
    }

    /// `take_from_loaned` moves the handle and EMPTIES the source, including
    /// the fourth pad slot the shared macro would have left behind.
    #[test]
    fn take_from_loaned_empties_all_four_pad_slots() {
        let mut src = z_owned_encoding_t::null_value();
        let mut dst = z_owned_encoding_t::null_value();
        // SAFETY: live locals.
        unsafe {
            assert_eq!(
                store_encoding(&mut src, parsed("text/plain;utf8").view()),
                Z_OK
            );
            // Dirty every pad slot so an under-wide clear is visible.
            src._pad = [1usize as *mut c_void; 4];
            let loaned = z_encoding_loan_mut(&mut src);
            assert_eq!(z_encoding_take_from_loaned(&mut dst, loaned), Z_OK);
            assert!(!z_internal_encoding_check(&src), "source emptied");
            assert!(src._pad.iter().all(|p| p.is_null()), "all four pad slots");
            assert_eq!(
                encoding_view(z_encoding_loan(&dst)).expect("moved").schema,
                Some(&b"utf8"[..])
            );
            z_encoding_drop(z_encoding_move(&mut dst));
        }
    }

    /// The ABI size a C program stack-allocates through pico's own header: five words, 40 B on a
    /// 64-bit host (`csrc/pico_layout_pins.c` holds the count against the header on any other).
    #[test]
    fn encoding_abi_size_matches_pico() {
        let words = 5 * core::mem::size_of::<*mut c_void>();
        assert_eq!(core::mem::size_of::<z_owned_encoding_t>(), words);
        assert_eq!(core::mem::size_of::<z_moved_encoding_t>(), words);
    }

    /// The packed id is the WIRE word, and bit 0 is derived from the schema
    /// rather than stored beside it — so the two cannot disagree.
    #[test]
    fn the_schema_flag_is_derived_not_stored() {
        let bare = parsed("text/plain");
        assert_eq!(bare.packed_id & 1, 0, "no schema, flag clear");
        assert_eq!(bare.packed_id >> 1, 4, "text/plain is id 4");
        assert!(bare.schema.is_none());

        let with = parsed("text/plain;utf8");
        assert_eq!(with.packed_id & 1, 1, "schema present, flag set");
        assert_eq!(with.packed_id >> 1, 4);
        assert_eq!(with.schema.as_deref(), Some(&b"utf8"[..]));
    }

    /// An UNRECOGNISED prefix is not an error — the whole string becomes the
    /// schema under the default id, which is pico's fallback and the reason
    /// `z_encoding_from_str` cannot fail on content.
    #[test]
    fn an_unknown_prefix_becomes_a_schema_on_the_default_id() {
        let e = parsed("application/x-made-up-thing-entirely");
        assert_eq!(e.packed_id >> 1, u32::from(ENCODING_ID_DEFAULT));
        assert_eq!(
            e.schema.as_deref(),
            Some(&b"application/x-made-up-thing-entirely"[..])
        );
    }

    /// zenoh-pico's contract for a schema that is not UTF-8: the setter copies
    /// the bytes it is handed (`src/api/encoding.c`,
    /// `z_encoding_set_schema_from_substr`), and `z_encoding_to_string` hands
    /// them back as they are after the id's name and `;`.
    #[test]
    fn a_schema_that_is_not_utf8_is_set_and_rendered_as_its_bytes() {
        let raw: &[u8] = &[0xFF, 0xFE, b'x'];
        let mut owned = z_owned_encoding_t::null_value();
        // SAFETY: live locals.
        unsafe {
            assert_eq!(
                store_encoding(&mut owned, parsed("text/plain").view()),
                Z_OK
            );
            assert_eq!(
                z_encoding_set_schema_from_substr(
                    z_encoding_loan_mut(&mut owned),
                    raw.as_ptr().cast(),
                    raw.len()
                ),
                Z_OK
            );
            let hint = encoding_view(z_encoding_loan(&owned)).expect("set");
            assert_eq!(hint.schema, Some(raw));
            let mut want = b"text/plain;".to_vec();
            want.extend_from_slice(raw);
            assert_eq!(
                wz_session_core::encoding_hint::parts_to_bytes(hint.packed_id, hint.schema),
                want
            );
            z_encoding_drop(z_encoding_move(&mut owned));
        }
    }

    /// A received encoding's schema is read where the message holds it, not copied; a kept copy
    /// holds it in an encoding of its own and reads the same after the message is gone; one with
    /// no schema reads as none and keeps nothing.
    #[test]
    fn a_received_schema_is_read_where_it_lies_and_kept_as_a_copy() {
        let message = b"utf8".to_vec();
        // SAFETY: the state is dropped before `message`.
        let received = unsafe { EncodingState::lent((4 << 1) | 1, Some(message.as_slice())) };
        let view = received.view();
        assert_eq!(view.packed_id, (4 << 1) | 1);
        assert_eq!(
            view.schema.map(<[u8]>::as_ptr),
            Some(message.as_ptr()),
            "the schema is the message's own bytes"
        );
        assert_eq!(
            wz_session_core::encoding_hint::parts_to_bytes(view.packed_id, view.schema),
            b"text/plain;utf8".to_vec()
        );

        let kept = received.kept().expect("room for the kept encoding");
        let kept_schema = kept.view().schema.expect("kept");
        assert_ne!(
            kept_schema.as_ptr(),
            message.as_ptr(),
            "a kept copy holds its own bytes"
        );
        assert_eq!(kept_schema, b"utf8");
        drop(received);
        drop(message);
        assert_eq!(kept.view().to_hint(), parsed("text/plain;utf8"));

        // SAFETY: a state of no schema borrows nothing.
        let bare = unsafe { EncodingState::lent(4 << 1, None) };
        assert_eq!(bare.view().schema, None);
        let bare_kept = bare.kept().expect("an encoding of no schema keeps nothing");
        assert!(matches!(bare_kept.schema, Schema::Absent));
    }

    /// An owned encoding reads its schema from the room of its own slot, and a schema set on it is
    /// written into that room; an empty one takes the schema and its flag away.
    #[test]
    fn an_owned_encoding_reads_and_sets_its_schema_in_its_own_room() {
        let mut owned = z_owned_encoding_t::null_value();
        // SAFETY: live locals.
        unsafe {
            assert_eq!(
                z_encoding_from_str(&mut owned, c"text/plain;utf8".as_ptr()),
                Z_OK
            );
            let held = owned.handle.cast::<HeldEncoding>();
            let room = core::ptr::addr_of!((*held).kept) as usize;
            let room = room..room + core::mem::size_of::<BoundedEncoding>();
            let read = encoding_view(z_encoding_loan(&owned)).expect("made");
            let at = read.schema.expect("a schema").as_ptr() as usize;
            assert!(
                room.contains(&at),
                "the schema lies in the encoding's own room"
            );
            assert_eq!(
                z_encoding_set_schema_from_str(z_encoding_loan_mut(&mut owned), c"other".as_ptr()),
                Z_OK
            );
            let set = encoding_view(z_encoding_loan(&owned)).expect("set");
            assert_eq!(set.schema, Some(&b"other"[..]));
            assert!(room.contains(&(set.schema.expect("set").as_ptr() as usize)));
            assert_eq!(
                z_encoding_set_schema_from_substr(
                    z_encoding_loan_mut(&mut owned),
                    core::ptr::null(),
                    0
                ),
                Z_OK
            );
            assert_eq!(
                encoding_view(z_encoding_loan(&owned)).expect("cleared"),
                EncodingRef {
                    packed_id: 4 << 1,
                    schema: None
                }
            );
            z_encoding_drop(z_encoding_move(&mut owned));
        }
    }

    /// A schema one byte past the room an encoding has is refused where it is made, with pico's
    /// code for a copy its heap cannot hold, the output left null; set on an encoding that holds
    /// one, it is refused and the encoding keeps its schema.
    #[test]
    fn a_schema_past_the_room_is_refused_and_leaves_its_target_as_it_was() {
        let mut label = b"text/plain;".to_vec();
        let past_room = label.len() + wz_session_core::caps::MAX_ENCODING_SCHEMA_BYTES + 1;
        label.resize(past_room, b's');
        let mut owned = z_owned_encoding_t::null_value();
        // SAFETY: live locals.
        unsafe {
            assert_eq!(
                z_encoding_from_substr(&mut owned, label.as_ptr().cast(), label.len()),
                Z_ERR_SYSTEM_OUT_OF_MEMORY
            );
            assert!(!z_internal_encoding_check(&owned), "refused, left null");
            assert_eq!(
                z_encoding_from_str(&mut owned, c"text/plain;utf8".as_ptr()),
                Z_OK
            );
            let past = &label[b"text/plain;".len()..];
            assert_eq!(
                z_encoding_set_schema_from_substr(
                    z_encoding_loan_mut(&mut owned),
                    past.as_ptr().cast(),
                    past.len()
                ),
                Z_ERR_SYSTEM_OUT_OF_MEMORY
            );
            assert_eq!(
                encoding_view(z_encoding_loan(&owned)).expect("kept").schema,
                Some(&b"utf8"[..]),
                "a refused schema leaves the one it had"
            );
            z_encoding_drop(z_encoding_move(&mut owned));
        }
    }

    /// Each well-known accessor sits at the index of its own id, so an encoding of no schema is read
    /// from the constant of its id.
    #[test]
    fn each_constant_sits_at_the_index_of_its_id() {
        for (id, accessor) in CONSTANTS.iter().enumerate() {
            // SAFETY: a `'static` view this module minted.
            let read = unsafe { encoding_view(accessor()) }.expect("a constant is never absent");
            assert_eq!(read.packed_id, (id as u32) << 1);
        }
        assert_eq!(CONSTANTS.len(), ENCODING_ID_TO_STR.len());
    }

    /// An encoding of no schema whose id the table names is its constant: it takes no slot, as
    /// zenoh-pico's allocates nothing for one, and dropping it leaves the constant as it was.
    #[test]
    fn an_encoding_of_no_schema_is_its_constant_and_takes_no_slot() {
        let mut owned = z_owned_encoding_t::null_value();
        // SAFETY: a live local and `'static` views.
        unsafe {
            assert_eq!(
                z_encoding_from_str(&mut owned, c"text/plain".as_ptr()),
                Z_OK
            );
            assert_eq!(
                owned.handle,
                (*z_encoding_text_plain()).handle,
                "the owned encoding is the constant's state"
            );
            z_encoding_drop(z_encoding_move(&mut owned));
            assert_eq!(
                encoding_view(z_encoding_text_plain())
                    .expect("still there")
                    .packed_id,
                4 << 1
            );
        }
    }

    /// zenoh-pico's own schema test: a schema set on the null encoding, which pico reads as the
    /// default, and on an encoding of no schema, gives each a schema of its own
    /// (`vendor/zenoh-pico/tests/z_api_encoding_test.c` @ `void test_with_schema(void) {`).
    #[test]
    fn a_schema_is_set_on_the_null_encoding_and_on_a_constant() {
        let rendered_of = |owned: &z_owned_encoding_t| {
            // SAFETY: a live owned encoding.
            let read = unsafe { encoding_view(z_encoding_loan(owned)) }.expect("an encoding");
            String::from_utf8(wz_session_core::encoding_hint::parts_to_bytes(
                read.packed_id,
                read.schema,
            ))
            .expect("text")
        };
        let mut owned = z_owned_encoding_t::null_value();
        // SAFETY: live locals.
        unsafe {
            z_internal_encoding_null(&mut owned);
            assert_eq!(
                z_encoding_set_schema_from_str(
                    z_encoding_loan_mut(&mut owned),
                    c"my_schema".as_ptr()
                ),
                Z_OK
            );
            assert_eq!(rendered_of(&owned), "zenoh/bytes;my_schema");
            z_encoding_drop(z_encoding_move(&mut owned));

            assert_eq!(
                z_encoding_from_str(&mut owned, c"zenoh/string;".as_ptr()),
                Z_OK
            );
            assert_eq!(
                owned.handle,
                (*z_encoding_zenoh_string()).handle,
                "an empty schema is none, so the encoding is the constant"
            );
            assert_eq!(
                z_encoding_set_schema_from_substr(
                    z_encoding_loan_mut(&mut owned),
                    c"my_schema".as_ptr(),
                    3
                ),
                Z_OK
            );
            assert_eq!(rendered_of(&owned), "zenoh/string;my_");
            assert_ne!(owned.handle, (*z_encoding_zenoh_string()).handle);
            z_encoding_drop(z_encoding_move(&mut owned));
            assert_eq!(
                encoding_view(z_encoding_zenoh_string())
                    .expect("the constant")
                    .schema,
                None,
                "the constant the schema was set over is as it was"
            );
        }
    }

    /// An owned encoding lies in a slot of the pool of encodings, not on the heap, in a library
    /// with the process pools.
    #[cfg(wz_process_pools)]
    #[test]
    fn an_owned_encoding_lies_in_the_pool_of_encodings() {
        let mut owned = z_owned_encoding_t::null_value();
        // SAFETY: a live local.
        unsafe {
            assert_eq!(
                z_encoding_from_str(&mut owned, c"text/plain;utf8".as_ptr()),
                Z_OK
            );
            let place = core::ptr::NonNull::new(owned.handle.cast::<u8>()).expect("made");
            assert!(crate::process_pool::lies_in_pools(place));
            z_encoding_drop(z_encoding_move(&mut owned));
        }
    }

    /// Round trip through the rendering, for the shapes the attachment
    /// programs actually use. The ORACLE test compares against upstream; this
    /// one keeps the intent readable without a built pico.
    #[test]
    fn to_string_round_trips_the_common_shapes() {
        for s in ["zenoh/bytes", "text/plain", "application/json"] {
            assert_eq!(rendered(&parsed(s)), s);
        }
        assert_eq!(rendered(&parsed("text/plain;utf8")), "text/plain;utf8");
    }
}
