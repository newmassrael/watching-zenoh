// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zext_payload_schema_*` and `zext_message_payload_*`: the payload of a catalog message set
//! and read field by field from C, under `.proto` files the program hands over when it runs.
//!
//! A host program that reads its deployment's message catalog and schema at run time has no code
//! generated for its messages. It makes a SCHEMA once, from the `FileDescriptorSet` `protoc`
//! compiled its `.proto` files into when it was built, or, in a build with `proto-text`, from the
//! files' text itself, then a PAYLOAD for a
//! message of the catalog, naming the message type of the schema the payload is; it sets values at
//! field paths (`origin.x`, `path[2].y`), encodes the protobuf bytes to put on the message's key,
//! decodes the bytes a sample carries and reads values back at paths. The paths, the values each
//! field takes, what reads as absent and how the bytes are written are
//! [`wz_app_frame::message_payload`]'s; the schema is read by `wz-app-frame`'s descriptor reader,
//! or its `.proto` text reader, into the same tables.
//!
//! A door wz has and zenoh-pico does not, so each is `zext_*`, declared in `zext.h`, and part
//! of the unstable surface: the `message-payload` capability implies `unstable-api` and
//! `message-catalog`.
//!
//! # Refusals
//!
//! A call on a payload that is refused returns a named code (`ZEXT_ERR_PAYLOAD_PATH`, `_TYPE`,
//! `_RANGE`, `_ABSENT`, `_WIRE`, or `Z_ERR_OVERFLOW` for a buffer too small or a storage with no
//! room left) and changes nothing, except a decode whose values do not fit the storage, which
//! leaves the payload empty; `zext_message_payload_refusal` gives the sentence of the last
//! refused call on the payload.
//!
//! # Storage
//!
//! A payload keeps its values in storage the program gives when it makes the payload
//! (`zext_message_payload_options_t`), as many values and bytes as the program states and
//! `zext_message_payload_storage_size` sizes, so setting, encoding, decoding and reading take
//! nothing from the heap.
//!
//! # Ownership and threads
//!
//! A schema does not change once read: any number of threads read one at once, and each payload
//! made from it holds it, so a schema may be dropped while its payloads live. A payload is one
//! message's values: every door holds its lock for the call, so it may be called from several
//! threads, one call at a time. `_new` makes an owned handle, every door that uses one takes the
//! loan, and `_drop` releases it and leaves the gravestone.

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::ffi::{c_char, c_void, CStr};
use core::mem::{align_of, size_of};
use core::ptr::NonNull;

use wz_app_frame::message_payload::{Entry, Given, Got, Payload, Refusal, Storage, Wanted};
use wz_app_frame::proto_decode::SchemaSet;
use wz_app_frame::proto_types::ProtoDiagnostic;
use wz_app_frame::proto_write::Narrowing;

use crate::abi::z_owned_string_t;
use crate::e2e::{
    adopt, behind, bytes_arg, clear_refusal, locked, release, utf8_arg, write_refusal,
};
use crate::ffi::{guard_val, guarded};
use crate::message_catalog::{
    zext_loaned_message_catalog_t, zext_message_catalog_entry, zext_message_entry_t,
};
#[cfg(feature = "proto-text")]
use crate::proto_file::{proto_files, zext_proto_file_t};
use crate::result::{
    ZResult, ZEXT_ERR_PAYLOAD_ABSENT, ZEXT_ERR_PAYLOAD_PATH, ZEXT_ERR_PAYLOAD_RANGE,
    ZEXT_ERR_PAYLOAD_TYPE, ZEXT_ERR_PAYLOAD_WIRE, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_NULL,
    Z_ERR_OVERFLOW, Z_OK,
};

/// An owned schema: the handle in its one word, null for the gravestone.
#[repr(C)]
#[derive(Debug)]
pub struct zext_owned_payload_schema_t {
    pub(crate) handle: *mut c_void,
}

/// A loaned schema: the owned layout, so the loan is a pointer cast.
#[repr(C)]
pub struct zext_loaned_payload_schema_t {
    pub(crate) handle: *mut c_void,
}

/// A moved schema (pico's `z_moved_*_t` shape).
#[repr(C)]
pub struct zext_moved_payload_schema_t {
    pub(crate) _this: zext_owned_payload_schema_t,
}

/// An owned payload: the handle in its one word, null for the gravestone.
#[repr(C)]
#[derive(Debug)]
pub struct zext_owned_message_payload_t {
    pub(crate) handle: *mut c_void,
}

/// A loaned payload: the owned layout, so the loan is a pointer cast.
#[repr(C)]
pub struct zext_loaned_message_payload_t {
    pub(crate) handle: *mut c_void,
}

/// A moved payload (pico's `z_moved_*_t` shape).
#[repr(C)]
pub struct zext_moved_message_payload_t {
    pub(crate) _this: zext_owned_message_payload_t,
}

/// How a payload is made: the storage it keeps its values in, the program's.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct zext_message_payload_options_t {
    /// `storage_len` bytes the payload keeps its values in, at least
    /// `zext_message_payload_storage_size(fields, bytes)`. The PROGRAM's, and it must stay valid
    /// and untouched until the payload is dropped. May be null when that size is 0.
    pub storage: *mut u8,
    /// How many bytes `storage` has.
    pub storage_len: usize,
    /// How many values the payload holds at once: each value, each element of a repeated field,
    /// each message field that holds others, and each field kept as the wire wrote it (one the
    /// schema does not know, a map's entry) takes one.
    pub fields: usize,
    /// How many bytes of strings, bytes and kept fields the payload holds at once.
    pub bytes: usize,
}

impl Default for zext_message_payload_options_t {
    fn default() -> Self {
        Self {
            storage: core::ptr::null_mut(),
            storage_len: 0,
            fields: 0,
            bytes: 0,
        }
    }
}

/// The storage a payload of `fields` values and `bytes` bytes takes wherever the program's
/// storage begins: its slots, with the room to align the first, then its bytes. `None` past the
/// address space.
fn storage_size(fields: usize, bytes: usize) -> Option<usize> {
    if fields == 0 {
        return Some(bytes);
    }
    fields
        .checked_mul(size_of::<Entry>())?
        .checked_add(align_of::<Entry>().saturating_sub(1))?
        .checked_add(bytes)
}

/// The program's storage of a payload: its slots, then its bytes.
struct ProgramStore {
    entries: NonNull<Entry>,
    fields: usize,
    bytes: NonNull<u8>,
    bytes_len: usize,
}

/// Why the program's storage makes no payload.
enum StoreRefused {
    /// Null storage for a store that takes some.
    Null,
    /// The text of a refusal of the shape or the storage.
    Invalid(&'static str),
}

impl ProgramStore {
    /// The store of `fields` slots and `bytes` bytes laid in the program's `storage`, every slot
    /// free and every byte zero.
    ///
    /// # Safety
    /// `storage` is null or writable for `storage_len` bytes, which nothing else touches while the
    /// store lives.
    unsafe fn lay(
        storage: *mut u8,
        storage_len: usize,
        fields: usize,
        bytes: usize,
    ) -> Result<Self, StoreRefused> {
        let need = storage_size(fields, bytes).ok_or(StoreRefused::Invalid(
            "fields and bytes: their storage does not fit the address space",
        ))?;
        if need == 0 {
            return Ok(Self {
                entries: NonNull::dangling(),
                fields: 0,
                bytes: NonNull::dangling(),
                bytes_len: 0,
            });
        }
        if storage.is_null() {
            return Err(StoreRefused::Null);
        }
        if storage_len < need {
            return Err(StoreRefused::Invalid(
                "storage: shorter than zext_message_payload_storage_size gives",
            ));
        }
        let mut rest = storage;
        let mut entries = NonNull::dangling();
        if fields != 0 {
            let pad = storage.align_offset(align_of::<Entry>());
            if pad >= align_of::<Entry>() {
                return Err(StoreRefused::Invalid(
                    "storage: no slot can be aligned in it",
                ));
            }
            // The padding, the slots and the bytes lie within `need` bytes, which `storage_len`
            // holds: the size counts the most padding an alignment takes.
            let first = storage.add(pad).cast::<Entry>();
            for at in 0..fields {
                first.add(at).write(Entry::default());
            }
            entries = NonNull::new_unchecked(first);
            rest = first.add(fields).cast::<u8>();
        }
        let mut at_bytes = NonNull::dangling();
        if bytes != 0 {
            rest.write_bytes(0, bytes);
            at_bytes = NonNull::new_unchecked(rest);
        }
        Ok(Self {
            entries,
            fields,
            bytes: at_bytes,
            bytes_len: bytes,
        })
    }
}

impl Storage for ProgramStore {
    fn entries(&self) -> &[Entry] {
        // SAFETY: `lay` wrote `fields` slots there (or made none, over a dangling pointer), and the
        // payload's contract keeps the program's storage to the payload while it lives.
        unsafe { core::slice::from_raw_parts(self.entries.as_ptr(), self.fields) }
    }

    fn entries_mut(&mut self) -> &mut [Entry] {
        // SAFETY: as for `entries`; the payload's lock gives one caller at a time.
        unsafe { core::slice::from_raw_parts_mut(self.entries.as_ptr(), self.fields) }
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: `lay` zeroed `bytes_len` bytes there (or made none), the program's as above.
        unsafe { core::slice::from_raw_parts(self.bytes.as_ptr(), self.bytes_len) }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as for `bytes`; the payload's lock gives one caller at a time.
        unsafe { core::slice::from_raw_parts_mut(self.bytes.as_ptr(), self.bytes_len) }
    }
}

/// What a payload handle holds: the payload over its schema in the program's storage, the key its
/// catalog message is put on, and the sentence of the last refused call.
struct Held {
    payload: Payload<Arc<SchemaSet>, ProgramStore>,
    key_expr: CString,
    refusal: Option<String>,
}

/// The schema behind a loaned handle; `None` for a null pointer or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned schema of this library.
unsafe fn schema_of<'a>(this_: *const zext_loaned_payload_schema_t) -> Option<&'a Arc<SchemaSet>> {
    if this_.is_null() {
        return None;
    }
    let handle = (*this_).handle;
    if handle.is_null() {
        return None;
    }
    Some(&*handle.cast::<Arc<SchemaSet>>())
}

/// The handle word of a loaned payload.
fn word(this_: *const zext_loaned_message_payload_t) -> *const *mut c_void {
    this_.cast::<*mut c_void>()
}

/// The code a refusal of the payload answers with.
fn code_of(why: &Refusal) -> ZResult {
    match why {
        Refusal::Path { .. } => ZEXT_ERR_PAYLOAD_PATH,
        Refusal::Type { .. } => ZEXT_ERR_PAYLOAD_TYPE,
        Refusal::Range { .. } => ZEXT_ERR_PAYLOAD_RANGE,
        Refusal::Absent { .. } => ZEXT_ERR_PAYLOAD_ABSENT,
        Refusal::Schema { .. } => Z_ERR_CONFIG_INVALID_VALUE,
        Refusal::Wire(_) => ZEXT_ERR_PAYLOAD_WIRE,
        Refusal::Full { .. } => Z_ERR_OVERFLOW,
    }
}

/// Record how a call on the payload ended, and the code it answers with.
fn answer(held: &mut Held, outcome: Result<(), Refusal>) -> ZResult {
    match outcome {
        Ok(()) => {
            held.refusal = None;
            Z_OK
        }
        Err(why) => {
            held.refusal = Some(why.to_string());
            code_of(&why)
        }
    }
}

/// A refusal for a value read as one kind and found another, which the reader never gives.
fn other_kind(path: &str) -> Refusal {
    Refusal::Type {
        path: String::from(path),
        reason: String::from("the value read is not of the kind asked for"),
    }
}

/// Run `act` on the payload behind `this_` at the path `path`, under its lock.
///
/// # Safety
/// `this_` is null or a loaned payload; `path` is null or a C string.
unsafe fn at_path(
    this_: *const zext_loaned_message_payload_t,
    path: *const c_char,
    act: impl FnOnce(&mut Held, &str) -> ZResult,
) -> ZResult {
    let Some(held) = behind::<Held>(word(this_)) else {
        return Z_ERR_NULL;
    };
    if path.is_null() {
        return Z_ERR_NULL;
    }
    let Some(path) = utf8_arg(path) else {
        return Z_EINVAL;
    };
    let mut guard = locked(held);
    let held: &mut Held = &mut guard;
    act(held, path)
}

/// Set the value at `path` to `value`.
///
/// # Safety
/// As [`at_path`].
unsafe fn set_at(
    this_: *const zext_loaned_message_payload_t,
    path: *const c_char,
    value: Given<'_>,
) -> ZResult {
    at_path(this_, path, |held, path| {
        let outcome = held.payload.set(path, value);
        answer(held, outcome)
    })
}

/// Read the value at `path` as `wanted`, and hand it to `take`, which writes it where the caller
/// asked; `out` is the caller's slot, refused when null.
///
/// # Safety
/// As [`at_path`].
unsafe fn get_at<T: Copy>(
    this_: *const zext_loaned_message_payload_t,
    path: *const c_char,
    wanted: Wanted,
    out: *mut T,
    take: impl Fn(Got<'_>) -> Option<T>,
) -> ZResult {
    if out.is_null() {
        return Z_ERR_NULL;
    }
    at_path(this_, path, |held, path| {
        let read = held
            .payload
            .get(path, wanted)
            .and_then(|got| take(got).ok_or_else(|| other_kind(path)));
        // `out` is not null, and the caller's contract makes it writable.
        let outcome = read.map(|value| *out = value);
        answer(held, outcome)
    })
}

/// Write a schema the reader read to `this_`, or its diagnostic to `refusal`.
///
/// # Safety
/// `this_` is writable and holds the gravestone; `refusal` is null or writable.
unsafe fn adopt_schema(
    this_: *mut zext_owned_payload_schema_t,
    read: Result<SchemaSet, ProtoDiagnostic>,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    match read {
        Ok(schema) => {
            (*this_).handle = Box::into_raw(Box::new(Arc::new(schema))).cast::<c_void>();
            Z_OK
        }
        Err(why) => {
            write_refusal(refusal, &why.to_string());
            Z_ERR_CONFIG_INVALID_VALUE
        }
    }
}

/// Read the `len` bytes at `bytes`, a `FileDescriptorSet` (what `protoc --include_imports -o`
/// writes for the program's `.proto` files when it is built), into a schema, written to `this_`.
///
/// `this_` holds the gravestone on every error. `refusal` may be null; when it is not, it holds the
/// gravestone on success and, on `_Z_ERR_CONFIG_INVALID_VALUE`, why the bytes are refused, naming
/// the file when the problem is in one.
///
/// Returns `Z_OK`; `Z_ERR_NULL` for a null `this_`, or a null `bytes` with a length;
/// `_Z_ERR_CONFIG_INVALID_VALUE` for bytes the descriptor reader refuses.
///
/// # Safety
/// `this_` is null or writable; `bytes` is null or readable for `len` bytes; `refusal` is null or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn zext_payload_schema_from_descriptor_set(
    this_: *mut zext_owned_payload_schema_t,
    bytes: *const u8,
    len: usize,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        clear_refusal(refusal);
        if this_.is_null() {
            return Z_ERR_NULL;
        }
        (*this_).handle = core::ptr::null_mut();
        if bytes.is_null() && len != 0 {
            return Z_ERR_NULL;
        }
        adopt_schema(
            this_,
            SchemaSet::from_descriptor_set(bytes_arg(bytes, len)),
            refusal,
        )
    })
}

/// Read every `.proto` file of `files` (each with what it imports) into a schema, written to
/// `this_`. In a build with `proto-text`, which links the text reader.
///
/// `this_` holds the gravestone on every error. `refusal` may be null; when it is not, it holds the
/// gravestone on success and, on `_Z_ERR_CONFIG_INVALID_VALUE`, the schema reader's diagnostic: the
/// file, the line and why.
///
/// Returns `Z_OK`; `Z_ERR_NULL` for a null `this_`, a null `files` with a count, or a file with a
/// null name or text; `Z_EINVAL` for a name or a text that is not UTF-8;
/// `_Z_ERR_CONFIG_INVALID_VALUE` for files the schema reader refuses.
///
/// # Safety
/// `this_` is null or writable; `files` is null or readable for `file_count` entries, each holding
/// NUL-terminated C strings; `refusal` is null or writable.
#[cfg(feature = "proto-text")]
#[no_mangle]
pub unsafe extern "C" fn zext_payload_schema_new(
    this_: *mut zext_owned_payload_schema_t,
    files: *const zext_proto_file_t,
    file_count: usize,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        clear_refusal(refusal);
        if this_.is_null() {
            return Z_ERR_NULL;
        }
        (*this_).handle = core::ptr::null_mut();
        let proto = match proto_files(files, file_count) {
            Ok(proto) => proto,
            Err(code) => return code,
        };
        adopt_schema(this_, SchemaSet::read(&proto), refusal)
    })
}

/// Borrow a schema. The loaned form has the owned layout, so this is a pointer cast.
///
/// # Safety
/// `this_` is null or an owned schema.
#[no_mangle]
pub unsafe extern "C" fn zext_payload_schema_loan(
    this_: *const zext_owned_payload_schema_t,
) -> *const zext_loaned_payload_schema_t {
    this_.cast::<zext_loaned_payload_schema_t>()
}

/// The moved form of a schema, for `zext_payload_schema_drop`: a cast, which nulls nothing.
///
/// # Safety
/// `this_` is null or an owned schema.
#[no_mangle]
pub unsafe extern "C" fn zext_payload_schema_move(
    this_: *mut zext_owned_payload_schema_t,
) -> *mut zext_moved_payload_schema_t {
    this_.cast::<zext_moved_payload_schema_t>()
}

/// Release a schema and leave the gravestone. The payloads made from it keep it until they are
/// dropped. A second drop, and a drop of the gravestone, do nothing.
///
/// # Safety
/// `this_` is null or a moved schema, which no other thread reads through this handle.
#[no_mangle]
pub unsafe extern "C" fn zext_payload_schema_drop(this_: *mut zext_moved_payload_schema_t) {
    let _ = guarded(|| {
        if !this_.is_null() {
            let slot = core::ptr::addr_of_mut!((*this_)._this.handle);
            let handle = *slot;
            *slot = core::ptr::null_mut();
            if !handle.is_null() {
                drop(Box::from_raw(handle.cast::<Arc<SchemaSet>>()));
            }
        }
        Z_OK
    });
}

/// Write the gravestone.
///
/// # Safety
/// `this_` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn zext_internal_payload_schema_null(
    this_: *mut zext_owned_payload_schema_t,
) {
    if !this_.is_null() {
        (*this_).handle = core::ptr::null_mut();
    }
}

/// Whether the slot holds a schema.
///
/// # Safety
/// `this_` is null or an owned schema.
#[no_mangle]
pub unsafe extern "C" fn zext_internal_payload_schema_check(
    this_: *const zext_owned_payload_schema_t,
) -> bool {
    guard_val(|| !this_.is_null() && !(*this_).handle.is_null())
}

/// Fill in the default payload options: a storage of no value and no byte.
///
/// # Safety
/// `this_` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_options_default(
    this_: *mut zext_message_payload_options_t,
) {
    if !this_.is_null() {
        *this_ = zext_message_payload_options_t::default();
    }
}

/// How many bytes of storage a payload of `fields` values and `bytes` bytes takes, wherever the
/// storage begins; 0 for one whose size overflows, and for a payload of no value and no byte.
#[no_mangle]
pub extern "C" fn zext_message_payload_storage_size(fields: usize, bytes: usize) -> usize {
    storage_size(fields, bytes).unwrap_or(0)
}

/// An empty payload of message `index` of `catalog`, of the message type `message` of `schema`
/// (its full name, package included), keeping its values in the storage `options` gives, written
/// to `this_`. The payload keeps the message's key expression and holds the schema.
///
/// `this_` holds the gravestone on every error. `refusal` may be null; when it is not, it holds the
/// gravestone on success and, on `_Z_ERR_CONFIG_INVALID_VALUE`, why: `message` names no message of
/// the schema, or the storage is shorter than its size.
///
/// Returns `Z_OK`; `Z_ERR_INVALID` for a message the catalog does not have; `Z_EINVAL` for a name
/// that is not UTF-8; `_Z_ERR_CONFIG_INVALID_VALUE` for a name the schema has no message of, a
/// storage shorter than `zext_message_payload_storage_size` gives, or a size that overflows;
/// `Z_ERR_NULL` for a null `this_`, `catalog`, `schema`, `message` or `options`, a null storage
/// of a size, or a gravestone.
///
/// # Safety
/// `this_` is null or writable; `catalog` is null or a loaned catalog; `schema` is null or a loaned
/// schema; `message` is null or a C string; `options` is null or readable, its `storage` null or
/// writable for `storage_len` bytes until the payload is dropped and touched by nothing else
/// meanwhile; `refusal` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_new(
    this_: *mut zext_owned_message_payload_t,
    catalog: *const zext_loaned_message_catalog_t,
    index: usize,
    schema: *const zext_loaned_payload_schema_t,
    message: *const c_char,
    options: *const zext_message_payload_options_t,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        clear_refusal(refusal);
        if this_.is_null() {
            return Z_ERR_NULL;
        }
        (*this_).handle = core::ptr::null_mut();
        let mut entry = zext_message_entry_t::default();
        let found = zext_message_catalog_entry(catalog, index, &mut entry);
        if found != Z_OK {
            return found;
        }
        let key_expr = CStr::from_ptr(entry.key_expr).to_owned();
        let Some(schema) = schema_of(schema) else {
            return Z_ERR_NULL;
        };
        if message.is_null() {
            return Z_ERR_NULL;
        }
        let Some(message) = utf8_arg(message) else {
            return Z_EINVAL;
        };
        let message = match schema.message(message) {
            Ok(message) => message,
            Err(why) => {
                write_refusal(refusal, &why);
                return Z_ERR_CONFIG_INVALID_VALUE;
            }
        };
        if options.is_null() {
            return Z_ERR_NULL;
        }
        let options = *options;
        let store = match ProgramStore::lay(
            options.storage,
            options.storage_len,
            options.fields,
            options.bytes,
        ) {
            Ok(store) => store,
            Err(StoreRefused::Null) => return Z_ERR_NULL,
            Err(StoreRefused::Invalid(why)) => {
                write_refusal(refusal, why);
                return Z_ERR_CONFIG_INVALID_VALUE;
            }
        };
        (*this_).handle = adopt(Held {
            payload: Payload::over(Arc::clone(schema), message, Narrowing::Type, store),
            key_expr,
            refusal: None,
        });
        Z_OK
    })
}

/// The key expression the payload's catalog message is put on, NUL-terminated, valid while the
/// payload lives; null for a null payload or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned payload.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_key_expr(
    this_: *const zext_loaned_message_payload_t,
) -> *const c_char {
    guard_val(|| {
        behind::<Held>(word(this_)).map_or(core::ptr::null(), |held| {
            // The key lives in the payload, past the lock.
            let held = locked(held);
            held.key_expr.as_ptr()
        })
    })
}

/// Set the integer or enum field `path` names to `value`.
///
/// Returns `Z_OK`; `ZEXT_ERR_PAYLOAD_PATH` for a path that names no field; `_TYPE` for a field
/// that holds no integer; `_RANGE` for a value the field cannot hold, a number a closed enum has
/// not, or an index past the end of its list; `Z_ERR_OVERFLOW` when the payload's storage has no
/// room for the value; `Z_EINVAL` for a path that is not UTF-8; `Z_ERR_NULL` for a null argument or
/// the gravestone. A refused call changes nothing.
///
/// # Safety
/// `this_` is null or a loaned payload; `path` is null or a C string.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_set_int(
    this_: *const zext_loaned_message_payload_t,
    path: *const c_char,
    value: i64,
) -> ZResult {
    guarded(|| set_at(this_, path, Given::Signed(value)))
}

/// Set the integer or enum field `path` names to `value`; as `zext_message_payload_set_int`.
///
/// # Safety
/// As `zext_message_payload_set_int`.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_set_uint(
    this_: *const zext_loaned_message_payload_t,
    path: *const c_char,
    value: u64,
) -> ZResult {
    guarded(|| set_at(this_, path, Given::Unsigned(value)))
}

/// Set the `float` or `double` field `path` names to `value`; `_RANGE` for a finite value a `float`
/// cannot hold. Otherwise as `zext_message_payload_set_int`.
///
/// # Safety
/// As `zext_message_payload_set_int`.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_set_double(
    this_: *const zext_loaned_message_payload_t,
    path: *const c_char,
    value: f64,
) -> ZResult {
    guarded(|| set_at(this_, path, Given::Real(value)))
}

/// Set the `bool` field `path` names to `value`; as `zext_message_payload_set_int`.
///
/// # Safety
/// As `zext_message_payload_set_int`.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_set_bool(
    this_: *const zext_loaned_message_payload_t,
    path: *const c_char,
    value: bool,
) -> ZResult {
    guarded(|| set_at(this_, path, Given::Bool(value)))
}

/// Set the `string` field `path` names to `value`, NUL-terminated UTF-8, or the enum field to its
/// value of that name (`_RANGE` for a name the enum has not); `Z_EINVAL` for a value that is not
/// UTF-8. Otherwise as `zext_message_payload_set_int`.
///
/// # Safety
/// As `zext_message_payload_set_int`; `value` is null or a C string.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_set_string(
    this_: *const zext_loaned_message_payload_t,
    path: *const c_char,
    value: *const c_char,
) -> ZResult {
    guarded(|| {
        if value.is_null() {
            return Z_ERR_NULL;
        }
        let Some(value) = utf8_arg(value) else {
            return Z_EINVAL;
        };
        set_at(this_, path, Given::Text(value))
    })
}

/// Set the `bytes` field `path` names to the `len` bytes at `data`; `Z_ERR_NULL` for a null `data`
/// with a length. Otherwise as `zext_message_payload_set_int`.
///
/// # Safety
/// As `zext_message_payload_set_int`; `data` is readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_set_bytes(
    this_: *const zext_loaned_message_payload_t,
    path: *const c_char,
    data: *const u8,
    len: usize,
) -> ZResult {
    guarded(|| {
        if data.is_null() && len != 0 {
            return Z_ERR_NULL;
        }
        set_at(this_, path, Given::Bytes(bytes_arg(data, len)))
    })
}

/// The value of the integer or enum field `path` names, written to `out`.
///
/// Returns `Z_OK`; `ZEXT_ERR_PAYLOAD_PATH` for a path that names no field; `_TYPE` for a field
/// that holds no integer; `_RANGE` for a value `out` cannot hold or an index past the end of its
/// list; `_ABSENT` for a field with presence that is not set, or a field of a message that is not
/// there (a field without presence reads as its default); `Z_EINVAL` for a path that is not UTF-8;
/// `Z_ERR_NULL` for a null argument or the gravestone. `out` is written only on `Z_OK`.
///
/// # Safety
/// `this_` is null or a loaned payload; `path` is null or a C string; `out` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_get_int(
    this_: *const zext_loaned_message_payload_t,
    path: *const c_char,
    out: *mut i64,
) -> ZResult {
    guarded(|| {
        get_at(this_, path, Wanted::Signed, out, |got| match got {
            Got::Signed(v) => Some(v),
            _ => None,
        })
    })
}

/// The value of the integer or enum field `path` names, written to `out`; as
/// `zext_message_payload_get_int`, `_RANGE` for a negative value.
///
/// # Safety
/// As `zext_message_payload_get_int`.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_get_uint(
    this_: *const zext_loaned_message_payload_t,
    path: *const c_char,
    out: *mut u64,
) -> ZResult {
    guarded(|| {
        get_at(this_, path, Wanted::Unsigned, out, |got| match got {
            Got::Unsigned(v) => Some(v),
            _ => None,
        })
    })
}

/// The value of the `float` or `double` field `path` names, written to `out`; as
/// `zext_message_payload_get_int`.
///
/// # Safety
/// As `zext_message_payload_get_int`.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_get_double(
    this_: *const zext_loaned_message_payload_t,
    path: *const c_char,
    out: *mut f64,
) -> ZResult {
    guarded(|| {
        get_at(this_, path, Wanted::Real, out, |got| match got {
            Got::Real(v) => Some(v),
            _ => None,
        })
    })
}

/// The value of the `bool` field `path` names, written to `out`; as
/// `zext_message_payload_get_int`.
///
/// # Safety
/// As `zext_message_payload_get_int`.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_get_bool(
    this_: *const zext_loaned_message_payload_t,
    path: *const c_char,
    out: *mut bool,
) -> ZResult {
    guarded(|| {
        get_at(this_, path, Wanted::Bool, out, |got| match got {
            Got::Bool(v) => Some(v),
            _ => None,
        })
    })
}

/// Copy text or bytes read at a path into the caller's `out`, `capacity` bytes long, with a NUL
/// after it when `nul`, and its length (without the NUL) into `len`.
///
/// # Safety
/// `out` is null or writable for `capacity` bytes; `len` is writable.
unsafe fn copy_out(
    held: &mut Held,
    path: &str,
    read: Result<&[u8], Refusal>,
    nul: bool,
    out: *mut u8,
    capacity: usize,
    len: *mut usize,
) -> ZResult {
    let outcome = read.map(|bytes| {
        // A length at the top of the address space is past every capacity, so it is refused.
        let need = bytes.len().saturating_add(usize::from(nul));
        if need > capacity {
            return Some((bytes.len(), need));
        }
        if !bytes.is_empty() {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
        }
        if nul {
            *out.add(bytes.len()) = 0;
        }
        *len = bytes.len();
        None
    });
    match outcome {
        Ok(Some((length, need))) => {
            *len = length;
            held.refusal = Some(format!(
                "`{path}`: the value needs {need} byte(s), and the buffer has {capacity}"
            ));
            Z_ERR_OVERFLOW
        }
        Ok(None) => answer(held, Ok(())),
        Err(why) => answer(held, Err(why)),
    }
}

/// The text of the `string` field `path` names, or the name of the enum field's value, written to
/// `out` with a NUL after it, and its length (without the NUL) to `len`.
///
/// Returns `Z_OK`; `Z_ERR_OVERFLOW` when `capacity` is less than the length and the NUL, `len` then
/// holding the length and `out` untouched (a `capacity` of 0 asks for the length alone); `_RANGE`
/// for an enum value with no name; otherwise as `zext_message_payload_get_int`, `Z_ERR_NULL`
/// also for a null `len`, and a null `out` with a capacity.
///
/// # Safety
/// `this_` is null or a loaned payload; `path` is null or a C string; `out` is null or writable for
/// `capacity` bytes; `len` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_get_string(
    this_: *const zext_loaned_message_payload_t,
    path: *const c_char,
    out: *mut c_char,
    capacity: usize,
    len: *mut usize,
) -> ZResult {
    guarded(|| {
        if len.is_null() || (out.is_null() && capacity != 0) {
            return Z_ERR_NULL;
        }
        at_path(this_, path, |held, path| {
            let read = match held.payload.get(path, Wanted::Text) {
                Ok(Got::Text(text)) => Ok(String::from(text)),
                Ok(_) => Err(other_kind(path)),
                Err(why) => Err(why),
            };
            match read {
                Ok(text) => copy_out(
                    held,
                    path,
                    Ok(text.as_bytes()),
                    true,
                    out.cast::<u8>(),
                    capacity,
                    len,
                ),
                Err(why) => copy_out(held, path, Err(why), true, out.cast::<u8>(), capacity, len),
            }
        })
    })
}

/// The bytes of the `bytes` field `path` names, written to `out`, and how many to `len`.
///
/// Returns `Z_OK`; `Z_ERR_OVERFLOW` when `capacity` is less than the bytes, `len` then holding how
/// many and `out` untouched (a `capacity` of 0 asks for the length alone); otherwise as
/// `zext_message_payload_get_int`, `Z_ERR_NULL` also for a null `len`, and a null `out` with a
/// capacity.
///
/// # Safety
/// As `zext_message_payload_get_string`.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_get_bytes(
    this_: *const zext_loaned_message_payload_t,
    path: *const c_char,
    out: *mut u8,
    capacity: usize,
    len: *mut usize,
) -> ZResult {
    guarded(|| {
        if len.is_null() || (out.is_null() && capacity != 0) {
            return Z_ERR_NULL;
        }
        at_path(this_, path, |held, path| {
            let read = match held.payload.get(path, Wanted::Bytes) {
                Ok(Got::Bytes(bytes)) => Ok(bytes.to_vec()),
                Ok(_) => Err(other_kind(path)),
                Err(why) => Err(why),
            };
            match read {
                Ok(bytes) => copy_out(held, path, Ok(bytes.as_slice()), false, out, capacity, len),
                Err(why) => copy_out(held, path, Err(why), false, out, capacity, len),
            }
        })
    })
}

/// How many elements the repeated field `path` names holds, written to `out`; 0 when a message
/// along the path is not there.
///
/// Returns `Z_OK`; `ZEXT_ERR_PAYLOAD_PATH` for a path that names no repeated field, or names one
/// element; `_RANGE` for an index along the path past the end of its list; `Z_EINVAL` for a path
/// that is not UTF-8; `Z_ERR_NULL` for a null argument or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned payload; `path` is null or a C string; `out` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_count(
    this_: *const zext_loaned_message_payload_t,
    path: *const c_char,
    out: *mut usize,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ERR_NULL;
        }
        at_path(this_, path, |held, path| {
            let outcome = held.payload.count(path).map(|n| {
                *out = n;
            });
            answer(held, outcome)
        })
    })
}

/// Clear the field `path` names (every element of a repeated one), or the one element it names,
/// the elements after it moving down; nothing to clear inside a message that is not there is not
/// refused.
///
/// Returns `Z_OK`; `ZEXT_ERR_PAYLOAD_PATH` for a path that names no field; `_RANGE` for an index
/// past the end of its list; `Z_EINVAL` for a path that is not UTF-8; `Z_ERR_NULL` for a null
/// argument or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned payload; `path` is null or a C string.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_clear(
    this_: *const zext_loaned_message_payload_t,
    path: *const c_char,
) -> ZResult {
    guarded(|| {
        at_path(this_, path, |held, path| {
            let outcome = held.payload.clear(path);
            answer(held, outcome)
        })
    })
}

/// Clear every field of the payload. `Z_ERR_NULL` for a null payload or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned payload.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_reset(
    this_: *const zext_loaned_message_payload_t,
) -> ZResult {
    guarded(|| {
        let Some(held) = behind::<Held>(word(this_)) else {
            return Z_ERR_NULL;
        };
        let mut held = locked(held);
        held.payload.reset();
        answer(&mut held, Ok(()))
    })
}

/// The protobuf bytes of the payload, written to `out`, and how many to `written`.
///
/// Returns `Z_OK`; `Z_ERR_OVERFLOW` when `capacity` is less than the bytes, `written` then holding
/// how many and `out` untouched (a `capacity` of 0 asks for the size alone);
/// `ZEXT_ERR_PAYLOAD_ABSENT` for a required field that is not set; `_Z_ERR_CONFIG_INVALID_VALUE`
/// for a `packed` option of the schema the writer cannot act on; `Z_ERR_NULL` for a null payload or
/// `written`, a null `out` with a capacity, or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned payload; `out` is null or writable for `capacity` bytes; `written`
/// is null or writable.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_encode(
    this_: *const zext_loaned_message_payload_t,
    out: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> ZResult {
    guarded(|| {
        if written.is_null() || (out.is_null() && capacity != 0) {
            return Z_ERR_NULL;
        }
        *written = 0;
        let Some(held) = behind::<Held>(word(this_)) else {
            return Z_ERR_NULL;
        };
        let mut held = locked(held);
        // Measured first and written where the program asked: nothing is built apart.
        let need = match held.payload.encoded_len() {
            Ok(need) => need,
            Err(why) => return answer(&mut held, Err(why)),
        };
        *written = need;
        if need > capacity {
            held.refusal = Some(format!(
                "`{}`: the value needs {need} byte(s), and the buffer has {capacity}",
                held.payload.message_name()
            ));
            return Z_ERR_OVERFLOW;
        }
        if need == 0 {
            return answer(&mut held, Ok(()));
        }
        // `out` is not null with a capacity, and the caller's contract makes it writable for it.
        let room = core::slice::from_raw_parts_mut(out, capacity);
        match held.payload.encode_into(room) {
            Ok(_) => answer(&mut held, Ok(())),
            Err(why) => {
                *written = 0;
                answer(&mut held, Err(why))
            }
        }
    })
}

/// Replace the payload's values with those the `len` bytes at `bytes` carry. Fields the schema
/// does not know and the entries of map fields are kept as written and encoded again.
///
/// Returns `Z_OK`; `ZEXT_ERR_PAYLOAD_WIRE` for bytes that are not a message of the schema, the
/// payload then as it was; `Z_ERR_OVERFLOW` for values the payload's storage has no room for, the
/// payload then empty; `Z_ERR_NULL` for a null payload, a null `bytes` with a length, or the
/// gravestone.
///
/// # Safety
/// `this_` is null or a loaned payload; `bytes` is readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_decode(
    this_: *const zext_loaned_message_payload_t,
    bytes: *const u8,
    len: usize,
) -> ZResult {
    guarded(|| {
        if bytes.is_null() && len != 0 {
            return Z_ERR_NULL;
        }
        let Some(held) = behind::<Held>(word(this_)) else {
            return Z_ERR_NULL;
        };
        let mut held = locked(held);
        let outcome = held.payload.decode(bytes_arg(bytes, len));
        answer(&mut held, outcome)
    })
}

/// Why the last call on the payload was refused, written to `out`; the gravestone when it was not
/// refused. `Z_ERR_NULL` for a null argument or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned payload; `out` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_refusal(
    this_: *const zext_loaned_message_payload_t,
    out: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ERR_NULL;
        }
        clear_refusal(out);
        let Some(held) = behind::<Held>(word(this_)) else {
            return Z_ERR_NULL;
        };
        if let Some(text) = &locked(held).refusal {
            write_refusal(out, text);
        }
        Z_OK
    })
}

/// Borrow a payload. The loaned form has the owned layout, so this is a pointer cast.
///
/// # Safety
/// `this_` is null or an owned payload.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_loan(
    this_: *const zext_owned_message_payload_t,
) -> *const zext_loaned_message_payload_t {
    this_.cast::<zext_loaned_message_payload_t>()
}

/// The moved form of a payload, for `zext_message_payload_drop`: a cast, which nulls nothing.
///
/// # Safety
/// `this_` is null or an owned payload.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_move(
    this_: *mut zext_owned_message_payload_t,
) -> *mut zext_moved_message_payload_t {
    this_.cast::<zext_moved_message_payload_t>()
}

/// Release a payload and leave the gravestone: the key expression it gave goes with it, and its
/// hold on the schema. A second drop, and a drop of the gravestone, do nothing.
///
/// # Safety
/// `this_` is null or a moved payload.
#[no_mangle]
pub unsafe extern "C" fn zext_message_payload_drop(this_: *mut zext_moved_message_payload_t) {
    let _ = guarded(|| {
        if !this_.is_null() {
            release::<Held>(core::ptr::addr_of_mut!((*this_)._this.handle));
        }
        Z_OK
    });
}

/// Write the gravestone.
///
/// # Safety
/// `this_` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn zext_internal_message_payload_null(
    this_: *mut zext_owned_message_payload_t,
) {
    if !this_.is_null() {
        (*this_).handle = core::ptr::null_mut();
    }
}

/// Whether the slot holds a payload.
///
/// # Safety
/// `this_` is null or an owned payload.
#[no_mangle]
pub unsafe extern "C" fn zext_internal_message_payload_check(
    this_: *const zext_owned_message_payload_t,
) -> bool {
    guard_val(|| !this_.is_null() && !(*this_).handle.is_null())
}
