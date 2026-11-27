// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zext_instance_keyer_*`: which instance of a message a sample is, read from fields of its
//! payload through the message's schema, from C.
//!
//! A keyer is made over the program's schema, the `FileDescriptorSet` `protoc` compiled its
//! `.proto` files into when it was built or, in a build with `proto-text`, the files' text, and a
//! description of the key fields and the values each may take; the position of a sample's values
//! in the product of those lists is its instance. With `e2e-receiver` the judging door judges a
//! frame in the receiver's stream of the instance its payload is, and with `e2e-sender` the
//! protecting door protects a payload on the sender's counter stream of its instance. A sample of
//! no instance is dropped, counted by reason, and reported at the rate the description states;
//! with `event-ring` each report is also an event of the node's log
//! (`ZEXT_EVENT_SOURCE_INSTANCE_KEY_DROPPED`). The last value of each instance is kept in storage
//! the program gives when it makes the keyer.
//!
//! A door wz has and zenoh-pico does not, so each is `zext_*`, declared in `zext.h`, and part
//! of the unstable surface: the `instance-key` capability implies `unstable-api`. The keyer is
//! [`wz_app_frame::instance_key`]; ownership and threads are as `crate::e2e` describes. The
//! judging and protecting doors hold the keyer's lock and then the receiver's or the sender's, and
//! no door takes them the other way round.

use alloc::format;
use alloc::string::ToString;
use core::ffi::{c_char, c_void};
use core::ptr::NonNull;

use wz_app_frame::instance_key::{Dropped, Keyer, LastValues, Limits, NewError, Refusal, Report};
use wz_app_frame::proto_decode::SchemaSet;

use crate::abi::z_owned_string_t;
use crate::e2e::{
    adopt, behind, bytes_arg, clear_refusal, locked, release, utf8_arg, write_refusal,
};
use crate::ffi::{guard_val, guarded};
#[cfg(feature = "proto-text")]
use crate::proto_file::{proto_files, zext_proto_file_t};
use crate::result::{
    ZResult, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_NULL, Z_ERR_OVERFLOW, Z_OK,
    Z_RES_CHANNEL_NODATA,
};
use crate::sized::{Out, SizedOut};

/// The sample is an instance: `instance` is its index.
pub const ZEXT_INSTANCE_KEY_INDEXED: u8 = 0;
/// The payload is not a message of the schema, or the frame is shorter than its header.
pub const ZEXT_INSTANCE_KEY_UNDECODABLE: u8 = 1;
/// A key field that has presence is not in the payload: `field` says which.
pub const ZEXT_INSTANCE_KEY_ABSENT: u8 = 2;
/// A key value is in no list: `field` says which.
pub const ZEXT_INSTANCE_KEY_NOT_LISTED: u8 = 3;

/// No last values are kept, or the sample was dropped.
pub const ZEXT_INSTANCE_KEY_LAST_NOT_KEPT: u8 = 0;
/// The payload is now the instance's last value.
pub const ZEXT_INSTANCE_KEY_LAST_RECORDED: u8 = 1;
/// The frame is not intact, so the instance's last value is the one before.
pub const ZEXT_INSTANCE_KEY_LAST_NOT_INTACT: u8 = 2;
/// The payload is longer than an instance's room, so its last value is the one before.
pub const ZEXT_INSTANCE_KEY_LAST_TOO_LONG: u8 = 3;

/// An owned keyer: the handle in its one word, null for the gravestone. `Debug` shows the word,
/// so a test can unwrap the refusal of a door that answers one or the other.
#[repr(C)]
#[derive(Debug)]
pub struct zext_owned_instance_keyer_t {
    pub(crate) handle: *mut c_void,
}

/// A loaned keyer: the owned layout, so the loan is a pointer cast.
#[repr(C)]
pub struct zext_loaned_instance_keyer_t {
    pub(crate) handle: *mut c_void,
}

/// A moved keyer (pico's `z_moved_*_t` shape).
#[repr(C)]
pub struct zext_moved_instance_keyer_t {
    pub(crate) _this: zext_owned_instance_keyer_t,
}

/// How a keyer is made.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct zext_instance_keyer_options_t {
    /// The storage of the last values: `value_capacity` bytes for each instance, the first
    /// instance's first. The PROGRAM's, and it must stay valid and untouched until the keyer is
    /// dropped. Read only when `value_capacity` is not 0.
    pub storage: *mut u8,
    /// How many bytes `storage` has.
    pub storage_len: usize,
    /// The room each instance's last value has; 0 keeps no last values.
    pub value_capacity: usize,
}

impl Default for zext_instance_keyer_options_t {
    fn default() -> Self {
        Self {
            storage: core::ptr::null_mut(),
            storage_len: 0,
            value_capacity: 0,
        }
    }
}

/// What became of one sample, as C reads it, written into a struct the program sized
/// (`crate::sized`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct zext_instance_key_t {
    /// The bytes of the struct the program was compiled with; a door sets it to the bytes it
    /// wrote.
    pub struct_size: usize,
    /// A `ZEXT_INSTANCE_KEY_*` status.
    pub status: u8,
    /// 1 when this drop carries the report of the drops since the last one (`dropped`).
    pub reported: u8,
    /// A `ZEXT_INSTANCE_KEY_LAST_*` value: what became of the instance's last value.
    pub last: u8,
    pub reserved: u8,
    /// For `_ABSENT` and `_NOT_LISTED`, the key field, in the order the description lists them.
    pub field: u32,
    /// When `reported` is 1, how many samples were dropped since the last report, this one
    /// included.
    pub dropped: u64,
    /// For `_INDEXED`, the instance.
    pub instance: usize,
}

impl Default for zext_instance_key_t {
    /// Nothing said, in a struct of this build's size.
    fn default() -> Self {
        Self {
            struct_size: core::mem::size_of::<Self>(),
            status: 0,
            reported: 0,
            last: 0,
            reserved: 0,
            field: 0,
            dropped: 0,
            instance: 0,
        }
    }
}

// SAFETY: `#[repr(C)]`, `struct_size` first.
unsafe impl SizedOut for zext_instance_key_t {
    const BASE: usize = core::mem::size_of::<Self>();
}

/// The program's storage of the last values.
struct CallerStorage {
    ptr: NonNull<u8>,
    len: usize,
}

impl AsRef<[u8]> for CallerStorage {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: the contract of the doors that make a keyer: `storage` is writable for
        // `storage_len` bytes until the keyer is dropped, and only the keyer, under its lock,
        // touches it.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl AsMut<[u8]> for CallerStorage {
    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: as for `as_ref`.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

/// What a keyer handle holds.
struct Held {
    keyer: Keyer,
    last: Option<LastValues<CallerStorage>>,
}

/// The handle word of a loaned keyer.
fn word(this_: *const zext_loaned_instance_keyer_t) -> *const *mut c_void {
    this_.cast::<*mut c_void>()
}

/// Write `refusal`'s status and field into `out`.
fn refused(out: &mut zext_instance_key_t, refusal: Refusal) {
    let (status, field) = match refusal {
        Refusal::Undecodable => (ZEXT_INSTANCE_KEY_UNDECODABLE, 0),
        Refusal::Absent { field } => (ZEXT_INSTANCE_KEY_ABSENT, field),
        Refusal::NotListed { field } => (ZEXT_INSTANCE_KEY_NOT_LISTED, field),
    };
    out.status = status;
    out.field = u32::try_from(field).unwrap_or(u32::MAX);
}

/// Write a report into `out`, and into the node's event log in a build that has one.
fn write_report(out: &mut zext_instance_key_t, due: Report) {
    out.reported = 1;
    out.dropped = due.dropped;
    #[cfg(feature = "event-ring")]
    {
        use crate::event_log::{
            zext_event_emit, ZEXT_EVENT_INSTANCE_KEY_ABSENT, ZEXT_EVENT_INSTANCE_KEY_NOT_LISTED,
            ZEXT_EVENT_INSTANCE_KEY_UNDECODABLE, ZEXT_EVENT_LEVEL_LIBRARY,
            ZEXT_EVENT_SOURCE_INSTANCE_KEY_DROPPED,
        };
        let (why, field) = match due.latest {
            Refusal::Undecodable => (ZEXT_EVENT_INSTANCE_KEY_UNDECODABLE, 0),
            Refusal::Absent { field } => (ZEXT_EVENT_INSTANCE_KEY_ABSENT, field),
            Refusal::NotListed { field } => (ZEXT_EVENT_INSTANCE_KEY_NOT_LISTED, field),
        };
        let args = [why, u64::try_from(field).unwrap_or(u64::MAX), due.dropped];
        // A full log under `drop-newest` refuses the report and counts it, as it does any event;
        // the keyer's own count in `out` stands either way.
        // SAFETY: `args` is readable for its length for the call.
        let _ = unsafe {
            zext_event_emit(
                ZEXT_EVENT_LEVEL_LIBRARY,
                ZEXT_EVENT_SOURCE_INSTANCE_KEY_DROPPED,
                args.as_ptr(),
                args.len(),
            )
        };
    }
}

/// The C form of a drop.
fn dropped(sample: Dropped) -> zext_instance_key_t {
    let mut out = zext_instance_key_t::default();
    refused(&mut out, sample.refusal);
    if let Some(due) = sample.report {
        write_report(&mut out, due);
    }
    out
}

/// The C form of a sample indexed as `instance`.
fn indexed(instance: usize, last: u8) -> zext_instance_key_t {
    zext_instance_key_t {
        status: ZEXT_INSTANCE_KEY_INDEXED,
        last,
        instance,
        ..zext_instance_key_t::default()
    }
}

/// Fill in the default keyer options: no last values.
///
/// # Safety
/// `this_` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn zext_instance_keyer_options_default(
    this_: *mut zext_instance_keyer_options_t,
) {
    if !this_.is_null() {
        *this_ = zext_instance_keyer_options_t::default();
    }
}

/// What the build allows one keyer.
fn limits() -> Limits {
    Limits {
        fields: wz_session_core::caps::INSTANCE_KEY_FIELDS,
        instances: wz_session_core::caps::INSTANCES_PER_MESSAGE,
    }
}

/// Write the keyer made, with the last values `options` asks for, to `this_`, or the reason it is
/// refused to `refusal`.
///
/// # Safety
/// `this_` is writable and holds the gravestone; `options` is null or valid, its `storage`
/// writable for `storage_len` bytes until the keyer is dropped; `refusal` is null or writable.
unsafe fn adopt_keyer(
    this_: *mut zext_owned_instance_keyer_t,
    made: Result<Keyer, NewError>,
    options: *const zext_instance_keyer_options_t,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    let options = if options.is_null() {
        zext_instance_keyer_options_t::default()
    } else {
        *options
    };
    let keyer = match made {
        Ok(keyer) => keyer,
        Err(why) => {
            write_refusal(refusal, &why.to_string());
            return Z_ERR_CONFIG_INVALID_VALUE;
        }
    };
    let last = if options.value_capacity == 0 {
        None
    } else {
        let Some(ptr) = NonNull::new(options.storage) else {
            return Z_ERR_NULL;
        };
        let storage = CallerStorage {
            ptr,
            len: options.storage_len,
        };
        match LastValues::new(storage, keyer.instances(), options.value_capacity) {
            Ok(last) => Some(last),
            Err(why) => {
                write_refusal(refusal, &format!("storage: {why}"));
                return Z_ERR_CONFIG_INVALID_VALUE;
            }
        }
    };
    (*this_).handle = adopt(Held { keyer, last });
    Z_OK
}

/// A keyer of the message `description` names, over the schema in the `len` bytes at `bytes`, a
/// `FileDescriptorSet` (what `protoc --include_imports -o` writes for the program's `.proto`
/// files when it is built), made as `options` says (null: no last values).
///
/// `description` is JSON: `{"message": "<full name>", "fields": [{"path": "<field>", "values":
/// [...]}, ...], "report_interval_ms": <n>}`. A path names a field, and a field inside a message
/// field as `holder.field`; an integer or enumeration field's values are integers or `{"range":
/// [low, high]}`, a string field's are strings. At most the build's `INSTANCE_KEY_FIELDS` fields,
/// and at most `INSTANCES_PER_MESSAGE` instances in the product of the lists.
///
/// `this_` holds the gravestone on every error. `refusal` may be null; when it is not, it holds the
/// gravestone on success and, on `_Z_ERR_CONFIG_INVALID_VALUE`, the reason, beginning `schema`
/// (why the bytes are refused), `description` or `storage`, or naming the limit exceeded.
///
/// Returns `Z_ERR_NULL` for a null `this_` or `description`, a null `bytes` with a length, or a
/// null `storage` with a `value_capacity`; `Z_EINVAL` for a description that is not UTF-8;
/// `_Z_ERR_CONFIG_INVALID_VALUE` for a schema, a description or storage that is refused; `Z_OK`
/// otherwise.
///
/// # Safety
/// `this_` is writable; `bytes` is null or readable for `len` bytes; `description` is null or a
/// NUL-terminated C string; `options` is null or valid, its `storage` writable for `storage_len`
/// bytes until the keyer is dropped and touched by nothing else meanwhile; `refusal` is null or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn zext_instance_keyer_from_descriptor_set(
    this_: *mut zext_owned_instance_keyer_t,
    bytes: *const u8,
    len: usize,
    description: *const c_char,
    options: *const zext_instance_keyer_options_t,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        clear_refusal(refusal);
        if this_.is_null() {
            return Z_ERR_NULL;
        }
        (*this_).handle = core::ptr::null_mut();
        if description.is_null() || (bytes.is_null() && len != 0) {
            return Z_ERR_NULL;
        }
        let Some(description) = utf8_arg(description) else {
            return Z_EINVAL;
        };
        let made = SchemaSet::from_descriptor_set(bytes_arg(bytes, len))
            .map_err(NewError::Schema)
            .and_then(|schema| Keyer::with_schema(schema, description, limits()));
        adopt_keyer(this_, made, options, refusal)
    })
}

/// A keyer of the message `description` names, over the `file_count` schema files `files` (every
/// one is read, with what it imports), made as `options` says (null: no last values). In a build
/// with `proto-text`, which links the text reader.
///
/// `description`, `this_` and `refusal` are as for [`zext_instance_keyer_from_descriptor_set`],
/// a schema refusal being the text reader's diagnostic: the file, the line and why.
///
/// Returns `Z_ERR_NULL` for a null `this_` or `description`, a null `files` with a count, a file
/// with a null name or text, or a null `storage` with a `value_capacity`; `Z_EINVAL` for text that
/// is not UTF-8; `_Z_ERR_CONFIG_INVALID_VALUE` for schema files, a description or storage that is
/// refused (too few bytes for every instance's room); `Z_OK` otherwise.
///
/// # Safety
/// `this_` is writable; `files` is null or readable for `file_count` entries, each holding
/// NUL-terminated C strings; `description` is null or a NUL-terminated C string; `options` is null
/// or valid, its `storage` writable for `storage_len` bytes until the keyer is dropped and touched
/// by nothing else meanwhile; `refusal` is null or writable.
#[cfg(feature = "proto-text")]
#[no_mangle]
pub unsafe extern "C" fn zext_instance_keyer_new(
    this_: *mut zext_owned_instance_keyer_t,
    files: *const zext_proto_file_t,
    file_count: usize,
    description: *const c_char,
    options: *const zext_instance_keyer_options_t,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        clear_refusal(refusal);
        if this_.is_null() {
            return Z_ERR_NULL;
        }
        (*this_).handle = core::ptr::null_mut();
        if description.is_null() {
            return Z_ERR_NULL;
        }
        let proto = match proto_files(files, file_count) {
            Ok(proto) => proto,
            Err(code) => return code,
        };
        let Some(description) = utf8_arg(description) else {
            return Z_EINVAL;
        };
        adopt_keyer(
            this_,
            Keyer::new(&proto, description, limits()),
            options,
            refusal,
        )
    })
}

/// How many instances the keyer's lists make, written to `out`: the streams a receiver or a sender
/// it is used with needs. `Z_ERR_NULL` for a null argument or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned keyer; `out` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn zext_instance_keyer_instances(
    this_: *const zext_loaned_instance_keyer_t,
    out: *mut usize,
) -> ZResult {
    guarded(|| {
        let Some(held) = behind::<Held>(word(this_)) else {
            return Z_ERR_NULL;
        };
        if out.is_null() {
            return Z_ERR_NULL;
        }
        *out = locked(held).keyer.instances();
        Z_OK
    })
}

/// The instance `payload`, received or about to be sent at `now_ms`, is, written to `out`. An
/// indexed payload becomes the instance's last value when the keyer keeps them; a payload of no
/// instance is counted, and `out` says why and whether it carries a report.
///
/// Returns `Z_OK` whatever `out` says; `Z_ERR_NULL` for a null keyer or `out`, the gravestone, or a
/// null payload with a length; `Z_EINVAL` for a `struct_size` short of the struct, nothing
/// written or counted then.
///
/// # Safety
/// `this_` is null or a loaned keyer; `payload` is readable for `len` bytes; `out` is null or a
/// struct of `struct_size` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn zext_instance_keyer_index(
    this_: *const zext_loaned_instance_keyer_t,
    payload: *const u8,
    len: usize,
    now_ms: u64,
    out: *mut zext_instance_key_t,
) -> ZResult {
    guarded(|| {
        let out = match Out::of(out) {
            Ok(out) => out,
            Err(code) => return code,
        };
        out.put(&zext_instance_key_t::default());
        let Some(held) = behind::<Held>(word(this_)) else {
            return Z_ERR_NULL;
        };
        if payload.is_null() && len != 0 {
            return Z_ERR_NULL;
        }
        let payload = bytes_arg(payload, len);
        let mut held = locked(held);
        let held = &mut *held;
        out.put(&match held.keyer.index(payload, now_ms) {
            Ok(instance) => {
                let last = match held.last.as_mut() {
                    None => ZEXT_INSTANCE_KEY_LAST_NOT_KEPT,
                    Some(store) => match store.record(instance, payload) {
                        Ok(()) => ZEXT_INSTANCE_KEY_LAST_RECORDED,
                        Err(_) => ZEXT_INSTANCE_KEY_LAST_TOO_LONG,
                    },
                };
                indexed(instance, last)
            }
            Err(drop) => dropped(drop),
        });
        Z_OK
    })
}

/// The report of the drops held since the last one, when the description's interval has passed at
/// `now_ms`: `true`, with `out` saying why the latest of them was dropped and how many there were.
/// `false`, with `out` zeroed, when none is due, and for a null argument or the gravestone; `false`
/// with nothing written or taken for a `struct_size` short of the struct.
///
/// # Safety
/// `this_` is null or a loaned keyer; `out` is null or a struct of `struct_size` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn zext_instance_keyer_flush(
    this_: *const zext_loaned_instance_keyer_t,
    now_ms: u64,
    out: *mut zext_instance_key_t,
) -> bool {
    guard_val(|| {
        let Ok(out) = Out::of(out) else {
            return false;
        };
        out.put(&zext_instance_key_t::default());
        let Some(held) = behind::<Held>(word(this_)) else {
            return false;
        };
        let Some(due) = locked(held).keyer.flush(now_ms) else {
            return false;
        };
        let mut key = zext_instance_key_t::default();
        refused(&mut key, due.latest);
        write_report(&mut key, due);
        out.put(&key);
        true
    })
}

/// How many samples were dropped, by reason. Any out may be null. `Z_ERR_NULL` for a null keyer or
/// the gravestone.
///
/// # Safety
/// `this_` is null or a loaned keyer; `undecodable`, `absent` and `not_listed` are null or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn zext_instance_keyer_counts(
    this_: *const zext_loaned_instance_keyer_t,
    undecodable: *mut u64,
    absent: *mut u64,
    not_listed: *mut u64,
) -> ZResult {
    guarded(|| {
        let Some(held) = behind::<Held>(word(this_)) else {
            return Z_ERR_NULL;
        };
        let counts = locked(held).keyer.counts();
        for (out, value) in [
            (undecodable, counts.undecodable),
            (absent, counts.absent),
            (not_listed, counts.not_listed),
        ] {
            if !out.is_null() {
                *out = value;
            }
        }
        Z_OK
    })
}

/// Copy the last value of `instance` into `out`, which has room for `capacity` bytes, and its
/// length into `len`.
///
/// Returns `Z_OK`; `Z_RES_CHANNEL_NODATA` when the instance has no value yet (`len` is 0);
/// `Z_ERR_OVERFLOW` when `capacity` is less than the value (`len` is its length, nothing is
/// copied); `Z_EINVAL` for an instance the keyer has not, or a keyer that keeps no last values;
/// `Z_ERR_NULL` for a null keyer or `len`, the gravestone, or a null `out` with a capacity.
///
/// # Safety
/// `this_` is null or a loaned keyer; `out` is writable for `capacity` bytes; `len` is null or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn zext_instance_keyer_last(
    this_: *const zext_loaned_instance_keyer_t,
    instance: usize,
    out: *mut u8,
    capacity: usize,
    len: *mut usize,
) -> ZResult {
    guarded(|| {
        let Some(held) = behind::<Held>(word(this_)) else {
            return Z_ERR_NULL;
        };
        if len.is_null() || (out.is_null() && capacity != 0) {
            return Z_ERR_NULL;
        }
        *len = 0;
        let held = locked(held);
        let Some(store) = held.last.as_ref() else {
            return Z_EINVAL;
        };
        if instance >= store.instances() {
            return Z_EINVAL;
        }
        let Some(value) = store.last(instance) else {
            return Z_RES_CHANNEL_NODATA;
        };
        *len = value.len();
        if value.len() > capacity {
            return Z_ERR_OVERFLOW;
        }
        if !value.is_empty() {
            core::ptr::copy_nonoverlapping(value.as_ptr(), out, value.len());
        }
        Z_OK
    })
}

/// Make `value` the last value of `instance`: the value a publisher sends before its first, or
/// one the program restores.
///
/// Returns `Z_OK`; `Z_ERR_OVERFLOW` for a value longer than an instance's room (the value before
/// is kept); `Z_EINVAL` for an instance the keyer has not, or a keyer that keeps no last values;
/// `Z_ERR_NULL` for a null keyer, the gravestone, or a null value with a length.
///
/// # Safety
/// `this_` is null or a loaned keyer; `value` is readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn zext_instance_keyer_set_last(
    this_: *const zext_loaned_instance_keyer_t,
    instance: usize,
    value: *const u8,
    len: usize,
) -> ZResult {
    guarded(|| {
        let Some(held) = behind::<Held>(word(this_)) else {
            return Z_ERR_NULL;
        };
        if value.is_null() && len != 0 {
            return Z_ERR_NULL;
        }
        let mut held = locked(held);
        let Some(store) = held.last.as_mut() else {
            return Z_EINVAL;
        };
        match store.record(instance, bytes_arg(value, len)) {
            Ok(()) => Z_OK,
            Err(wz_app_frame::instance_key::RecordError::TooLong { .. }) => Z_ERR_OVERFLOW,
            Err(wz_app_frame::instance_key::RecordError::NoSuchInstance { .. }) => Z_EINVAL,
        }
    })
}

/// Judge `frame`, received at `now_ms`, in `receiver`'s stream of the instance its payload is: the
/// payload is what follows the receiver's header. `key` says which instance, or why none; `verdict`
/// is the receiver's, and zeroed when the frame was dropped, which moves no state of the receiver.
/// The payload of an intact frame becomes its instance's last value when the keyer keeps them.
///
/// Returns `Z_OK` whatever `key` and `verdict` say; `_Z_ERR_CONFIG_INVALID_VALUE` for a receiver
/// that keeps its streams per sender (instance keys and sender slots are exclusive on one message)
/// or keeps fewer streams than the keyer has instances; `Z_EINVAL` for a frame the receiver cannot
/// judge (a counter of another profile's width), and for a `struct_size` of `key` or `verdict`
/// short of its struct, neither written then; `Z_ERR_NULL` for a null keyer, receiver, `key` or
/// `verdict`, the gravestone, or a null frame with a length. A call that does not return `Z_OK`
/// counts nothing.
///
/// # Safety
/// `this_` is null or a loaned keyer; `receiver` is null or a loaned receiver; `frame` is readable
/// for `len` bytes; `key` and `verdict` are null or structs of their `struct_size` writable
/// bytes.
#[cfg(feature = "e2e-receiver")]
#[no_mangle]
pub unsafe extern "C" fn zext_instance_keyer_judge(
    this_: *const zext_loaned_instance_keyer_t,
    receiver: *const crate::e2e_receiver::zext_loaned_e2e_receiver_t,
    frame: *const u8,
    len: usize,
    now_ms: u64,
    key: *mut zext_instance_key_t,
    verdict: *mut crate::e2e_receiver::zext_e2e_verdict_t,
) -> ZResult {
    use wz_app_frame::e2e_receiver::Receiver;
    use wz_app_frame::instance_key::{judge, JudgeError, Judged, LastOutcome};

    guarded(|| {
        let (key, verdict) = match (Out::of(key), Out::of(verdict)) {
            (Ok(key), Ok(verdict)) => (key, verdict),
            (Err(code), _) | (_, Err(code)) => return code,
        };
        key.put(&zext_instance_key_t::default());
        verdict.put(&crate::e2e_receiver::zext_e2e_verdict_t::default());
        let Some(held) = behind::<Held>(word(this_)) else {
            return Z_ERR_NULL;
        };
        let Some(rx) = behind::<Receiver>(receiver.cast::<*mut c_void>()) else {
            return Z_ERR_NULL;
        };
        if frame.is_null() && len != 0 {
            return Z_ERR_NULL;
        }
        let mut held = locked(held);
        let held = &mut *held;
        let mut rx = locked(rx);
        match judge(
            &mut held.keyer,
            &mut rx,
            held.last.as_mut(),
            bytes_arg(frame, len),
            now_ms,
        ) {
            Ok(Judged::Instance {
                instance,
                verdict: judged,
                last,
            }) => {
                let last = match last {
                    LastOutcome::Recorded => ZEXT_INSTANCE_KEY_LAST_RECORDED,
                    LastOutcome::NotIntact => ZEXT_INSTANCE_KEY_LAST_NOT_INTACT,
                    LastOutcome::TooLong { .. } => ZEXT_INSTANCE_KEY_LAST_TOO_LONG,
                    LastOutcome::NotKept => ZEXT_INSTANCE_KEY_LAST_NOT_KEPT,
                };
                key.put(&indexed(instance, last));
                verdict.put(&crate::e2e_receiver::to_c(&judged));
                Z_OK
            }
            Ok(Judged::Dropped(drop)) => {
                key.put(&dropped(drop));
                Z_OK
            }
            Err(
                JudgeError::SenderKeyed
                | JudgeError::TooFewStreams { .. }
                | JudgeError::TooFewLastValues { .. },
            ) => Z_ERR_CONFIG_INVALID_VALUE,
            Err(JudgeError::Receive(_)) => Z_EINVAL,
        }
    })
}

/// Protect `payload`, about to be sent at `now_ms`, on `sender`'s counter stream of the instance it
/// is: the frame, written to `out`, which has room for `capacity` bytes, with its length in
/// `written` and the counter it carries in `counter` (which may be null). `key` says which
/// instance, or why none. An indexed payload becomes the instance's last value when the keyer keeps
/// them.
///
/// Returns `Z_OK`; `Z_EINVAL` when the payload is no instance of the keyer (`key` says why; it was
/// counted, no frame was built and no counter value consumed) or the sender refuses the frame, and
/// for a `struct_size` of `key` short of its struct, nothing written then; `Z_ERR_OVERFLOW` when `capacity` is less than the frame (`zext_e2e_sender_frame_size`);
/// `_Z_ERR_CONFIG_INVALID_VALUE` for a sender that keeps fewer streams than the keyer has
/// instances; `Z_ERR_NULL` for a null keyer, sender, `out`, `written` or `key`, the gravestone, or
/// a null payload with a length. A call that does not return `Z_OK` writes nothing to `out`.
///
/// # Safety
/// `this_` is null or a loaned keyer; `sender` is null or a loaned sender; `payload` is readable
/// for `len` bytes; `out` is writable for `capacity` bytes; `written` and `counter` are null or
/// writable; `key` is null or a struct of `struct_size` writable bytes.
#[cfg(feature = "e2e-sender")]
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn zext_instance_keyer_protect(
    this_: *const zext_loaned_instance_keyer_t,
    sender: *const crate::e2e_sender::zext_loaned_e2e_sender_t,
    payload: *const u8,
    len: usize,
    now_ms: u64,
    out: *mut u8,
    capacity: usize,
    written: *mut usize,
    counter: *mut u64,
    key: *mut zext_instance_key_t,
) -> ZResult {
    use wz_app_frame::e2e_stream_sender::StreamSender;
    use wz_app_frame::instance_key::{protect_into, KeyedWritten, ProtectError};

    guarded(|| {
        if written.is_null() {
            return Z_ERR_NULL;
        }
        let key = match Out::of(key) {
            Ok(key) => key,
            Err(code) => return code,
        };
        key.put(&zext_instance_key_t::default());
        *written = 0;
        let Some(held) = behind::<Held>(word(this_)) else {
            return Z_ERR_NULL;
        };
        let Some(tx) = behind::<StreamSender>(sender.cast::<*mut c_void>()) else {
            return Z_ERR_NULL;
        };
        if out.is_null() || (payload.is_null() && len != 0) {
            return Z_ERR_NULL;
        }
        let payload = bytes_arg(payload, len);
        let mut held = locked(held);
        let held = &mut *held;
        let mut tx = locked(tx);
        if capacity < tx.frame_bytes(len) {
            return Z_ERR_OVERFLOW;
        }
        // The frame is written where the program asked for it, by the sender itself: nothing is
        // built apart and copied.
        let out = core::slice::from_raw_parts_mut(out, capacity);
        match protect_into(&mut held.keyer, &mut tx, payload, now_ms, out) {
            Ok(KeyedWritten::Built {
                instance,
                written: frame,
            }) => {
                *written = frame.len;
                if !counter.is_null() {
                    *counter = frame.counter;
                }
                let last = match held.last.as_mut() {
                    None => ZEXT_INSTANCE_KEY_LAST_NOT_KEPT,
                    Some(store) => match store.record(instance, payload) {
                        Ok(()) => ZEXT_INSTANCE_KEY_LAST_RECORDED,
                        Err(_) => ZEXT_INSTANCE_KEY_LAST_TOO_LONG,
                    },
                };
                key.put(&indexed(instance, last));
                Z_OK
            }
            Ok(KeyedWritten::Dropped(drop)) => {
                key.put(&dropped(drop));
                Z_EINVAL
            }
            Err(ProtectError::TooFewStreams { .. }) => Z_ERR_CONFIG_INVALID_VALUE,
            Err(ProtectError::Send(_)) => Z_EINVAL,
        }
    })
}

/// Borrow a keyer. The loaned form has the owned layout, so this is a pointer cast.
///
/// # Safety
/// `this_` is null or an owned keyer.
#[no_mangle]
pub unsafe extern "C" fn zext_instance_keyer_loan(
    this_: *const zext_owned_instance_keyer_t,
) -> *const zext_loaned_instance_keyer_t {
    this_.cast::<zext_loaned_instance_keyer_t>()
}

/// The moved form of a keyer, for `zext_instance_keyer_drop`: a cast, which nulls nothing.
///
/// # Safety
/// `this_` is null or an owned keyer.
#[no_mangle]
pub unsafe extern "C" fn zext_instance_keyer_move(
    this_: *mut zext_owned_instance_keyer_t,
) -> *mut zext_moved_instance_keyer_t {
    this_.cast::<zext_moved_instance_keyer_t>()
}

/// Release a keyer and leave the gravestone; the storage of its last values is the program's
/// again once this returns. A second drop, and a drop of the gravestone, do nothing.
///
/// # Safety
/// `this_` is null or a moved keyer.
#[no_mangle]
pub unsafe extern "C" fn zext_instance_keyer_drop(this_: *mut zext_moved_instance_keyer_t) {
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
pub unsafe extern "C" fn zext_internal_instance_keyer_null(
    this_: *mut zext_owned_instance_keyer_t,
) {
    if !this_.is_null() {
        (*this_).handle = core::ptr::null_mut();
    }
}

/// Whether the slot holds a keyer.
///
/// # Safety
/// `this_` is null or an owned keyer.
#[no_mangle]
pub unsafe extern "C" fn zext_internal_instance_keyer_check(
    this_: *const zext_owned_instance_keyer_t,
) -> bool {
    guard_val(|| !this_.is_null() && !(*this_).handle.is_null())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sized::a_short_struct_is_refused_untouched;

    /// Every door that writes what became of a sample refuses, untouched, a struct a byte short of
    /// its own, before the keyer is read. Turned red by a write before the size is read.
    #[test]
    fn a_key_short_of_its_struct_is_refused_untouched() {
        a_short_struct_is_refused_untouched::<zext_instance_key_t, _>(
            |out| {
                // SAFETY: `out` is a live struct of this build's size; no keyer is named.
                unsafe {
                    zext_instance_keyer_index(core::ptr::null(), core::ptr::null(), 0, 0, out)
                }
            },
            Z_EINVAL,
        );
        a_short_struct_is_refused_untouched::<zext_instance_key_t, _>(
            |out| {
                // SAFETY: as above.
                unsafe { zext_instance_keyer_flush(core::ptr::null(), 0, out) }
            },
            false,
        );
    }

    /// The judging door writes neither struct when either is short, the other left as it was.
    #[cfg(feature = "e2e-receiver")]
    #[test]
    fn a_judgement_with_a_short_struct_writes_neither() {
        use crate::e2e_receiver::zext_e2e_verdict_t;
        let mut verdict = zext_e2e_verdict_t {
            counter: 7,
            ..zext_e2e_verdict_t::default()
        };
        a_short_struct_is_refused_untouched::<zext_instance_key_t, _>(
            |key| {
                // SAFETY: both structs are live; no keyer, receiver or frame is named.
                unsafe {
                    zext_instance_keyer_judge(
                        core::ptr::null(),
                        core::ptr::null(),
                        core::ptr::null(),
                        0,
                        0,
                        key,
                        &mut verdict,
                    )
                }
            },
            Z_EINVAL,
        );
        assert_eq!(
            verdict.counter, 7,
            "the full verdict was not written either"
        );
        let mut key = zext_instance_key_t {
            field: 7,
            ..zext_instance_key_t::default()
        };
        a_short_struct_is_refused_untouched::<zext_e2e_verdict_t, _>(
            |verdict| {
                // SAFETY: as above.
                unsafe {
                    zext_instance_keyer_judge(
                        core::ptr::null(),
                        core::ptr::null(),
                        core::ptr::null(),
                        0,
                        0,
                        &mut key,
                        verdict,
                    )
                }
            },
            Z_EINVAL,
        );
        assert_eq!(key.field, 7, "the full key was not written either");
    }

    /// The protecting door refuses a short key before it writes the length or the key.
    #[cfg(feature = "e2e-sender")]
    #[test]
    fn a_protection_with_a_short_key_writes_nothing() {
        let mut written = 7usize;
        let mut frame = [0u8; 4];
        a_short_struct_is_refused_untouched::<zext_instance_key_t, _>(
            |key| {
                // SAFETY: every pointer is a live local or null; no keyer or sender is named.
                unsafe {
                    zext_instance_keyer_protect(
                        core::ptr::null(),
                        core::ptr::null(),
                        core::ptr::null(),
                        0,
                        0,
                        frame.as_mut_ptr(),
                        frame.len(),
                        &mut written,
                        core::ptr::null_mut(),
                        key,
                    )
                }
            },
            Z_EINVAL,
        );
        assert_eq!(written, 7, "the length was not written");
    }
}
