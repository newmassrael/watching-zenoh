// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_instance_keyer_*`: which instance of a message a sample is, read from fields of its
//! payload through the message's schema, from C.
//!
//! A keyer is made over the program's `.proto` files and a description of the key fields and the
//! values each may take; the position of a sample's values in the product of those lists is its
//! instance. With `e2e-receiver` the judging door judges a frame in the receiver's stream of the
//! instance its payload is, and with `e2e-sender` the protecting door protects a payload on the
//! sender's counter stream of its instance. A sample of no instance is dropped, counted by reason,
//! and reported at the rate the description states; with `event-ring` each report is also an
//! event of the node's log (`WZ_EXT_EVENT_SOURCE_INSTANCE_KEY_DROPPED`). The last value of each
//! instance is kept in storage the program gives when it makes the keyer.
//!
//! A door wz has and zenoh-pico does not, so each is `wz_ext_*`, declared in `wz_ext.h`, and part
//! of the unstable surface: the `instance-key` capability implies `unstable-api`. The keyer is
//! [`wz_app_frame::instance_key`]; ownership and threads are as `crate::e2e` describes. The
//! judging and protecting doors hold the keyer's lock and then the receiver's or the sender's, and
//! no door takes them the other way round.

use core::ffi::{c_char, c_void};
use core::ptr::NonNull;

use wz_app_frame::instance_key::{Dropped, Keyer, LastValues, Limits, Refusal, Report};
use wz_app_frame::proto_schema::ProtoFile;

use crate::abi::z_owned_string_t;
use crate::e2e::{
    adopt, behind, bytes_arg, clear_refusal, locked, release, utf8_arg, write_refusal,
};
use crate::ffi::{guard_val, guarded};
use crate::result::{
    ZResult, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_NULL, Z_ERR_OVERFLOW, Z_OK,
    Z_RES_CHANNEL_NODATA,
};

/// The sample is an instance: `instance` is its index.
pub const WZ_EXT_INSTANCE_KEY_INDEXED: u8 = 0;
/// The payload is not a message of the schema, or the frame is shorter than its header.
pub const WZ_EXT_INSTANCE_KEY_UNDECODABLE: u8 = 1;
/// A key field that has presence is not in the payload: `field` says which.
pub const WZ_EXT_INSTANCE_KEY_ABSENT: u8 = 2;
/// A key value is in no list: `field` says which.
pub const WZ_EXT_INSTANCE_KEY_NOT_LISTED: u8 = 3;

/// No last values are kept, or the sample was dropped.
pub const WZ_EXT_INSTANCE_KEY_LAST_NOT_KEPT: u8 = 0;
/// The payload is now the instance's last value.
pub const WZ_EXT_INSTANCE_KEY_LAST_RECORDED: u8 = 1;
/// The frame is not intact, so the instance's last value is the one before.
pub const WZ_EXT_INSTANCE_KEY_LAST_NOT_INTACT: u8 = 2;
/// The payload is longer than an instance's room, so its last value is the one before.
pub const WZ_EXT_INSTANCE_KEY_LAST_TOO_LONG: u8 = 3;

/// One `.proto` file, as the program hands it over: the name other files import it by and its
/// text, both NUL-terminated UTF-8, BORROWED for the call.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct wz_ext_proto_file_t {
    pub name: *const c_char,
    pub text: *const c_char,
}

/// An owned keyer: the handle in its one word, null for the gravestone. `Debug` shows the word,
/// so a test can unwrap the refusal of a door that answers one or the other.
#[repr(C)]
#[derive(Debug)]
pub struct wz_ext_owned_instance_keyer_t {
    pub(crate) handle: *mut c_void,
}

/// A loaned keyer: the owned layout, so the loan is a pointer cast.
#[repr(C)]
pub struct wz_ext_loaned_instance_keyer_t {
    pub(crate) handle: *mut c_void,
}

/// A moved keyer (pico's `z_moved_*_t` shape).
#[repr(C)]
pub struct wz_ext_moved_instance_keyer_t {
    pub(crate) _this: wz_ext_owned_instance_keyer_t,
}

/// How a keyer is made.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct wz_ext_instance_keyer_options_t {
    /// The storage of the last values: `value_capacity` bytes for each instance, the first
    /// instance's first. The PROGRAM's, and it must stay valid and untouched until the keyer is
    /// dropped. Read only when `value_capacity` is not 0.
    pub storage: *mut u8,
    /// How many bytes `storage` has.
    pub storage_len: usize,
    /// The room each instance's last value has; 0 keeps no last values.
    pub value_capacity: usize,
}

impl Default for wz_ext_instance_keyer_options_t {
    fn default() -> Self {
        Self {
            storage: core::ptr::null_mut(),
            storage_len: 0,
            value_capacity: 0,
        }
    }
}

/// What became of one sample, as C reads it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct wz_ext_instance_key_t {
    /// A `WZ_EXT_INSTANCE_KEY_*` status.
    pub status: u8,
    /// 1 when this drop carries the report of the drops since the last one (`dropped`).
    pub reported: u8,
    /// A `WZ_EXT_INSTANCE_KEY_LAST_*` value: what became of the instance's last value.
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

/// The program's storage of the last values.
struct CallerStorage {
    ptr: NonNull<u8>,
    len: usize,
}

impl AsRef<[u8]> for CallerStorage {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: `wz_ext_instance_keyer_new`'s contract: `storage` is writable for `storage_len`
        // bytes until the keyer is dropped, and only the keyer, under its lock, touches it.
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
fn word(this_: *const wz_ext_loaned_instance_keyer_t) -> *const *mut c_void {
    this_.cast::<*mut c_void>()
}

/// Write `refusal`'s status and field into `out`.
fn refused(out: &mut wz_ext_instance_key_t, refusal: Refusal) {
    let (status, field) = match refusal {
        Refusal::Undecodable => (WZ_EXT_INSTANCE_KEY_UNDECODABLE, 0),
        Refusal::Absent { field } => (WZ_EXT_INSTANCE_KEY_ABSENT, field),
        Refusal::NotListed { field } => (WZ_EXT_INSTANCE_KEY_NOT_LISTED, field),
    };
    out.status = status;
    out.field = u32::try_from(field).unwrap_or(u32::MAX);
}

/// Write a report into `out`, and into the node's event log in a build that has one.
fn write_report(out: &mut wz_ext_instance_key_t, due: Report) {
    out.reported = 1;
    out.dropped = due.dropped;
    #[cfg(feature = "event-ring")]
    {
        use crate::event_log::{
            wz_ext_event_emit, WZ_EXT_EVENT_INSTANCE_KEY_ABSENT,
            WZ_EXT_EVENT_INSTANCE_KEY_NOT_LISTED, WZ_EXT_EVENT_INSTANCE_KEY_UNDECODABLE,
            WZ_EXT_EVENT_LEVEL_LIBRARY, WZ_EXT_EVENT_SOURCE_INSTANCE_KEY_DROPPED,
        };
        let (why, field) = match due.latest {
            Refusal::Undecodable => (WZ_EXT_EVENT_INSTANCE_KEY_UNDECODABLE, 0),
            Refusal::Absent { field } => (WZ_EXT_EVENT_INSTANCE_KEY_ABSENT, field),
            Refusal::NotListed { field } => (WZ_EXT_EVENT_INSTANCE_KEY_NOT_LISTED, field),
        };
        let args = [why, u64::try_from(field).unwrap_or(u64::MAX), due.dropped];
        // A full log under `drop-newest` refuses the report and counts it, as it does any event;
        // the keyer's own count in `out` stands either way.
        // SAFETY: `args` is readable for its length for the call.
        let _ = unsafe {
            wz_ext_event_emit(
                WZ_EXT_EVENT_LEVEL_LIBRARY,
                WZ_EXT_EVENT_SOURCE_INSTANCE_KEY_DROPPED,
                args.as_ptr(),
                args.len(),
            )
        };
    }
}

/// The C form of a drop.
fn dropped(sample: Dropped) -> wz_ext_instance_key_t {
    let mut out = wz_ext_instance_key_t::default();
    refused(&mut out, sample.refusal);
    if let Some(due) = sample.report {
        write_report(&mut out, due);
    }
    out
}

/// The C form of a sample indexed as `instance`.
fn indexed(instance: usize, last: u8) -> wz_ext_instance_key_t {
    wz_ext_instance_key_t {
        status: WZ_EXT_INSTANCE_KEY_INDEXED,
        last,
        instance,
        ..wz_ext_instance_key_t::default()
    }
}

/// Fill in the default keyer options: no last values.
///
/// # Safety
/// `this_` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_instance_keyer_options_default(
    this_: *mut wz_ext_instance_keyer_options_t,
) {
    if !this_.is_null() {
        *this_ = wz_ext_instance_keyer_options_t::default();
    }
}

/// A keyer of the message `description` names, over the `file_count` schema files `files` (every
/// one is read, with what it imports), made as `options` says (null: no last values).
///
/// `description` is JSON: `{"message": "<full name>", "fields": [{"path": "<field>", "values":
/// [...]}, ...], "report_interval_ms": <n>}`. A path names a field, and a field inside a message
/// field as `holder.field`; an integer or enumeration field's values are integers or `{"range":
/// [low, high]}`, a string field's are strings. At most the build's `INSTANCE_KEY_FIELDS` fields,
/// and at most `INSTANCES_PER_MESSAGE` instances in the product of the lists.
///
/// `this_` holds the gravestone on every error. `refusal` may be null; when it is not, it holds the
/// gravestone on success and, on `_Z_ERR_CONFIG_INVALID_VALUE`, the reason, beginning `schema`,
/// `description` or `storage`, or naming the limit exceeded.
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
#[no_mangle]
pub unsafe extern "C" fn wz_ext_instance_keyer_new(
    this_: *mut wz_ext_owned_instance_keyer_t,
    files: *const wz_ext_proto_file_t,
    file_count: usize,
    description: *const c_char,
    options: *const wz_ext_instance_keyer_options_t,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        clear_refusal(refusal);
        if this_.is_null() {
            return Z_ERR_NULL;
        }
        (*this_).handle = core::ptr::null_mut();
        if description.is_null() || (files.is_null() && file_count != 0) {
            return Z_ERR_NULL;
        }
        let given: &[wz_ext_proto_file_t] = if file_count == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(files, file_count)
        };
        let mut proto: Vec<ProtoFile<'_>> = Vec::with_capacity(given.len());
        for file in given {
            if file.name.is_null() || file.text.is_null() {
                return Z_ERR_NULL;
            }
            let (Some(name), Some(text)) = (utf8_arg(file.name), utf8_arg(file.text)) else {
                return Z_EINVAL;
            };
            proto.push(ProtoFile {
                name,
                text: text.as_bytes(),
            });
        }
        let Some(description) = utf8_arg(description) else {
            return Z_EINVAL;
        };
        let options = if options.is_null() {
            wz_ext_instance_keyer_options_t::default()
        } else {
            *options
        };
        let limits = Limits {
            fields: wz_session_core::caps::INSTANCE_KEY_FIELDS,
            instances: wz_session_core::caps::INSTANCES_PER_MESSAGE,
        };
        let keyer = match Keyer::new(&proto, description, limits) {
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
    })
}

/// How many instances the keyer's lists make, written to `out`: the streams a receiver or a sender
/// it is used with needs. `Z_ERR_NULL` for a null argument or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned keyer; `out` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_instance_keyer_instances(
    this_: *const wz_ext_loaned_instance_keyer_t,
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
/// null payload with a length.
///
/// # Safety
/// `this_` is null or a loaned keyer; `payload` is readable for `len` bytes; `out` is null or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_instance_keyer_index(
    this_: *const wz_ext_loaned_instance_keyer_t,
    payload: *const u8,
    len: usize,
    now_ms: u64,
    out: *mut wz_ext_instance_key_t,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ERR_NULL;
        }
        *out = wz_ext_instance_key_t::default();
        let Some(held) = behind::<Held>(word(this_)) else {
            return Z_ERR_NULL;
        };
        if payload.is_null() && len != 0 {
            return Z_ERR_NULL;
        }
        let payload = bytes_arg(payload, len);
        let mut held = locked(held);
        let held = &mut *held;
        *out = match held.keyer.index(payload, now_ms) {
            Ok(instance) => {
                let last = match held.last.as_mut() {
                    None => WZ_EXT_INSTANCE_KEY_LAST_NOT_KEPT,
                    Some(store) => match store.record(instance, payload) {
                        Ok(()) => WZ_EXT_INSTANCE_KEY_LAST_RECORDED,
                        Err(_) => WZ_EXT_INSTANCE_KEY_LAST_TOO_LONG,
                    },
                };
                indexed(instance, last)
            }
            Err(drop) => dropped(drop),
        };
        Z_OK
    })
}

/// The report of the drops held since the last one, when the description's interval has passed at
/// `now_ms`: `true`, with `out` saying why the latest of them was dropped and how many there were.
/// `false`, with `out` zeroed, when none is due, and for a null argument or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned keyer; `out` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_instance_keyer_flush(
    this_: *const wz_ext_loaned_instance_keyer_t,
    now_ms: u64,
    out: *mut wz_ext_instance_key_t,
) -> bool {
    guard_val(false, || {
        if out.is_null() {
            return false;
        }
        *out = wz_ext_instance_key_t::default();
        let Some(held) = behind::<Held>(word(this_)) else {
            return false;
        };
        let Some(due) = locked(held).keyer.flush(now_ms) else {
            return false;
        };
        let mut key = wz_ext_instance_key_t::default();
        refused(&mut key, due.latest);
        write_report(&mut key, due);
        *out = key;
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
pub unsafe extern "C" fn wz_ext_instance_keyer_counts(
    this_: *const wz_ext_loaned_instance_keyer_t,
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
pub unsafe extern "C" fn wz_ext_instance_keyer_last(
    this_: *const wz_ext_loaned_instance_keyer_t,
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
pub unsafe extern "C" fn wz_ext_instance_keyer_set_last(
    this_: *const wz_ext_loaned_instance_keyer_t,
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
/// judge (a counter of another profile's width); `Z_ERR_NULL` for a null keyer, receiver, `key` or
/// `verdict`, the gravestone, or a null frame with a length. A call that does not return `Z_OK`
/// counts nothing.
///
/// # Safety
/// `this_` is null or a loaned keyer; `receiver` is null or a loaned receiver; `frame` is readable
/// for `len` bytes; `key` and `verdict` are null or writable.
#[cfg(feature = "e2e-receiver")]
#[no_mangle]
pub unsafe extern "C" fn wz_ext_instance_keyer_judge(
    this_: *const wz_ext_loaned_instance_keyer_t,
    receiver: *const crate::e2e_receiver::wz_ext_loaned_e2e_receiver_t,
    frame: *const u8,
    len: usize,
    now_ms: u64,
    key: *mut wz_ext_instance_key_t,
    verdict: *mut crate::e2e_receiver::wz_ext_e2e_verdict_t,
) -> ZResult {
    use wz_app_frame::e2e_receiver::Receiver;
    use wz_app_frame::instance_key::{judge, JudgeError, Judged, LastOutcome};

    guarded(|| {
        if key.is_null() || verdict.is_null() {
            return Z_ERR_NULL;
        }
        *key = wz_ext_instance_key_t::default();
        *verdict = crate::e2e_receiver::wz_ext_e2e_verdict_t::default();
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
                    LastOutcome::Recorded => WZ_EXT_INSTANCE_KEY_LAST_RECORDED,
                    LastOutcome::NotIntact => WZ_EXT_INSTANCE_KEY_LAST_NOT_INTACT,
                    LastOutcome::TooLong { .. } => WZ_EXT_INSTANCE_KEY_LAST_TOO_LONG,
                    LastOutcome::NotKept => WZ_EXT_INSTANCE_KEY_LAST_NOT_KEPT,
                };
                *key = indexed(instance, last);
                *verdict = crate::e2e_receiver::to_c(&judged);
                Z_OK
            }
            Ok(Judged::Dropped(drop)) => {
                *key = dropped(drop);
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
/// counted, no frame was built and no counter value consumed) or the sender refuses the frame;
/// `Z_ERR_OVERFLOW` when `capacity` is less than the frame (`wz_ext_e2e_sender_frame_size`);
/// `_Z_ERR_CONFIG_INVALID_VALUE` for a sender that keeps fewer streams than the keyer has
/// instances; `Z_ERR_NULL` for a null keyer, sender, `out`, `written` or `key`, the gravestone, or
/// a null payload with a length. A call that does not return `Z_OK` writes nothing to `out`.
///
/// # Safety
/// `this_` is null or a loaned keyer; `sender` is null or a loaned sender; `payload` is readable
/// for `len` bytes; `out` is writable for `capacity` bytes; `written`, `counter` and `key` are null
/// or writable.
#[cfg(feature = "e2e-sender")]
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn wz_ext_instance_keyer_protect(
    this_: *const wz_ext_loaned_instance_keyer_t,
    sender: *const crate::e2e_sender::wz_ext_loaned_e2e_sender_t,
    payload: *const u8,
    len: usize,
    now_ms: u64,
    out: *mut u8,
    capacity: usize,
    written: *mut usize,
    counter: *mut u64,
    key: *mut wz_ext_instance_key_t,
) -> ZResult {
    use wz_app_frame::e2e_stream_sender::StreamSender;
    use wz_app_frame::instance_key::{protect, KeyedFrame, ProtectError};

    guarded(|| {
        if key.is_null() || written.is_null() {
            return Z_ERR_NULL;
        }
        *key = wz_ext_instance_key_t::default();
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
        match protect(&mut held.keyer, &mut tx, payload, now_ms) {
            Ok(KeyedFrame::Built { instance, frame }) => {
                core::ptr::copy_nonoverlapping(frame.bytes.as_ptr(), out, frame.bytes.len());
                *written = frame.bytes.len();
                if !counter.is_null() {
                    *counter = frame.counter;
                }
                let last = match held.last.as_mut() {
                    None => WZ_EXT_INSTANCE_KEY_LAST_NOT_KEPT,
                    Some(store) => match store.record(instance, payload) {
                        Ok(()) => WZ_EXT_INSTANCE_KEY_LAST_RECORDED,
                        Err(_) => WZ_EXT_INSTANCE_KEY_LAST_TOO_LONG,
                    },
                };
                *key = indexed(instance, last);
                Z_OK
            }
            Ok(KeyedFrame::Dropped(drop)) => {
                *key = dropped(drop);
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
pub unsafe extern "C" fn wz_ext_instance_keyer_loan(
    this_: *const wz_ext_owned_instance_keyer_t,
) -> *const wz_ext_loaned_instance_keyer_t {
    this_.cast::<wz_ext_loaned_instance_keyer_t>()
}

/// The moved form of a keyer, for `wz_ext_instance_keyer_drop`: a cast, which nulls nothing.
///
/// # Safety
/// `this_` is null or an owned keyer.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_instance_keyer_move(
    this_: *mut wz_ext_owned_instance_keyer_t,
) -> *mut wz_ext_moved_instance_keyer_t {
    this_.cast::<wz_ext_moved_instance_keyer_t>()
}

/// Release a keyer and leave the gravestone; the storage of its last values is the program's
/// again once this returns. A second drop, and a drop of the gravestone, do nothing.
///
/// # Safety
/// `this_` is null or a moved keyer.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_instance_keyer_drop(this_: *mut wz_ext_moved_instance_keyer_t) {
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
pub unsafe extern "C" fn wz_ext_internal_instance_keyer_null(
    this_: *mut wz_ext_owned_instance_keyer_t,
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
pub unsafe extern "C" fn wz_ext_internal_instance_keyer_check(
    this_: *const wz_ext_owned_instance_keyer_t,
) -> bool {
    guard_val(false, || !this_.is_null() && !(*this_).handle.is_null())
}
