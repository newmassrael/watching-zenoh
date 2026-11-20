// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_message_catalog_*`: a deployment's MESSAGE CATALOG, from C. The program hands over the
//! catalog's JSON5 text once; the library reads and judges it and answers, per message, its entry
//! (key expression, id, period, replay depth, supervision) and the pieces the other doors are made
//! from: an e2e sender for a node that publishes it, an e2e receiver for one that subscribes, and
//! the rows of a reception supervisor. One library serves every deployment whose catalog it is
//! given; the catalog, not the build, says which messages exist.
//!
//! A door wz has and zenoh-pico does not, so each is `wz_ext_*`, declared in `wz_ext.h`, and part
//! of the unstable surface: the `message-catalog` capability implies `unstable-api`. The doors that
//! make a sender, a receiver or supervision rows are in a build that also has `e2e-sender`,
//! `e2e-receiver` or `e2e-supervision`, and hand back the same handles those capabilities' own
//! doors make. The reader is [`wz_app_frame::message_catalog`].
//!
//! # Ownership and threads
//!
//! `_new` makes an owned catalog, every door that reads it takes the loan, and `_drop` releases
//! it and leaves the gravestone. A catalog does not change once it is read, so any number of
//! threads may read one at once. A message and a node are named by their index: the place of the
//! message in the catalog's `messages` and of the node in its `nodes`.

use core::ffi::{c_char, c_void, CStr};
use std::ffi::CString;

use wz_app_frame::message_catalog::{build_limits, Catalog};

use crate::abi::z_owned_string_t;
use crate::bytes::{z_internal_string_null, z_string_copy_from_substr};
use crate::ffi::{guard_val, guarded};
use crate::result::{
    ZResult, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_INVALID, Z_ERR_NULL, Z_OK,
};

#[cfg(any(
    feature = "e2e-sender",
    feature = "e2e-receiver",
    feature = "e2e-supervision"
))]
use wz_app_frame::message_catalog::HandleError;

/// The node publishes the message.
pub const WZ_EXT_MESSAGE_PUBLISHES: u8 = 1;
/// The node subscribes to the message.
pub const WZ_EXT_MESSAGE_SUBSCRIBES: u8 = 2;

/// The bits of `has`: what a message's entry states.
pub const WZ_EXT_MESSAGE_HAS_PERIOD: u8 = 1;
pub const WZ_EXT_MESSAGE_HAS_PROTECTION: u8 = 2;
pub const WZ_EXT_MESSAGE_HAS_SENDERS: u8 = 4;
pub const WZ_EXT_MESSAGE_HAS_INSTANCE_KEY: u8 = 8;
pub const WZ_EXT_MESSAGE_HAS_REPLAY: u8 = 16;
pub const WZ_EXT_MESSAGE_HAS_SUPERVISION: u8 = 32;
pub const WZ_EXT_MESSAGE_HAS_SEGMENT_PROFILE: u8 = 64;

/// An owned catalog: the handle in its one word, null for the gravestone. `Debug` shows the word,
/// so a test can unwrap the refusal of a door that answers one or the other.
#[repr(C)]
#[derive(Debug)]
pub struct wz_ext_owned_message_catalog_t {
    pub(crate) handle: *mut c_void,
}

/// A loaned catalog: the owned layout, so the loan is a pointer cast.
#[repr(C)]
pub struct wz_ext_loaned_message_catalog_t {
    pub(crate) handle: *mut c_void,
}

/// A moved catalog (pico's `z_moved_*_t` shape).
#[repr(C)]
pub struct wz_ext_moved_message_catalog_t {
    pub(crate) _this: wz_ext_owned_message_catalog_t,
}

/// One message's entry, as C reads it. A number whose `has` bit is clear is 0.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct wz_ext_message_entry_t {
    /// The literal key the message is put on, NUL-terminated, valid while the catalog lives.
    pub key_expr: *const c_char,
    /// Its id.
    pub id: u32,
    /// Its period in milliseconds; 0 for a message sent on an event.
    pub period_ms: u32,
    /// How many of its last frames a publisher keeps; 0 for no replay.
    pub replay_depth: u32,
    /// How many periods a stream may miss; 0 when its reception is not supervised.
    pub supervision_factor: u16,
    /// The `WZ_EXT_MESSAGE_HAS_*` bits.
    pub has: u8,
    /// 1 when a supervised stream can be lost before its first reception.
    pub supervision_awaited: u8,
    /// How many senders a receiver binds its slots to; 0 for one stream.
    pub senders: u32,
    pub reserved: u32,
}

impl Default for wz_ext_message_entry_t {
    fn default() -> Self {
        Self {
            key_expr: core::ptr::null(),
            id: 0,
            period_ms: 0,
            replay_depth: 0,
            supervision_factor: 0,
            has: 0,
            supervision_awaited: 0,
            senders: 0,
            reserved: 0,
        }
    }
}

/// What a catalog handle holds: the catalog, and each message's key as a C string.
struct Held {
    catalog: Catalog,
    keys: Vec<CString>,
}

/// The catalog behind a loaned handle; `None` for a null pointer or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned catalog of this library.
unsafe fn held<'a>(this_: *const wz_ext_loaned_message_catalog_t) -> Option<&'a Held> {
    if this_.is_null() {
        return None;
    }
    let handle = (*this_).handle;
    if handle.is_null() {
        return None;
    }
    Some(&*handle.cast::<Held>())
}

/// Write the gravestone into the caller's refusal slot, when it gave one.
///
/// # Safety
/// `out` is null or writable for a `z_owned_string_t`.
unsafe fn clear_refusal(out: *mut z_owned_string_t) {
    z_internal_string_null(out);
}

/// Write `text` as the caller's refusal, when it gave a slot for one: a string the core's
/// `z_string_*` made, which the program drops with them.
///
/// # Safety
/// `out` is null or writable for a `z_owned_string_t`.
unsafe fn write_refusal(out: *mut z_owned_string_t, text: &str) {
    if !out.is_null() {
        // The copy refuses only a null slot or a null text with a length, and neither is here.
        z_string_copy_from_substr(out, text.as_ptr().cast::<c_char>(), text.len());
    }
}

/// A NUL-terminated UTF-8 argument; `None` when it is not UTF-8.
///
/// # Safety
/// `text` is a valid C string.
unsafe fn utf8_arg<'a>(text: *const c_char) -> Option<&'a str> {
    CStr::from_ptr(text).to_str().ok()
}

/// Read and judge the catalog `text` (JSON5), against this build's `MESSAGE_CATALOG_ENTRIES`,
/// `REPLAY_DEPTH_MAX` and `E2E_SENDER_SLOTS`.
///
/// `this_` holds the gravestone on every error. `refusal` may be null; when it is not, it holds the
/// gravestone on success and, on `_Z_ERR_CONFIG_INVALID_VALUE`, why: the refusal's word (the
/// schema's, such as `duplicate_id` or `replay_depth_out_of_range`), the JSON pointer to the place,
/// and a sentence.
///
/// Returns `Z_ERR_NULL` for a null `this_` or `text`; `Z_EINVAL` for text that is not UTF-8;
/// `_Z_ERR_CONFIG_INVALID_VALUE` for a catalog that is refused; `Z_OK` otherwise.
///
/// # Safety
/// `this_` is writable; `text` is null or a NUL-terminated C string; `refusal` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_message_catalog_new(
    this_: *mut wz_ext_owned_message_catalog_t,
    text: *const c_char,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        clear_refusal(refusal);
        if this_.is_null() {
            return Z_ERR_NULL;
        }
        (*this_).handle = core::ptr::null_mut();
        if text.is_null() {
            return Z_ERR_NULL;
        }
        let Some(text) = utf8_arg(text) else {
            return Z_EINVAL;
        };
        let catalog = match Catalog::parse(text, build_limits()) {
            Ok(catalog) => catalog,
            Err(why) => {
                write_refusal(refusal, &why.to_string());
                return Z_ERR_CONFIG_INVALID_VALUE;
            }
        };
        let mut keys = Vec::with_capacity(catalog.messages().len());
        for (i, message) in catalog.messages().iter().enumerate() {
            match CString::new(message.key_expr.as_str()) {
                Ok(key) => keys.push(key),
                Err(_) => {
                    write_refusal(
                        refusal,
                        &format!(
                            "key_expr at /messages/{i}/key_expr: a NUL byte, which a C string \
                             cannot carry"
                        ),
                    );
                    return Z_ERR_CONFIG_INVALID_VALUE;
                }
            }
        }
        let held = Held { catalog, keys };
        (*this_).handle = Box::into_raw(Box::new(held)).cast::<c_void>();
        Z_OK
    })
}

/// How many messages the catalog declares; 0 for a null catalog or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned catalog.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_message_catalog_len(
    this_: *const wz_ext_loaned_message_catalog_t,
) -> usize {
    guard_val(0, || held(this_).map_or(0, |h| h.catalog.messages().len()))
}

/// Write to `out` the index of a match `found` gives, for the doors that look one up.
///
/// # Safety
/// `out` is null or writable.
unsafe fn answer_index(found: Option<usize>, out: *mut usize) -> ZResult {
    if out.is_null() {
        return Z_ERR_NULL;
    }
    match found {
        Some(index) => {
            *out = index;
            Z_OK
        }
        None => Z_ERR_INVALID,
    }
}

/// The index of the message put on `key_expr`, written to `out_index`.
///
/// Returns `Z_OK`; `Z_ERR_INVALID` when no message is put on it; `Z_EINVAL` for a key that is not
/// UTF-8; `Z_ERR_NULL` for a null argument or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned catalog; `key_expr` is null or a C string; `out_index` is null or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_message_catalog_find(
    this_: *const wz_ext_loaned_message_catalog_t,
    key_expr: *const c_char,
    out_index: *mut usize,
) -> ZResult {
    guarded(|| {
        let Some(held) = held(this_) else {
            return Z_ERR_NULL;
        };
        if key_expr.is_null() {
            return Z_ERR_NULL;
        }
        let Some(key_expr) = utf8_arg(key_expr) else {
            return Z_EINVAL;
        };
        answer_index(held.catalog.find_key_expr(key_expr), out_index)
    })
}

/// The index of the message of `id`, written to `out_index`.
///
/// Returns `Z_OK`; `Z_ERR_INVALID` when no message has the id; `Z_ERR_NULL` for a null argument
/// or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned catalog; `out_index` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_message_catalog_find_id(
    this_: *const wz_ext_loaned_message_catalog_t,
    id: u32,
    out_index: *mut usize,
) -> ZResult {
    guarded(|| {
        let Some(held) = held(this_) else {
            return Z_ERR_NULL;
        };
        answer_index(held.catalog.find_id(id), out_index)
    })
}

/// The index of the node called `name`, written to `out_node`.
///
/// Returns `Z_OK`; `Z_ERR_INVALID` when no node has the name; `Z_EINVAL` for a name that is not
/// UTF-8; `Z_ERR_NULL` for a null argument or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned catalog; `name` is null or a C string; `out_node` is null or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_message_catalog_node(
    this_: *const wz_ext_loaned_message_catalog_t,
    name: *const c_char,
    out_node: *mut usize,
) -> ZResult {
    guarded(|| {
        let Some(held) = held(this_) else {
            return Z_ERR_NULL;
        };
        if name.is_null() {
            return Z_ERR_NULL;
        }
        let Some(name) = utf8_arg(name) else {
            return Z_EINVAL;
        };
        answer_index(held.catalog.node_index(name), out_node)
    })
}

/// The entry of message `index`, written to `out`, which is zeroed on every error.
///
/// Returns `Z_OK`; `Z_ERR_INVALID` for a message the catalog does not have; `Z_ERR_NULL` for a
/// null argument or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned catalog; `out` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_message_catalog_entry(
    this_: *const wz_ext_loaned_message_catalog_t,
    index: usize,
    out: *mut wz_ext_message_entry_t,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ERR_NULL;
        }
        *out = wz_ext_message_entry_t::default();
        let Some(held) = held(this_) else {
            return Z_ERR_NULL;
        };
        let (Some(message), Some(key)) = (held.catalog.messages().get(index), held.keys.get(index))
        else {
            return Z_ERR_INVALID;
        };
        let mut has = 0u8;
        let mut entry = wz_ext_message_entry_t {
            key_expr: key.as_ptr(),
            id: message.id,
            // Each list is bounded by a build limit far below 2^32.
            senders: message.senders.len() as u32,
            ..wz_ext_message_entry_t::default()
        };
        if let Some(period) = message.period_ms {
            has |= WZ_EXT_MESSAGE_HAS_PERIOD;
            entry.period_ms = period;
        }
        if message.protection.is_some() {
            has |= WZ_EXT_MESSAGE_HAS_PROTECTION;
        }
        if !message.senders.is_empty() {
            has |= WZ_EXT_MESSAGE_HAS_SENDERS;
        }
        if !message.instance_key.is_empty() {
            has |= WZ_EXT_MESSAGE_HAS_INSTANCE_KEY;
        }
        if let Some(depth) = message.replay_depth {
            has |= WZ_EXT_MESSAGE_HAS_REPLAY;
            entry.replay_depth = depth;
        }
        if let Some(supervision) = message.supervision {
            has |= WZ_EXT_MESSAGE_HAS_SUPERVISION;
            entry.supervision_factor = supervision.factor;
            entry.supervision_awaited = u8::from(supervision.awaited);
        }
        if message.segment_profile.is_some() {
            has |= WZ_EXT_MESSAGE_HAS_SEGMENT_PROFILE;
        }
        entry.has = has;
        *out = entry;
        Z_OK
    })
}

/// Whether `node` publishes or subscribes to message `index`: the `WZ_EXT_MESSAGE_PUBLISHES` and
/// `WZ_EXT_MESSAGE_SUBSCRIBES` bits, 0 for neither, a message or a node the catalog does not have,
/// a null catalog or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned catalog.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_message_catalog_direction(
    this_: *const wz_ext_loaned_message_catalog_t,
    index: usize,
    node: usize,
) -> u8 {
    guard_val(0, || {
        let Some(message) = held(this_).and_then(|h| h.catalog.messages().get(index)) else {
            return 0;
        };
        let mut bits = 0;
        if message.publishers.contains(&node) {
            bits |= WZ_EXT_MESSAGE_PUBLISHES;
        }
        if message.subscribers.contains(&node) {
            bits |= WZ_EXT_MESSAGE_SUBSCRIBES;
        }
        bits
    })
}

/// The start delay every reception supervisor of the deployment is made with, in milliseconds; 0
/// when the catalog states none, and for a null catalog or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned catalog.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_message_catalog_supervision_start_delay(
    this_: *const wz_ext_loaned_message_catalog_t,
) -> u32 {
    guard_val(0, || {
        held(this_).map_or(0, |h| h.catalog.supervision_start_delay_ms())
    })
}

/// The code and the reason of a piece the catalog entry does not give.
#[cfg(any(
    feature = "e2e-sender",
    feature = "e2e-receiver",
    feature = "e2e-supervision"
))]
unsafe fn handle_refused(why: &HandleError, refusal: *mut z_owned_string_t) -> ZResult {
    match why {
        HandleError::NoSuchMessage | HandleError::NoSuchNode => Z_ERR_INVALID,
        other => {
            write_refusal(refusal, &other.to_string());
            Z_ERR_CONFIG_INVALID_VALUE
        }
    }
}

/// The e2e sender `node` protects message `index` with: the message's profile and header values,
/// the node's address for the fields the profile derives from it, made as `options` says (null:
/// the defaults of `wz_ext_e2e_sender_options_default`). The handle is the one
/// `wz_ext_e2e_sender_new` makes, and the `wz_ext_e2e_sender_*` doors take it.
///
/// `out` holds the gravestone on every error. `refusal` may be null; when it is not, it holds the
/// gravestone on success and the reason on `_Z_ERR_CONFIG_INVALID_VALUE`.
///
/// Returns `Z_OK`; `Z_ERR_INVALID` for a message or a node the catalog does not have; `Z_EINVAL`
/// for a rollover this library does not know; `_Z_ERR_CONFIG_INVALID_VALUE` when the node does not
/// publish the message, the message is not protected, or the options are refused; `Z_ERR_NULL`
/// for a null catalog or `out`, or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned catalog; `options` is null or valid; `out` is null or writable;
/// `refusal` is null or writable.
#[cfg(feature = "e2e-sender")]
#[no_mangle]
pub unsafe extern "C" fn wz_ext_message_catalog_e2e_sender_new(
    this_: *const wz_ext_loaned_message_catalog_t,
    index: usize,
    node: usize,
    options: *const crate::e2e_sender::wz_ext_e2e_sender_options_t,
    out: *mut crate::e2e_sender::wz_ext_owned_e2e_sender_t,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        clear_refusal(refusal);
        if out.is_null() {
            return Z_ERR_NULL;
        }
        (*out).handle = core::ptr::null_mut();
        let Some(held) = held(this_) else {
            return Z_ERR_NULL;
        };
        let options = match crate::e2e_sender::sender_options(options) {
            Ok(options) => options,
            Err(code) => return code,
        };
        match held.catalog.sender(index, node, options) {
            Ok(sender) => {
                crate::e2e_sender::adopt_sender(&mut *out, sender);
                Z_OK
            }
            Err(why) => handle_refused(&why, refusal),
        }
    })
}

/// Whether a receiver of message `index` needs sender slots this build does not have: the entry
/// lists senders, and the build has no `e2e-sender-demux`.
#[cfg(all(feature = "e2e-receiver", not(feature = "e2e-sender-demux")))]
fn wants_sender_slots(catalog: &Catalog, index: usize) -> bool {
    catalog
        .messages()
        .get(index)
        .is_some_and(|m| !m.senders.is_empty())
}

#[cfg(feature = "e2e-sender-demux")]
fn wants_sender_slots(_catalog: &Catalog, _index: usize) -> bool {
    false
}

/// The e2e receiver `node` judges message `index` with: the message's profile, the header values
/// for the identifier it expects, and one slot per sender the entry lists, bound to its identity,
/// or one stream when it lists none. The handle is the one `wz_ext_e2e_receiver_new` makes, and
/// the `wz_ext_e2e_receiver_*` doors take it.
///
/// `out` holds the gravestone on every error. `refusal` may be null; when it is not, it holds the
/// gravestone on success and the reason on `_Z_ERR_CONFIG_INVALID_VALUE`.
///
/// Returns `Z_OK`; `Z_ERR_INVALID` for a message or a node the catalog does not have;
/// `WZ_EXT_ERR_UNSUPPORTED` for a message that lists senders in a build without
/// `e2e-sender-demux`; `_Z_ERR_CONFIG_INVALID_VALUE` when the node does not subscribe to the
/// message or the message is not protected; `Z_ERR_NULL` for a null catalog or `out`, or the
/// gravestone.
///
/// # Safety
/// `this_` is null or a loaned catalog; `out` is null or writable; `refusal` is null or writable.
#[cfg(feature = "e2e-receiver")]
#[no_mangle]
pub unsafe extern "C" fn wz_ext_message_catalog_e2e_receiver_new(
    this_: *const wz_ext_loaned_message_catalog_t,
    index: usize,
    node: usize,
    out: *mut crate::e2e_receiver::wz_ext_owned_e2e_receiver_t,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        clear_refusal(refusal);
        if out.is_null() {
            return Z_ERR_NULL;
        }
        (*out).handle = core::ptr::null_mut();
        let Some(held) = held(this_) else {
            return Z_ERR_NULL;
        };
        if wants_sender_slots(&held.catalog, index) {
            return crate::result::WZ_EXT_ERR_UNSUPPORTED;
        }
        match held
            .catalog
            .receiver(index, node, crate::e2e_receiver::SLOT_LIMIT)
        {
            Ok(receiver) => {
                crate::e2e_receiver::adopt_receiver(&mut *out, receiver);
                Z_OK
            }
            Err(why) => handle_refused(&why, refusal),
        }
    })
}

/// How many rows a reception supervisor of `node` takes for message `index`, written to
/// `out_rows`: one per sender the entry lists, else one.
///
/// Returns `Z_OK`; `Z_ERR_INVALID` for a message or a node the catalog does not have;
/// `_Z_ERR_CONFIG_INVALID_VALUE` when the node does not subscribe to the message or its reception
/// is not supervised (`refusal` saying which, when it is not null); `Z_ERR_NULL` for a null
/// catalog or `out_rows`, or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned catalog; `out_rows` is null or writable; `refusal` is null or
/// writable.
#[cfg(feature = "e2e-supervision")]
#[no_mangle]
pub unsafe extern "C" fn wz_ext_message_catalog_supervision_rows(
    this_: *const wz_ext_loaned_message_catalog_t,
    index: usize,
    node: usize,
    out_rows: *mut usize,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        clear_refusal(refusal);
        if out_rows.is_null() {
            return Z_ERR_NULL;
        }
        *out_rows = 0;
        let Some(held) = held(this_) else {
            return Z_ERR_NULL;
        };
        match held.catalog.supervision_rows(index, node) {
            Ok(rows) => {
                *out_rows = rows.len();
                Z_OK
            }
            Err(why) => handle_refused(&why, refusal),
        }
    })
}

/// Add to `supervisor` the rows of message `index` as `node` receives it: the message's period and
/// factor, and as each row's sender the index of the node that sends the stream (the number
/// `wz_ext_stream_supervisor_set_sender_present` takes). The stream numbers the supervisor gives
/// are written to `out_streams` in the order of the receiver's slots (the order of the senders the
/// entry lists, else one), and how many to `written`.
///
/// Returns `Z_OK`; `Z_ERR_OVERFLOW` when `capacity` is less than the rows
/// (`wz_ext_message_catalog_supervision_rows`), before any is added; `Z_ERR_INVALID` for a message
/// or a node the catalog does not have; `_Z_ERR_CONFIG_INVALID_VALUE` when the node does not
/// subscribe to the message or its reception is not supervised; a code of
/// `wz_ext_stream_supervisor_add` when the supervisor refuses a row, the rows before it added and
/// counted in `written`; `Z_ERR_NULL` for a null argument or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned catalog; `supervisor` is null or a loaned supervisor; `out_streams`
/// is writable for `capacity` numbers; `written` and `refusal` are null or writable.
#[cfg(feature = "e2e-supervision")]
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn wz_ext_message_catalog_supervise(
    this_: *const wz_ext_loaned_message_catalog_t,
    index: usize,
    node: usize,
    supervisor: *const crate::stream_supervision::wz_ext_loaned_stream_supervisor_t,
    out_streams: *mut u32,
    capacity: usize,
    written: *mut usize,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        clear_refusal(refusal);
        if written.is_null() {
            return Z_ERR_NULL;
        }
        *written = 0;
        let Some(held) = held(this_) else {
            return Z_ERR_NULL;
        };
        if supervisor.is_null() || out_streams.is_null() {
            return Z_ERR_NULL;
        }
        let rows = match held.catalog.supervision_rows(index, node) {
            Ok(rows) => rows,
            Err(why) => return handle_refused(&why, refusal),
        };
        if capacity < rows.len() {
            return crate::result::Z_ERR_OVERFLOW;
        }
        for (n, row) in rows.iter().enumerate() {
            let mut stream = 0u32;
            let code = crate::stream_supervision::wz_ext_stream_supervisor_add(
                supervisor,
                row.period_ms,
                row.factor,
                row.sender,
                row.awaited,
                &mut stream,
            );
            if code != Z_OK {
                return code;
            }
            *out_streams.add(n) = stream;
            *written = n + 1;
        }
        Z_OK
    })
}

/// Borrow a catalog. The loaned form has the owned layout, so this is a pointer cast.
///
/// # Safety
/// `this_` is null or an owned catalog.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_message_catalog_loan(
    this_: *const wz_ext_owned_message_catalog_t,
) -> *const wz_ext_loaned_message_catalog_t {
    this_.cast::<wz_ext_loaned_message_catalog_t>()
}

/// The moved form of a catalog, for `wz_ext_message_catalog_drop`: a cast, which nulls nothing.
///
/// # Safety
/// `this_` is null or an owned catalog.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_message_catalog_move(
    this_: *mut wz_ext_owned_message_catalog_t,
) -> *mut wz_ext_moved_message_catalog_t {
    this_.cast::<wz_ext_moved_message_catalog_t>()
}

/// Release a catalog and leave the gravestone: every key expression an entry pointed at goes with
/// it. A second drop, and a drop of the gravestone, do nothing.
///
/// # Safety
/// `this_` is null or a moved catalog, which no other thread reads.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_message_catalog_drop(this_: *mut wz_ext_moved_message_catalog_t) {
    let _ = guarded(|| {
        if !this_.is_null() {
            let slot = core::ptr::addr_of_mut!((*this_)._this.handle);
            let handle = *slot;
            *slot = core::ptr::null_mut();
            if !handle.is_null() {
                drop(Box::from_raw(handle.cast::<Held>()));
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
pub unsafe extern "C" fn wz_ext_internal_message_catalog_null(
    this_: *mut wz_ext_owned_message_catalog_t,
) {
    if !this_.is_null() {
        (*this_).handle = core::ptr::null_mut();
    }
}

/// Whether the slot holds a catalog.
///
/// # Safety
/// `this_` is null or an owned catalog.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_internal_message_catalog_check(
    this_: *const wz_ext_owned_message_catalog_t,
) -> bool {
    guard_val(false, || !this_.is_null() && !(*this_).handle.is_null())
}
