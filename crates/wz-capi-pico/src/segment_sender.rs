// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_segment_*`: the SENDING side of a declared segment profile, from C. One message of the
//! application's own is cut into the pieces whose header the profile declares, and the pieces are
//! put on a publisher or handed to a callback, in order.
//!
//! A door wz has and zenoh-pico does not, so each is `wz_ext_*`, declared in `wz_ext.h` (the
//! extension namespace, apart from the drop-in headers), and part of the unstable surface: the
//! `segment-sender` capability implies `unstable-api`.
//!
//! The writer is [`wz_app_frame::segment_sender`], the one the zenoh-c ABI's
//! `wz_capi_c_segment_sender_*` doors write with, and it writes each piece by the field layout and
//! the CRC rule of the reader that joins them ([`wz_app_frame::segment_profile`]). This file is the
//! pico ABI's names, result codes and ownership around it.
//!
//! # Ownership
//!
//! `wz_ext_segment_sender_new` makes a `wz_ext_owned_segment_sender_t`, and every door that uses it
//! takes the loan (`wz_ext_segment_sender_loan`). `wz_ext_segment_sender_drop` releases it through
//! the moved form (`wz_ext_segment_sender_move`) and leaves the gravestone, so a second drop does
//! nothing; `wz_ext_internal_segment_sender_null` writes the gravestone and
//! `wz_ext_internal_segment_sender_check` tells it from a sender, as pico's own owned types do.
//!
//! # The transfer number
//!
//! A message refused before any piece (empty, longer than the profile admits, a chunk size of zero,
//! a value that does not fit its field, a number past the largest under
//! [`WZ_EXT_SEGMENT_ROLLOVER_REFUSE`]) emits nothing and consumes no number. A message whose first
//! piece was handed on has consumed its number, whether or not every piece then went out.
//!
//! # Threads
//!
//! One handle may be called from several threads: a message's pieces are written and handed on
//! under one lock, so the pieces of two messages never interleave on one stream. A callback must
//! therefore not call its own sender.

use core::ffi::{c_char, c_void, CStr};
use std::sync::{Mutex, MutexGuard, PoisonError};

use wz_app_frame::segment_sender::{Rollover, SegmentSender, Split, SplitError};

use crate::abi::{z_moved_bytes_t, z_owned_bytes_t, z_owned_string_t};
use crate::bytes::{store_owned_string, z_bytes_copy_from_buf};
use crate::ffi::{guard_val, guarded};
use crate::pubsub::{
    z_loaned_publisher_t, z_publisher_put, z_publisher_put_options_default,
    z_publisher_put_options_t, z_timestamp_t,
};
use crate::result::{ZResult, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_NULL, Z_OK};

/// What a sender does after the message that carried the largest transfer number its field holds.
pub type wz_ext_segment_rollover_t = u8;

/// Refuse the next message. The value a caller passes unless its deployment states otherwise.
pub const WZ_EXT_SEGMENT_ROLLOVER_REFUSE: wz_ext_segment_rollover_t = 0;
/// Go back to the number the sender was made with: "never 0, wrap to 1" is a sender made with 1
/// that restarts.
pub const WZ_EXT_SEGMENT_ROLLOVER_RESTART: wz_ext_segment_rollover_t = 1;

/// An owned sender: the handle in its one word, null for the gravestone. wz's own, so there is no
/// upstream size to pad to.
#[repr(C)]
pub struct wz_ext_owned_segment_sender_t {
    pub(crate) handle: *mut c_void,
}

/// A loaned sender: the owned layout, so the loan is a pointer cast.
#[repr(C)]
pub struct wz_ext_loaned_segment_sender_t {
    pub(crate) handle: *mut c_void,
}

/// A moved sender (pico's `z_moved_*_t` shape).
#[repr(C)]
pub struct wz_ext_moved_segment_sender_t {
    pub(crate) _this: wz_ext_owned_segment_sender_t,
}

/// How far one put or split went.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct wz_ext_segment_result_t {
    /// The transfer number every piece carried; 0 when the message was refused before any piece.
    pub transfer: u64,
    /// How many pieces the message was cut into; 0 when it was refused.
    pub pieces: usize,
    /// How many pieces went out.
    pub sent: usize,
}

/// The options of [`wz_ext_segment_sender_put`].
#[repr(C)]
pub struct wz_ext_segment_put_options_t {
    /// The timestamp every piece carries, BORROWED for the call; null for none.
    pub timestamp: *const z_timestamp_t,
}

/// What [`wz_ext_segment_sender_split`] hands each piece to, with the caller's context. A return
/// other than `Z_OK` stops the split, which returns it. The piece is valid only during the call.
pub type wz_ext_segment_piece_fn =
    unsafe extern "C" fn(context: *mut c_void, piece: *const u8, len: usize) -> ZResult;

impl wz_ext_owned_segment_sender_t {
    fn null_value() -> Self {
        Self {
            handle: core::ptr::null_mut(),
        }
    }

    fn adopt(sender: SegmentSender) -> Self {
        Self {
            handle: Box::into_raw(Box::new(Mutex::new(sender))).cast::<c_void>(),
        }
    }
}

/// The sender behind a loaned handle; `None` for a null pointer or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned sender of this library.
unsafe fn sender_of<'a>(
    this_: *const wz_ext_loaned_segment_sender_t,
) -> Option<&'a Mutex<SegmentSender>> {
    if this_.is_null() {
        return None;
    }
    let handle = (*this_).handle;
    if handle.is_null() {
        return None;
    }
    Some(&*handle.cast::<Mutex<SegmentSender>>())
}

/// The lock, past a poison: a panic inside a call was caught at the door, and the sender's number
/// moves only after a message is admitted.
fn locked(sender: &Mutex<SegmentSender>) -> MutexGuard<'_, SegmentSender> {
    sender.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Write the gravestone into the caller's refusal slot, when it gave one.
///
/// # Safety
/// `out` is null or writable for a `z_owned_string_t`.
unsafe fn clear_refusal(out: *mut z_owned_string_t) {
    if !out.is_null() {
        *out = z_owned_string_t::null_value();
    }
}

/// Write `text` as the caller's refusal, when it gave a slot for one.
///
/// # Safety
/// `out` is null or writable for a `z_owned_string_t`.
unsafe fn write_refusal(out: *mut z_owned_string_t, text: &str) {
    if !out.is_null() {
        store_owned_string(out, text.as_bytes());
    }
}

/// A NUL-terminated UTF-8 argument; `None` when it is not UTF-8.
///
/// # Safety
/// `text` is a valid C string.
unsafe fn utf8_arg<'a>(text: *const c_char) -> Option<&'a str> {
    CStr::from_ptr(text).to_str().ok()
}

/// The message argument as a slice.
///
/// # Safety
/// `message` is readable for `len` bytes when `len` is not 0, and non-null then.
unsafe fn message_arg<'a>(message: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(message, len)
    }
}

/// The rollover a C value names; `None` for a value this library does not know.
fn rollover_of(value: wz_ext_segment_rollover_t) -> Option<Rollover> {
    match value {
        WZ_EXT_SEGMENT_ROLLOVER_REFUSE => Some(Rollover::Refuse),
        WZ_EXT_SEGMENT_ROLLOVER_RESTART => Some(Rollover::Restart),
        _ => None,
    }
}

/// A sender for the profile `profile_json` describes, with the fields the caller owns stated in
/// `values_json` (a JSON object keyed by field name: every field that is not fixed by `equals` and
/// is not the transfer, total, offset or CRC field), whose first message carries `first_transfer`.
///
/// `this_` holds the gravestone on every error. `refusal` may be null; when it is not, it holds the
/// gravestone on success and, on `_Z_ERR_CONFIG_INVALID_VALUE`, the reason, beginning `profile` or
/// `values` and naming the place.
///
/// Returns `Z_ERR_NULL` for a null `this_`, `profile_json` or `values_json`; `Z_EINVAL` for text
/// that is not UTF-8 or a `rollover` this library does not know; `_Z_ERR_CONFIG_INVALID_VALUE` for
/// a profile or values text that is refused; `Z_OK` otherwise.
///
/// # Safety
/// `this_` is writable; `profile_json` and `values_json` are null or NUL-terminated C strings;
/// `refusal` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_segment_sender_new(
    this_: *mut wz_ext_owned_segment_sender_t,
    profile_json: *const c_char,
    values_json: *const c_char,
    first_transfer: u64,
    rollover: wz_ext_segment_rollover_t,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        clear_refusal(refusal);
        if this_.is_null() {
            return Z_ERR_NULL;
        }
        *this_ = wz_ext_owned_segment_sender_t::null_value();
        if profile_json.is_null() || values_json.is_null() {
            return Z_ERR_NULL;
        }
        let (Some(profile), Some(values)) = (utf8_arg(profile_json), utf8_arg(values_json)) else {
            return Z_EINVAL;
        };
        let Some(rollover) = rollover_of(rollover) else {
            return Z_EINVAL;
        };
        match SegmentSender::new(profile, values, first_transfer, rollover) {
            Ok(sender) => {
                *this_ = wz_ext_owned_segment_sender_t::adopt(sender);
                Z_OK
            }
            Err(why) => {
                write_refusal(refusal, &why.to_string());
                Z_ERR_CONFIG_INVALID_VALUE
            }
        }
    })
}

/// Fill in the default put options: no timestamp.
///
/// # Safety
/// `this_` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_segment_put_options_default(
    this_: *mut wz_ext_segment_put_options_t,
) {
    if !this_.is_null() {
        *this_ = wz_ext_segment_put_options_t {
            timestamp: core::ptr::null(),
        };
    }
}

/// Split one message with the sender behind `this_`, handing each piece to `emit`, and report it
/// through `result` and `refusal`: the one body both doors share.
///
/// # Safety
/// The arguments are those of the two doors.
unsafe fn split_reporting(
    this_: *const wz_ext_loaned_segment_sender_t,
    message: *const u8,
    len: usize,
    chunk_bytes: usize,
    result: *mut wz_ext_segment_result_t,
    refusal: *mut z_owned_string_t,
    emit: impl FnMut(&[u8]) -> Result<(), ZResult>,
) -> ZResult {
    clear_refusal(refusal);
    if !result.is_null() {
        *result = wz_ext_segment_result_t::default();
    }
    let Some(sender) = sender_of(this_) else {
        return Z_ERR_NULL;
    };
    if message.is_null() && len != 0 {
        return Z_ERR_NULL;
    }
    let message = message_arg(message, len);
    let (code, report) = match locked(sender).split(message, chunk_bytes, emit) {
        Ok(Split { transfer, pieces }) => (
            Z_OK,
            wz_ext_segment_result_t {
                transfer,
                pieces,
                sent: pieces,
            },
        ),
        Err(SplitError::Refused(why)) => {
            write_refusal(refusal, &why.to_string());
            return Z_EINVAL;
        }
        Err(SplitError::Emit {
            error,
            transfer,
            sent,
            pieces,
        }) => {
            write_refusal(
                refusal,
                &format!(
                    "piece {} of {pieces} of transfer {transfer} was not sent (code {error}); \
                     the transfer number is used",
                    sent.saturating_add(1)
                ),
            );
            (
                error,
                wz_ext_segment_result_t {
                    transfer,
                    pieces,
                    sent,
                },
            )
        }
    };
    if !result.is_null() {
        *result = report;
    }
    code
}

/// Cut `message` into chunks of `chunk_bytes` and put each piece on `publisher`, in order, every
/// piece with the timestamp `options` gives (`options` may be null: no timestamp).
///
/// `result` and `refusal` may be null. `result` says how far the message went; `refusal` holds the
/// gravestone when every piece went out and says why otherwise.
///
/// Returns `Z_OK` when every piece was put; `Z_EINVAL` when the message was refused before any
/// piece (`refusal` says why, and no transfer number was used); the code of the put that failed,
/// after `result.sent` pieces, when one did (the transfer number is used); `Z_ERR_NULL` for a null
/// sender or publisher, the gravestone, or a null message with a length.
///
/// # Safety
/// `this_` is null or a loaned sender; `publisher` is null or a loaned publisher; `message` is
/// readable for `len` bytes; `options` is null or valid, its timestamp null or valid for the call;
/// `result` and `refusal` are null or writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn wz_ext_segment_sender_put(
    this_: *const wz_ext_loaned_segment_sender_t,
    publisher: *const z_loaned_publisher_t,
    message: *const u8,
    len: usize,
    chunk_bytes: usize,
    options: *const wz_ext_segment_put_options_t,
    result: *mut wz_ext_segment_result_t,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if publisher.is_null() {
            clear_refusal(refusal);
            if !result.is_null() {
                *result = wz_ext_segment_result_t::default();
            }
            return Z_ERR_NULL;
        }
        let timestamp = if options.is_null() {
            core::ptr::null()
        } else {
            (*options).timestamp
        };
        let put = |piece: &[u8]| -> Result<(), ZResult> {
            let mut payload = z_owned_bytes_t::null_value();
            let copied = z_bytes_copy_from_buf(&mut payload, piece.as_ptr(), piece.len());
            if copied != Z_OK {
                return Err(copied);
            }
            let mut moved = z_moved_bytes_t { _this: payload };
            let mut defaults = core::mem::MaybeUninit::<z_publisher_put_options_t>::uninit();
            z_publisher_put_options_default(defaults.as_mut_ptr());
            let mut put_options = defaults.assume_init();
            put_options.timestamp = timestamp.cast_mut();
            match z_publisher_put(publisher, &mut moved, &put_options) {
                Z_OK => Ok(()),
                code => Err(code),
            }
        };
        split_reporting(this_, message, len, chunk_bytes, result, refusal, put)
    })
}

/// Cut `message` into chunks of `chunk_bytes` and hand each piece, header and chunk, to `emit` with
/// `context`, in order: for a caller that sends the pieces some other way, as the replies of a
/// query for instance. The piece is valid only during the call; `emit` must not call this sender.
///
/// Returns `Z_OK` when `emit` accepted every piece; `Z_EINVAL` when the message was refused before
/// any piece (`refusal` says why, and no transfer number was used); what `emit` returned, after
/// `result.sent` pieces, when it returned anything but `Z_OK` (the transfer number is used);
/// `Z_ERR_NULL` for a null sender or `emit`, the gravestone, or a null message with a length.
///
/// # Safety
/// `this_` is null or a loaned sender; `message` is readable for `len` bytes; `emit` is safe to call
/// with `context`; `result` and `refusal` are null or writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn wz_ext_segment_sender_split(
    this_: *const wz_ext_loaned_segment_sender_t,
    message: *const u8,
    len: usize,
    chunk_bytes: usize,
    emit: Option<wz_ext_segment_piece_fn>,
    context: *mut c_void,
    result: *mut wz_ext_segment_result_t,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        let Some(emit) = emit else {
            clear_refusal(refusal);
            if !result.is_null() {
                *result = wz_ext_segment_result_t::default();
            }
            return Z_ERR_NULL;
        };
        let hand = |piece: &[u8]| -> Result<(), ZResult> {
            match emit(context, piece.as_ptr(), piece.len()) {
                Z_OK => Ok(()),
                code => Err(code),
            }
        };
        split_reporting(this_, message, len, chunk_bytes, result, refusal, hand)
    })
}

/// The number the next message carries. Returns `false`, and writes nothing, when the largest was
/// sent and the sender does not restart, or when an argument is null or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned sender; `out` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_segment_sender_next(
    this_: *const wz_ext_loaned_segment_sender_t,
    out: *mut u64,
) -> bool {
    guard_val(false, || {
        if out.is_null() {
            return false;
        }
        let Some(sender) = sender_of(this_) else {
            return false;
        };
        let Some(next) = locked(sender).next() else {
            return false;
        };
        *out = next;
        true
    })
}

/// Make `value` the number the next message carries. A value past the transfer field's width is
/// accepted here and refused by the next message, as a first number is.
///
/// Returns `Z_ERR_NULL` for a null sender or the gravestone and `Z_OK` otherwise.
///
/// # Safety
/// `this_` is null or a loaned sender.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_segment_sender_set(
    this_: *const wz_ext_loaned_segment_sender_t,
    value: u64,
) -> ZResult {
    guarded(|| {
        let Some(sender) = sender_of(this_) else {
            return Z_ERR_NULL;
        };
        locked(sender).set(value);
        Z_OK
    })
}

/// Borrow a sender. The loaned form has the owned layout, so this is a pointer cast.
///
/// # Safety
/// `this_` is null or an owned sender.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_segment_sender_loan(
    this_: *const wz_ext_owned_segment_sender_t,
) -> *const wz_ext_loaned_segment_sender_t {
    this_.cast::<wz_ext_loaned_segment_sender_t>()
}

/// The moved form of a sender, for `wz_ext_segment_sender_drop`: a cast, which nulls nothing.
///
/// # Safety
/// `this_` is null or an owned sender.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_segment_sender_move(
    this_: *mut wz_ext_owned_segment_sender_t,
) -> *mut wz_ext_moved_segment_sender_t {
    this_.cast::<wz_ext_moved_segment_sender_t>()
}

/// Release a sender and leave the gravestone. A second drop, and a drop of the gravestone, do
/// nothing.
///
/// # Safety
/// `this_` is null or a moved sender.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_segment_sender_drop(this_: *mut wz_ext_moved_segment_sender_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        let handle = (*this_)._this.handle;
        (*this_)._this = wz_ext_owned_segment_sender_t::null_value();
        if !handle.is_null() {
            drop(Box::from_raw(handle.cast::<Mutex<SegmentSender>>()));
        }
        Z_OK
    });
}

/// Write the gravestone.
///
/// # Safety
/// `this_` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_internal_segment_sender_null(
    this_: *mut wz_ext_owned_segment_sender_t,
) {
    if !this_.is_null() {
        *this_ = wz_ext_owned_segment_sender_t::null_value();
    }
}

/// Whether the slot holds a sender.
///
/// # Safety
/// `this_` is null or an owned sender.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_internal_segment_sender_check(
    this_: *const wz_ext_owned_segment_sender_t,
) -> bool {
    guard_val(false, || !this_.is_null() && !(*this_).handle.is_null())
}
