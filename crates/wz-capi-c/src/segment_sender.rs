// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The SENDING side of a segment profile, reachable from the library a participant
//! links: one message of the application's own, cut into pieces whose header the
//! profile declares, put on a publisher or handed to the caller piece by piece.
//!
//! # What this is
//!
//! The dissect library joins the pieces a deployment splits its large messages
//! into, by a profile the caller declares (`wz_capture::segment_profile`). A
//! participant that SENDS such a message to that deployment must write the same
//! header, and this module is the writer: an owned sender made from the same
//! profile text, which writes each piece by the reader's own field layout and CRC
//! rule (`wz_capture::segment_sender`). The two cannot disagree about a header.
//!
//! # Two doors for the pieces
//!
//! * [`wz_capi_c_segment_sender_put`] puts each piece on a publisher, in order,
//!   all with the one timestamp the options give.
//! * [`wz_capi_c_segment_sender_split`] hands each piece to a callback instead,
//!   for a caller that sends the pieces some other way: as the replies of a
//!   query, say, which a deployment that splits its history replies expects.
//!
//! # The transfer number
//!
//! The sender numbers the messages of its stream, starting at the value it is made
//! with. A message refused before any piece (empty, longer than the profile
//! admits, a chunk size of zero, a value that does not fit its field) consumes no
//! number. A message whose first piece was handed on has consumed its number,
//! whether or not every piece then went out. The number does not wrap by default:
//! after the largest value the field holds the next message is refused;
//! [`WZ_CAPI_C_SEGMENT_ROLLOVER_RESTART`] goes back to the first value instead,
//! which is how "never 0, wrap to 1" is stated (first value 1, restarting).
//!
//! # Threads
//!
//! One handle may be called from several threads: a message's pieces are written
//! and handed on under one lock, so the pieces of two messages never interleave on
//! one stream. A callback must therefore not call its own sender.
//!
//! The doors carry wz's own prefix and no `zenoh-c-no-unstable-api` gate: upstream
//! zenoh-c has nothing of the kind to be a drop-in for. They are behind the
//! `segment-sender` capability, off by default as the other wz-own doors are.

#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_void, CStr};
use std::sync::{Mutex, MutexGuard, PoisonError};

use wz_capture::segment_sender::{Rollover, SegmentSender, Split, SplitError};

use crate::abi::{
    z_loaned_publisher_t, z_moved_bytes_t, z_owned_bytes_t, z_owned_string_t, Handle,
};
use crate::ffi::guarded;
use crate::publisher::{
    z_publisher_put, z_publisher_put_options_default, z_publisher_put_options_t,
};
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_EPARSE, Z_OK};
use crate::string::{null_string, owned_string_from};
use crate::timestamp::z_timestamp_t;

/// What a sender does after the message that carried the largest transfer number.
pub type wz_capi_c_segment_rollover_t = i32;

/// Refuse the next message. The default a caller should pass unless its
/// deployment has a rule that says otherwise.
pub const WZ_CAPI_C_SEGMENT_ROLLOVER_REFUSE: wz_capi_c_segment_rollover_t = 0;
/// Go back to the number the sender was made with.
pub const WZ_CAPI_C_SEGMENT_ROLLOVER_RESTART: wz_capi_c_segment_rollover_t = 1;

/// An owned sender. One handle; wz-own, so there is no upstream size to pad to.
#[repr(C)]
pub struct wz_capi_c_owned_segment_sender_t {
    pub(crate) handle: Handle,
}

/// A loaned sender: the same layout, so `loan` is a pointer cast.
#[repr(C)]
pub struct wz_capi_c_loaned_segment_sender_t {
    pub(crate) handle: Handle,
}

/// A moved sender.
#[repr(C)]
pub struct wz_capi_c_moved_segment_sender_t {
    pub(crate) _this: wz_capi_c_owned_segment_sender_t,
}

/// What one put or split did, as far as it went.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct wz_capi_c_segment_result_t {
    /// The transfer number the pieces carried; 0 when the message was refused
    /// before any piece.
    pub transfer: u64,
    /// How many pieces the message was cut into; 0 when it was refused.
    pub pieces: usize,
    /// How many pieces went out.
    pub sent: usize,
}

/// The options of [`wz_capi_c_segment_sender_put`].
#[repr(C)]
pub struct wz_capi_c_segment_put_options_t {
    /// The timestamp every piece carries, BORROWED; NULL for none.
    pub timestamp: *const z_timestamp_t,
}

/// The callback [`wz_capi_c_segment_sender_split`] hands each piece to. A return
/// other than `Z_OK` stops the split, which returns it.
pub type wz_capi_c_segment_piece_fn =
    Option<unsafe extern "C" fn(context: *mut c_void, piece: *const u8, len: usize) -> ZResult>;

impl wz_capi_c_owned_segment_sender_t {
    fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
        }
    }

    fn adopt(sender: SegmentSender) -> Self {
        Self {
            handle: Box::into_raw(Box::new(Mutex::new(sender))) as Handle,
        }
    }
}

/// The sender behind a loaned handle.
///
/// # Safety
/// `this_` must be null or a valid loaned sender.
unsafe fn sender_of<'a>(
    this_: *const wz_capi_c_loaned_segment_sender_t,
) -> Option<&'a Mutex<SegmentSender>> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    // SAFETY: a live `Mutex<SegmentSender>` this crate boxed in `adopt`.
    (!handle.is_null()).then(|| unsafe { &*(handle as *const Mutex<SegmentSender>) })
}

/// The lock, past a poison: a panic inside a call was caught at the door, and the
/// sender's number moves only after a message is admitted.
fn locked(sender: &Mutex<SegmentSender>) -> MutexGuard<'_, SegmentSender> {
    sender.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Write `text` as the owned string `out`, when `out` is not null.
///
/// # Safety
/// `out` null or writable for a `z_owned_string_t`.
unsafe fn write_refusal(out: *mut z_owned_string_t, text: &str) {
    if !out.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *out = owned_string_from(text.as_bytes()) };
    }
}

/// Read a NUL-terminated UTF-8 argument.
///
/// # Safety
/// `text` must be a valid C string.
unsafe fn utf8_arg<'a>(text: *const c_char) -> Option<&'a str> {
    // SAFETY: the caller's contract.
    unsafe { CStr::from_ptr(text) }.to_str().ok()
}

/// The message argument as a slice.
///
/// # Safety
/// `message` readable for `len` bytes when `len` is not 0.
unsafe fn message_arg<'a>(message: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        // SAFETY: the caller's contract; the caller checked non-null.
        unsafe { std::slice::from_raw_parts(message, len) }
    }
}

/// A sender for the profile `profile_json` describes, with the fields the caller
/// owns stated in `values_json` (a JSON object keyed by field name: every field
/// that is not fixed by `equals`, not the transfer, total, offset or CRC field),
/// whose first message carries `first_transfer`.
///
/// `this_` holds a gravestone on every error. `refusal` may be NULL; when it is
/// not, it is set to an empty string on success, and on `Z_EPARSE` it holds the
/// reason, beginning `profile` or `values` and naming the place.
///
/// Returns `Z_ENULL` for a null `this_`, `profile_json` or `values_json`,
/// `Z_EINVAL` for text that is not UTF-8 or a `rollover` this library does not
/// know, `Z_EPARSE` for a profile or values text that is refused, and `Z_OK`
/// otherwise.
///
/// # Safety
/// `this_` writable; `profile_json` and `values_json` NUL-terminated C strings;
/// `refusal` null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_segment_sender_new(
    this_: *mut wz_capi_c_owned_segment_sender_t,
    profile_json: *const c_char,
    values_json: *const c_char,
    first_transfer: u64,
    rollover: wz_capi_c_segment_rollover_t,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if !refusal.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *refusal = null_string() };
        }
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = wz_capi_c_owned_segment_sender_t::null_value() };
        if profile_json.is_null() || values_json.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let (Some(profile), Some(values)) = (unsafe { utf8_arg(profile_json) }, unsafe {
            utf8_arg(values_json)
        }) else {
            return Z_EINVAL;
        };
        let rollover = match rollover {
            WZ_CAPI_C_SEGMENT_ROLLOVER_REFUSE => Rollover::Refuse,
            WZ_CAPI_C_SEGMENT_ROLLOVER_RESTART => Rollover::Restart,
            _ => return Z_EINVAL,
        };
        match SegmentSender::new(profile, values, first_transfer, rollover) {
            Ok(sender) => {
                // SAFETY: checked non-null above.
                unsafe { *this_ = wz_capi_c_owned_segment_sender_t::adopt(sender) };
                Z_OK
            }
            Err(why) => {
                // SAFETY: the caller's contract.
                unsafe { write_refusal(refusal, &why.to_string()) };
                Z_EPARSE
            }
        }
    })
}

/// Fill in the default put options: no timestamp.
///
/// # Safety
/// `this_` null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_segment_put_options_default(
    this_: *mut wz_capi_c_segment_put_options_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe {
            *this_ = wz_capi_c_segment_put_options_t {
                timestamp: std::ptr::null(),
            }
        };
    }
}

/// Split one message with the sender behind `this_`, handing each piece to `emit`,
/// and report it through `result` and `refusal`: the one body both doors share.
///
/// # Safety
/// The arguments are those of the two doors.
unsafe fn split_reporting(
    this_: *const wz_capi_c_loaned_segment_sender_t,
    message: *const u8,
    len: usize,
    chunk_bytes: usize,
    result: *mut wz_capi_c_segment_result_t,
    refusal: *mut z_owned_string_t,
    emit: impl FnMut(&[u8]) -> Result<(), ZResult>,
) -> ZResult {
    if !refusal.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *refusal = null_string() };
    }
    if !result.is_null() {
        // SAFETY: the caller's contract.
        unsafe {
            *result = wz_capi_c_segment_result_t {
                transfer: 0,
                pieces: 0,
                sent: 0,
            }
        };
    }
    // SAFETY: the caller's contract.
    let Some(sender) = (unsafe { sender_of(this_) }) else {
        return Z_ENULL;
    };
    if message.is_null() && len != 0 {
        return Z_ENULL;
    }
    // SAFETY: the caller's contract; non-null was checked above.
    let message = unsafe { message_arg(message, len) };
    let (code, report) = match locked(sender).split(message, chunk_bytes, emit) {
        Ok(Split { transfer, pieces }) => (
            Z_OK,
            wz_capi_c_segment_result_t {
                transfer,
                pieces,
                sent: pieces,
            },
        ),
        Err(SplitError::Refused(why)) => {
            // SAFETY: the caller's contract.
            unsafe { write_refusal(refusal, &why.to_string()) };
            return Z_EINVAL;
        }
        Err(SplitError::Emit {
            error,
            transfer,
            sent,
            pieces,
        }) => {
            // SAFETY: the caller's contract.
            unsafe {
                write_refusal(
                    refusal,
                    &format!(
                        "piece {} of {pieces} of transfer {transfer} was not sent (code \
                         {error}); the transfer number is used",
                        sent + 1
                    ),
                )
            };
            (
                error,
                wz_capi_c_segment_result_t {
                    transfer,
                    pieces,
                    sent,
                },
            )
        }
    };
    if !result.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *result = report };
    }
    code
}

/// Cut `message` into chunks of `chunk_bytes` and put each piece on `publisher`,
/// in order, every piece with the timestamp `options` gives (`options` may be
/// NULL: no timestamp).
///
/// `result` and `refusal` may be NULL. `result` says how far the message went;
/// `refusal` is empty when every piece went out and says why otherwise.
///
/// Returns `Z_OK` when every piece was put; `Z_EINVAL` when the message was
/// refused before any piece (`refusal` says why, and no transfer number was
/// used); the code of the put that failed, after `result.sent` pieces, when one
/// did (the transfer number is used); `Z_ENULL` for a null sender, publisher, or
/// message with a length.
///
/// # Safety
/// `this_` null or a valid loaned sender; `publisher` null or a valid loaned
/// publisher; `message` readable for `len` bytes; `options` null or valid, its
/// timestamp null or valid for the call; `result` and `refusal` null or writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn wz_capi_c_segment_sender_put(
    this_: *const wz_capi_c_loaned_segment_sender_t,
    publisher: *const z_loaned_publisher_t,
    message: *const u8,
    len: usize,
    chunk_bytes: usize,
    options: *const wz_capi_c_segment_put_options_t,
    result: *mut wz_capi_c_segment_result_t,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if publisher.is_null() {
            if !refusal.is_null() {
                // SAFETY: the caller's contract.
                unsafe { *refusal = null_string() };
            }
            return Z_ENULL;
        }
        let timestamp: *const z_timestamp_t = if options.is_null() {
            std::ptr::null()
        } else {
            // SAFETY: the caller's contract.
            unsafe { (*options).timestamp }
        };
        let put = |piece: &[u8]| -> Result<(), ZResult> {
            let mut payload = z_owned_bytes_t::null_value();
            // SAFETY: `piece` is a live slice; `payload` is a local owned slot.
            let copied = unsafe {
                crate::bytes::z_bytes_copy_from_buf(&mut payload, piece.as_ptr(), piece.len())
            };
            if copied != Z_OK {
                return Err(copied);
            }
            let mut moved = z_moved_bytes_t { _this: payload };
            let mut opts = std::mem::MaybeUninit::<z_publisher_put_options_t>::uninit();
            // SAFETY: the default assigns the whole struct.
            let mut opts = unsafe {
                z_publisher_put_options_default(opts.as_mut_ptr());
                opts.assume_init()
            };
            opts.timestamp = timestamp.cast::<c_void>();
            // SAFETY: the caller's contract for `publisher` and the timestamp; the
            // payload is moved into the put on every path.
            match unsafe { z_publisher_put(publisher, &mut moved, &mut opts) } {
                Z_OK => Ok(()),
                code => Err(code),
            }
        };
        // SAFETY: the caller's contract.
        unsafe { split_reporting(this_, message, len, chunk_bytes, result, refusal, put) }
    })
}

/// Cut `message` into chunks of `chunk_bytes` and hand each piece, header and
/// chunk, to `emit` with `context`, in order. The piece is valid only during the
/// call; `emit` must not call this sender.
///
/// Returns `Z_OK` when `emit` accepted every piece; `Z_EINVAL` when the message
/// was refused before any piece (`refusal` says why, and no transfer number was
/// used); what `emit` returned, after `result.sent` pieces, when it returned
/// anything but `Z_OK` (the transfer number is used); `Z_ENULL` for a null sender
/// or `emit`, or a null message with a length.
///
/// # Safety
/// `this_` null or a valid loaned sender; `message` readable for `len` bytes;
/// `emit` safe to call with `context`; `result` and `refusal` null or writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn wz_capi_c_segment_sender_split(
    this_: *const wz_capi_c_loaned_segment_sender_t,
    message: *const u8,
    len: usize,
    chunk_bytes: usize,
    emit: wz_capi_c_segment_piece_fn,
    context: *mut c_void,
    result: *mut wz_capi_c_segment_result_t,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        let Some(emit) = emit else {
            if !refusal.is_null() {
                // SAFETY: the caller's contract.
                unsafe { *refusal = null_string() };
            }
            return Z_ENULL;
        };
        let hand = |piece: &[u8]| -> Result<(), ZResult> {
            // SAFETY: the caller's contract for `emit` and `context`.
            match unsafe { emit(context, piece.as_ptr(), piece.len()) } {
                Z_OK => Ok(()),
                code => Err(code),
            }
        };
        // SAFETY: the caller's contract.
        unsafe { split_reporting(this_, message, len, chunk_bytes, result, refusal, hand) }
    })
}

/// The number the next message carries. Returns `false`, and writes nothing, when
/// the largest was sent and the sender does not restart, or when an argument is
/// null.
///
/// # Safety
/// `this_` null or a valid loaned sender; `out` null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_segment_sender_next(
    this_: *const wz_capi_c_loaned_segment_sender_t,
    out: *mut u64,
) -> bool {
    if out.is_null() {
        return false;
    }
    // SAFETY: the caller's contract.
    let Some(sender) = (unsafe { sender_of(this_) }) else {
        return false;
    };
    let Some(next) = locked(sender).next() else {
        return false;
    };
    // SAFETY: checked non-null above.
    unsafe { *out = next };
    true
}

/// Make `value` the number the next message carries. A value past the transfer
/// field's width is accepted here and refused by the next message, as a first
/// number is.
///
/// Returns `Z_ENULL` for a null or empty handle and `Z_OK` otherwise.
///
/// # Safety
/// `this_` null or a valid loaned sender.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_segment_sender_set(
    this_: *const wz_capi_c_loaned_segment_sender_t,
    value: u64,
) -> ZResult {
    // SAFETY: the caller's contract.
    let Some(sender) = (unsafe { sender_of(this_) }) else {
        return Z_ENULL;
    };
    locked(sender).set(value);
    Z_OK
}

/// Borrow a sender.
///
/// # Safety
/// `this_` null or a valid owned sender.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_segment_sender_loan(
    this_: *const wz_capi_c_owned_segment_sender_t,
) -> *const wz_capi_c_loaned_segment_sender_t {
    this_ as *const wz_capi_c_loaned_segment_sender_t
}

/// Release a sender. A second drop is a no-op.
///
/// # Safety
/// `this_` null or a valid moved sender.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_segment_sender_drop(
    this_: *mut wz_capi_c_moved_segment_sender_t,
) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        // SAFETY: the caller's contract.
        unsafe { (*this_)._this = wz_capi_c_owned_segment_sender_t::null_value() };
        if !handle.is_null() {
            // SAFETY: a live `Box<Mutex<SegmentSender>>` this crate leaked in `adopt`.
            drop(unsafe { Box::from_raw(handle as *mut Mutex<SegmentSender>) });
        }
        Z_OK
    });
}

/// Write the gravestone.
///
/// # Safety
/// `this_` null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_internal_segment_sender_null(
    this_: *mut wz_capi_c_owned_segment_sender_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = wz_capi_c_owned_segment_sender_t::null_value() };
    }
}

/// Whether the slot holds a sender.
///
/// # Safety
/// `this_` null or a valid owned sender.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_internal_segment_sender_check(
    this_: *const wz_capi_c_owned_segment_sender_t,
) -> bool {
    // SAFETY: the caller's contract.
    !this_.is_null() && !unsafe { (*this_).handle }.is_null()
}
