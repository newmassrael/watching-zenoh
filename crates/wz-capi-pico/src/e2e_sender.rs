// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_e2e_sender_*`: the SENDING side of end-to-end protection, from C. A payload is protected
//! under a profile and the program's header values, with the counter the sender keeps for each
//! stream it sends on.
//!
//! A door wz has and zenoh-pico does not, so each is `wz_ext_*`, declared in `wz_ext.h`, and part
//! of the unstable surface: the `e2e-sender` capability implies `unstable-api`. The sender is
//! [`wz_app_frame::e2e_stream_sender`]; ownership and threads are as `crate::e2e` describes.

use core::ffi::{c_char, c_void};

use wz_app_frame::e2e_frame::Values;
use wz_app_frame::e2e_profile::Profile;
use wz_app_frame::e2e_stream_sender::{describe, Rollover, SenderOptions, StreamSender};

use crate::abi::z_owned_string_t;
use crate::e2e::{
    adopt, behind, bytes_arg, clear_refusal, locked, release, utf8_arg, write_refusal,
};
use crate::ffi::{guard_val, guarded};
use crate::result::{
    ZResult, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_NULL, Z_ERR_OVERFLOW, Z_OK,
};

/// What a stream does after the frame that carried its counter's largest value.
pub type wz_ext_e2e_rollover_t = u8;

/// Refuse the stream's next frame. The value a caller passes unless its deployment states
/// otherwise.
pub const WZ_EXT_E2E_ROLLOVER_REFUSE: wz_ext_e2e_rollover_t = 0;
/// Count on from zero.
pub const WZ_EXT_E2E_ROLLOVER_WRAP: wz_ext_e2e_rollover_t = 1;

/// An owned sender: the handle in its one word, null for the gravestone.
#[repr(C)]
pub struct wz_ext_owned_e2e_sender_t {
    pub(crate) handle: *mut c_void,
}

/// A loaned sender: the owned layout, so the loan is a pointer cast.
#[repr(C)]
pub struct wz_ext_loaned_e2e_sender_t {
    pub(crate) handle: *mut c_void,
}

/// A moved sender (pico's `z_moved_*_t` shape).
#[repr(C)]
pub struct wz_ext_moved_e2e_sender_t {
    pub(crate) _this: wz_ext_owned_e2e_sender_t,
}

/// How a sender is made.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct wz_ext_e2e_sender_options_t {
    /// The counter the first frame of every stream carries.
    pub first_counter: u64,
    /// How many streams the sender keeps a counter for, at least 1.
    pub streams: usize,
    /// A `WZ_EXT_E2E_ROLLOVER_*` value.
    pub rollover: wz_ext_e2e_rollover_t,
    /// Whether a stream keeps its last frame, to protect an unchanged payload again without the
    /// full CRC computation. The frame is the same either way.
    pub crc_cache: bool,
}

impl Default for wz_ext_e2e_sender_options_t {
    fn default() -> Self {
        Self {
            first_counter: 0,
            streams: 1,
            rollover: WZ_EXT_E2E_ROLLOVER_REFUSE,
            crc_cache: false,
        }
    }
}

/// The handle word of a loaned sender.
fn word(this_: *const wz_ext_loaned_e2e_sender_t) -> *const *mut c_void {
    this_.cast::<*mut c_void>()
}

/// The sender options `options` states (null: the defaults); `Z_EINVAL` for a rollover this
/// library does not know. Every door that makes a sender reads them here.
///
/// # Safety
/// `options` is null or valid.
pub(crate) unsafe fn sender_options(
    options: *const wz_ext_e2e_sender_options_t,
) -> Result<SenderOptions, ZResult> {
    let options = if options.is_null() {
        wz_ext_e2e_sender_options_t::default()
    } else {
        *options
    };
    let rollover = match options.rollover {
        WZ_EXT_E2E_ROLLOVER_REFUSE => Rollover::Refuse,
        WZ_EXT_E2E_ROLLOVER_WRAP => Rollover::Wrap,
        _ => return Err(Z_EINVAL),
    };
    Ok(SenderOptions {
        streams: options.streams,
        first_counter: options.first_counter,
        rollover,
        crc_cache: options.crc_cache,
    })
}

/// Box a made sender behind the caller's handle word.
pub(crate) fn adopt_sender(this_: &mut wz_ext_owned_e2e_sender_t, sender: StreamSender) {
    this_.handle = adopt(sender);
}

/// Fill in the default sender options: one stream, a first counter of 0, refuse after the largest
/// value, no CRC cache.
///
/// # Safety
/// `this_` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_e2e_sender_options_default(
    this_: *mut wz_ext_e2e_sender_options_t,
) {
    if !this_.is_null() {
        *this_ = wz_ext_e2e_sender_options_t::default();
    }
}

/// A sender for the profile `profile_json` describes, whose fixed header values are `values_json`
/// (every field but the CRC, the length and the counter; `"@address"` for the fields the profile
/// derives from the node's address), made as `options` says (null: the defaults).
///
/// `this_` holds the gravestone on every error. `refusal` may be null; when it is not, it holds the
/// gravestone on success and, on `_Z_ERR_CONFIG_INVALID_VALUE`, the reason, beginning `profile` or
/// `values` and naming the place, or naming the option refused.
///
/// Returns `Z_ERR_NULL` for a null `this_`, `profile_json` or `values_json`; `Z_EINVAL` for text
/// that is not UTF-8 or a rollover this library does not know; `_Z_ERR_CONFIG_INVALID_VALUE` for a
/// profile, values or option that is refused; `Z_OK` otherwise.
///
/// # Safety
/// `this_` is writable; `profile_json` and `values_json` are null or NUL-terminated C strings;
/// `options` is null or valid; `refusal` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_e2e_sender_new(
    this_: *mut wz_ext_owned_e2e_sender_t,
    profile_json: *const c_char,
    values_json: *const c_char,
    options: *const wz_ext_e2e_sender_options_t,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        clear_refusal(refusal);
        if this_.is_null() {
            return Z_ERR_NULL;
        }
        (*this_).handle = core::ptr::null_mut();
        if profile_json.is_null() || values_json.is_null() {
            return Z_ERR_NULL;
        }
        let (Some(profile), Some(values)) = (utf8_arg(profile_json), utf8_arg(values_json)) else {
            return Z_EINVAL;
        };
        let options = match sender_options(options) {
            Ok(options) => options,
            Err(code) => return code,
        };
        let profile = match Profile::parse(profile) {
            Ok(p) => p,
            Err(e) => {
                write_refusal(refusal, &format!("profile: {e}"));
                return Z_ERR_CONFIG_INVALID_VALUE;
            }
        };
        let values = match Values::parse(values) {
            Ok(v) => v,
            Err(e) => {
                write_refusal(refusal, &format!("values: {e}"));
                return Z_ERR_CONFIG_INVALID_VALUE;
            }
        };
        match StreamSender::new(profile, values, options) {
            Ok(sender) => {
                adopt_sender(&mut *this_, sender);
                Z_OK
            }
            Err(why) => {
                write_refusal(refusal, &describe(&why));
                Z_ERR_CONFIG_INVALID_VALUE
            }
        }
    })
}

/// The size of the frame that protects a payload of `payload_len` bytes: the profile's header and
/// the payload. `Z_ERR_NULL` for a null argument or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned sender; `out` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_e2e_sender_frame_size(
    this_: *const wz_ext_loaned_e2e_sender_t,
    payload_len: usize,
    out: *mut usize,
) -> ZResult {
    guarded(|| {
        let Some(sender) = behind::<StreamSender>(word(this_)) else {
            return Z_ERR_NULL;
        };
        if out.is_null() {
            return Z_ERR_NULL;
        }
        *out = locked(sender).frame_bytes(payload_len);
        Z_OK
    })
}

/// Protect `payload` on `stream`: the frame, header and payload, written to `out`, which has room
/// for `capacity` bytes, with its length in `written` and the counter it carries in `counter`
/// (which may be null). The stream's counter then moves on.
///
/// Returns `Z_OK`; `Z_ERR_OVERFLOW` when `capacity` is less than the frame
/// (`wz_ext_e2e_sender_frame_size`); `Z_EINVAL` when the frame is refused (a stream the sender does
/// not have, a stream that sent its largest value and does not wrap, a payload longer than the
/// length field describes), `refusal` saying why; `Z_ERR_NULL` for a null sender, `out` or
/// `written`, the gravestone, or a null payload with a length. A call that does not return `Z_OK`
/// writes nothing to `out` and consumes no counter value.
///
/// # Safety
/// `this_` is null or a loaned sender; `payload` is readable for `len` bytes; `out` is writable for
/// `capacity` bytes; `written`, `counter` and `refusal` are null or writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn wz_ext_e2e_sender_protect(
    this_: *const wz_ext_loaned_e2e_sender_t,
    stream: usize,
    payload: *const u8,
    len: usize,
    out: *mut u8,
    capacity: usize,
    written: *mut usize,
    counter: *mut u64,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        clear_refusal(refusal);
        if !written.is_null() {
            *written = 0;
        }
        let Some(sender) = behind::<StreamSender>(word(this_)) else {
            return Z_ERR_NULL;
        };
        if out.is_null() || written.is_null() || (payload.is_null() && len != 0) {
            return Z_ERR_NULL;
        }
        let mut sender = locked(sender);
        if capacity < sender.frame_bytes(len) {
            return Z_ERR_OVERFLOW;
        }
        match sender.protect(stream, bytes_arg(payload, len)) {
            Ok(frame) => {
                core::ptr::copy_nonoverlapping(frame.bytes.as_ptr(), out, frame.bytes.len());
                *written = frame.bytes.len();
                if !counter.is_null() {
                    *counter = frame.counter;
                }
                Z_OK
            }
            Err(why) => {
                write_refusal(refusal, &why.to_string());
                Z_EINVAL
            }
        }
    })
}

/// The counter the stream's next frame carries. Returns `false`, and writes nothing, when the
/// stream sent its largest value and does not wrap, for a stream the sender does not have, or for a
/// null argument or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned sender; `out` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_e2e_sender_next(
    this_: *const wz_ext_loaned_e2e_sender_t,
    stream: usize,
    out: *mut u64,
) -> bool {
    guard_val(false, || {
        if out.is_null() {
            return false;
        }
        let Some(sender) = behind::<StreamSender>(word(this_)) else {
            return false;
        };
        let Ok(Some(next)) = locked(sender).next(stream) else {
            return false;
        };
        *out = next;
        true
    })
}

/// Make `value` the counter the stream's next frame carries.
///
/// Returns `Z_OK`; `Z_EINVAL` for a value the counter field cannot hold or a stream the sender does
/// not have; `Z_ERR_NULL` for a null sender or the gravestone.
///
/// # Safety
/// `this_` is null or a loaned sender.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_e2e_sender_set(
    this_: *const wz_ext_loaned_e2e_sender_t,
    stream: usize,
    value: u64,
) -> ZResult {
    guarded(|| {
        let Some(sender) = behind::<StreamSender>(word(this_)) else {
            return Z_ERR_NULL;
        };
        match locked(sender).set(stream, value) {
            Ok(()) => Z_OK,
            Err(_) => Z_EINVAL,
        }
    })
}

/// Borrow a sender. The loaned form has the owned layout, so this is a pointer cast.
///
/// # Safety
/// `this_` is null or an owned sender.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_e2e_sender_loan(
    this_: *const wz_ext_owned_e2e_sender_t,
) -> *const wz_ext_loaned_e2e_sender_t {
    this_.cast::<wz_ext_loaned_e2e_sender_t>()
}

/// The moved form of a sender, for `wz_ext_e2e_sender_drop`: a cast, which nulls nothing.
///
/// # Safety
/// `this_` is null or an owned sender.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_e2e_sender_move(
    this_: *mut wz_ext_owned_e2e_sender_t,
) -> *mut wz_ext_moved_e2e_sender_t {
    this_.cast::<wz_ext_moved_e2e_sender_t>()
}

/// Release a sender and leave the gravestone. A second drop, and a drop of the gravestone, do
/// nothing.
///
/// # Safety
/// `this_` is null or a moved sender.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_e2e_sender_drop(this_: *mut wz_ext_moved_e2e_sender_t) {
    let _ = guarded(|| {
        if !this_.is_null() {
            release::<StreamSender>(core::ptr::addr_of_mut!((*this_)._this.handle));
        }
        Z_OK
    });
}

/// Write the gravestone.
///
/// # Safety
/// `this_` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_internal_e2e_sender_null(this_: *mut wz_ext_owned_e2e_sender_t) {
    if !this_.is_null() {
        (*this_).handle = core::ptr::null_mut();
    }
}

/// Whether the slot holds a sender.
///
/// # Safety
/// `this_` is null or an owned sender.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_internal_e2e_sender_check(
    this_: *const wz_ext_owned_e2e_sender_t,
) -> bool {
    guard_val(false, || !this_.is_null() && !(*this_).handle.is_null())
}
