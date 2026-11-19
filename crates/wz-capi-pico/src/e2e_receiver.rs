// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_e2e_receiver_*`: the RECEIVING judge of end-to-end protected frames, from C. Every frame
//! the program hands over is judged in the state the receiver keeps for each stream, or for each
//! sender, and the verdict is written beside the payload, which is reported whatever it says.
//!
//! A door wz has and zenoh-pico does not, so each is `wz_ext_*`, declared in `wz_ext.h`, and part
//! of the unstable surface: the `e2e-receiver` capability implies `unstable-api`. Its sender slots
//! are `e2e-sender-demux`; a build without them refuses sender keying by name
//! (`WZ_EXT_ERR_UNSUPPORTED`). The judge is [`wz_app_frame::e2e_receiver`]; ownership and threads
//! are as `crate::e2e` describes.

use core::ffi::{c_char, c_void};

use wz_app_frame::e2e_frame::Values;
use wz_app_frame::e2e_profile::Profile;
use wz_app_frame::e2e_receiver::{Keying, Receiver, Status, Unslotted, Verdict};

use crate::abi::z_owned_string_t;
use crate::e2e::{
    adopt, behind, bytes_arg, clear_refusal, locked, release, utf8_arg, write_refusal,
};
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_NULL, Z_OK};

/// The caller names the stream of every frame: one per message, or per instance of it.
pub const WZ_EXT_E2E_KEYING_INDEXED: u8 = 0;
/// One stream per sender, slots taken in arrival order by intact frames (`e2e-sender-demux`).
pub const WZ_EXT_E2E_KEYING_SENDERS_ARRIVAL: u8 = 1;
/// One stream per sender, slots bound to the listed senders (`e2e-sender-demux`).
pub const WZ_EXT_E2E_KEYING_SENDERS_BOUND: u8 = 2;

/// Intact, and the next frame of its stream.
pub const WZ_EXT_E2E_OK: u8 = 0;
/// Intact, and the first of its stream: the baseline.
pub const WZ_EXT_E2E_FIRST: u8 = 1;
/// Intact, and the same counter again.
pub const WZ_EXT_E2E_REPEATED: u8 = 2;
/// Intact, and a step above the largest gap.
pub const WZ_EXT_E2E_OUT_OF_RANGE: u8 = 3;
/// A repetition or a step out of range, under a profile that reports the two as one.
pub const WZ_EXT_E2E_COUNTER_ERROR: u8 = 4;
/// Not intact: `failed` says which check.
pub const WZ_EXT_E2E_INTEGRITY: u8 = 5;
/// Of a sender no slot holds, so judged in no stream; `unslotted` says why.
pub const WZ_EXT_E2E_UNSLOTTED: u8 = 6;

/// The bits of `failed`.
pub const WZ_EXT_E2E_FAILED_CRC: u8 = wz_app_frame::e2e_receiver::FAILED_CRC;
pub const WZ_EXT_E2E_FAILED_IDENT: u8 = wz_app_frame::e2e_receiver::FAILED_IDENT;
pub const WZ_EXT_E2E_FAILED_LENGTH: u8 = wz_app_frame::e2e_receiver::FAILED_LENGTH;
pub const WZ_EXT_E2E_FAILED_SHORT: u8 = wz_app_frame::e2e_receiver::FAILED_SHORT;

/// The values of `unslotted`.
pub const WZ_EXT_E2E_SLOTTED: u8 = 0;
pub const WZ_EXT_E2E_NOT_LISTED: u8 = 1;
pub const WZ_EXT_E2E_SLOTS_FULL: u8 = 2;

/// The bits of `has`: which of the optional numbers of a verdict hold a value.
pub const WZ_EXT_E2E_HAS_COUNTER: u8 = 1;
pub const WZ_EXT_E2E_HAS_STEP: u8 = 2;
pub const WZ_EXT_E2E_HAS_KIND: u8 = 4;
pub const WZ_EXT_E2E_HAS_RESULT: u8 = 8;
pub const WZ_EXT_E2E_HAS_SENDER: u8 = 16;
pub const WZ_EXT_E2E_HAS_STREAM: u8 = 32;
pub const WZ_EXT_E2E_HAS_SILENCE: u8 = 64;

/// An owned receiver: the handle in its one word, null for the gravestone.
#[repr(C)]
pub struct wz_ext_owned_e2e_receiver_t {
    pub(crate) handle: *mut c_void,
}

/// A loaned receiver: the owned layout, so the loan is a pointer cast.
#[repr(C)]
pub struct wz_ext_loaned_e2e_receiver_t {
    pub(crate) handle: *mut c_void,
}

/// A moved receiver (pico's `z_moved_*_t` shape).
#[repr(C)]
pub struct wz_ext_moved_e2e_receiver_t {
    pub(crate) _this: wz_ext_owned_e2e_receiver_t,
}

/// How a receiver is made.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct wz_ext_e2e_receiver_options_t {
    /// The largest gap, in place of the profile's own and at most its ceiling; 0 for the
    /// profile's.
    pub max_gap: u64,
    /// The senders the slots are bound to, for `WZ_EXT_E2E_KEYING_SENDERS_BOUND`; BORROWED for the
    /// call.
    pub senders: *const u64,
    /// How many `senders` there are.
    pub senders_len: usize,
    /// How many streams (indexed keying) or sender slots (sender keying), at least 1. The storage
    /// is allocated once, here.
    pub streams: usize,
    /// A `WZ_EXT_E2E_KEYING_*` value.
    pub keying: u8,
}

impl Default for wz_ext_e2e_receiver_options_t {
    fn default() -> Self {
        Self {
            max_gap: 0,
            senders: core::ptr::null(),
            senders_len: 0,
            streams: 1,
            keying: WZ_EXT_E2E_KEYING_INDEXED,
        }
    }
}

/// The verdict on one frame, as C reads it. A number whose `has` bit is clear is 0.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct wz_ext_e2e_verdict_t {
    /// A `WZ_EXT_E2E_*` status.
    pub status: u8,
    /// The `WZ_EXT_E2E_FAILED_*` bits of the integrity checks the frame failed.
    pub failed: u8,
    /// The `WZ_EXT_E2E_HAS_*` bits.
    pub has: u8,
    /// 1 when the silence before the frame exceeded the profile's timeout.
    pub timeout: u8,
    /// For `WZ_EXT_E2E_UNSLOTTED`, why: `WZ_EXT_E2E_NOT_LISTED` or `_SLOTS_FULL`.
    pub unslotted: u8,
    pub reserved: [u8; 3],
    /// The counter the frame carries.
    pub counter: u64,
    /// The step from the stream's baseline.
    pub step: u64,
    /// The kind, the result and the sender identity of the message cell.
    pub kind: u64,
    pub result: u64,
    pub sender: u64,
    /// The silence before the frame, in milliseconds.
    pub silence_ms: u64,
    /// The stream, or the sender slot, the frame was judged in.
    pub stream: usize,
    /// Where the payload starts in the frame, and how long it is: the payload is reported whatever
    /// the status.
    pub payload_offset: usize,
    pub payload_len: usize,
}

/// The most sender slots a receiver of this build keeps.
#[cfg(feature = "e2e-sender-demux")]
pub(crate) const SLOT_LIMIT: usize = wz_session_core::caps::E2E_SENDER_SLOTS;
#[cfg(not(feature = "e2e-sender-demux"))]
pub(crate) const SLOT_LIMIT: usize = 0;

/// The handle word of a loaned receiver.
fn word(this_: *const wz_ext_loaned_e2e_receiver_t) -> *const *mut c_void {
    this_.cast::<*mut c_void>()
}

/// Box a made receiver behind the caller's handle word.
pub(crate) fn adopt_receiver(this_: &mut wz_ext_owned_e2e_receiver_t, receiver: Receiver) {
    this_.handle = adopt(receiver);
}

/// The sender keying the options state; `WZ_EXT_ERR_UNSUPPORTED` in a build without the
/// receiver's sender slots.
///
/// # Safety
/// `options.senders` is null or readable for `options.senders_len` values.
#[cfg(feature = "e2e-sender-demux")]
unsafe fn sender_keying(options: &wz_ext_e2e_receiver_options_t) -> Result<Keying, ZResult> {
    let bound = if options.keying == WZ_EXT_E2E_KEYING_SENDERS_BOUND {
        if options.senders.is_null() && options.senders_len != 0 {
            return Err(Z_EINVAL);
        }
        let list: &[u64] = if options.senders_len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(options.senders, options.senders_len)
        };
        Some(list.to_vec())
    } else {
        None
    };
    Ok(Keying::Senders {
        slots: options.streams,
        bound,
    })
}

#[cfg(not(feature = "e2e-sender-demux"))]
unsafe fn sender_keying(_options: &wz_ext_e2e_receiver_options_t) -> Result<Keying, ZResult> {
    Err(crate::result::WZ_EXT_ERR_UNSUPPORTED)
}

/// Fill in the default receiver options: one stream named by the caller, the profile's gap.
///
/// # Safety
/// `this_` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_e2e_receiver_options_default(
    this_: *mut wz_ext_e2e_receiver_options_t,
) {
    if !this_.is_null() {
        *this_ = wz_ext_e2e_receiver_options_t::default();
    }
}

/// A receiver of the frames the profile `profile_json` describes, made as `options` says (null:
/// the defaults). `expected_json` gives the identifier field the profile's `judge.ident` names, in
/// the values shape a sender's values text has (other fields it states are not read, so both ends
/// may be handed one text); it may be null when the profile judges no identifier.
///
/// `this_` holds the gravestone on every error. `refusal` may be null; when it is not, it holds the
/// gravestone on success and, on `_Z_ERR_CONFIG_INVALID_VALUE`, the reason, beginning `profile`,
/// `expected` or naming the option refused.
///
/// Returns `Z_ERR_NULL` for a null `this_` or `profile_json`; `Z_EINVAL` for text that is not
/// UTF-8, a keying this library does not know, or a null `senders` with a length;
/// `WZ_EXT_ERR_UNSUPPORTED` for sender keying in a build without `e2e-sender-demux`;
/// `_Z_ERR_CONFIG_INVALID_VALUE` for a profile, expected values or option that is refused (no
/// stream, a gap above the profile's ceiling, sender keying under a profile whose cell names no
/// sender, more slots than `E2E_SENDER_SLOTS`, a bound list that does not fit); `Z_OK` otherwise.
///
/// # Safety
/// `this_` is writable; `profile_json` and `expected_json` are null or NUL-terminated C strings;
/// `options` is null or valid, its `senders` readable for `senders_len` values; `refusal` is null
/// or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_e2e_receiver_new(
    this_: *mut wz_ext_owned_e2e_receiver_t,
    profile_json: *const c_char,
    expected_json: *const c_char,
    options: *const wz_ext_e2e_receiver_options_t,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        clear_refusal(refusal);
        if this_.is_null() {
            return Z_ERR_NULL;
        }
        (*this_).handle = core::ptr::null_mut();
        if profile_json.is_null() {
            return Z_ERR_NULL;
        }
        let Some(profile) = utf8_arg(profile_json) else {
            return Z_EINVAL;
        };
        let expected = if expected_json.is_null() {
            None
        } else {
            let Some(text) = utf8_arg(expected_json) else {
                return Z_EINVAL;
            };
            Some(text)
        };
        let options = if options.is_null() {
            wz_ext_e2e_receiver_options_t::default()
        } else {
            *options
        };
        let keying = match options.keying {
            WZ_EXT_E2E_KEYING_INDEXED => Keying::Indexed {
                streams: options.streams,
            },
            WZ_EXT_E2E_KEYING_SENDERS_ARRIVAL | WZ_EXT_E2E_KEYING_SENDERS_BOUND => {
                match sender_keying(&options) {
                    Ok(keying) => keying,
                    Err(code) => return code,
                }
            }
            _ => return Z_EINVAL,
        };
        let profile = match Profile::parse(profile) {
            Ok(p) => p,
            Err(e) => {
                write_refusal(refusal, &format!("profile: {e}"));
                return Z_ERR_CONFIG_INVALID_VALUE;
            }
        };
        let expected = match expected.map(Values::parse).transpose() {
            Ok(v) => v.unwrap_or_default(),
            Err(e) => {
                write_refusal(refusal, &format!("expected: {e}"));
                return Z_ERR_CONFIG_INVALID_VALUE;
            }
        };
        let max_gap = (options.max_gap != 0).then_some(options.max_gap);
        match Receiver::new(profile, &expected, keying, max_gap, SLOT_LIMIT) {
            Ok(receiver) => {
                adopt_receiver(&mut *this_, receiver);
                Z_OK
            }
            Err(why) => {
                write_refusal(refusal, &format!("{why}"));
                Z_ERR_CONFIG_INVALID_VALUE
            }
        }
    })
}

/// The C form of a verdict; the instance keys' judging door writes it too.
pub(crate) fn to_c(verdict: &Verdict) -> wz_ext_e2e_verdict_t {
    let mut out = wz_ext_e2e_verdict_t {
        status: match verdict.status {
            Status::Ok => WZ_EXT_E2E_OK,
            Status::First => WZ_EXT_E2E_FIRST,
            Status::Repeated => WZ_EXT_E2E_REPEATED,
            Status::OutOfRange => WZ_EXT_E2E_OUT_OF_RANGE,
            Status::CounterError => WZ_EXT_E2E_COUNTER_ERROR,
            Status::Integrity => WZ_EXT_E2E_INTEGRITY,
            Status::Unslotted => WZ_EXT_E2E_UNSLOTTED,
        },
        failed: verdict.failed,
        timeout: u8::from(verdict.timeout),
        unslotted: match verdict.unslotted {
            None => WZ_EXT_E2E_SLOTTED,
            Some(Unslotted::NotListed) => WZ_EXT_E2E_NOT_LISTED,
            Some(Unslotted::Full) => WZ_EXT_E2E_SLOTS_FULL,
        },
        payload_offset: verdict.payload_offset,
        payload_len: verdict.payload_bytes,
        ..wz_ext_e2e_verdict_t::default()
    };
    let mut has = 0u8;
    let mut take = |bit: u8, value: Option<u64>| {
        if value.is_some() {
            has |= bit;
        }
        value.unwrap_or(0)
    };
    out.counter = take(WZ_EXT_E2E_HAS_COUNTER, verdict.counter);
    out.step = take(WZ_EXT_E2E_HAS_STEP, verdict.step);
    out.kind = take(WZ_EXT_E2E_HAS_KIND, verdict.kind);
    out.result = take(WZ_EXT_E2E_HAS_RESULT, verdict.result);
    out.sender = take(WZ_EXT_E2E_HAS_SENDER, verdict.sender);
    out.silence_ms = take(WZ_EXT_E2E_HAS_SILENCE, verdict.silence_ms);
    if let Some(stream) = verdict.stream {
        has |= WZ_EXT_E2E_HAS_STREAM;
        out.stream = stream;
    }
    out.has = has;
    out
}

/// Judge `frame`, received at `now_ms` on `stream`, and write the verdict to `out`. Under sender
/// keying the receiver chooses the stream, and `stream` must be 0.
///
/// Returns `Z_OK` with the verdict, whatever it says; `Z_EINVAL` for a stream the receiver does
/// not have (the verdict is zeroed and nothing moved); `Z_ERR_NULL` for a null receiver or `out`,
/// the gravestone, or a null frame with a length.
///
/// # Safety
/// `this_` is null or a loaned receiver; `frame` is readable for `len` bytes; `out` is null or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_e2e_receiver_judge(
    this_: *const wz_ext_loaned_e2e_receiver_t,
    stream: usize,
    frame: *const u8,
    len: usize,
    now_ms: u64,
    out: *mut wz_ext_e2e_verdict_t,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ERR_NULL;
        }
        *out = wz_ext_e2e_verdict_t::default();
        let Some(receiver) = behind::<Receiver>(word(this_)) else {
            return Z_ERR_NULL;
        };
        if frame.is_null() && len != 0 {
            return Z_ERR_NULL;
        }
        match locked(receiver).receive(stream, bytes_arg(frame, len), now_ms) {
            Ok(verdict) => {
                *out = to_c(&verdict);
                Z_OK
            }
            Err(_) => Z_EINVAL,
        }
    })
}

/// How many frames were judged in no slot: of a sender a bound list does not name, and of a sender
/// for whom every slot was taken. Either out may be null. `Z_ERR_NULL` for a null receiver or the
/// gravestone.
///
/// # Safety
/// `this_` is null or a loaned receiver; `not_listed` and `full` are null or writable.
#[cfg(feature = "e2e-sender-demux")]
#[no_mangle]
pub unsafe extern "C" fn wz_ext_e2e_receiver_counts(
    this_: *const wz_ext_loaned_e2e_receiver_t,
    not_listed: *mut u64,
    full: *mut u64,
) -> ZResult {
    guarded(|| {
        let Some(receiver) = behind::<Receiver>(word(this_)) else {
            return Z_ERR_NULL;
        };
        let counts = locked(receiver).counts();
        if !not_listed.is_null() {
            *not_listed = counts.not_listed;
        }
        if !full.is_null() {
            *full = counts.full;
        }
        Z_OK
    })
}

/// The sender identity a slot holds. Returns `false`, and writes nothing, for a free slot, a slot
/// the receiver does not have, a receiver keyed by index, or a null argument.
///
/// # Safety
/// `this_` is null or a loaned receiver; `out` is null or writable.
#[cfg(feature = "e2e-sender-demux")]
#[no_mangle]
pub unsafe extern "C" fn wz_ext_e2e_receiver_slot_sender(
    this_: *const wz_ext_loaned_e2e_receiver_t,
    slot: usize,
    out: *mut u64,
) -> bool {
    guard_val(false, || {
        if out.is_null() {
            return false;
        }
        let Some(receiver) = behind::<Receiver>(word(this_)) else {
            return false;
        };
        let Some(sender) = locked(receiver).slot_sender(slot) else {
            return false;
        };
        *out = sender;
        true
    })
}

/// Borrow a receiver. The loaned form has the owned layout, so this is a pointer cast.
///
/// # Safety
/// `this_` is null or an owned receiver.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_e2e_receiver_loan(
    this_: *const wz_ext_owned_e2e_receiver_t,
) -> *const wz_ext_loaned_e2e_receiver_t {
    this_.cast::<wz_ext_loaned_e2e_receiver_t>()
}

/// The moved form of a receiver, for `wz_ext_e2e_receiver_drop`: a cast, which nulls nothing.
///
/// # Safety
/// `this_` is null or an owned receiver.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_e2e_receiver_move(
    this_: *mut wz_ext_owned_e2e_receiver_t,
) -> *mut wz_ext_moved_e2e_receiver_t {
    this_.cast::<wz_ext_moved_e2e_receiver_t>()
}

/// Release a receiver and leave the gravestone. A second drop, and a drop of the gravestone, do
/// nothing.
///
/// # Safety
/// `this_` is null or a moved receiver.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_e2e_receiver_drop(this_: *mut wz_ext_moved_e2e_receiver_t) {
    let _ = guarded(|| {
        if !this_.is_null() {
            release::<Receiver>(core::ptr::addr_of_mut!((*this_)._this.handle));
        }
        Z_OK
    });
}

/// Write the gravestone.
///
/// # Safety
/// `this_` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_internal_e2e_receiver_null(
    this_: *mut wz_ext_owned_e2e_receiver_t,
) {
    if !this_.is_null() {
        (*this_).handle = core::ptr::null_mut();
    }
}

/// Whether the slot holds a receiver.
///
/// # Safety
/// `this_` is null or an owned receiver.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_internal_e2e_receiver_check(
    this_: *const wz_ext_owned_e2e_receiver_t,
) -> bool {
    guard_val(false, || !this_.is_null() && !(*this_).handle.is_null())
}
