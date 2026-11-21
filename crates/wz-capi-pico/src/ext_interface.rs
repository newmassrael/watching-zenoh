// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_interface_*`: what the doors of the additional features ask of the core beyond the
//! pico ABI, as a versioned C interface.
//!
//! The additional features are the end-to-end protection, the reception supervision, the instance
//! key, the replay cache and the message catalog. Their doors are layered over the core: a door
//! names the core through the pico ABI's public functions and types and through this module, and
//! the core names none of them (`scripts/lib/layer_direction_gate.py` holds both). So the features
//! can be built as a library of their own, which calls this interface through C as the doors call
//! it through Rust here.
//!
//! # The shape of every door here
//!
//! - A session and a payload cross as the pico ABI's loans: the core made them and frees them.
//! - What the core answers is written into storage the caller supplies; a struct the caller
//!   supplies states its own size in its first field, so a caller and a core of different minor
//!   versions agree on what was written.
//! - Nothing allocated on one side is freed on the other, and no Rust type crosses.
//!
//! # Versions
//!
//! `wz_ext_interface_version` answers a major and a minor number. The major moves when a door or a
//! field changes meaning or goes; the minor when one is added, a field always at the end of its
//! struct. A library written against major M and minor N runs over a core of major M and minor N
//! or later.
//!
//! The major version is also the name of a function the core exports, `wz_ext_interface_major_1`
//! for major 1. The doors of the additional features call it, so a library of them built apart
//! from the core (`docs/capi-pico-additional-library.md`) names it among its imports, and the
//! system's loader refuses to load that library over a core of another major version before any
//! door runs. A minor version adds functions, which that library imports by name too, so a core
//! older than its minor version is refused the same way. `wz_ext_additional_interface` asks both
//! at run time.

use core::ffi::c_void;
use core::mem::size_of;

use crate::abi::z_loaned_bytes_t;
use crate::bytes::bytes_ref;
use crate::ffi::{guarded, InCallback};
use crate::result::{ZResult, Z_EINVAL, Z_ERR_NULL, Z_OK};
#[cfg(feature = "query")]
use crate::session::{session_handle, z_loaned_session_t};

/// The major version of this interface.
pub const WZ_EXT_INTERFACE_MAJOR: u16 = 1;
/// The minor version of this interface.
pub const WZ_EXT_INTERFACE_MINOR: u16 = 0;

/// `replay_reply_shape` of the session facts: one reply per frame, as it was sent.
pub const WZ_EXT_REPLAY_SHAPE_FRAME_PER_SAMPLE: u8 = 0;
/// `replay_reply_shape` of the session facts: each frame as the pieces of its segment profile.
pub const WZ_EXT_REPLAY_SHAPE_SEGMENTED: u8 = 1;
/// `replay_live_before_answer` of the session facts: a live sample is handed on as it arrives.
pub const WZ_EXT_REPLAY_LIVE_DELIVER: u8 = 0;
/// `replay_live_before_answer` of the session facts: live samples wait for the first round.
pub const WZ_EXT_REPLAY_LIVE_HOLD_BACK: u8 = 1;

/// The version of this interface. 8 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct wz_ext_interface_version_t {
    /// In: the size of this struct as the caller was compiled with it. Out: the bytes written.
    pub struct_size: u32,
    pub major: u16,
    pub minor: u16,
}

/// What the core says of a session that a door of the additional features reads. 24 bytes on a
/// 64-bit target, 20 on a 32-bit one.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct wz_ext_session_facts_t {
    /// In: the size of this struct as the caller was compiled with it. Out: the bytes written.
    pub struct_size: u32,
    /// 1 once the session has been closed, 0 while it is open.
    pub closed: u8,
    /// The session's `replay-reply-shape`: `WZ_EXT_REPLAY_SHAPE_FRAME_PER_SAMPLE` or `_SEGMENTED`.
    pub replay_reply_shape: u8,
    /// The session's `replay-serve-holds-sends`: 1 on, 0 off.
    pub replay_serve_holds_sends: u8,
    /// The session's `replay-live-before-answer`: `WZ_EXT_REPLAY_LIVE_DELIVER` or `_HOLD_BACK`.
    pub replay_live_before_answer: u8,
    /// 1 when a get the session asks may be addressed to one node (`wz_ext_get_to_peer`): the
    /// session's `targeted-query` is on, in a build whose domain of it holds on.
    pub targeted_query: u8,
    pub reserved: [u8; 7],
    /// How many queries one querier of the session may have in flight at once, 0 for no bound.
    pub querier_max_pending_queries: usize,
}

/// Whether a caller's struct of `stated` bytes holds every field this version writes into `T`.
fn holds<T>(stated: u32) -> bool {
    usize::try_from(stated).is_ok_and(|stated| stated >= size_of::<T>())
}

/// The size this version writes of `T`, as its `struct_size` says it.
fn written<T>() -> u32 {
    // Every struct of this interface is a few dozen bytes.
    size_of::<T>() as u32
}

/// Write the version of this interface into `out`, whose `struct_size` the caller has set.
///
/// Returns `Z_OK`; `Z_ERR_NULL` for a null `out`; `Z_EINVAL` when `struct_size` is smaller than
/// the struct of this version, and nothing is written.
///
/// # Safety
/// `out` is null or valid and writable for `struct_size` bytes.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_interface_version(out: *mut wz_ext_interface_version_t) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ERR_NULL;
        }
        if !holds::<wz_ext_interface_version_t>((*out).struct_size) {
            return Z_EINVAL;
        }
        *out = wz_ext_interface_version_t {
            struct_size: written::<wz_ext_interface_version_t>(),
            major: WZ_EXT_INTERFACE_MAJOR,
            minor: WZ_EXT_INTERFACE_MINOR,
        };
        Z_OK
    })
}

/// The major version of this interface, exported under a name that carries it: a library that calls
/// it cannot be loaded over a core of another major version, whose function has another name.
#[no_mangle]
pub extern "C" fn wz_ext_interface_major_1() -> u16 {
    WZ_EXT_INTERFACE_MAJOR
}

/// Write what the core says of `session` into `out`, whose `struct_size` the caller has set. A
/// closed session is answered too, with `closed` 1. In a build with the requesting end of a
/// query, which every door that reads it has.
///
/// Returns `Z_OK`; `Z_ERR_NULL` for a null `out`, a null session or the gravestone; `Z_EINVAL`
/// when `struct_size` is smaller than the struct of this version. Nothing is written on a
/// refusal.
///
/// # Safety
/// `session` is null or a loaned session of this library; `out` is null or valid and writable for
/// `struct_size` bytes.
#[cfg(feature = "query")]
#[no_mangle]
pub unsafe extern "C" fn wz_ext_interface_session_facts(
    session: *const z_loaned_session_t,
    out: *mut wz_ext_session_facts_t,
) -> ZResult {
    use wz_session_core::policy::{ReplayLiveBeforeAnswer, ReplayReplyShape};

    guarded(|| {
        if out.is_null() {
            return Z_ERR_NULL;
        }
        if !holds::<wz_ext_session_facts_t>((*out).struct_size) {
            return Z_EINVAL;
        }
        let Some(handle) = session_handle(session) else {
            return Z_ERR_NULL;
        };
        let policy = &handle.ext.policy;
        *out = wz_ext_session_facts_t {
            struct_size: written::<wz_ext_session_facts_t>(),
            closed: u8::from(handle.is_closed()),
            replay_reply_shape: match policy.replay_reply_shape() {
                ReplayReplyShape::FramePerSample => WZ_EXT_REPLAY_SHAPE_FRAME_PER_SAMPLE,
                ReplayReplyShape::Segmented => WZ_EXT_REPLAY_SHAPE_SEGMENTED,
            },
            replay_serve_holds_sends: u8::from(policy.replay_serve_holds_sends()),
            replay_live_before_answer: match policy.replay_live_before_answer() {
                ReplayLiveBeforeAnswer::Deliver => WZ_EXT_REPLAY_LIVE_DELIVER,
                ReplayLiveBeforeAnswer::HoldBack => WZ_EXT_REPLAY_LIVE_HOLD_BACK,
            },
            targeted_query: u8::from(crate::get_to_peer::targeted_by(policy)),
            reserved: [0; 7],
            querier_max_pending_queries: wz_session_core::caps::QUERIER_MAX_PENDING_QUERIES,
        };
        Z_OK
    })
}

/// Write where the bytes of `bytes` are into `*data` and `*len`, in place: the payload is one
/// buffer in this library, so the view is the whole payload and nothing is copied, valid while
/// the loan is. An empty payload is a length of 0.
///
/// Returns `Z_OK`; `Z_ERR_NULL` for a null `data` or `len`, and for a null payload or the
/// gravestone, with `*data` null and `*len` 0.
///
/// # Safety
/// `bytes` is null or a loaned payload of this library; `data` and `len` are null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_interface_bytes_view(
    bytes: *const z_loaned_bytes_t,
    data: *mut *const u8,
    len: *mut usize,
) -> ZResult {
    guarded(|| {
        if data.is_null() || len.is_null() {
            return Z_ERR_NULL;
        }
        *data = core::ptr::null();
        *len = 0;
        let Some(buf) = bytes_ref(bytes) else {
            return Z_ERR_NULL;
        };
        let view = buf.as_slice();
        *data = view.as_ptr();
        *len = view.len();
        Z_OK
    })
}

/// Run `body(context)` as one of the program's callbacks, on the calling thread: a door of the
/// core that waits for the program's callbacks to finish (an undeclare, a close) returns without
/// waiting when `body` calls it, as it does inside a callback the core runs itself, since the
/// wait would be for the callback that is waiting.
///
/// Returns `Z_OK` once `body` has returned; `Z_ERR_NULL` for no `body`, which runs nothing.
///
/// # Safety
/// `body` is null or safe to call with `context`.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_interface_run_in_callback(
    body: Option<unsafe extern "C" fn(context: *mut c_void)>,
    context: *mut c_void,
) -> ZResult {
    let Some(body) = body else {
        return Z_ERR_NULL;
    };
    let _in_callback = InCallback::enter();
    // `body` is a C function: nothing unwinds out of it into this frame.
    body(context);
    Z_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_structs_have_the_layout_the_header_declares() {
        assert_eq!(size_of::<wz_ext_interface_version_t>(), 8);
        assert_eq!(core::mem::offset_of!(wz_ext_session_facts_t, closed), 4);
        assert_eq!(
            core::mem::offset_of!(wz_ext_session_facts_t, targeted_query),
            8
        );
        assert_eq!(
            core::mem::offset_of!(wz_ext_session_facts_t, querier_max_pending_queries),
            16
        );
        assert_eq!(size_of::<wz_ext_session_facts_t>(), 16 + size_of::<usize>());
    }

    #[test]
    fn the_function_named_by_the_major_version_answers_it() {
        assert_eq!(wz_ext_interface_major_1(), WZ_EXT_INTERFACE_MAJOR);
        assert_eq!(
            WZ_EXT_INTERFACE_MAJOR, 1,
            "a new major version renames wz_ext_interface_major_1 with its number"
        );
    }

    #[test]
    fn the_version_is_written_for_a_caller_that_states_its_size() {
        let mut version = wz_ext_interface_version_t {
            struct_size: 8,
            major: 0,
            minor: 0,
        };
        // SAFETY: a local the door may write.
        assert_eq!(unsafe { wz_ext_interface_version(&mut version) }, Z_OK);
        assert_eq!(
            version,
            wz_ext_interface_version_t {
                struct_size: 8,
                major: WZ_EXT_INTERFACE_MAJOR,
                minor: WZ_EXT_INTERFACE_MINOR,
            }
        );
    }

    #[test]
    fn a_struct_smaller_than_this_version_s_is_refused_and_left_as_it_was() {
        let stale = wz_ext_interface_version_t {
            struct_size: 7,
            major: 9,
            minor: 9,
        };
        let mut version = stale;
        // SAFETY: a local the door may write, and a null pointer.
        unsafe {
            assert_eq!(wz_ext_interface_version(&mut version), Z_EINVAL);
            assert_eq!(wz_ext_interface_version(core::ptr::null_mut()), Z_ERR_NULL);
        }
        assert_eq!(version, stale);
    }

    #[test]
    fn a_later_caller_s_larger_struct_is_told_how_much_was_written() {
        #[repr(C)]
        struct Later {
            version: wz_ext_interface_version_t,
            added: u32,
        }
        let mut later = Later {
            version: wz_ext_interface_version_t {
                struct_size: size_of::<Later>() as u32,
                major: 0,
                minor: 0,
            },
            added: 0xdead_beef,
        };
        // SAFETY: the caller's struct is writable for the size it states.
        assert_eq!(
            unsafe { wz_ext_interface_version(&mut later.version) },
            Z_OK
        );
        assert_eq!(later.version.struct_size, 8);
        assert_eq!(later.version.major, WZ_EXT_INTERFACE_MAJOR);
        assert_eq!(
            later.added, 0xdead_beef,
            "a field this version has not is untouched"
        );
    }

    #[cfg(feature = "query")]
    #[test]
    fn the_facts_of_no_session_are_refused_and_nothing_is_written() {
        let blank = wz_ext_session_facts_t {
            struct_size: size_of::<wz_ext_session_facts_t>() as u32,
            closed: 7,
            replay_reply_shape: 7,
            replay_serve_holds_sends: 7,
            replay_live_before_answer: 7,
            targeted_query: 7,
            reserved: [7; 7],
            querier_max_pending_queries: 7,
        };
        let mut facts = blank;
        // SAFETY: a local the doors may write, a null session and a gravestone's loan.
        unsafe {
            let mut gravestone: crate::session::z_owned_session_t = core::mem::zeroed();
            crate::session::z_internal_session_null(&mut gravestone);
            assert_eq!(
                wz_ext_interface_session_facts(core::ptr::null(), &mut facts),
                Z_ERR_NULL
            );
            assert_eq!(
                wz_ext_interface_session_facts(
                    crate::session::z_session_loan(&gravestone),
                    &mut facts
                ),
                Z_ERR_NULL
            );
            assert_eq!(
                wz_ext_interface_session_facts(core::ptr::null(), core::ptr::null_mut()),
                Z_ERR_NULL
            );
            facts.struct_size = 4;
            assert_eq!(
                wz_ext_interface_session_facts(core::ptr::null(), &mut facts),
                Z_EINVAL,
                "the size is judged before the session"
            );
        }
        assert_eq!(
            facts,
            wz_ext_session_facts_t {
                struct_size: 4,
                ..blank
            }
        );
    }

    #[test]
    fn a_payload_is_viewed_in_place() {
        let mut payload: crate::abi::z_owned_bytes_t = unsafe { core::mem::zeroed() };
        let text = b"frame";
        let mut data = core::ptr::null::<u8>();
        let mut len = usize::MAX;
        // SAFETY: locals the doors may write; the payload is dropped before it goes.
        unsafe {
            assert_eq!(
                crate::bytes::z_bytes_copy_from_buf(&mut payload, text.as_ptr(), text.len()),
                Z_OK
            );
            let loaned = crate::bytes::z_bytes_loan(&payload);
            assert_eq!(
                wz_ext_interface_bytes_view(loaned, &mut data, &mut len),
                Z_OK
            );
            assert_eq!(core::slice::from_raw_parts(data, len), text);
            assert_eq!(
                data,
                bytes_ref(loaned).expect("a payload").as_slice().as_ptr(),
                "the view is the payload's own buffer"
            );
            crate::bytes::z_bytes_drop(crate::bytes::z_bytes_move(&mut payload));
        }
    }

    #[test]
    fn no_payload_is_refused_with_an_empty_view() {
        let stale = 0u8;
        let mut data: *const u8 = &stale;
        let mut len = 9usize;
        // SAFETY: locals the door may write, and null pointers.
        unsafe {
            assert_eq!(
                wz_ext_interface_bytes_view(core::ptr::null(), &mut data, &mut len),
                Z_ERR_NULL
            );
            assert!(data.is_null());
            assert_eq!(len, 0);
            assert_eq!(
                wz_ext_interface_bytes_view(core::ptr::null(), core::ptr::null_mut(), &mut len),
                Z_ERR_NULL
            );
        }
    }

    #[test]
    fn the_body_runs_as_a_callback_and_the_mark_is_gone_after() {
        unsafe extern "C" fn probe(context: *mut c_void) {
            *context.cast::<bool>() = InCallback::here();
        }
        let mut inside = false;
        assert!(!InCallback::here());
        // SAFETY: the probe writes the local it is handed, for the call.
        let code = unsafe {
            wz_ext_interface_run_in_callback(
                Some(probe),
                core::ptr::addr_of_mut!(inside).cast::<c_void>(),
            )
        };
        assert_eq!(code, Z_OK);
        assert!(inside, "the body ran inside the mark");
        assert!(!InCallback::here(), "the mark ends with the body");
        // SAFETY: no body is named.
        assert_eq!(
            unsafe { wz_ext_interface_run_in_callback(None, core::ptr::null_mut()) },
            Z_ERR_NULL
        );
    }
}
