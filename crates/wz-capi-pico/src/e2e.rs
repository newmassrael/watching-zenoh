// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the end-to-end protection doors share with the other doors of the additional features:
//! the argument readers, the refusal slot and the handle word, and what the replay doors read of
//! the core. The doors are each capability's own module, as every wz door of this ABI is:
//! `crate::e2e_sender` (`e2e-sender`) and `crate::e2e_receiver` (`e2e-receiver`, with its
//! sender slots under `e2e-sender-demux`).
//!
//! The mechanism is `wz-app-frame`'s ([`wz_app_frame::e2e_stream_sender`],
//! [`wz_app_frame::e2e_receiver`]); the two door modules are the pico ABI's names, result codes and
//! ownership around it. The profile, the header values and the expected identifier are runtime data
//! the program hands over as JSON text: the library holds no deployment's constants.
//!
//! These doors are a layer over the core: what they need of it they take through the pico ABI's
//! public functions and the extension interface (`crate::ext_interface`), never through the core's
//! own helpers, so the refusal text a door writes is a string the core's `z_string_*` made.
//!
//! # Ownership and threads
//!
//! `*_new` makes an owned handle, every door that uses it takes the loan, and `*_drop` releases it
//! through the moved form and leaves the gravestone, so a second drop does nothing. One handle may
//! be called from several threads: each call holds the handle's lock for its whole work.

use core::ffi::{c_char, c_void, CStr};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::abi::z_owned_string_t;
use crate::bytes::{z_internal_string_null, z_string_copy_from_substr};

/// Write the gravestone into the caller's refusal slot, when it gave one.
///
/// # Safety
/// `out` is null or writable for a `z_owned_string_t`.
pub(crate) unsafe fn clear_refusal(out: *mut z_owned_string_t) {
    z_internal_string_null(out);
}

/// Write `text` as the caller's refusal, when it gave a slot for one.
///
/// # Safety
/// `out` is null or writable for a `z_owned_string_t`.
pub(crate) unsafe fn write_refusal(out: *mut z_owned_string_t, text: &str) {
    if !out.is_null() {
        // The copy refuses only a null slot or a null text with a length, and neither is here.
        z_string_copy_from_substr(out, text.as_ptr().cast::<c_char>(), text.len());
    }
}

/// A NUL-terminated UTF-8 argument; `None` when it is not UTF-8.
///
/// # Safety
/// `text` is a valid C string.
pub(crate) unsafe fn utf8_arg<'a>(text: *const c_char) -> Option<&'a str> {
    CStr::from_ptr(text).to_str().ok()
}

/// A byte argument as a slice.
///
/// # Safety
/// `bytes` is readable for `len` bytes when `len` is not 0, and non-null then.
pub(crate) unsafe fn bytes_arg<'a>(bytes: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(bytes, len)
    }
}

/// The lock, past a poison: a panic inside a call was caught at the door, and the state behind
/// the lock moves only once a call has succeeded.
pub(crate) fn locked<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The value behind a loaned handle; `None` for a null pointer or the gravestone.
///
/// # Safety
/// `handle` is null or points at a handle word these modules wrote, whose value is null or a live
/// `Mutex<T>` they boxed.
pub(crate) unsafe fn behind<'a, T>(handle: *const *mut c_void) -> Option<&'a Mutex<T>> {
    if handle.is_null() {
        return None;
    }
    let value = *handle;
    if value.is_null() {
        return None;
    }
    Some(&*value.cast::<Mutex<T>>())
}

/// Box `value` behind a handle word.
pub(crate) fn adopt<T>(value: T) -> *mut c_void {
    Box::into_raw(Box::new(Mutex::new(value))).cast::<c_void>()
}

/// Release what a handle word holds and leave it null.
///
/// # Safety
/// `handle` is null or points at a handle word whose value is null or a live `Mutex<T>` these
/// modules boxed.
pub(crate) unsafe fn release<T>(handle: *mut *mut c_void) {
    if handle.is_null() {
        return;
    }
    let value = *handle;
    *handle = core::ptr::null_mut();
    if !value.is_null() {
        drop(Box::from_raw(value.cast::<Mutex<T>>()));
    }
}

/// The text of a loaned key expression, read through the pico ABI; `None` for the gravestone and
/// for text that is not UTF-8.
///
/// # Safety
/// `keyexpr` is null or a loaned key expression of this library, which outlives the text.
#[cfg(feature = "replay-cache")]
pub(crate) unsafe fn keyexpr_text<'a>(
    keyexpr: *const crate::abi::z_loaned_keyexpr_t,
) -> Option<&'a str> {
    use crate::bytes::{z_string_data, z_string_len};
    use crate::keyexpr::{z_keyexpr_as_view_string, z_view_string_loan};

    let mut view: crate::abi::z_view_string_t = core::mem::zeroed();
    if z_keyexpr_as_view_string(keyexpr, &mut view) != crate::result::Z_OK {
        return None;
    }
    let text = z_view_string_loan(&view);
    let data = z_string_data(text);
    if data.is_null() {
        return None;
    }
    core::str::from_utf8(bytes_arg(data.cast::<u8>(), z_string_len(text))).ok()
}

/// What the core says of `session`, through the extension interface; `Err` with the interface's
/// code for a null session or the gravestone.
///
/// # Safety
/// `session` is null or a loaned session of this library.
#[cfg(feature = "replay-cache")]
pub(crate) unsafe fn session_facts(
    session: *const crate::session::z_loaned_session_t,
) -> Result<crate::ext_interface::wz_ext_session_facts_t, crate::result::ZResult> {
    use crate::ext_interface::{wz_ext_interface_session_facts, wz_ext_session_facts_t};

    let mut facts: wz_ext_session_facts_t = core::mem::zeroed();
    // The struct is a few dozen bytes.
    facts.struct_size = core::mem::size_of::<wz_ext_session_facts_t>() as u32;
    match wz_ext_interface_session_facts(session, &mut facts) {
        crate::result::Z_OK => Ok(facts),
        code => Err(code),
    }
}

/// The replay policies of a session, as the core reports them.
#[cfg(feature = "replay-cache")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReplayPolicies {
    pub(crate) reply_shape: wz_session_core::policy::ReplayReplyShape,
    pub(crate) serve_holds_sends: bool,
    pub(crate) live_before_answer: wz_session_core::policy::ReplayLiveBeforeAnswer,
}

#[cfg(feature = "replay-cache")]
impl ReplayPolicies {
    /// The policies `facts` reports; `None` for a value these doors do not know, which only a core
    /// of a later interface than theirs can report.
    pub(crate) fn of(facts: &crate::ext_interface::wz_ext_session_facts_t) -> Option<Self> {
        use crate::ext_interface::{
            WZ_EXT_REPLAY_LIVE_DELIVER, WZ_EXT_REPLAY_LIVE_HOLD_BACK,
            WZ_EXT_REPLAY_SHAPE_FRAME_PER_SAMPLE, WZ_EXT_REPLAY_SHAPE_SEGMENTED,
        };
        use wz_session_core::policy::{ReplayLiveBeforeAnswer, ReplayReplyShape};

        let reply_shape = match facts.replay_reply_shape {
            WZ_EXT_REPLAY_SHAPE_FRAME_PER_SAMPLE => ReplayReplyShape::FramePerSample,
            WZ_EXT_REPLAY_SHAPE_SEGMENTED => ReplayReplyShape::Segmented,
            _ => return None,
        };
        let serve_holds_sends = match facts.replay_serve_holds_sends {
            0 => false,
            1 => true,
            _ => return None,
        };
        let live_before_answer = match facts.replay_live_before_answer {
            WZ_EXT_REPLAY_LIVE_DELIVER => ReplayLiveBeforeAnswer::Deliver,
            WZ_EXT_REPLAY_LIVE_HOLD_BACK => ReplayLiveBeforeAnswer::HoldBack,
            _ => return None,
        };
        Some(Self {
            reply_shape,
            serve_holds_sends,
            live_before_answer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_is_a_string_the_core_made_and_a_cleared_slot_is_the_gravestone() {
        use crate::bytes::{
            z_internal_string_check, z_string_data, z_string_drop, z_string_len, z_string_loan,
            z_string_move,
        };

        // SAFETY: a local slot the helpers and the doors may write, dropped before it goes.
        unsafe {
            let mut slot: z_owned_string_t = core::mem::zeroed();
            write_refusal(&mut slot, "depth: out of range");
            assert!(z_internal_string_check(&slot));
            let text = z_string_loan(&slot);
            assert_eq!(
                bytes_arg(z_string_data(text).cast::<u8>(), z_string_len(text)),
                b"depth: out of range"
            );
            z_string_drop(z_string_move(&mut slot));
            core::ptr::write_bytes(&mut slot, 0xa5, 1);
            assert!(
                z_internal_string_check(&slot),
                "a stale word reads as a string"
            );
            clear_refusal(&mut slot);
            assert!(!z_internal_string_check(&slot));
            write_refusal(core::ptr::null_mut(), "nowhere");
            clear_refusal(core::ptr::null_mut());
        }
    }

    #[cfg(feature = "replay-cache")]
    fn facts(shape: u8, holds: u8, live: u8) -> crate::ext_interface::wz_ext_session_facts_t {
        crate::ext_interface::wz_ext_session_facts_t {
            struct_size: core::mem::size_of::<crate::ext_interface::wz_ext_session_facts_t>()
                as u32,
            closed: 0,
            replay_reply_shape: shape,
            replay_serve_holds_sends: holds,
            replay_live_before_answer: live,
            targeted_query: 0,
            reserved: [0; 7],
            querier_max_pending_queries: 0,
            replay_depth_max: 0,
        }
    }

    #[cfg(feature = "replay-cache")]
    #[test]
    fn the_replay_policies_are_the_codes_the_core_reports() {
        use crate::ext_interface::{
            WZ_EXT_REPLAY_LIVE_DELIVER, WZ_EXT_REPLAY_LIVE_HOLD_BACK,
            WZ_EXT_REPLAY_SHAPE_FRAME_PER_SAMPLE, WZ_EXT_REPLAY_SHAPE_SEGMENTED,
        };
        use wz_session_core::policy::{ReplayLiveBeforeAnswer, ReplayReplyShape};

        assert_eq!(
            ReplayPolicies::of(&facts(
                WZ_EXT_REPLAY_SHAPE_SEGMENTED,
                1,
                WZ_EXT_REPLAY_LIVE_HOLD_BACK
            )),
            Some(ReplayPolicies {
                reply_shape: ReplayReplyShape::Segmented,
                serve_holds_sends: true,
                live_before_answer: ReplayLiveBeforeAnswer::HoldBack,
            })
        );
        assert_eq!(
            ReplayPolicies::of(&facts(
                WZ_EXT_REPLAY_SHAPE_FRAME_PER_SAMPLE,
                0,
                WZ_EXT_REPLAY_LIVE_DELIVER
            )),
            Some(ReplayPolicies {
                reply_shape: ReplayReplyShape::FramePerSample,
                serve_holds_sends: false,
                live_before_answer: ReplayLiveBeforeAnswer::Deliver,
            })
        );
    }

    #[cfg(feature = "replay-cache")]
    #[test]
    fn a_code_these_doors_do_not_know_is_refused() {
        for unknown in [facts(2, 0, 0), facts(0, 2, 0), facts(0, 0, 2)] {
            assert_eq!(ReplayPolicies::of(&unknown), None);
        }
    }

    #[cfg(feature = "replay-cache")]
    #[test]
    fn a_key_expression_s_text_is_read_through_the_abi() {
        use crate::abi::z_view_keyexpr_t;
        use crate::keyexpr::{z_view_keyexpr_empty, z_view_keyexpr_from_str, z_view_keyexpr_loan};

        // SAFETY: a local view over a static text, its gravestone, and a null key.
        unsafe {
            let mut view: z_view_keyexpr_t = core::mem::zeroed();
            assert_eq!(
                z_view_keyexpr_from_str(&mut view, c"demo/replay".as_ptr()),
                crate::result::Z_OK
            );
            assert_eq!(
                keyexpr_text(z_view_keyexpr_loan(&view)),
                Some("demo/replay")
            );
            z_view_keyexpr_empty(&mut view);
            assert_eq!(keyexpr_text(z_view_keyexpr_loan(&view)), None);
            assert_eq!(keyexpr_text(core::ptr::null()), None);
        }
    }

    #[cfg(feature = "replay-cache")]
    #[test]
    fn the_facts_of_no_session_are_the_interface_s_refusal() {
        // SAFETY: a null session.
        let read = unsafe { session_facts(core::ptr::null()) };
        assert_eq!(read.err(), Some(crate::result::Z_ERR_NULL));
    }
}
