// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The doors of the end-to-end sender a participant process holds across
//! frames: `wz_capi_c_e2e_sender_new`, `_wrap`, `_next` and `_set`.
//!
//! Input: a byte of choices (the rollover, whether `refusal` and a payload
//! pointer are given), the counter the first frame carries (eight bytes), the
//! profile (JSON, to a NUL), the values (JSON, to a NUL), then the payload.
//!
//! Beyond each door's contract: a refused frame consumes no counter value; a
//! sender that refused a profile holds nothing; a frame the sender built opens
//! under the same profile with its CRC checking, as for the stateless door
//! (`e2e`); and a dropped sender answers like a null one, then drops again
//! without harm.

#![no_main]

use core::ffi::{c_char, CStr};
use core::mem::zeroed;

use libfuzzer_sys::fuzz_target;
use wz_capi_c::abi::{z_moved_string_t, z_owned_string_t};
use wz_capi_c::e2e_sender::*;
use wz_capi_c::result::{ZResult, Z_EINVAL, Z_ENULL, Z_EPARSE, Z_OK};
use wz_capi_c::string::{z_string_data, z_string_drop, z_string_len, z_string_loan};
use wz_capi_dissect::{wz_dissect_e2e_open, wz_dissect_string_free, WZ_DISSECT_OK};
use wz_fuzz::{frame_of, Reader};

/// How many frames one input asks the sender for.
const FRAMES: usize = 4;

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let choices = r.u8();
    let first_counter = r.u64();
    let profile = r.c_field();
    let values = r.c_field();
    let payload = r.rest();

    let rollover = match choices & 3 {
        0 => WZ_CAPI_C_E2E_ROLLOVER_REFUSE,
        1 => WZ_CAPI_C_E2E_ROLLOVER_WRAP,
        // A value the library does not know: refused, not guessed.
        _ => 2,
    };
    let want_refusal = choices & 4 != 0;

    let mut sender = empty_sender();
    let mut refusal = empty_text();
    // SAFETY: `sender` is writable, `profile` is NUL-terminated and `refusal`
    // is null or writable.
    let rc = unsafe {
        wz_capi_c_e2e_sender_new(
            &mut sender,
            profile.as_ptr(),
            first_counter,
            rollover,
            if want_refusal {
                &mut refusal
            } else {
                core::ptr::null_mut()
            },
        )
    };
    let refusal_text = take(&mut refusal);
    assert!(
        matches!(rc, Z_OK | Z_EINVAL | Z_EPARSE | Z_ENULL),
        "e2e_sender_new: answered {rc}, a code the door does not state"
    );
    let holds = unsafe { wz_capi_c_internal_e2e_sender_check(&sender) };
    assert_eq!(
        holds,
        rc == Z_OK,
        "e2e_sender_new: answered {rc} and the slot holds a sender: {holds}"
    );
    if rc == Z_OK || !want_refusal {
        assert_eq!(refusal_text, "", "e2e_sender_new: a refusal text with {rc}");
    }
    if rc == Z_EPARSE && want_refusal {
        assert!(
            serde_json::from_str::<serde_json::Value>(&refusal_text).is_ok(),
            "e2e_sender_new: Z_EPARSE with a refusal that is not the wrap document: {refusal_text}"
        );
    }

    if rc == Z_OK {
        for _ in 0..FRAMES {
            one_frame(&sender, &profile, &values, payload, choices & 8 != 0);
        }
        // A start value the caller chooses is the next one, or the sender says
        // why not.
        let at = r_set(&sender, first_counter ^ u64::from(choices));
        assert_eq!(at, Z_OK, "e2e_sender_set: answered {at} for a live sender");
        one_frame(&sender, &profile, &values, payload, false);
    }

    // SAFETY: an owned sender slot, dropped twice; the second is a no-op.
    unsafe {
        let moved = (&mut sender as *mut wz_capi_c_owned_e2e_sender_t).cast();
        wz_capi_c_e2e_sender_drop(moved);
        assert!(
            !wz_capi_c_internal_e2e_sender_check(&sender),
            "e2e_sender_drop: the slot still holds the sender"
        );
        wz_capi_c_e2e_sender_drop(moved);
    }
    // After the drop the slot answers as a null one does.
    let mut out = empty_text();
    // SAFETY: a gravestone slot is a valid, empty loan; `out` is writable.
    let rc = unsafe {
        wz_capi_c_e2e_sender_wrap(
            wz_capi_c_e2e_sender_loan(&sender),
            values.as_ptr(),
            payload.as_ptr(),
            payload.len(),
            &mut out,
        )
    };
    assert_eq!(
        rc, Z_ENULL,
        "e2e_sender_wrap: a dropped sender answered {rc}"
    );
    assert_eq!(take(&mut out), "");
    assert_eq!(
        r_set(&sender, 1),
        Z_ENULL,
        "e2e_sender_set: a dropped sender"
    );
    let mut next = 0u64;
    assert!(
        !unsafe { wz_capi_c_e2e_sender_next(wz_capi_c_e2e_sender_loan(&sender), &mut next) },
        "e2e_sender_next: a dropped sender gave a value"
    );
});

/// Ask for one frame and hold the answer to the sender's contract.
fn one_frame(
    sender: &wz_capi_c_owned_e2e_sender_t,
    profile: &std::ffi::CString,
    values: &std::ffi::CString,
    payload: &[u8],
    null_payload_with_length: bool,
) {
    let before = next_of(sender);
    let mut out = empty_text();
    // A payload pointer is null only when its length is zero, unless a null
    // one is given a length on purpose: the door answers `Z_ENULL` for that.
    let given: *const u8 = if payload.is_empty() || null_payload_with_length {
        core::ptr::null()
    } else {
        payload.as_ptr()
    };
    // SAFETY: `sender` is a live owned sender, `values` is NUL-terminated,
    // `given` is readable for `payload.len()` bytes when it is not null, and
    // `out` is writable.
    let rc = unsafe {
        wz_capi_c_e2e_sender_wrap(
            wz_capi_c_e2e_sender_loan(sender),
            values.as_ptr(),
            given,
            payload.len(),
            &mut out,
        )
    };
    let document = take(&mut out);
    assert!(
        matches!(rc, Z_OK | Z_EINVAL | Z_ENULL),
        "e2e_sender_wrap: answered {rc}, a code the door does not state"
    );
    if given.is_null() && !payload.is_empty() {
        assert_eq!(rc, Z_ENULL, "e2e_sender_wrap: a null payload with a length");
    }
    if rc != Z_OK {
        assert_eq!(document, "", "e2e_sender_wrap: a document with {rc}");
        assert_eq!(
            next_of(sender),
            before,
            "e2e_sender_wrap: {rc} consumed a value"
        );
        return;
    }
    let value: serde_json::Value = serde_json::from_str(&document).unwrap_or_else(|e| {
        panic!("e2e_sender_wrap: a document that is not JSON ({e}): {document}")
    });
    let built = value.get("ok") == Some(&serde_json::Value::Bool(true));
    let after = next_of(sender);
    if !built {
        assert_eq!(
            after, before,
            "e2e_sender_wrap: a refused frame consumed a value: {document}"
        );
        return;
    }
    // A built frame moved the counter on by one, to the end of its field
    // (nothing more) or round to zero (the sender that wraps).
    if let Some(sent) = before {
        let on_by_one = sent.checked_add(1).is_some_and(|n| after == Some(n));
        assert!(
            on_by_one || after.is_none() || after == Some(0),
            "e2e_sender_wrap: counter {sent} then {after:?} after a built frame"
        );
    }
    // The frame opens under the profile with its CRC checking.
    let frame = frame_of(&document).expect("a document that says ok has a frame");
    let mut opened: *mut c_char = core::ptr::null_mut();
    // SAFETY: both are valid for the call; `opened` is writable.
    let rc =
        unsafe { wz_dissect_e2e_open(profile.as_ptr(), frame.as_ptr(), frame.len(), &mut opened) };
    assert_eq!(
        rc, WZ_DISSECT_OK,
        "e2e_sender_wrap built a frame the profile does not open ({rc}): {document}"
    );
    // SAFETY: the door handed out a NUL-terminated string.
    let doc = unsafe { CStr::from_ptr(opened) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: handed out by this crate and not freed yet.
    unsafe { wz_dissect_string_free(opened) };
    assert!(
        !doc.contains("\"crc_ok\":false"),
        "e2e_sender_wrap: the CRC of a frame the sender built does not check: {doc}"
    );
}

fn next_of(sender: &wz_capi_c_owned_e2e_sender_t) -> Option<u64> {
    let mut value = 0u64;
    // SAFETY: a live owned sender and a writable value.
    unsafe { wz_capi_c_e2e_sender_next(wz_capi_c_e2e_sender_loan(sender), &mut value) }
        .then_some(value)
}

fn r_set(sender: &wz_capi_c_owned_e2e_sender_t, value: u64) -> ZResult {
    // SAFETY: an owned sender slot, live or its gravestone.
    unsafe { wz_capi_c_e2e_sender_set(wz_capi_c_e2e_sender_loan(sender), value) }
}

fn empty_sender() -> wz_capi_c_owned_e2e_sender_t {
    // SAFETY: a zeroed handle is the slot every door writes first.
    let mut slot: wz_capi_c_owned_e2e_sender_t = unsafe { zeroed() };
    // SAFETY: `slot` is writable.
    unsafe { wz_capi_c_internal_e2e_sender_null(&mut slot) };
    slot
}

fn empty_text() -> z_owned_string_t {
    // SAFETY: an all-zero string slot is the gravestone every door writes first.
    unsafe { zeroed() }
}

/// The text of `out`, which is then dropped.
fn take(out: &mut z_owned_string_t) -> String {
    // SAFETY: `out` was written by a door, or is the gravestone.
    let loaned = unsafe { z_string_loan(out) };
    let text = unsafe {
        let (ptr, len) = (z_string_data(loaned), z_string_len(loaned));
        // An empty string may carry no pointer at all.
        if len == 0 {
            String::new()
        } else {
            std::str::from_utf8(core::slice::from_raw_parts(ptr.cast::<u8>(), len))
                .unwrap_or_else(|e| panic!("a door handed out text that is not UTF-8: {e}"))
                .to_owned()
        }
    };
    // SAFETY: dropped once; a gravestone drops as a no-op.
    unsafe { z_string_drop((out as *mut z_owned_string_t).cast::<z_moved_string_t>()) };
    text
}
