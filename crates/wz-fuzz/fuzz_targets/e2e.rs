// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The doors that read an end-to-end protection header a person describes:
//! `wz_dissect_e2e_wrap`, `_open`, `_open_body` and `_open_expecting`.
//!
//! Input: the profile (JSON, to a NUL), a second text (to a NUL) that is the
//! values of `wrap`, the body of `open_body` and the expectation of
//! `open_expecting`, then the bytes: the payload of `wrap` and the frame of
//! the three others.
//!
//! Beyond each door's contract, one property: a frame `wrap` built opens under
//! the same profile with its CRC checking (`"crc_ok"` is never `false`).

#![no_main]

use core::ffi::{c_char, c_int, CStr};

use libfuzzer_sys::fuzz_target;
use wz_capi_dissect::*;
use wz_fuzz::{frame_of, is_dissect_code, string_answer, string_door, Reader};

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let profile = r.c_field();
    let second = r.c_field();
    let bytes = r.rest();
    let (p, s, b, n) = (
        profile.as_ptr(),
        second.as_ptr(),
        bytes.as_ptr(),
        bytes.len(),
    );

    // SAFETY (every call): both strings are NUL-terminated and outlive the
    // call, `b` points at `n` readable bytes, and `o` is writable.
    let wrapped = wrap(p, s, b, n);
    string_door("e2e_open", |o| unsafe { wz_dissect_e2e_open(p, b, n, o) });
    string_door("e2e_open_body", |o| unsafe {
        wz_dissect_e2e_open_body(p, s, b, n, o)
    });
    string_door("e2e_open_expecting", |o| unsafe {
        wz_dissect_e2e_open_expecting(p, s, b, n, o)
    });

    if let Some(frame) = wrapped {
        let mut out: *mut c_char = core::ptr::null_mut();
        let rc = unsafe { wz_dissect_e2e_open(p, frame.as_ptr(), frame.len(), &mut out) };
        assert_eq!(
            rc, WZ_DISSECT_OK,
            "e2e_open: answered {rc} for a frame e2e_wrap built"
        );
        let doc = unsafe { CStr::from_ptr(out) }
            .to_string_lossy()
            .into_owned();
        unsafe { string_answer("e2e_open", rc, out) };
        assert!(
            !doc.contains("\"crc_ok\":false"),
            "e2e_open: the CRC of a frame e2e_wrap built does not check: {doc}"
        );
    }
});

/// Wrap, hold the answer to the contract, and answer the frame it built, if it
/// built one.
fn wrap(p: *const c_char, s: *const c_char, b: *const u8, n: usize) -> Option<Vec<u8>> {
    let mut out: *mut c_char = core::ptr::null_mut();
    // SAFETY: as for every call of this target.
    let rc: c_int = unsafe { wz_dissect_e2e_wrap(p, s, b, n, &mut out) };
    assert!(is_dissect_code(rc), "e2e_wrap: answered {rc}");
    let frame = (!out.is_null())
        .then(|| {
            unsafe { CStr::from_ptr(out) }
                .to_str()
                .ok()
                .and_then(frame_of)
        })
        .flatten();
    // SAFETY: `out` started null and only the door wrote it.
    unsafe { string_answer("e2e_wrap", rc, out) };
    frame
}
