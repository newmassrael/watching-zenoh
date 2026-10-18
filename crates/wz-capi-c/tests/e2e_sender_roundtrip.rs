// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The sender of an end-to-end protected message through the
//! `wz_capi_c_e2e_sender_*` doors, driven exactly as a C program would drive them.
//!
//! What a unit test of the sender cannot show is the part a participant process
//! relies on: that the HANDLE keeps the counter across calls made through the
//! ABI, that a refusal comes back as a document under `Z_OK` and consumes
//! nothing, that the end of the counter is a refusal and not a wrap, that two
//! handles keep two counters, and that the string a call hands back is the
//! caller's to drop. The frame itself is judged against the stateless door of the
//! same writer, `wz_capture::e2e_json::wrap_document`, asked for the same
//! counter: a sender whose frame differed by a byte would be a second opinion
//! about the header.

use std::ffi::CString;

use wz_capi_c::abi::{z_moved_string_t, z_owned_string_t};
use wz_capi_c::e2e_sender::*;
use wz_capi_c::result::{Z_EINVAL, Z_ENULL, Z_EPARSE, Z_OK};
use wz_capi_c::string::{z_string_data, z_string_drop, z_string_len, z_string_loan};
use wz_capture::e2e_json::wrap_document;

/// A made-up profile with a ONE-byte counter, so its end is a few calls away.
const PROFILE: &str = r#"{
  "name": "tiny",
  "fields": [
    {"name": "crc", "bytes": 4},
    {"name": "length", "bytes": 2},
    {"name": "counter", "bytes": 1}
  ],
  "crc": {"field": "crc", "width": 32, "poly": "0xF4ACFB13", "init": "0xFFFFFFFF",
          "refin": true, "refout": true, "xorout": "0xFFFFFFFF",
          "cover": ["length", "@payload", "counter"]},
  "length": {"field": "length", "counts": "frame"},
  "counter": {"field": "counter", "max_gap": 10, "timeout_ms": 1000}
}"#;

/// A sender slot in its gravestone state.
fn empty() -> wz_capi_c_owned_e2e_sender_t {
    // The field is the crate's own, so the slot is made the way C makes one:
    // zeroed memory that the gravestone door then writes.
    let mut slot = std::mem::MaybeUninit::<wz_capi_c_owned_e2e_sender_t>::zeroed();
    // SAFETY: `slot` is writable, and a zeroed pointer is a valid handle field.
    unsafe {
        wz_capi_c_internal_e2e_sender_null(slot.as_mut_ptr());
        slot.assume_init()
    }
}

fn text_slot() -> z_owned_string_t {
    // SAFETY: an all-zero string slot is the gravestone every door writes first.
    unsafe { std::mem::zeroed() }
}

/// The text of `out`, which is then dropped.
fn take(out: &mut z_owned_string_t) -> String {
    // SAFETY: `out` was written by a door.
    let loaned = unsafe { z_string_loan(out) };
    let text = unsafe {
        let (ptr, len) = (z_string_data(loaned), z_string_len(loaned));
        // An empty string may carry no pointer at all, and a slice over a null
        // pointer is not one even at length zero.
        if len == 0 {
            String::new()
        } else {
            String::from_utf8_lossy(std::slice::from_raw_parts(ptr.cast::<u8>(), len)).into_owned()
        }
    };
    unsafe { z_string_drop((out as *mut z_owned_string_t).cast::<z_moved_string_t>()) };
    text
}

fn make(first: u64, rollover: wz_capi_c_e2e_rollover_t) -> wz_capi_c_owned_e2e_sender_t {
    let profile = CString::new(PROFILE).expect("no NUL");
    let mut sender = empty();
    let mut refusal = text_slot();
    let rc = unsafe {
        wz_capi_c_e2e_sender_new(&mut sender, profile.as_ptr(), first, rollover, &mut refusal)
    };
    assert_eq!(rc, Z_OK, "{}", take(&mut refusal));
    assert!(unsafe { wz_capi_c_internal_e2e_sender_check(&sender) });
    assert_eq!(take(&mut refusal), "", "empty on success");
    sender
}

/// One call through the door; the return code and the document.
fn wrap(sender: &wz_capi_c_owned_e2e_sender_t, values: &str, payload: &[u8]) -> (i8, String) {
    let values = CString::new(values).expect("no NUL");
    let mut out = text_slot();
    let rc = unsafe {
        wz_capi_c_e2e_sender_wrap(
            wz_capi_c_e2e_sender_loan(sender),
            values.as_ptr(),
            if payload.is_empty() {
                std::ptr::null()
            } else {
                payload.as_ptr()
            },
            payload.len(),
            &mut out,
        )
    };
    (rc, take(&mut out))
}

fn next(sender: &wz_capi_c_owned_e2e_sender_t) -> Option<u64> {
    let mut value = 0u64;
    unsafe { wz_capi_c_e2e_sender_next(wz_capi_c_e2e_sender_loan(sender), &mut value) }
        .then_some(value)
}

fn drop_sender(sender: &mut wz_capi_c_owned_e2e_sender_t) {
    unsafe { wz_capi_c_e2e_sender_drop((sender as *mut wz_capi_c_owned_e2e_sender_t).cast()) };
}

fn stated(counter: u64) -> String {
    format!(r#"{{"counter": {counter}}}"#)
}

#[test]
fn the_handle_keeps_the_counter_and_every_frame_is_the_stateless_doors() {
    let mut sender = make(40, WZ_CAPI_C_E2E_ROLLOVER_REFUSE);
    for sent in 40..44 {
        let (rc, document) = wrap(&sender, "{}", b"abc");
        assert_eq!(rc, Z_OK);
        assert_eq!(document, wrap_document(PROFILE, &stated(sent), b"abc"));
    }
    assert_eq!(next(&sender), Some(44));
    drop_sender(&mut sender);
    assert!(!unsafe { wz_capi_c_internal_e2e_sender_check(&sender) });
    drop_sender(&mut sender);
}

#[test]
fn a_refusal_is_a_document_under_ok_and_consumes_no_value() {
    let mut sender = make(7, WZ_CAPI_C_E2E_ROLLOVER_REFUSE);
    for bad in [r#"{"nope": 1}"#, r#"{"counter": 1}"#, "{\"counter\":"] {
        let (rc, document) = wrap(&sender, bad, b"");
        assert_eq!(rc, Z_OK, "a refused text is a successful diagnosis");
        assert!(document.contains("\"ok\":false"), "{document}");
        assert_eq!(next(&sender), Some(7), "nothing was consumed by {bad}");
    }
    let (_, document) = wrap(&sender, "{}", b"");
    assert_eq!(document, wrap_document(PROFILE, &stated(7), b""));
    drop_sender(&mut sender);
}

#[test]
fn the_end_of_the_counter_is_a_refusal_and_wrap_is_a_choice_made_by_name() {
    let mut sender = make(255, WZ_CAPI_C_E2E_ROLLOVER_REFUSE);
    let (_, last) = wrap(&sender, "{}", b"");
    assert_eq!(last, wrap_document(PROFILE, &stated(255), b""));
    assert_eq!(next(&sender), None, "no next value");
    for _ in 0..2 {
        let (rc, document) = wrap(&sender, "{}", b"");
        assert_eq!(rc, Z_OK);
        assert!(document.contains("\"ok\":false"), "{document}");
        assert!(document.contains("largest value, 255"), "{document}");
    }
    assert_eq!(
        unsafe { wz_capi_c_e2e_sender_set(wz_capi_c_e2e_sender_loan(&sender), 3) },
        Z_OK
    );
    let (_, again) = wrap(&sender, "{}", b"");
    assert_eq!(
        again,
        wrap_document(PROFILE, &stated(3), b""),
        "set restores it"
    );
    drop_sender(&mut sender);

    let mut wrapping = make(255, WZ_CAPI_C_E2E_ROLLOVER_WRAP);
    let _ = wrap(&wrapping, "{}", b"");
    let (_, zero) = wrap(&wrapping, "{}", b"");
    assert_eq!(zero, wrap_document(PROFILE, &stated(0), b""));
    drop_sender(&mut wrapping);
}

#[test]
fn two_messages_keep_two_counters() {
    let mut first = make(1, WZ_CAPI_C_E2E_ROLLOVER_REFUSE);
    let mut second = make(100, WZ_CAPI_C_E2E_ROLLOVER_REFUSE);
    let _ = wrap(&first, "{}", b"");
    let _ = wrap(&first, "{}", b"");
    let _ = wrap(&second, "{}", b"");
    assert_eq!(next(&first), Some(3));
    assert_eq!(next(&second), Some(101));
    drop_sender(&mut first);
    drop_sender(&mut second);
}

#[test]
fn one_handle_called_from_two_threads_hands_out_two_values() {
    /// The handle lent to several threads, which is what its lock is for.
    struct Lent<'a>(&'a wz_capi_c_owned_e2e_sender_t);
    // SAFETY: the doors take the sender's own lock around the counter and the
    // frame, which is the contract this test exercises.
    unsafe impl Sync for Lent<'_> {}

    let mut sender = make(0, WZ_CAPI_C_E2E_ROLLOVER_REFUSE);
    let shared = Lent(&sender);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                // The whole of `shared`, not its field: a closure captures what
                // it names, and the field alone is not `Sync`.
                let lent: &Lent<'_> = &shared;
                for _ in 0..10 {
                    let (rc, document) = wrap(lent.0, "{}", b"");
                    assert_eq!(rc, Z_OK);
                    assert!(document.contains("\"ok\":true"), "{document}");
                }
            });
        }
    });
    assert_eq!(
        next(&sender),
        Some(40),
        "forty frames, forty values, none twice"
    );
    drop_sender(&mut sender);
}

#[test]
fn a_profile_that_is_not_one_is_eparse_with_the_document_in_the_refusal() {
    let mut sender = empty();
    let mut refusal = text_slot();
    let profile = CString::new("{}").expect("no NUL");
    let rc = unsafe {
        wz_capi_c_e2e_sender_new(
            &mut sender,
            profile.as_ptr(),
            0,
            WZ_CAPI_C_E2E_ROLLOVER_REFUSE,
            &mut refusal,
        )
    };
    assert_eq!(rc, Z_EPARSE);
    assert!(!unsafe { wz_capi_c_internal_e2e_sender_check(&sender) });
    let document = take(&mut refusal);
    assert_eq!(document, wrap_document("{}", "{}", b""));
}

#[test]
fn the_arguments_a_caller_can_get_wrong_are_refused_by_code() {
    let profile = CString::new(PROFILE).expect("no NUL");
    let mut sender = empty();
    assert_eq!(
        unsafe {
            wz_capi_c_e2e_sender_new(
                std::ptr::null_mut(),
                profile.as_ptr(),
                0,
                0,
                std::ptr::null_mut(),
            )
        },
        Z_ENULL
    );
    assert_eq!(
        unsafe {
            wz_capi_c_e2e_sender_new(&mut sender, std::ptr::null(), 0, 0, std::ptr::null_mut())
        },
        Z_ENULL
    );
    assert_eq!(
        unsafe {
            wz_capi_c_e2e_sender_new(&mut sender, profile.as_ptr(), 0, 9, std::ptr::null_mut())
        },
        Z_EINVAL,
        "a rollover this library does not know"
    );
    assert!(!unsafe { wz_capi_c_internal_e2e_sender_check(&sender) });

    let mut live = make(0, WZ_CAPI_C_E2E_ROLLOVER_REFUSE);
    let values = CString::new("{}").expect("no NUL");
    let mut out = text_slot();
    assert_eq!(
        unsafe {
            wz_capi_c_e2e_sender_wrap(
                wz_capi_c_e2e_sender_loan(&live),
                values.as_ptr(),
                std::ptr::null(),
                3,
                &mut out,
            )
        },
        Z_ENULL,
        "a length with no bytes"
    );
    assert_eq!(
        unsafe {
            wz_capi_c_e2e_sender_wrap(
                std::ptr::null(),
                values.as_ptr(),
                std::ptr::null(),
                0,
                &mut out,
            )
        },
        Z_ENULL
    );
    assert!(!unsafe { wz_capi_c_e2e_sender_next(std::ptr::null(), &mut 0u64) });
    drop_sender(&mut live);
}
