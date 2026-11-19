// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! End-to-end protection through the `wz_ext_e2e_*` doors, driven as a C program drives them:
//! a sender protects payloads into the program's buffer, a receiver judges each frame, and the
//! verdict and the payload view come back in the C structs.
//!
//! The oracle of every frame is `wz_app_frame::e2e_frame::build`, the reference builder the
//! sender's CRC cache is held to as well. What the model tests of `wz-app-frame` cannot show is
//! the part a C program relies on: that a handle keeps each stream's counter across calls, that a
//! refusal is a code and a reason and consumes nothing, that a buffer too small is refused before
//! anything moves, and that a verdict's numbers are present exactly where its `has` bits say. The
//! profile is synthetic, deliberately unlike any deployed one.

#![cfg(all(feature = "e2e-sender", feature = "e2e-receiver"))]

use std::ffi::CString;

use wz_app_frame::e2e_frame::{build, Values};
use wz_app_frame::e2e_profile::Profile;
use wz_capi_pico::e2e::*;
use wz_capi_pico::result::{
    ZResult, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_NULL, Z_ERR_OVERFLOW, Z_OK,
};
use wz_capi_pico::{
    z_internal_string_check, z_owned_string_t, z_string_data, z_string_drop, z_string_len,
    z_string_loan, z_string_move,
};

/// A two-byte counter last in the feeding order, a 16-bit CRC, an identifier split in two and
/// XORed with a constant, and a message cell whose sender part is derived from the address.
const PROFILE: &str = r#"{
  "name": "door-demo",
  "fields": [
    {"name": "length", "bytes": 2},
    {"name": "ident", "bytes": 3, "xor": "0x3C3C3C",
     "split": [{"name": "app", "lsb": 12, "width": 12}, {"name": "msg", "lsb": 0, "width": 12}]},
    {"name": "crc", "bytes": 2},
    {"name": "cell", "bytes": 4,
     "split": [{"name": "kind", "lsb": 28, "width": 4},
               {"name": "sender", "lsb": 0, "width": 28,
                "derive": {"from": "address", "mask": "0x0F00FF00", "xor": "0x77"}}]},
    {"name": "counter", "bytes": 2}
  ],
  "crc": {"field": "crc", "width": 16, "poly": "0x1021", "init": "0xFFFF",
          "refin": false, "refout": false, "xorout": "0x0000",
          "cover": ["length", "ident", "cell", "@payload", "counter"]},
  "length": {"field": "length", "counts": "frame"},
  "counter": {"field": "counter", "max_gap": 2, "timeout_ms": 50},
  "judge": {"ident": "ident", "length": true},
  "cell": {"field": "cell", "kind": "kind", "sender": "sender"}
}"#;

const ADDRESS_A: u64 = 0x0C0A_1234;
const ADDRESS_B: u64 = ADDRESS_A ^ 0x0000_0100;

fn values_text(address: u64) -> String {
    format!(
        r#"{{"ident": {{"app": 801, "msg": 99}}, "cell": {{"kind": 5}}, "@address": {address}}}"#
    )
}

fn reference(address: u64, counter: u64, payload: &[u8]) -> Vec<u8> {
    let profile = Profile::parse(PROFILE).expect("valid");
    let values = Values::parse(&values_text(address))
        .expect("valid")
        .whole("counter", counter);
    build(&profile, &values, payload).expect("builds").bytes
}

/// The text of a refusal slot a door wrote, which is then dropped; empty for the null state.
unsafe fn take(out: &mut z_owned_string_t) -> String {
    if !z_internal_string_check(out) {
        return String::new();
    }
    let loaned = z_string_loan(out);
    let len = z_string_len(loaned);
    let text = if len == 0 {
        String::new()
    } else {
        let bytes = std::slice::from_raw_parts(z_string_data(loaned).cast::<u8>(), len);
        String::from_utf8_lossy(bytes).into_owned()
    };
    z_string_drop(z_string_move(out));
    text
}

unsafe fn sender(
    profile: &str,
    values: &str,
    options: Option<&wz_ext_e2e_sender_options_t>,
) -> Result<wz_ext_owned_e2e_sender_t, (ZResult, String)> {
    let profile = CString::new(profile).unwrap();
    let values = CString::new(values).unwrap();
    let mut this: wz_ext_owned_e2e_sender_t = std::mem::zeroed();
    let mut refusal: z_owned_string_t = std::mem::zeroed();
    let options = options.map_or(std::ptr::null(), |o| o as *const _);
    let rc = wz_ext_e2e_sender_new(
        &mut this,
        profile.as_ptr(),
        values.as_ptr(),
        options,
        &mut refusal,
    );
    let text = take(&mut refusal);
    if rc == Z_OK {
        assert!(text.is_empty(), "a made sender leaves no refusal: {text}");
        assert!(wz_ext_internal_e2e_sender_check(&this));
        Ok(this)
    } else {
        assert!(
            !wz_ext_internal_e2e_sender_check(&this),
            "a refused sender leaves the null state"
        );
        Err((rc, text))
    }
}

unsafe fn receiver(
    expected: Option<&str>,
    options: &wz_ext_e2e_receiver_options_t,
) -> Result<wz_ext_owned_e2e_receiver_t, (ZResult, String)> {
    let profile = CString::new(PROFILE).unwrap();
    let expected = expected.map(|e| CString::new(e).unwrap());
    let expected_ptr = expected.as_ref().map_or(std::ptr::null(), |e| e.as_ptr());
    let mut this: wz_ext_owned_e2e_receiver_t = std::mem::zeroed();
    let mut refusal: z_owned_string_t = std::mem::zeroed();
    let rc = wz_ext_e2e_receiver_new(
        &mut this,
        profile.as_ptr(),
        expected_ptr,
        options,
        &mut refusal,
    );
    let text = take(&mut refusal);
    if rc == Z_OK {
        assert!(wz_ext_internal_e2e_receiver_check(&this));
        Ok(this)
    } else {
        assert!(!wz_ext_internal_e2e_receiver_check(&this));
        Err((rc, text))
    }
}

/// Protect `payload` on `stream` into a buffer of `capacity`: the code, the frame and its counter.
unsafe fn protect(
    tx: &wz_ext_owned_e2e_sender_t,
    stream: usize,
    payload: &[u8],
    capacity: usize,
) -> (ZResult, Vec<u8>, u64, String) {
    let mut out = vec![0u8; capacity];
    let mut written = usize::MAX;
    let mut counter = u64::MAX;
    let mut refusal: z_owned_string_t = std::mem::zeroed();
    let rc = wz_ext_e2e_sender_protect(
        wz_ext_e2e_sender_loan(tx),
        stream,
        payload.as_ptr(),
        payload.len(),
        out.as_mut_ptr(),
        capacity,
        &mut written,
        &mut counter,
        &mut refusal,
    );
    let text = take(&mut refusal);
    if rc == Z_OK {
        out.truncate(written);
    } else {
        assert_eq!(written, 0, "a refused frame writes no length");
        out.clear();
    }
    (rc, out, counter, text)
}

unsafe fn judge(
    rx: &wz_ext_owned_e2e_receiver_t,
    stream: usize,
    frame: &[u8],
    now: u64,
) -> (ZResult, wz_ext_e2e_verdict_t) {
    let mut verdict: wz_ext_e2e_verdict_t = std::mem::zeroed();
    let rc = wz_ext_e2e_receiver_judge(
        wz_ext_e2e_receiver_loan(rx),
        stream,
        frame.as_ptr(),
        frame.len(),
        now,
        &mut verdict,
    );
    (rc, verdict)
}

fn indexed(streams: usize) -> wz_ext_e2e_receiver_options_t {
    let mut options: wz_ext_e2e_receiver_options_t = unsafe { std::mem::zeroed() };
    unsafe { wz_ext_e2e_receiver_options_default(&mut options) };
    options.streams = streams;
    options
}

#[test]
fn a_round_trip_through_the_doors_is_the_reference_frame_judged_in_order() {
    unsafe {
        let mut options: wz_ext_e2e_sender_options_t = std::mem::zeroed();
        wz_ext_e2e_sender_options_default(&mut options);
        options.streams = 2;
        options.first_counter = 0xFFFE;
        options.rollover = WZ_EXT_E2E_ROLLOVER_WRAP;
        options.crc_cache = true;
        let mut tx = sender(PROFILE, &values_text(ADDRESS_A), Some(&options)).expect("made");
        let mut rx = receiver(Some(&values_text(ADDRESS_A)), &indexed(2)).expect("made");

        let mut size = 0usize;
        assert_eq!(
            wz_ext_e2e_sender_frame_size(wz_ext_e2e_sender_loan(&tx), 5, &mut size),
            Z_OK
        );
        assert_eq!(size, 2 + 3 + 2 + 4 + 2 + 5);

        // Stream 0 wraps from 0xFFFE through 0; the payload repeats, so the cache serves it.
        let expected_status = [
            WZ_EXT_E2E_FIRST,
            WZ_EXT_E2E_OK,
            WZ_EXT_E2E_OK,
            WZ_EXT_E2E_OK,
        ];
        for (i, want) in expected_status.iter().enumerate() {
            let (rc, frame, counter, text) = protect(&tx, 0, b"hello", 64);
            assert_eq!(rc, Z_OK, "{text}");
            assert_eq!(counter, (0xFFFE + i as u64) & 0xFFFF);
            assert_eq!(frame, reference(ADDRESS_A, counter, b"hello"), "frame {i}");
            let (rc, v) = judge(&rx, 0, &frame, 10 * i as u64);
            assert_eq!(rc, Z_OK);
            assert_eq!((v.status, v.failed), (*want, 0), "frame {i}");
            assert_eq!(v.counter, counter);
            assert_eq!(v.kind, 5);
            assert_eq!(v.sender, (ADDRESS_A & 0x0F00_FF00) ^ 0x77);
            let has = WZ_EXT_E2E_HAS_COUNTER
                | WZ_EXT_E2E_HAS_KIND
                | WZ_EXT_E2E_HAS_SENDER
                | WZ_EXT_E2E_HAS_STREAM;
            assert_eq!(v.has & has, has, "frame {i}");
            assert_eq!(v.has & WZ_EXT_E2E_HAS_RESULT, 0, "the cell names no result");
            assert_eq!(v.result, 0, "a number without its bit is 0");
            assert_eq!(
                v.has & WZ_EXT_E2E_HAS_STEP != 0,
                i > 0,
                "a step after the baseline"
            );
            assert_eq!(
                &frame[v.payload_offset..v.payload_offset + v.payload_len],
                b"hello"
            );
        }

        // Stream 1 keeps its own counter.
        let (_, frame, counter, _) = protect(&tx, 1, b"other", 64);
        assert_eq!(counter, 0xFFFE);
        assert_eq!(judge(&rx, 1, &frame, 0).1.status, WZ_EXT_E2E_FIRST);
        // A repetition, then a step above the gap, each reported as itself.
        assert_eq!(judge(&rx, 1, &frame, 1).1.status, WZ_EXT_E2E_REPEATED);
        wz_ext_e2e_sender_set(wz_ext_e2e_sender_loan(&tx), 1, 3);
        let (_, frame, _, _) = protect(&tx, 1, b"other", 64);
        let (_, v) = judge(&rx, 1, &frame, 2);
        assert_eq!((v.status, v.step), (WZ_EXT_E2E_OUT_OF_RANGE, 5));

        // A damaged frame: integrity, the payload still reported.
        let (_, mut frame, _, _) = protect(&tx, 0, b"hello", 64);
        let last = frame.len() - 1;
        frame[last - 2] ^= 0x10;
        let (_, v) = judge(&rx, 0, &frame, 100);
        assert_eq!(
            (v.status, v.failed & WZ_EXT_E2E_FAILED_CRC),
            (WZ_EXT_E2E_INTEGRITY, WZ_EXT_E2E_FAILED_CRC)
        );
        assert_eq!(v.payload_len, 5);
        // A frame shorter than the header.
        let (_, v) = judge(&rx, 0, &frame[..3], 101);
        assert_eq!(
            (v.status, v.failed, v.payload_len),
            (WZ_EXT_E2E_INTEGRITY, WZ_EXT_E2E_FAILED_SHORT, 0)
        );
        assert_eq!(v.has & WZ_EXT_E2E_HAS_COUNTER, 0);
        // A frame of another identifier.
        let other = r#"{"ident": {"app": 802, "msg": 99}, "cell": {"kind": 5}, "@address": 1}"#;
        let mut stranger = sender(PROFILE, other, None).expect("made");
        let (_, frame, _, _) = protect(&stranger, 0, b"x", 64);
        assert_eq!(judge(&rx, 0, &frame, 102).1.failed, WZ_EXT_E2E_FAILED_IDENT);
        // A stream the receiver does not have.
        let (rc, v) = judge(&rx, 2, &frame, 103);
        assert_eq!((rc, v.status, v.has), (Z_EINVAL, 0, 0));

        wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(&mut stranger));
        wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(&mut tx));
        wz_ext_e2e_receiver_drop(wz_ext_e2e_receiver_move(&mut rx));
        assert!(!wz_ext_internal_e2e_sender_check(&tx));
        assert!(!wz_ext_internal_e2e_receiver_check(&rx));
        // A second drop does nothing.
        wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(&mut tx));
        wz_ext_e2e_receiver_drop(wz_ext_e2e_receiver_move(&mut rx));
    }
}

#[test]
fn a_refusal_is_a_code_and_a_reason_and_consumes_nothing() {
    unsafe {
        let stated =
            r#"{"ident": {"app": 1, "msg": 2}, "cell": {"kind": 5}, "counter": 4, "@address": 1}"#;
        let (rc, text) = sender(PROFILE, stated, None).err().expect("refused");
        assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
        assert!(text.starts_with("values"), "{text}");
        let (rc, text) = sender("{", &values_text(ADDRESS_A), None)
            .err()
            .expect("refused");
        assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
        assert!(text.starts_with("profile"), "{text}");
        let no_address = r#"{"ident": {"app": 1, "msg": 2}, "cell": {"kind": 5}}"#;
        let (rc, text) = sender(PROFILE, no_address, None).err().expect("refused");
        assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
        assert!(text.contains("@address"), "{text}");
        let mut bad: wz_ext_e2e_sender_options_t = std::mem::zeroed();
        wz_ext_e2e_sender_options_default(&mut bad);
        bad.rollover = 7;
        assert_eq!(
            sender(PROFILE, &values_text(ADDRESS_A), Some(&bad))
                .err()
                .map(|e| e.0),
            Some(Z_EINVAL)
        );

        let mut tx = sender(PROFILE, &values_text(ADDRESS_A), None).expect("made");
        // A buffer one byte short: refused, and the counter is still 0.
        let size = 2 + 3 + 2 + 4 + 2 + 3;
        let (rc, _, _, _) = protect(&tx, 0, b"abc", size - 1);
        assert_eq!(rc, Z_ERR_OVERFLOW);
        let mut next = u64::MAX;
        assert!(wz_ext_e2e_sender_next(
            wz_ext_e2e_sender_loan(&tx),
            0,
            &mut next
        ));
        assert_eq!(next, 0);
        // A stream the sender does not have.
        let (rc, _, _, text) = protect(&tx, 1, b"abc", 64);
        assert_eq!(rc, Z_EINVAL);
        assert!(text.contains("stream 1"), "{text}");
        // A counter the two-byte field cannot hold.
        assert_eq!(
            wz_ext_e2e_sender_set(wz_ext_e2e_sender_loan(&tx), 0, 0x1_0000),
            Z_EINVAL
        );
        // The largest value, then refused under the default rollover.
        assert_eq!(
            wz_ext_e2e_sender_set(wz_ext_e2e_sender_loan(&tx), 0, 0xFFFF),
            Z_OK
        );
        assert_eq!(protect(&tx, 0, b"abc", 64).0, Z_OK);
        let (rc, _, _, text) = protect(&tx, 0, b"abc", 64);
        assert_eq!(rc, Z_EINVAL);
        assert!(text.contains("largest counter value"), "{text}");
        assert!(!wz_ext_e2e_sender_next(
            wz_ext_e2e_sender_loan(&tx),
            0,
            &mut next
        ));
        // Null arguments and the gravestone.
        let mut written = 0usize;
        assert_eq!(
            wz_ext_e2e_sender_protect(
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                [0u8; 4].as_mut_ptr(),
                4,
                &mut written,
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ),
            Z_ERR_NULL
        );
        wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(&mut tx));
        assert_eq!(protect(&tx, 0, b"abc", 64).0, Z_ERR_NULL);

        // The receiver: a gap above the profile's largest, no stream, an expected text that is not one.
        let mut options = indexed(1);
        options.max_gap = 0x1_0000;
        let (rc, text) = receiver(Some(&values_text(ADDRESS_A)), &options)
            .err()
            .expect("refused");
        assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
        assert!(text.contains("max_gap"), "{text}");
        let (rc, _) = receiver(Some(&values_text(ADDRESS_A)), &indexed(0))
            .err()
            .expect("refused");
        assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
        let (rc, text) = receiver(None, &indexed(1)).err().expect("refused");
        assert_eq!(
            rc, Z_ERR_CONFIG_INVALID_VALUE,
            "the profile judges an identifier"
        );
        assert!(text.starts_with("expected"), "{text}");
        let mut unknown = indexed(1);
        unknown.keying = 9;
        assert_eq!(receiver(None, &unknown).err().map(|e| e.0), Some(Z_EINVAL));
    }
}

#[cfg(feature = "e2e-sender-demux")]
#[test]
fn a_receiver_keyed_by_sender_keeps_a_slot_per_sender_and_counts_the_rest() {
    unsafe {
        let mut options = indexed(1);
        options.keying = WZ_EXT_E2E_KEYING_SENDERS_ARRIVAL;
        let mut rx = receiver(Some(&values_text(ADDRESS_A)), &options).expect("made");
        let mut a = sender(PROFILE, &values_text(ADDRESS_A), None).expect("made");
        let mut b = sender(PROFILE, &values_text(ADDRESS_B), None).expect("made");
        let (_, fa, _, _) = protect(&a, 0, b"a", 64);
        let (_, fb, _, _) = protect(&b, 0, b"b", 64);
        let (_, v) = judge(&rx, 0, &fa, 0);
        assert_eq!((v.status, v.stream), (WZ_EXT_E2E_FIRST, 0));
        let mut held = 0u64;
        assert!(wz_ext_e2e_receiver_slot_sender(
            wz_ext_e2e_receiver_loan(&rx),
            0,
            &mut held
        ));
        assert_eq!(held, (ADDRESS_A & 0x0F00_FF00) ^ 0x77);
        // One slot, a second sender: not judged, counted, the payload still reported.
        let (_, v) = judge(&rx, 0, &fb, 1);
        assert_eq!(
            (v.status, v.unslotted, v.payload_len),
            (WZ_EXT_E2E_UNSLOTTED, WZ_EXT_E2E_SLOTS_FULL, 1)
        );
        assert_eq!(v.has & WZ_EXT_E2E_HAS_STREAM, 0);
        let (mut not_listed, mut full) = (u64::MAX, u64::MAX);
        assert_eq!(
            wz_ext_e2e_receiver_counts(wz_ext_e2e_receiver_loan(&rx), &mut not_listed, &mut full),
            Z_OK
        );
        assert_eq!((not_listed, full), (0, 1));
        // The stream is the receiver's to choose.
        assert_eq!(judge(&rx, 1, &fa, 2).0, Z_EINVAL);

        // Bound slots: a listed sender is judged, another is counted.
        let listed = [(ADDRESS_B & 0x0F00_FF00) ^ 0x77];
        let mut bound = indexed(4);
        bound.keying = WZ_EXT_E2E_KEYING_SENDERS_BOUND;
        bound.senders = listed.as_ptr();
        bound.senders_len = listed.len();
        let mut rx2 = receiver(Some(&values_text(ADDRESS_A)), &bound).expect("made");
        assert_eq!(judge(&rx2, 0, &fb, 0).1.status, WZ_EXT_E2E_FIRST);
        let (_, v) = judge(&rx2, 0, &fa, 0);
        assert_eq!(
            (v.status, v.unslotted),
            (WZ_EXT_E2E_UNSLOTTED, WZ_EXT_E2E_NOT_LISTED)
        );
        // More slots than the build allows.
        let mut many = indexed(wz_session_core::caps::E2E_SENDER_SLOTS + 1);
        many.keying = WZ_EXT_E2E_KEYING_SENDERS_ARRIVAL;
        let (rc, text) = receiver(Some(&values_text(ADDRESS_A)), &many)
            .err()
            .expect("refused");
        assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
        assert!(text.contains("sender slots"), "{text}");

        wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(&mut a));
        wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(&mut b));
        wz_ext_e2e_receiver_drop(wz_ext_e2e_receiver_move(&mut rx));
        wz_ext_e2e_receiver_drop(wz_ext_e2e_receiver_move(&mut rx2));
    }
}

#[cfg(not(feature = "e2e-sender-demux"))]
#[test]
fn a_build_without_sender_slots_refuses_sender_keying_by_name() {
    unsafe {
        for keying in [
            WZ_EXT_E2E_KEYING_SENDERS_ARRIVAL,
            WZ_EXT_E2E_KEYING_SENDERS_BOUND,
        ] {
            let mut options = indexed(2);
            options.keying = keying;
            let refused = receiver(Some(&values_text(ADDRESS_A)), &options).err();
            assert_eq!(
                refused.map(|e| e.0),
                Some(wz_capi_pico::result::WZ_EXT_ERR_UNSUPPORTED)
            );
        }
    }
}
