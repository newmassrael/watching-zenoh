// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! Instance keys through the `wz_ext_instance_keyer_*` doors, driven as a C program drives them: a
//! keyer made over the program's `.proto` text and a description, payloads indexed, the last value
//! of each instance copied back out of the program's storage, and, with the end-to-end doors, a
//! frame judged and a payload protected in the stream of its instance.
//!
//! What the model tests of `wz-app-frame` cannot show is the part a C program relies on: that a
//! refusal is a code and a reason and leaves the gravestone, that the storage the program hands
//! over is where the last values are, that a dropped sample moves no state of the receiver, and
//! that a receiver kept per sender is refused by the judging door. Every payload is laid by hand
//! and the schema, the values and the profile are synthetic.

#![cfg(feature = "instance-key")]

use std::ffi::CString;

use wz_capi_pico::instance_key::*;
use wz_capi_pico::result::{
    ZResult, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_NULL, Z_ERR_OVERFLOW, Z_OK,
    Z_RES_CHANNEL_NODATA,
};
use wz_capi_pico::{
    z_internal_string_check, z_owned_string_t, z_string_data, z_string_drop, z_string_len,
    z_string_loan, z_string_move,
};

const SCHEMA: &str = r#"
syntax = "proto3";
package syn.door;
message Reading {
  optional uint32 bay = 1;
  sint32 tilt = 2;
  bytes body = 3;
}
"#;

/// Three bays and two tilts: six instances, the tilt varying fastest.
const DESCRIPTION: &str = r#"{
  "message": "syn.door.Reading",
  "fields": [
    {"path": "bay", "values": [12, 30, 44]},
    {"path": "tilt", "values": [-3, 5]}
  ],
  "report_interval_ms": 1000
}"#;

fn varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// A reading of `bay` and `tilt` (zigzag-encoded, as `sint32` is), with a body of `body`.
fn reading(bay: u64, tilt: i32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    varint(1 << 3, &mut out);
    varint(bay, &mut out);
    varint(2 << 3, &mut out);
    varint(u64::from(((tilt << 1) ^ (tilt >> 31)) as u32), &mut out);
    varint((3 << 3) | 2, &mut out);
    varint(body.len() as u64, &mut out);
    out.extend_from_slice(body);
    out
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

/// A keyer over `schema` and `description`, with `options`.
unsafe fn keyer(
    schema: &str,
    description: &str,
    options: Option<&wz_ext_instance_keyer_options_t>,
) -> Result<wz_ext_owned_instance_keyer_t, (ZResult, String)> {
    let name = CString::new("door.proto").unwrap();
    let text = CString::new(schema).unwrap();
    let files = [wz_ext_proto_file_t {
        name: name.as_ptr(),
        text: text.as_ptr(),
    }];
    let description = CString::new(description).unwrap();
    let mut this: wz_ext_owned_instance_keyer_t = std::mem::zeroed();
    let mut refusal: z_owned_string_t = std::mem::zeroed();
    let options = options.map_or(std::ptr::null(), |o| o as *const _);
    let rc = wz_ext_instance_keyer_new(
        &mut this,
        files.as_ptr(),
        files.len(),
        description.as_ptr(),
        options,
        &mut refusal,
    );
    let reason = take(&mut refusal);
    if rc == Z_OK {
        assert!(
            reason.is_empty(),
            "a made keyer leaves no refusal: {reason}"
        );
        assert!(wz_ext_internal_instance_keyer_check(&this));
        Ok(this)
    } else {
        assert!(
            !wz_ext_internal_instance_keyer_check(&this),
            "a refused keyer leaves the null state"
        );
        Err((rc, reason))
    }
}

unsafe fn index(
    k: &wz_ext_owned_instance_keyer_t,
    payload: &[u8],
    now: u64,
) -> wz_ext_instance_key_t {
    let mut out: wz_ext_instance_key_t = std::mem::zeroed();
    let rc = wz_ext_instance_keyer_index(
        wz_ext_instance_keyer_loan(k),
        payload.as_ptr(),
        payload.len(),
        now,
        &mut out,
    );
    assert_eq!(rc, Z_OK);
    out
}

unsafe fn last(
    k: &wz_ext_owned_instance_keyer_t,
    instance: usize,
    capacity: usize,
) -> (ZResult, Vec<u8>) {
    let mut out = vec![0u8; capacity];
    let mut len = usize::MAX;
    let rc = wz_ext_instance_keyer_last(
        wz_ext_instance_keyer_loan(k),
        instance,
        out.as_mut_ptr(),
        capacity,
        &mut len,
    );
    out.truncate(len.min(capacity));
    (rc, out)
}

unsafe fn drop_keyer(mut k: wz_ext_owned_instance_keyer_t) {
    wz_ext_instance_keyer_drop(wz_ext_instance_keyer_move(&mut k));
    assert!(!wz_ext_internal_instance_keyer_check(&k));
    wz_ext_instance_keyer_drop(wz_ext_instance_keyer_move(&mut k));
}

#[test]
fn every_combination_is_its_place_in_the_product_and_its_last_value_is_the_programs() {
    unsafe {
        let mut storage = vec![0u8; 6 * 16];
        let mut options: wz_ext_instance_keyer_options_t = std::mem::zeroed();
        wz_ext_instance_keyer_options_default(&mut options);
        options.storage = storage.as_mut_ptr();
        options.storage_len = storage.len();
        options.value_capacity = 16;
        let k = keyer(SCHEMA, DESCRIPTION, Some(&options)).expect("made");
        let mut instances = 0usize;
        assert_eq!(
            wz_ext_instance_keyer_instances(wz_ext_instance_keyer_loan(&k), &mut instances),
            Z_OK
        );
        assert_eq!(instances, 6);
        assert_eq!(
            last(&k, 0, 16).0,
            Z_RES_CHANNEL_NODATA,
            "no value before the first"
        );
        for (bi, bay) in [12u64, 30, 44].into_iter().enumerate() {
            for (ti, tilt) in [-3i32, 5].into_iter().enumerate() {
                let payload = reading(bay, tilt, &[bi as u8, ti as u8]);
                let key = index(&k, &payload, 0);
                assert_eq!(key.status, WZ_EXT_INSTANCE_KEY_INDEXED, "{bay} {tilt}");
                assert_eq!(key.instance, bi * 2 + ti, "{bay} {tilt}");
                assert_eq!(key.last, WZ_EXT_INSTANCE_KEY_LAST_RECORDED);
                assert_eq!(key.reported, 0);
                let (rc, value) = last(&k, key.instance, 16);
                assert_eq!(rc, Z_OK);
                assert_eq!(value, payload);
                // The value is in the program's storage, at the instance's room.
                let room = key.instance * 16;
                assert_eq!(&storage[room..room + payload.len()], &payload[..]);
            }
        }
        // A copy into too little room says how long the value is and copies nothing.
        let mut tiny = [0xAAu8; 2];
        let mut len = 0usize;
        assert_eq!(
            wz_ext_instance_keyer_last(
                wz_ext_instance_keyer_loan(&k),
                0,
                tiny.as_mut_ptr(),
                2,
                &mut len
            ),
            Z_ERR_OVERFLOW
        );
        assert_eq!((len, tiny), (reading(12, -3, &[0, 0]).len(), [0xAA, 0xAA]));
        assert_eq!(last(&k, 6, 16).0, Z_EINVAL, "an instance the keyer has not");
        drop_keyer(k);
    }
}

#[test]
fn a_sample_of_no_instance_is_dropped_counted_and_reported_once_per_interval() {
    unsafe {
        let k = keyer(SCHEMA, DESCRIPTION, None).expect("made");
        let outside = index(&k, &reading(30, 4, b""), 5_000);
        assert_eq!(outside.status, WZ_EXT_INSTANCE_KEY_NOT_LISTED);
        assert_eq!(outside.field, 1, "the tilt");
        assert_eq!(
            (outside.reported, outside.dropped),
            (1, 1),
            "the first is reported"
        );
        let held = index(&k, &reading(31, 5, b""), 5_100);
        assert_eq!(
            (held.status, held.field),
            (WZ_EXT_INSTANCE_KEY_NOT_LISTED, 0)
        );
        assert_eq!(held.reported, 0, "within the interval it is held");
        let mut no_bay = Vec::new();
        varint(2 << 3, &mut no_bay);
        varint(10, &mut no_bay);
        let absent = index(&k, &no_bay, 5_200);
        assert_eq!(
            (absent.status, absent.field),
            (WZ_EXT_INSTANCE_KEY_ABSENT, 0)
        );
        let broken = index(&k, &[0x08], 5_300);
        assert_eq!(broken.status, WZ_EXT_INSTANCE_KEY_UNDECODABLE);
        // An indexed sample keeps no last value: the keyer was made without storage.
        let kept = index(&k, &reading(44, 5, b""), 5_400);
        assert_eq!(
            (kept.status, kept.instance),
            (WZ_EXT_INSTANCE_KEY_INDEXED, 5)
        );
        assert_eq!(kept.last, WZ_EXT_INSTANCE_KEY_LAST_NOT_KEPT);

        let mut report: wz_ext_instance_key_t = std::mem::zeroed();
        assert!(!wz_ext_instance_keyer_flush(
            wz_ext_instance_keyer_loan(&k),
            5_999,
            &mut report
        ));
        assert!(wz_ext_instance_keyer_flush(
            wz_ext_instance_keyer_loan(&k),
            6_000,
            &mut report
        ));
        assert_eq!(
            (report.status, report.reported, report.dropped),
            (WZ_EXT_INSTANCE_KEY_UNDECODABLE, 1, 3),
            "the latest drop's reason and the three held"
        );
        let (mut undecodable, mut absent_n, mut not_listed) = (0u64, 0u64, 0u64);
        assert_eq!(
            wz_ext_instance_keyer_counts(
                wz_ext_instance_keyer_loan(&k),
                &mut undecodable,
                &mut absent_n,
                &mut not_listed
            ),
            Z_OK
        );
        assert_eq!((undecodable, absent_n, not_listed), (1, 1, 2));
        drop_keyer(k);
    }
}

#[test]
fn a_keyer_is_refused_by_a_code_and_a_reason() {
    unsafe {
        let (rc, reason) = keyer("message {", DESCRIPTION, None).unwrap_err();
        assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
        assert!(reason.starts_with("schema"), "{reason}");

        let (rc, reason) = keyer(
            SCHEMA,
            r#"{"message": "syn.door.Nothing", "fields": []}"#,
            None,
        )
        .unwrap_err();
        assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
        assert!(reason.starts_with("description: /message"), "{reason}");

        let (rc, reason) = keyer(
            SCHEMA,
            r#"{"message": "syn.door.Reading", "fields": [{"path": "body", "values": [1]}]}"#,
            None,
        )
        .unwrap_err();
        assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
        assert!(
            reason.starts_with("description: /fields/0/path"),
            "{reason}"
        );

        let mut storage = vec![0u8; 6 * 4 - 1];
        let mut options: wz_ext_instance_keyer_options_t = std::mem::zeroed();
        wz_ext_instance_keyer_options_default(&mut options);
        options.storage = storage.as_mut_ptr();
        options.storage_len = storage.len();
        options.value_capacity = 4;
        let (rc, reason) = keyer(SCHEMA, DESCRIPTION, Some(&options)).unwrap_err();
        assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
        assert!(reason.starts_with("storage"), "{reason}");

        options.storage = std::ptr::null_mut();
        assert_eq!(
            keyer(SCHEMA, DESCRIPTION, Some(&options)).unwrap_err().0,
            Z_ERR_NULL
        );

        let mut this: wz_ext_owned_instance_keyer_t = std::mem::zeroed();
        let description = CString::new(DESCRIPTION).unwrap();
        assert_eq!(
            wz_ext_instance_keyer_new(
                &mut this,
                std::ptr::null(),
                1,
                description.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut()
            ),
            Z_ERR_NULL,
            "a null file list with a count"
        );
        let bad = [0xFFu8, 0];
        let name = CString::new("door.proto").unwrap();
        let files = [wz_ext_proto_file_t {
            name: name.as_ptr(),
            text: bad.as_ptr().cast(),
        }];
        assert_eq!(
            wz_ext_instance_keyer_new(
                &mut this,
                files.as_ptr(),
                1,
                description.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut()
            ),
            Z_EINVAL,
            "a file that is not UTF-8"
        );
        assert!(!wz_ext_internal_instance_keyer_check(&this));

        // The doors of the gravestone refuse it.
        let mut instances = 0usize;
        assert_eq!(
            wz_ext_instance_keyer_instances(wz_ext_instance_keyer_loan(&this), &mut instances),
            Z_ERR_NULL
        );
        let mut out: wz_ext_instance_key_t = std::mem::zeroed();
        assert_eq!(
            wz_ext_instance_keyer_index(
                wz_ext_instance_keyer_loan(&this),
                [].as_ptr(),
                0,
                0,
                &mut out
            ),
            Z_ERR_NULL
        );
    }
}

#[test]
fn the_last_value_of_an_instance_is_set_by_the_program() {
    unsafe {
        let mut storage = vec![0u8; 6 * 4];
        let mut options: wz_ext_instance_keyer_options_t = std::mem::zeroed();
        wz_ext_instance_keyer_options_default(&mut options);
        options.storage = storage.as_mut_ptr();
        options.storage_len = storage.len();
        options.value_capacity = 4;
        let k = keyer(SCHEMA, DESCRIPTION, Some(&options)).expect("made");
        let loan = wz_ext_instance_keyer_loan(&k);
        assert_eq!(
            wz_ext_instance_keyer_set_last(loan, 0, b"dflt".as_ptr(), 4),
            Z_OK
        );
        assert_eq!(last(&k, 0, 4), (Z_OK, b"dflt".to_vec()));
        assert_eq!(
            wz_ext_instance_keyer_set_last(loan, 0, b"toolong".as_ptr(), 7),
            Z_ERR_OVERFLOW
        );
        assert_eq!(
            last(&k, 0, 4),
            (Z_OK, b"dflt".to_vec()),
            "the value before is kept"
        );
        assert_eq!(
            wz_ext_instance_keyer_set_last(loan, 6, b"x".as_ptr(), 1),
            Z_EINVAL
        );
        drop_keyer(k);

        let without = keyer(SCHEMA, DESCRIPTION, None).expect("made");
        assert_eq!(
            wz_ext_instance_keyer_set_last(
                wz_ext_instance_keyer_loan(&without),
                0,
                b"x".as_ptr(),
                1
            ),
            Z_EINVAL,
            "a keyer that keeps no last values"
        );
        assert_eq!(last(&without, 0, 4).0, Z_EINVAL);
        drop_keyer(without);
    }
}

#[cfg(feature = "event-ring")]
#[test]
fn a_report_of_drops_is_an_event_of_the_nodes_log() {
    use wz_capi_pico::event_log::*;
    unsafe {
        let k = keyer(SCHEMA, DESCRIPTION, None).expect("made");
        // A tilt in no list, reported at once as the first drop.
        let key = index(&k, &reading(12, 9, b""), 0);
        assert_eq!(key.reported, 1);
        let mut cursor = 0u64;
        let mut found = false;
        for _ in 0..4096 {
            let mut event: wz_ext_event_t = std::mem::zeroed();
            let mut args = [0u64; 4];
            assert_eq!(
                wz_ext_event_read(&mut cursor, &mut event, args.as_mut_ptr(), args.len()),
                Z_OK
            );
            if event.kind == WZ_EXT_EVENT_EMPTY {
                break;
            }
            if event.kind == WZ_EXT_EVENT_RECORD
                && event.source == WZ_EXT_EVENT_SOURCE_INSTANCE_KEY_DROPPED
                && args[..3] == [WZ_EXT_EVENT_INSTANCE_KEY_NOT_LISTED, 1, 1]
            {
                assert_eq!(event.level, WZ_EXT_EVENT_LEVEL_LIBRARY);
                assert_eq!(event.arg_count, 3);
                found = true;
            }
        }
        assert!(found, "the report is in the log");
        drop_keyer(k);
    }
}

/// The end-to-end doors, with a profile whose message cell names a sender so a receiver can be
/// keyed by sender: a two-byte CRC first, the length, the cell and a one-byte counter last.
#[cfg(all(feature = "e2e-sender", feature = "e2e-receiver"))]
mod streams {
    use super::*;
    use wz_capi_pico::e2e_receiver::*;
    use wz_capi_pico::e2e_sender::*;

    const PROFILE: &str = r#"{
      "name": "door-keyed",
      "fields": [
        {"name": "crc", "bytes": 2},
        {"name": "length", "bytes": 2},
        {"name": "cell", "bytes": 2, "split": [{"name": "sender", "lsb": 0, "width": 16}]},
        {"name": "counter", "bytes": 1}
      ],
      "crc": {"field": "crc", "width": 16, "poly": "0x8BB7", "init": "0x0000",
              "refin": false, "refout": false, "xorout": "0x0000",
              "cover": ["length", "cell", "counter", "@payload"]},
      "length": {"field": "length", "counts": "frame"},
      "counter": {"field": "counter", "max_gap": 3, "timeout_ms": 100},
      "cell": {"field": "cell", "sender": "sender"}
    }"#;

    const VALUES: &str = r#"{"cell": {"sender": 737}}"#;

    unsafe fn sender(streams: usize) -> wz_ext_owned_e2e_sender_t {
        let mut options: wz_ext_e2e_sender_options_t = std::mem::zeroed();
        wz_ext_e2e_sender_options_default(&mut options);
        options.streams = streams;
        let profile = CString::new(PROFILE).unwrap();
        let values = CString::new(VALUES).unwrap();
        let mut this: wz_ext_owned_e2e_sender_t = std::mem::zeroed();
        let rc = wz_ext_e2e_sender_new(
            &mut this,
            profile.as_ptr(),
            values.as_ptr(),
            &options,
            std::ptr::null_mut(),
        );
        assert_eq!(rc, Z_OK);
        this
    }

    unsafe fn receiver(
        options: &wz_ext_e2e_receiver_options_t,
    ) -> Result<wz_ext_owned_e2e_receiver_t, ZResult> {
        let profile = CString::new(PROFILE).unwrap();
        let mut this: wz_ext_owned_e2e_receiver_t = std::mem::zeroed();
        let rc = wz_ext_e2e_receiver_new(
            &mut this,
            profile.as_ptr(),
            std::ptr::null(),
            options,
            std::ptr::null_mut(),
        );
        if rc == Z_OK {
            Ok(this)
        } else {
            Err(rc)
        }
    }

    fn indexed(streams: usize) -> wz_ext_e2e_receiver_options_t {
        let mut options: wz_ext_e2e_receiver_options_t = unsafe { std::mem::zeroed() };
        unsafe { wz_ext_e2e_receiver_options_default(&mut options) };
        options.streams = streams;
        options
    }

    /// Protect `payload` on the stream of its instance: the code, the frame and the key.
    unsafe fn protect(
        k: &wz_ext_owned_instance_keyer_t,
        tx: &wz_ext_owned_e2e_sender_t,
        payload: &[u8],
    ) -> (ZResult, Vec<u8>, u64, wz_ext_instance_key_t) {
        let mut out = vec![0u8; 64];
        let mut written = usize::MAX;
        let mut counter = u64::MAX;
        let mut key: wz_ext_instance_key_t = std::mem::zeroed();
        let rc = wz_ext_instance_keyer_protect(
            wz_ext_instance_keyer_loan(k),
            wz_ext_e2e_sender_loan(tx),
            payload.as_ptr(),
            payload.len(),
            0,
            out.as_mut_ptr(),
            out.len(),
            &mut written,
            &mut counter,
            &mut key,
        );
        out.truncate(if rc == Z_OK { written } else { 0 });
        (rc, out, counter, key)
    }

    unsafe fn judge(
        k: &wz_ext_owned_instance_keyer_t,
        rx: &wz_ext_owned_e2e_receiver_t,
        frame: &[u8],
        now: u64,
    ) -> (ZResult, wz_ext_instance_key_t, wz_ext_e2e_verdict_t) {
        let mut key: wz_ext_instance_key_t = std::mem::zeroed();
        let mut verdict: wz_ext_e2e_verdict_t = std::mem::zeroed();
        let rc = wz_ext_instance_keyer_judge(
            wz_ext_instance_keyer_loan(k),
            wz_ext_e2e_receiver_loan(rx),
            frame.as_ptr(),
            frame.len(),
            now,
            &mut key,
            &mut verdict,
        );
        (rc, key, verdict)
    }

    #[test]
    fn the_receiver_judges_two_instances_apart_through_the_stream_number() {
        unsafe {
            let tx_keyer = keyer(SCHEMA, DESCRIPTION, None).expect("made");
            let rx_keyer = keyer(SCHEMA, DESCRIPTION, None).expect("made");
            let mut tx = sender(6);
            let mut rx = receiver(&indexed(6)).expect("made");
            let first = reading(12, -3, b"a");
            let other = reading(30, 5, b"b");
            let mut frames = Vec::new();
            for payload in [&first, &other, &first, &other] {
                let (rc, frame, _, key) = protect(&tx_keyer, &tx, payload);
                assert_eq!(rc, Z_OK);
                frames.push((frame, key.instance));
            }
            assert_eq!(frames[0].1, 0);
            assert_eq!(frames[1].1, 3);
            // Each instance's counter starts at 0: judged in one stream, the second instance's
            // first frame would repeat the first's.
            let want = [
                WZ_EXT_E2E_FIRST,
                WZ_EXT_E2E_FIRST,
                WZ_EXT_E2E_OK,
                WZ_EXT_E2E_OK,
            ];
            for (i, ((frame, instance), status)) in frames.iter().zip(want).enumerate() {
                let (rc, key, verdict) = judge(&rx_keyer, &rx, frame, i as u64);
                assert_eq!(rc, Z_OK);
                assert_eq!(
                    (key.status, key.instance),
                    (WZ_EXT_INSTANCE_KEY_INDEXED, *instance)
                );
                assert_eq!(verdict.status, status, "frame {i}");
                assert_eq!(verdict.has & WZ_EXT_E2E_HAS_STREAM, WZ_EXT_E2E_HAS_STREAM);
                assert_eq!(verdict.stream, *instance);
            }

            // A payload of no instance is refused by the protecting door and builds nothing;
            // sent anyway on a stream of the sender's own choosing, the judging door drops it
            // and the receiver does not see it.
            let stray = reading(12, 9, b"c");
            let (rc, frame, _, key) = protect(&tx_keyer, &tx, &stray);
            assert_eq!((rc, frame.len()), (Z_EINVAL, 0));
            assert_eq!((key.status, key.field), (WZ_EXT_INSTANCE_KEY_NOT_LISTED, 1));
            let mut out = vec![0u8; 64];
            let mut written = 0usize;
            assert_eq!(
                wz_ext_e2e_sender_protect(
                    wz_ext_e2e_sender_loan(&tx),
                    0,
                    stray.as_ptr(),
                    stray.len(),
                    out.as_mut_ptr(),
                    out.len(),
                    &mut written,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                ),
                Z_OK
            );
            out.truncate(written);
            let (rc, key, verdict) = judge(&rx_keyer, &rx, &out, 10);
            assert_eq!(rc, Z_OK);
            assert_eq!(key.status, WZ_EXT_INSTANCE_KEY_NOT_LISTED);
            assert_eq!(
                verdict,
                wz_ext_e2e_verdict_t::default(),
                "a dropped frame is not judged"
            );
            // The next frame of the first instance is still the next one.
            let (_, next, _, _) = protect(&tx_keyer, &tx, &first);
            let (_, _, verdict) = judge(&rx_keyer, &rx, &next, 11);
            assert_eq!(verdict.status, WZ_EXT_E2E_OK);

            let mut narrow = receiver(&indexed(2)).expect("made");
            let (rc, _, _) = judge(&rx_keyer, &narrow, &next, 12);
            assert_eq!(
                rc, Z_ERR_CONFIG_INVALID_VALUE,
                "fewer streams than instances"
            );

            wz_ext_e2e_receiver_drop(wz_ext_e2e_receiver_move(&mut narrow));
            wz_ext_e2e_receiver_drop(wz_ext_e2e_receiver_move(&mut rx));
            wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(&mut tx));
            drop_keyer(tx_keyer);
            drop_keyer(rx_keyer);
        }
    }

    #[cfg(feature = "e2e-sender-demux")]
    #[test]
    fn a_receiver_kept_per_sender_is_refused_by_the_judging_door() {
        unsafe {
            let k = keyer(SCHEMA, DESCRIPTION, None).expect("made");
            let mut tx = sender(6);
            let (_, frame, _, _) = protect(&k, &tx, &reading(44, 5, b""));
            let mut options = indexed(6);
            options.keying = WZ_EXT_E2E_KEYING_SENDERS_ARRIVAL;
            let mut rx = receiver(&options).expect("made");
            let (rc, key, verdict) = judge(&k, &rx, &frame, 0);
            assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
            assert_eq!(key, wz_ext_instance_key_t::default());
            assert_eq!(verdict, wz_ext_e2e_verdict_t::default());
            let (mut undecodable, mut absent, mut not_listed) = (9u64, 9u64, 9u64);
            wz_ext_instance_keyer_counts(
                wz_ext_instance_keyer_loan(&k),
                &mut undecodable,
                &mut absent,
                &mut not_listed,
            );
            assert_eq!(
                (undecodable, absent, not_listed),
                (0, 0, 0),
                "a refusal counts nothing"
            );
            wz_ext_e2e_receiver_drop(wz_ext_e2e_receiver_move(&mut rx));
            wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(&mut tx));
            drop_keyer(k);
        }
    }
}
