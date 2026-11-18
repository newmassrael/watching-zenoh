// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The sender of a declared segment profile through the `wz_ext_segment_*` doors, driven as a C
//! program drives them.
//!
//! The oracle is the synthetic profile's own piece builder (`segment_profile::synthetic::piece`),
//! which lays each field by hand and computes the CRC from the model's parameters, not from a
//! parsed profile: a door whose header differed by a bit from the one the profile describes fails
//! the byte comparison. What a unit test of the writer cannot show is the part a C program relies
//! on: that the handle keeps the transfer number across calls, that a refusal comes back as a code
//! and a reason and consumes nothing, that a callback which stops the split has used the number,
//! and that the put door puts each piece on a real publisher, in order.

#![cfg(feature = "segment-sender")]

use std::ffi::{c_void, CString};

use wz_app_frame::segment_profile::synthetic;
use wz_capi_pico::result::{ZResult, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_NULL, Z_OK};
use wz_capi_pico::segment_sender::*;
use wz_capi_pico::{
    z_internal_string_check, z_owned_string_t, z_string_data, z_string_drop, z_string_len,
    z_string_loan, z_string_move,
};

/// The stream value the program states for the synthetic profile's one free field, `origin`.
const ORIGIN: u16 = 0x0102;
/// The same value as the values text states it.
const VALUES: &str = r#"{"origin": 258}"#;
/// A code no door of the library returns, for a callback that stops a split.
const STOPPED: ZResult = -42;

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

/// The piece the profile describes for `msg` cut at `chunk`, piece `index`, under `transfer`.
fn expected_piece(transfer: u8, msg: &[u8], chunk: usize, index: usize) -> Vec<u8> {
    let at = index * chunk;
    let end = (at + chunk).min(msg.len());
    synthetic::piece(ORIGIN, transfer, msg.len() as u32, at as u32, &msg[at..end])
}

/// A three-byte little-endian field of a piece's header.
fn le24(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])
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

/// A sender made through the door, or the code it answered and the refusal it wrote. A refused
/// slot holds the null state, which is checked here so every refusal below is held to it.
unsafe fn make_raw(
    profile: &CString,
    values: &CString,
    first: u64,
    rollover: wz_ext_segment_rollover_t,
) -> Result<wz_ext_owned_segment_sender_t, (ZResult, String)> {
    let mut sender: wz_ext_owned_segment_sender_t = std::mem::zeroed();
    let mut refusal: z_owned_string_t = std::mem::zeroed();
    let rc = wz_ext_segment_sender_new(
        &mut sender,
        profile.as_ptr(),
        values.as_ptr(),
        first,
        rollover,
        &mut refusal,
    );
    let text = take(&mut refusal);
    if rc == Z_OK {
        assert!(text.is_empty(), "a made sender leaves no refusal: {text}");
        assert!(wz_ext_internal_segment_sender_check(&sender));
        Ok(sender)
    } else {
        assert!(
            !wz_ext_internal_segment_sender_check(&sender),
            "a refused sender leaves the null state"
        );
        Err((rc, text))
    }
}

unsafe fn make(
    profile: &str,
    values: &str,
    first: u64,
    rollover: wz_ext_segment_rollover_t,
) -> Result<wz_ext_owned_segment_sender_t, (ZResult, String)> {
    let profile = CString::new(profile).unwrap();
    let values = CString::new(values).unwrap();
    make_raw(&profile, &values, first, rollover)
}

unsafe fn demo(first: u64, rollover: wz_ext_segment_rollover_t) -> wz_ext_owned_segment_sender_t {
    make(synthetic::PROFILE, VALUES, first, rollover).expect("the synthetic profile makes a sender")
}

unsafe fn release(sender: &mut wz_ext_owned_segment_sender_t) {
    wz_ext_segment_sender_drop(wz_ext_segment_sender_move(sender));
}

unsafe fn next_of(sender: &wz_ext_owned_segment_sender_t) -> Option<u64> {
    let mut out = u64::MAX;
    wz_ext_segment_sender_next(wz_ext_segment_sender_loan(sender), &mut out).then_some(out)
}

unsafe extern "C" fn collect(context: *mut c_void, piece: *const u8, len: usize) -> ZResult {
    let pieces = &mut *context.cast::<Vec<Vec<u8>>>();
    pieces.push(std::slice::from_raw_parts(piece, len).to_vec());
    Z_OK
}

/// Accepts as many pieces as the counter behind `context` says, then stops the split.
unsafe extern "C" fn stop_after(context: *mut c_void, _piece: *const u8, _len: usize) -> ZResult {
    let left = &mut *context.cast::<usize>();
    if *left == 0 {
        return STOPPED;
    }
    *left -= 1;
    Z_OK
}

/// What one split through the door did: its code, its result, the pieces the callback was
/// handed and the refusal text.
struct Outcome {
    rc: ZResult,
    result: wz_ext_segment_result_t,
    pieces: Vec<Vec<u8>>,
    refusal: String,
}

unsafe fn split_raw(
    sender: *const wz_ext_loaned_segment_sender_t,
    message: *const u8,
    len: usize,
    chunk: usize,
) -> Outcome {
    let mut pieces: Vec<Vec<u8>> = Vec::new();
    // A result the door must overwrite, so a door that left it alone is seen.
    let mut result = wz_ext_segment_result_t {
        transfer: 99,
        pieces: 99,
        sent: 99,
    };
    let mut refusal: z_owned_string_t = std::mem::zeroed();
    let rc = wz_ext_segment_sender_split(
        sender,
        message,
        len,
        chunk,
        Some(collect),
        (&mut pieces as *mut Vec<Vec<u8>>).cast::<c_void>(),
        &mut result,
        &mut refusal,
    );
    let refusal = take(&mut refusal);
    Outcome {
        rc,
        result,
        pieces,
        refusal,
    }
}

unsafe fn split(sender: &wz_ext_owned_segment_sender_t, msg: &[u8], chunk: usize) -> Outcome {
    split_raw(
        wz_ext_segment_sender_loan(sender),
        msg.as_ptr(),
        msg.len(),
        chunk,
    )
}

/// A refusal before any piece: `Z_EINVAL`, a zeroed result, no piece and a reason.
fn assert_refused(outcome: &Outcome, reason: &str) {
    assert_eq!(outcome.rc, Z_EINVAL, "refused: {}", outcome.refusal);
    assert_eq!(outcome.result, wz_ext_segment_result_t::default());
    assert!(outcome.pieces.is_empty(), "a refused message emits nothing");
    assert!(
        outcome.refusal.contains(reason),
        "the refusal names why ({reason}): {}",
        outcome.refusal
    );
}

#[test]
fn a_split_hands_the_callback_each_piece_the_profile_describes() {
    // SAFETY: every handle is made by its door and dropped before the test returns; the buffers
    // outlive each call.
    unsafe {
        let mut sender = demo(7, WZ_EXT_SEGMENT_ROLLOVER_REFUSE);
        let msg = message(30);
        let outcome = split(&sender, &msg, 8);
        assert_eq!(outcome.rc, Z_OK, "{}", outcome.refusal);
        assert!(outcome.refusal.is_empty());
        assert_eq!(
            outcome.result,
            wz_ext_segment_result_t {
                transfer: 7,
                pieces: 4,
                sent: 4
            }
        );
        assert_eq!(outcome.pieces.len(), 4);
        for (index, piece) in outcome.pieces.iter().enumerate() {
            assert_eq!(
                piece,
                &expected_piece(7, &msg, 8, index),
                "piece {index} is the one the profile describes, CRC included"
            );
            // The header field by field, as a reader of the profile places it.
            let chunk = &msg[index * 8..(index * 8 + 8).min(msg.len())];
            assert_eq!(&piece[0..2], &[0xA5u8, 0xC3], "the mark the profile fixes");
            assert_eq!(u16::from_le_bytes([piece[2], piece[3]]), ORIGIN);
            assert_eq!(piece[4], 7, "the transfer number");
            assert_eq!(le24(&piece[5..8]), 30, "the total is the message's length");
            assert_eq!(
                le24(&piece[8..11]) as usize,
                index * 8,
                "where the chunk starts"
            );
            assert_eq!(&piece[synthetic::HEADER_BYTES..], chunk);
        }
        assert_eq!(
            outcome.pieces[3].len(),
            synthetic::HEADER_BYTES + 6,
            "the last chunk is the rest"
        );
        assert_eq!(
            next_of(&sender),
            Some(8),
            "the next message carries the next number"
        );

        // A message no longer than one chunk is one piece, still with its header.
        let short = message(5);
        let outcome = split(&sender, &short, 8);
        assert_eq!(outcome.rc, Z_OK);
        assert_eq!(outcome.pieces.len(), 1);
        assert_eq!(outcome.pieces[0], expected_piece(8, &short, 8, 0));
        assert_eq!(next_of(&sender), Some(9));
        release(&mut sender);
    }
}

#[test]
fn a_refused_message_emits_nothing_and_consumes_no_number() {
    // SAFETY: as above.
    unsafe {
        let mut sender = demo(7, WZ_EXT_SEGMENT_ROLLOVER_REFUSE);
        let msg = message(30);

        assert_refused(&split(&sender, &msg, 0), "chunk size is zero");
        assert_eq!(next_of(&sender), Some(7));

        // An empty message, with a pointer and without one.
        assert_refused(&split(&sender, &[], 8), "empty");
        let outcome = split_raw(wz_ext_segment_sender_loan(&sender), std::ptr::null(), 0, 8);
        assert_refused(&outcome, "empty");
        assert_eq!(next_of(&sender), Some(7));

        // Longer than the profile's total_max (4096).
        assert_refused(&split(&sender, &message(4097), 1024), "total_max");
        assert_eq!(next_of(&sender), Some(7));

        // The null arguments: nothing is split and the result is zeroed.
        let outcome = split_raw(wz_ext_segment_sender_loan(&sender), std::ptr::null(), 4, 8);
        assert_eq!(outcome.rc, Z_ERR_NULL, "a null message with a length");
        assert_eq!(outcome.result, wz_ext_segment_result_t::default());
        let outcome = split_raw(std::ptr::null(), msg.as_ptr(), msg.len(), 8);
        assert_eq!(outcome.rc, Z_ERR_NULL, "a null sender");
        assert!(outcome.pieces.is_empty());
        let mut result = wz_ext_segment_result_t {
            transfer: 99,
            pieces: 99,
            sent: 99,
        };
        assert_eq!(
            wz_ext_segment_sender_split(
                wz_ext_segment_sender_loan(&sender),
                msg.as_ptr(),
                msg.len(),
                8,
                None,
                std::ptr::null_mut(),
                &mut result,
                std::ptr::null_mut(),
            ),
            Z_ERR_NULL,
            "a null callback"
        );
        assert_eq!(result, wz_ext_segment_result_t::default());
        assert_eq!(next_of(&sender), Some(7));

        // After every refusal the next message carries the number the sender was made with.
        let outcome = split(&sender, &msg, 8);
        assert_eq!(outcome.rc, Z_OK);
        assert_eq!(outcome.result.transfer, 7);
        release(&mut sender);
    }
}

#[test]
fn a_callback_that_stops_the_split_has_used_the_number() {
    // SAFETY: as above.
    unsafe {
        let mut sender = demo(7, WZ_EXT_SEGMENT_ROLLOVER_REFUSE);
        let msg = message(30);
        let mut left = 1usize;
        let mut result = wz_ext_segment_result_t::default();
        let mut refusal: z_owned_string_t = std::mem::zeroed();
        let rc = wz_ext_segment_sender_split(
            wz_ext_segment_sender_loan(&sender),
            msg.as_ptr(),
            msg.len(),
            8,
            Some(stop_after),
            (&mut left as *mut usize).cast::<c_void>(),
            &mut result,
            &mut refusal,
        );
        let refusal = take(&mut refusal);
        assert_eq!(rc, STOPPED, "the split returns what the callback returned");
        assert_eq!(
            result,
            wz_ext_segment_result_t {
                transfer: 7,
                pieces: 4,
                sent: 1
            }
        );
        assert!(
            refusal.contains("piece 2 of 4 of transfer 7"),
            "the refusal names the piece that did not go: {refusal}"
        );
        assert_eq!(
            next_of(&sender),
            Some(8),
            "a reader may have seen piece 1 under 7"
        );
        release(&mut sender);
    }
}

#[test]
fn the_number_is_refused_past_its_largest_value_unless_the_sender_restarts() {
    // SAFETY: as above.
    unsafe {
        let msg = message(10);

        // The profile's transfer field is one byte: 255 is its largest value.
        let mut refusing = demo(255, WZ_EXT_SEGMENT_ROLLOVER_REFUSE);
        assert_eq!(split(&refusing, &msg, 8).result.transfer, 255);
        assert_eq!(next_of(&refusing), None, "nothing comes after the largest");
        assert_refused(&split(&refusing, &msg, 8), "largest value");
        assert_eq!(next_of(&refusing), None);
        // `set` gives the stream a number again.
        assert_eq!(
            wz_ext_segment_sender_set(wz_ext_segment_sender_loan(&refusing), 3),
            Z_OK
        );
        assert_eq!(split(&refusing, &msg, 8).result.transfer, 3);
        release(&mut refusing);

        // Restarting goes back to the number the sender was made with, not to 0.
        let mut restarting = demo(1, WZ_EXT_SEGMENT_ROLLOVER_RESTART);
        assert_eq!(
            wz_ext_segment_sender_set(wz_ext_segment_sender_loan(&restarting), 255),
            Z_OK
        );
        let outcome = split(&restarting, &msg, 8);
        assert_eq!(outcome.result.transfer, 255);
        assert_eq!(outcome.pieces[0], expected_piece(255, &msg, 8, 0));
        assert_eq!(next_of(&restarting), Some(1));
        release(&mut restarting);

        // A first number past the field is taken, and refused by the message that would carry it.
        let mut wide = demo(256, WZ_EXT_SEGMENT_ROLLOVER_REFUSE);
        assert_refused(&split(&wide, &msg, 8), "past the largest value it holds");
        assert_eq!(next_of(&wide), Some(256), "and nothing was consumed");
        release(&mut wide);
    }
}

#[test]
fn a_sender_is_refused_for_a_text_it_cannot_take() {
    // SAFETY: as above; the C strings outlive each call.
    unsafe {
        let refused = |profile: &str, values: &str| match make(
            profile,
            values,
            1,
            WZ_EXT_SEGMENT_ROLLOVER_REFUSE,
        ) {
            Err(refusal) => refusal,
            Ok(mut sender) => {
                release(&mut sender);
                panic!("expected a refusal of {profile} / {values}");
            }
        };

        let (rc, why) = refused(synthetic::PROFILE, "{}");
        assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
        assert!(why.starts_with("values") && why.contains("origin"), "{why}");

        let (rc, why) = refused(synthetic::PROFILE, r#"{"origin": 258, "number": 2}"#);
        assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE, "the mechanism's field");
        assert!(why.starts_with("values") && why.contains("number"), "{why}");

        let (rc, why) = refused(synthetic::PROFILE, r#"{"origin": 258, "nowhere": 1}"#);
        assert_eq!(
            rc, Z_ERR_CONFIG_INVALID_VALUE,
            "a field the profile has not"
        );
        assert!(
            why.starts_with("values") && why.contains("nowhere"),
            "{why}"
        );

        let (rc, why) = refused(r#"{"name": "not-a-segment-profile"}"#, VALUES);
        assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
        assert!(why.starts_with("profile"), "{why}");

        // A rollover the library does not know.
        let (rc, why) = make(synthetic::PROFILE, VALUES, 1, 2)
            .err()
            .expect("refused");
        assert_eq!(rc, Z_EINVAL);
        assert!(
            why.is_empty(),
            "an argument it cannot read writes no reason: {why}"
        );

        // Text that is not UTF-8.
        let profile = CString::new(synthetic::PROFILE).unwrap();
        let not_utf8 = CString::new(vec![0xFFu8, 0xFE]).unwrap();
        let (rc, _) = make_raw(&profile, &not_utf8, 1, WZ_EXT_SEGMENT_ROLLOVER_REFUSE)
            .err()
            .expect("refused");
        assert_eq!(rc, Z_EINVAL);

        // The null arguments.
        let values = CString::new(VALUES).unwrap();
        let mut sender: wz_ext_owned_segment_sender_t = std::mem::zeroed();
        assert_eq!(
            wz_ext_segment_sender_new(
                &mut sender,
                std::ptr::null(),
                values.as_ptr(),
                1,
                WZ_EXT_SEGMENT_ROLLOVER_REFUSE,
                std::ptr::null_mut(),
            ),
            Z_ERR_NULL
        );
        assert!(!wz_ext_internal_segment_sender_check(&sender));
        assert_eq!(
            wz_ext_segment_sender_new(
                std::ptr::null_mut(),
                profile.as_ptr(),
                values.as_ptr(),
                1,
                WZ_EXT_SEGMENT_ROLLOVER_REFUSE,
                std::ptr::null_mut(),
            ),
            Z_ERR_NULL
        );
    }
}

#[test]
fn a_dropped_sender_is_the_null_state_and_a_second_drop_does_nothing() {
    // SAFETY: as above.
    unsafe {
        let mut sender = demo(1, WZ_EXT_SEGMENT_ROLLOVER_REFUSE);
        release(&mut sender);
        assert!(!wz_ext_internal_segment_sender_check(&sender));
        release(&mut sender);
        wz_ext_segment_sender_drop(std::ptr::null_mut());

        assert_eq!(next_of(&sender), None);
        assert_eq!(
            wz_ext_segment_sender_set(wz_ext_segment_sender_loan(&sender), 4),
            Z_ERR_NULL
        );
        let msg = message(4);
        let outcome = split(&sender, &msg, 8);
        assert_eq!(outcome.rc, Z_ERR_NULL);
        assert!(outcome.pieces.is_empty());

        // The null state written by its own door reads the same. The handle is copied out first,
        // as a C program copies the struct, so the sender is still released.
        let mut slot = demo(1, WZ_EXT_SEGMENT_ROLLOVER_REFUSE);
        let mut kept = std::ptr::read(&slot);
        wz_ext_internal_segment_sender_null(&mut slot);
        assert!(!wz_ext_internal_segment_sender_check(&slot));
        assert!(wz_ext_internal_segment_sender_check(&kept));
        release(&mut kept);

        let mut options = wz_ext_segment_put_options_t {
            timestamp: std::ptr::NonNull::<wz_capi_pico::z_timestamp_t>::dangling()
                .as_ptr()
                .cast_const(),
        };
        wz_ext_segment_put_options_default(&mut options);
        assert!(
            options.timestamp.is_null(),
            "the default carries no timestamp"
        );
    }
}

/// The put door over a loopback link: a session that listens holds a subscriber, a session that
/// dials it holds the publisher, and each piece of one message arrives as one sample, in order.
#[cfg(feature = "peer")]
mod over_loopback {
    use std::ffi::{c_void, CStr, CString};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use wz_capi_pico::result::{Z_ERR_NULL, Z_OK};
    use wz_capi_pico::segment_sender::*;
    use wz_capi_pico::{
        z_bytes_copy_from_buf, z_bytes_move, z_bytes_to_slice, z_close, z_closure_sample,
        z_closure_sample_move, z_config_default, z_config_loan_mut, z_config_move,
        z_declare_publisher, z_declare_subscriber, z_loaned_sample_t, z_open, z_owned_config_t,
        z_owned_publisher_t, z_owned_session_t, z_owned_slice_t, z_owned_subscriber_t,
        z_publisher_loan, z_publisher_move, z_publisher_put, z_sample_payload, z_session_drop,
        z_session_loan, z_session_loan_mut, z_session_move, z_slice_data, z_slice_drop,
        z_slice_len, z_slice_loan, z_slice_move, z_subscriber_move, z_undeclare_publisher,
        z_undeclare_subscriber, z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t,
        zp_config_insert, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY,
    };
    use wz_runtime_tokio_test_support::free_port;

    use super::{demo, expected_piece, message, next_of, release};

    type Seen = Arc<Mutex<Vec<Vec<u8>>>>;

    unsafe extern "C" fn on_sample(sample: *const z_loaned_sample_t, context: *mut c_void) {
        let seen = &*context.cast::<Seen>();
        let mut slice: z_owned_slice_t = std::mem::zeroed();
        if z_bytes_to_slice(z_sample_payload(sample), &mut slice) == Z_OK {
            let loaned = z_slice_loan(&slice);
            let (data, len) = (z_slice_data(loaned), z_slice_len(loaned));
            let bytes = if data.is_null() || len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(data, len).to_vec()
            };
            seen.lock().unwrap().push(bytes);
            z_slice_drop(z_slice_move(&mut slice));
        }
    }

    unsafe extern "C" fn on_drop(context: *mut c_void) {
        drop(Box::from_raw(context.cast::<Seen>()));
    }

    unsafe fn open_with(key: u8, endpoint: &CStr) -> Option<z_owned_session_t> {
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        assert_eq!(
            zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
            Z_OK
        );
        let mut session: z_owned_session_t = std::mem::zeroed();
        (z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()) == Z_OK).then_some(session)
    }

    unsafe fn view(text: &CStr) -> z_view_keyexpr_t {
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, text.as_ptr()), Z_OK);
        ke
    }

    unsafe fn plain_put(publisher: &z_owned_publisher_t, payload: &[u8]) {
        let mut bytes = std::mem::zeroed();
        assert_eq!(
            z_bytes_copy_from_buf(&mut bytes, payload.as_ptr(), payload.len()),
            Z_OK
        );
        assert_eq!(
            z_publisher_put(
                z_publisher_loan(publisher),
                z_bytes_move(&mut bytes),
                std::ptr::null()
            ),
            Z_OK
        );
    }

    /// Wait for `n` samples, and return them; fails, naming what arrived, when they do not.
    fn wait_for(seen: &Seen, n: usize) -> Vec<Vec<u8>> {
        for _ in 0..250 {
            if seen.lock().unwrap().len() >= n {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let got = seen.lock().unwrap().clone();
        assert_eq!(got.len(), n, "expected {n} samples, got {got:?}");
        got
    }

    #[test]
    fn a_put_reaches_a_subscriber_as_one_sample_per_piece_in_order() {
        let port = free_port();
        let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
        // SAFETY: every session, entity and handle is made by its door and released before the
        // test returns; the subscriber's context is released by its drop callback.
        unsafe {
            let mut listener =
                open_with(Z_CONFIG_LISTEN_KEY, &endpoint).expect("the listener opens");
            let seen: Seen = Arc::new(Mutex::new(Vec::new()));
            let context = Box::into_raw(Box::new(seen.clone())).cast::<c_void>();
            let mut closure = std::mem::zeroed();
            assert_eq!(
                z_closure_sample(&mut closure, Some(on_sample), Some(on_drop), context),
                Z_OK
            );
            let sub_ke = view(c"demo/segments/**");
            let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
            assert_eq!(
                z_declare_subscriber(
                    z_session_loan(&listener),
                    &mut subscriber,
                    z_view_keyexpr_loan(&sub_ke),
                    z_closure_sample_move(&mut closure),
                    std::ptr::null(),
                ),
                Z_OK
            );

            let mut dialer = None;
            for _ in 0..250 {
                if let Some(session) = open_with(Z_CONFIG_CONNECT_KEY, &endpoint) {
                    dialer = Some(session);
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let mut dialer = dialer.expect("the dialer opens");
            let pub_ke = view(c"demo/segments/one");
            let mut publisher: z_owned_publisher_t = std::mem::zeroed();
            assert_eq!(
                z_declare_publisher(
                    z_session_loan(&dialer),
                    &mut publisher,
                    z_view_keyexpr_loan(&pub_ke),
                    std::ptr::null(),
                ),
                Z_OK
            );

            // Republish a plain sample until one crosses, so the subscriber's declaration has
            // reached the dialer before a transfer number is spent on a put.
            for _ in 0..250 {
                if !seen.lock().unwrap().is_empty() {
                    break;
                }
                plain_put(&publisher, b"warm-up");
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(
                !seen.lock().unwrap().is_empty(),
                "CALIBRATION FAILED: no sample crossed the link, so nothing below measures the put"
            );
            std::thread::sleep(Duration::from_millis(300));
            seen.lock().unwrap().clear();

            let mut sender = demo(1, WZ_EXT_SEGMENT_ROLLOVER_REFUSE);
            let msg = message(30);
            let mut options: wz_ext_segment_put_options_t = std::mem::zeroed();
            wz_ext_segment_put_options_default(&mut options);
            let mut result = wz_ext_segment_result_t::default();
            let mut refusal: wz_capi_pico::z_owned_string_t = std::mem::zeroed();
            assert_eq!(
                wz_ext_segment_sender_put(
                    wz_ext_segment_sender_loan(&sender),
                    z_publisher_loan(&publisher),
                    msg.as_ptr(),
                    msg.len(),
                    8,
                    &options,
                    &mut result,
                    &mut refusal,
                ),
                Z_OK
            );
            assert!(!wz_capi_pico::z_internal_string_check(&refusal));
            assert_eq!(
                result,
                wz_ext_segment_result_t {
                    transfer: 1,
                    pieces: 4,
                    sent: 4
                }
            );
            let got = wait_for(&seen, 4);
            for (index, piece) in got.iter().enumerate() {
                assert_eq!(
                    piece,
                    &expected_piece(1, &msg, 8, index),
                    "sample {index} is piece {index}"
                );
            }

            // A put with no publisher is refused before the message is looked at, and consumes
            // nothing.
            assert_eq!(
                wz_ext_segment_sender_put(
                    wz_ext_segment_sender_loan(&sender),
                    std::ptr::null(),
                    msg.as_ptr(),
                    msg.len(),
                    8,
                    std::ptr::null(),
                    &mut result,
                    std::ptr::null_mut(),
                ),
                Z_ERR_NULL
            );
            assert_eq!(result, wz_ext_segment_result_t::default());
            assert_eq!(next_of(&sender), Some(2));

            release(&mut sender);
            z_undeclare_publisher(z_publisher_move(&mut publisher));
            z_undeclare_subscriber(z_subscriber_move(&mut subscriber));
            z_close(z_session_loan_mut(&mut dialer), std::ptr::null());
            z_session_drop(z_session_move(&mut dialer));
            z_close(z_session_loan_mut(&mut listener), std::ptr::null());
            z_session_drop(z_session_move(&mut listener));
        }
    }
}
