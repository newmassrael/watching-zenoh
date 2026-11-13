// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The sender of a declared segment profile through the `wz_capi_c_segment_*`
//! doors, driven exactly as a C program would drive them.
//!
//! The oracle is the READER: every piece a door hands on is read by
//! `wz_capture::segment_profile` and joined by `wz_capture::segment_chain`, and
//! the joined message must be the one the caller gave. A door whose header
//! differed from the reader's by a bit would fail the CRC or the place, and one
//! that reordered or dropped a piece would never close its transfer.
//!
//! What a unit test of the writer cannot show is the part a participant relies
//! on: that the HANDLE keeps the transfer number across calls made through the
//! ABI, that a refusal comes back as a code and a reason and uses no number, that
//! a callback which stops the split has used it, and that the put door puts the
//! pieces on a real publisher in order, every one with the caller's timestamp.
#![cfg(feature = "segment-sender")]

use std::ffi::{c_void, CString};
use std::sync::{Arc, Mutex};

use wz_capi_c::abi::{z_moved_string_t, z_owned_string_t};
use wz_capi_c::result::{ZResult, Z_EINVAL, Z_ENULL, Z_EPARSE, Z_OK};
use wz_capi_c::segment_sender::*;
use wz_capi_c::string::{z_string_data, z_string_drop, z_string_len, z_string_loan};
use wz_capture::segment_chain::{KeyRef, SegmentLedger};
use wz_capture::segment_profile::SegmentProfile;

/// A made-up profile, unlike any deployed header: a fixed mark, a two-byte
/// stream value, a one-byte transfer number, three-byte little-endian size and
/// offset, and a CRC-16 over all of it with the chunk last.
const PROFILE: &str = concat!(
    r#"{"name":"made-up","segments":{"fields":["#,
    r#"{"name":"mark","bytes":2,"equals":"0x6B1D"},"#,
    r#"{"name":"origin","bytes":2,"order":"little"},"#,
    r#"{"name":"number","bytes":1},"#,
    r#"{"name":"size","bytes":3,"order":"little"},"#,
    r#"{"name":"at","bytes":3,"order":"little"},"#,
    r#"{"name":"check","bytes":2}],"#,
    r#""crc":{"field":"check","width":16,"poly":"0x1021","init":"0xFFFF","#,
    r#""refin":false,"refout":false,"xorout":"0x0000","#,
    r#""cover":["mark","origin","number","size","at","@chunk"]},"#,
    r#""stream":["origin"],"transfer":"number","total":"size","offset":"at","#,
    r#""total_max":65536}}"#
);

const VALUES: &str = r#"{"origin": 513}"#;

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 13 + 5) as u8).collect()
}

/// A sender slot in its gravestone state, made as C makes one.
fn empty() -> wz_capi_c_owned_segment_sender_t {
    let mut slot = std::mem::MaybeUninit::<wz_capi_c_owned_segment_sender_t>::zeroed();
    // SAFETY: `slot` is writable, and a zeroed pointer is a valid handle field.
    unsafe {
        wz_capi_c_internal_segment_sender_null(slot.as_mut_ptr());
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
        if len == 0 {
            String::new()
        } else {
            String::from_utf8_lossy(std::slice::from_raw_parts(ptr.cast::<u8>(), len)).into_owned()
        }
    };
    unsafe { z_string_drop((out as *mut z_owned_string_t).cast::<z_moved_string_t>()) };
    text
}

fn make(values: &str, first: u64) -> Result<wz_capi_c_owned_segment_sender_t, (ZResult, String)> {
    let (profile, values) = (
        CString::new(PROFILE).unwrap(),
        CString::new(values).unwrap(),
    );
    let mut sender = empty();
    let mut refusal = text_slot();
    let rc = unsafe {
        wz_capi_c_segment_sender_new(
            &mut sender,
            profile.as_ptr(),
            values.as_ptr(),
            first,
            WZ_CAPI_C_SEGMENT_ROLLOVER_REFUSE,
            &mut refusal,
        )
    };
    let why = take(&mut refusal);
    if rc == Z_OK {
        assert!(unsafe { wz_capi_c_internal_segment_sender_check(&sender) });
        assert_eq!(why, "", "empty on success");
        Ok(sender)
    } else {
        assert!(!unsafe { wz_capi_c_internal_segment_sender_check(&sender) });
        Err((rc, why))
    }
}

fn next(sender: &wz_capi_c_owned_segment_sender_t) -> Option<u64> {
    let mut value = 0u64;
    unsafe { wz_capi_c_segment_sender_next(wz_capi_c_segment_sender_loan(sender), &mut value) }
        .then_some(value)
}

fn drop_sender(sender: &mut wz_capi_c_owned_segment_sender_t) {
    unsafe {
        wz_capi_c_segment_sender_drop((sender as *mut wz_capi_c_owned_segment_sender_t).cast())
    };
}

/// What the split callback is given: the pieces so far, and the code it answers
/// for the piece at `stop_at`.
struct Collect {
    pieces: Vec<Vec<u8>>,
    stop_at: Option<(usize, ZResult)>,
}

unsafe extern "C" fn collect(context: *mut c_void, piece: *const u8, len: usize) -> ZResult {
    let ctx = &mut *(context as *mut Collect);
    if let Some((at, code)) = ctx.stop_at {
        if ctx.pieces.len() == at {
            return code;
        }
    }
    ctx.pieces
        .push(std::slice::from_raw_parts(piece, len).to_vec());
    Z_OK
}

struct Outcome {
    rc: ZResult,
    result: wz_capi_c_segment_result_t,
    refusal: String,
    pieces: Vec<Vec<u8>>,
}

fn split(
    sender: &wz_capi_c_owned_segment_sender_t,
    msg: &[u8],
    chunk: usize,
    stop_at: Option<(usize, ZResult)>,
) -> Outcome {
    let mut ctx = Collect {
        pieces: Vec::new(),
        stop_at,
    };
    let mut result = wz_capi_c_segment_result_t {
        transfer: 99,
        pieces: 99,
        sent: 99,
    };
    let mut refusal = text_slot();
    let rc = unsafe {
        wz_capi_c_segment_sender_split(
            wz_capi_c_segment_sender_loan(sender),
            if msg.is_empty() {
                std::ptr::null()
            } else {
                msg.as_ptr()
            },
            msg.len(),
            chunk,
            Some(collect),
            (&mut ctx as *mut Collect).cast::<c_void>(),
            &mut result,
            &mut refusal,
        )
    };
    Outcome {
        rc,
        result,
        refusal: take(&mut refusal),
        pieces: ctx.pieces,
    }
}

/// Read every piece with the reader and join them; the joined message, or why
/// a piece did not join.
fn join(pieces: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let profile = SegmentProfile::parse(PROFILE).expect("the test profile is a profile");
    let mut ledger = SegmentLedger::new();
    let mut joined = None;
    for (i, bytes) in pieces.iter().enumerate() {
        let piece = profile
            .recognise(bytes)
            .ok_or_else(|| format!("piece {i} is not a piece"))?;
        let verdict = ledger.receive(
            &profile,
            &piece,
            0,
            Some(true),
            KeyRef::Resolved("k".into()),
        );
        if let Some(why) = verdict.unjoined {
            return Err(format!("piece {i} did not join: {why:?}"));
        }
        joined = verdict.joined;
    }
    joined
        .map(|whole| whole.to_vec())
        .ok_or_else(|| String::from("the transfer never closed"))
}

#[test]
fn the_split_door_hands_on_pieces_the_reader_joins_and_the_handle_numbers_them() {
    let mut sender = make(VALUES, 7).expect("a sender");
    for (sent, chunk) in [(7u64, 10usize), (8, 1), (9, 4096)] {
        let msg = message(37);
        let out = split(&sender, &msg, chunk, None);
        assert_eq!(out.rc, Z_OK, "{}", out.refusal);
        assert_eq!(out.refusal, "");
        let pieces = msg.len().div_ceil(chunk);
        assert_eq!(
            (out.result.transfer, out.result.pieces, out.result.sent),
            (sent, pieces, pieces)
        );
        assert_eq!(out.pieces.len(), pieces);
        assert_eq!(join(&out.pieces), Ok(msg), "chunk {chunk}");
    }
    assert_eq!(next(&sender), Some(10));
    drop_sender(&mut sender);
    assert!(!unsafe { wz_capi_c_internal_segment_sender_check(&sender) });
    drop_sender(&mut sender);
}

#[test]
fn a_refusal_is_a_code_and_a_reason_and_uses_no_number() {
    let (rc, why) = make("{}", 1).err().expect("refused");
    assert_eq!(rc, Z_EPARSE);
    assert!(why.starts_with("values /origin"), "{why}");
    let (rc, why) = make(r#"{"origin": 1, "number": 2}"#, 1)
        .err()
        .expect("refused");
    assert_eq!(rc, Z_EPARSE);
    assert!(why.starts_with("values /number"), "{why}");

    let mut sender = make(VALUES, 3).expect("a sender");
    for (msg, chunk, says) in [
        (Vec::new(), 8, "empty"),
        (message(8), 0, "chunk size is zero"),
        (message(65537), 4096, "total_max"),
    ] {
        let out = split(&sender, &msg, chunk, None);
        assert_eq!(out.rc, Z_EINVAL);
        assert!(out.refusal.contains(says), "{}", out.refusal);
        assert_eq!(
            (out.result.transfer, out.result.pieces, out.result.sent),
            (0, 0, 0)
        );
        assert!(out.pieces.is_empty());
        assert_eq!(next(&sender), Some(3), "no number used");
    }
    let rc = unsafe {
        wz_capi_c_segment_sender_split(
            wz_capi_c_segment_sender_loan(&sender),
            message(4).as_ptr(),
            4,
            4,
            None,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, Z_ENULL);
    drop_sender(&mut sender);
}

#[test]
fn a_callback_that_stops_the_split_has_used_the_number() {
    let mut sender = make(VALUES, 20).expect("a sender");
    let out = split(&sender, &message(25), 10, Some((1, -77)));
    assert_eq!(out.rc, -77, "the callback's code comes back");
    assert_eq!(
        (out.result.transfer, out.result.pieces, out.result.sent),
        (20, 3, 1)
    );
    assert!(out.refusal.contains("transfer 20"), "{}", out.refusal);
    assert_eq!(next(&sender), Some(21));
    drop_sender(&mut sender);
}

/// The put door on a real publisher: a subscriber of the same session receives
/// every piece, in order, each with the timestamp the options gave, and the
/// reader joins them into the message.
#[cfg(all(feature = "peer", feature = "timestamping"))]
#[test]
fn the_put_door_puts_every_piece_in_order_with_one_timestamp() {
    use std::time::{Duration, Instant};

    use wz_capi_c::abi::{
        z_loaned_sample_t, z_moved_closure_sample_t, z_moved_config_t, z_moved_publisher_t,
        z_moved_session_t, z_moved_subscriber_t, z_owned_closure_sample_t, z_owned_config_t,
        z_owned_publisher_t, z_owned_session_t, z_owned_slice_t, z_owned_subscriber_t,
        z_view_keyexpr_t,
    };
    use wz_capi_c::bytes::z_bytes_to_slice;
    use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
    use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
    use wz_capi_c::publisher::{z_declare_publisher, z_publisher_loan, z_undeclare_publisher};
    use wz_capi_c::sample::{z_sample_payload, z_sample_timestamp};
    use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
    use wz_capi_c::slice::{z_slice_data, z_slice_drop, z_slice_len, z_slice_loan};
    use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber, z_undeclare_subscriber};
    use wz_capi_c::timestamp::{z_timestamp_new, z_timestamp_ntp64_time, z_timestamp_t};
    use wz_runtime_tokio_test_support::free_port;

    type Seen = Arc<Mutex<Vec<(Vec<u8>, Option<u64>)>>>;

    unsafe extern "C" fn on_sample(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
        let seen = &*(ctx as *const Mutex<Vec<(Vec<u8>, Option<u64>)>>);
        let mut slice: z_owned_slice_t = std::mem::zeroed();
        if z_bytes_to_slice(z_sample_payload(sample), &mut slice) != Z_OK {
            return;
        }
        let loaned = z_slice_loan(&slice);
        let (data, len) = (z_slice_data(loaned), z_slice_len(loaned));
        let bytes = if data.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(data, len).to_vec()
        };
        z_slice_drop((&mut slice as *mut z_owned_slice_t).cast());
        let ts = z_sample_timestamp(sample);
        let ntp = (!ts.is_null()).then(|| z_timestamp_ntp64_time(ts));
        seen.lock().unwrap().push((bytes, ntp));
    }

    const KEY: &str = "wz/segment-sender/put";
    let msg = message(3000);
    let chunk = 700;
    let want = msg.len().div_ceil(chunk);

    // SAFETY: a session this test opens and closes; every owned slot is a local
    // the door or the test drops.
    unsafe {
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        for (k, v) in [
            ("scouting/multicast/enabled", String::from("false")),
            (
                "listen/endpoints",
                format!("[\"tcp/127.0.0.1:{}\"]", free_port()),
            ),
        ] {
            let (k, v) = (CString::new(k).unwrap(), CString::new(v).unwrap());
            assert_eq!(
                zc_config_insert_json5(z_config_loan_mut(&mut cfg), k.as_ptr(), v.as_ptr()),
                Z_OK
            );
        }
        let mut session: z_owned_session_t = std::mem::zeroed();
        assert_eq!(
            z_open(
                &mut session,
                (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
                std::ptr::null()
            ),
            Z_OK
        );

        let key = CString::new(KEY).unwrap();
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut view, key.as_ptr()), Z_OK);

        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let ctx = Arc::into_raw(seen.clone()) as *mut c_void;
        let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
        z_closure_sample(&mut closure, Some(on_sample), None, ctx);
        let mut sub: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&session),
                &mut sub,
                z_view_keyexpr_loan(&view),
                (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
                std::ptr::null_mut(),
            ),
            Z_OK
        );
        let mut publisher: z_owned_publisher_t = std::mem::zeroed();
        assert_eq!(
            z_declare_publisher(
                z_session_loan(&session),
                &mut publisher,
                z_view_keyexpr_loan(&view),
                std::ptr::null_mut(),
            ),
            Z_OK
        );

        let mut stamp: z_timestamp_t = std::mem::zeroed();
        assert_eq!(z_timestamp_new(&mut stamp, z_session_loan(&session)), Z_OK);
        let mut options = std::mem::MaybeUninit::<wz_capi_c_segment_put_options_t>::uninit();
        wz_capi_c_segment_put_options_default(options.as_mut_ptr());
        let mut options = options.assume_init();
        assert!(options.timestamp.is_null(), "the default stamps nothing");
        options.timestamp = &stamp;

        let mut sender = make(VALUES, 1).expect("a sender");
        let mut result = wz_capi_c_segment_result_t {
            transfer: 0,
            pieces: 0,
            sent: 0,
        };
        let mut refusal = text_slot();
        let rc = wz_capi_c_segment_sender_put(
            wz_capi_c_segment_sender_loan(&sender),
            z_publisher_loan(&publisher),
            msg.as_ptr(),
            msg.len(),
            chunk,
            &options,
            &mut result,
            &mut refusal,
        );
        assert_eq!(rc, Z_OK, "{}", take(&mut refusal));
        assert_eq!(
            (result.transfer, result.pieces, result.sent),
            (1, want, want)
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        while seen.lock().unwrap().len() < want && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let got = seen.lock().unwrap().clone();
        assert_eq!(got.len(), want, "every piece arrived");
        let minted = z_timestamp_ntp64_time(&stamp);
        assert!(
            got.iter().all(|(_, ts)| *ts == Some(minted)),
            "every piece carries the one timestamp the options gave"
        );
        let pieces: Vec<Vec<u8>> = got.into_iter().map(|(bytes, _)| bytes).collect();
        assert_eq!(join(&pieces), Ok(msg));

        drop_sender(&mut sender);
        let _ = z_undeclare_publisher(
            (&mut publisher as *mut z_owned_publisher_t).cast::<z_moved_publisher_t>(),
        );
        let _ = z_undeclare_subscriber(
            (&mut sub as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>(),
        );
        let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
        z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
    }
}
