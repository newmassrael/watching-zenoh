// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The end-to-end doors of the pico C ABI: the sender (`wz_ext_e2e_sender_*`) and the receiving
//! judge (`wz_ext_e2e_receiver_*`), made from a profile and header values the fuzzer writes, and
//! driven with frames it writes and payloads it has the sender protect.
//!
//! Input: a byte of choices, the counter every stream's first frame carries (eight bytes), the
//! largest gap the receivers are made with (one byte, 0 for the profile's), the profile (JSON, to a
//! NUL), the header values (JSON, to a NUL), then the operations, each a unit behind its two-byte
//! little-endian length whose first byte chooses it:
//!
//! | op % 3 | operation |
//! |--------|-----------|
//! | 0      | the judge reads the rest of the unit as a frame, on stream `op / 4` (modulo one past the last) |
//! | 1      | the sender protects the rest as a payload on stream `op / 4`, and a receiver of its own judges the frame |
//! | 2      | the sender's stream `op / 4` is set to the counter the next eight bytes give |
//!
//! | choice bits | what they choose |
//! |-------------|------------------|
//! | 0           | the sender wraps after its counter's largest value (else it refuses) |
//! | 1           | the sender keeps each stream's last frame (the CRC cache) |
//! | 2           | the receivers are handed the header values as the identifier they expect |
//! | 3..=5       | how many streams the sender and the receivers keep (0 is refused) |
//! | 6..=7       | how the judge keys its streams: indexed, by sender in arrival order, bound to senders |
//!
//! Held beside not crashing: each door answers a code its documentation states; a refused making
//! leaves the gravestone and a made one leaves no refusal; a verdict's numbers are 0 where its
//! `has` bits are clear, a status that is not an integrity failure names no failed check, and the
//! payload it reports lies in the frame; a refused protection consumes no counter value; a frame
//! the sender built is judged by a receiver of the same profile and values with its CRC, its
//! length and its size intact, the counter the sender reported, and the payload it was given; a
//! dropped handle answers like a null one and drops again without harm.

#![no_main]

use std::ffi::CString;

use libfuzzer_sys::fuzz_target;
use wz_capi_pico::e2e_receiver::*;
use wz_capi_pico::e2e_sender::*;
use wz_capi_pico::result::{
    WZ_EXT_ERR_UNSUPPORTED, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_NULL, Z_ERR_OVERFLOW, Z_OK,
};
use wz_fuzz_ingress_common::units;
use wz_fuzz_pico_ext::{empty_string, stated, take_string, Reader};

/// The senders a receiver bound to its slots is handed, for the keying that binds them.
static BOUND: [u64; 3] = [0x0007_A100, 0x0007_B200, 0x0C0A_1234];

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let choices = r.u8();
    let first_counter = r.u64();
    let max_gap = u64::from(r.u8());
    let profile = r.c_field();
    let values = r.c_field();
    let ops = r.rest();

    let streams = usize::from((choices >> 3) & 7);
    let keying = match choices >> 6 {
        0 => WZ_EXT_E2E_KEYING_INDEXED,
        1 => WZ_EXT_E2E_KEYING_SENDERS_ARRIVAL,
        _ => WZ_EXT_E2E_KEYING_SENDERS_BOUND,
    };
    let expected = (choices & 4 != 0).then_some(&values);

    let mut sender_options: wz_ext_e2e_sender_options_t = unsafe { core::mem::zeroed() };
    // SAFETY: `sender_options` is writable.
    unsafe { wz_ext_e2e_sender_options_default(&mut sender_options) };
    sender_options.first_counter = first_counter;
    sender_options.streams = streams;
    sender_options.rollover = if choices & 1 != 0 {
        WZ_EXT_E2E_ROLLOVER_WRAP
    } else {
        WZ_EXT_E2E_ROLLOVER_REFUSE
    };
    sender_options.crc_cache = choices & 2 != 0;
    let mut tx = new_sender(&profile, &values, &sender_options);

    let mut judge_options = receiver_options(streams, max_gap, keying);
    let mut rx = new_receiver(&profile, expected, &judge_options, keying);
    // The receiver a protected frame is judged by: indexed like the sender's streams, so every
    // frame the sender builds has the stream it was built on.
    judge_options = receiver_options(streams, max_gap, WZ_EXT_E2E_KEYING_INDEXED);
    let mut trip = new_receiver(
        &profile,
        expected,
        &judge_options,
        WZ_EXT_E2E_KEYING_INDEXED,
    );

    let mut now_ms = 0u64;
    for unit in units(ops) {
        let Some((&op, rest)) = unit.split_first() else {
            continue;
        };
        // One stream past the last, so the refusal of a stream the handle does not keep is met.
        let stream = usize::from(op >> 2) % (streams + 1);
        now_ms += u64::from(op & 3) * 7;
        match op % 3 {
            0 => {
                // Under sender keying the judge chooses the stream, and the caller names 0.
                let stream = if keying == WZ_EXT_E2E_KEYING_INDEXED {
                    stream
                } else {
                    0
                };
                judge(&rx, stream, streams, keying, rest, now_ms);
            }
            1 => protect_and_judge(&tx, &trip, stream, rest, now_ms),
            _ => set_counter(&tx, stream, rest),
        }
    }

    drop_sender(&mut tx);
    drop_receiver(&mut rx);
    drop_receiver(&mut trip);
});

fn receiver_options(streams: usize, max_gap: u64, keying: u8) -> wz_ext_e2e_receiver_options_t {
    let mut options: wz_ext_e2e_receiver_options_t = unsafe { core::mem::zeroed() };
    // SAFETY: `options` is writable.
    unsafe { wz_ext_e2e_receiver_options_default(&mut options) };
    options.streams = streams;
    options.max_gap = max_gap;
    options.keying = keying;
    if keying == WZ_EXT_E2E_KEYING_SENDERS_BOUND {
        options.senders = BOUND.as_ptr();
        options.senders_len = BOUND.len().min(streams);
    }
    options
}

fn new_sender(
    profile: &CString,
    values: &CString,
    options: &wz_ext_e2e_sender_options_t,
) -> wz_ext_owned_e2e_sender_t {
    let mut this: wz_ext_owned_e2e_sender_t = unsafe { core::mem::zeroed() };
    let mut refusal = empty_string();
    // SAFETY: every argument is valid for the call; `refusal` is writable.
    let rc = unsafe {
        wz_ext_e2e_sender_new(
            &mut this,
            profile.as_ptr(),
            values.as_ptr(),
            options,
            &mut refusal,
        )
    };
    let why = unsafe { take_string("e2e_sender_new", &mut refusal) };
    stated(
        "e2e_sender_new",
        rc,
        &[Z_OK, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE],
    );
    let holds = unsafe { wz_ext_internal_e2e_sender_check(&this) };
    assert_eq!(
        holds,
        rc == Z_OK,
        "e2e_sender_new: {rc} and a sender held: {holds}"
    );
    if rc == Z_OK {
        assert!(
            why.is_empty(),
            "e2e_sender_new: a made sender left a refusal: {why}"
        );
    }
    if rc == Z_ERR_CONFIG_INVALID_VALUE {
        assert!(!why.is_empty(), "e2e_sender_new: refused with no reason");
    }
    this
}

fn new_receiver(
    profile: &CString,
    expected: Option<&CString>,
    options: &wz_ext_e2e_receiver_options_t,
    keying: u8,
) -> wz_ext_owned_e2e_receiver_t {
    let mut this: wz_ext_owned_e2e_receiver_t = unsafe { core::mem::zeroed() };
    let mut refusal = empty_string();
    let expected = expected.map_or(core::ptr::null(), |e| e.as_ptr());
    // SAFETY: every argument is valid for the call; the bound senders outlive it.
    let rc = unsafe {
        wz_ext_e2e_receiver_new(&mut this, profile.as_ptr(), expected, options, &mut refusal)
    };
    let why = unsafe { take_string("e2e_receiver_new", &mut refusal) };
    // Sender keying is refused by name only in a build without the sender slots.
    let unsupported = !cfg!(feature = "e2e-sender-demux") && keying != WZ_EXT_E2E_KEYING_INDEXED;
    if unsupported {
        stated(
            "e2e_receiver_new",
            rc,
            &[WZ_EXT_ERR_UNSUPPORTED, Z_ERR_CONFIG_INVALID_VALUE, Z_EINVAL],
        );
    } else {
        stated(
            "e2e_receiver_new",
            rc,
            &[Z_OK, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE],
        );
    }
    let holds = unsafe { wz_ext_internal_e2e_receiver_check(&this) };
    assert_eq!(
        holds,
        rc == Z_OK,
        "e2e_receiver_new: {rc} and a receiver held: {holds}"
    );
    if rc == Z_OK {
        assert!(
            why.is_empty(),
            "e2e_receiver_new: a made receiver left a refusal: {why}"
        );
    }
    if rc == Z_ERR_CONFIG_INVALID_VALUE {
        assert!(!why.is_empty(), "e2e_receiver_new: refused with no reason");
    }
    this
}

/// Judge `frame` and hold the verdict to its documented shape; the verdict, when the door gave one.
fn judge(
    rx: &wz_ext_owned_e2e_receiver_t,
    stream: usize,
    streams: usize,
    keying: u8,
    frame: &[u8],
    now_ms: u64,
) -> Option<wz_ext_e2e_verdict_t> {
    let mut verdict: wz_ext_e2e_verdict_t = unsafe { core::mem::zeroed() };
    // SAFETY: `rx` is an owned receiver or the gravestone; `frame` is readable; `verdict` writable.
    let rc = unsafe {
        wz_ext_e2e_receiver_judge(
            wz_ext_e2e_receiver_loan(rx),
            stream,
            frame.as_ptr(),
            frame.len(),
            now_ms,
            &mut verdict,
        )
    };
    let held = unsafe { wz_ext_internal_e2e_receiver_check(rx) };
    if !held {
        assert_eq!(
            rc, Z_ERR_NULL,
            "e2e_receiver_judge: the gravestone answered {rc}"
        );
        return None;
    }
    stated("e2e_receiver_judge", rc, &[Z_OK, Z_EINVAL]);
    if keying == WZ_EXT_E2E_KEYING_INDEXED && stream >= streams {
        assert_eq!(
            rc, Z_EINVAL,
            "e2e_receiver_judge: stream {stream} of {streams} was judged"
        );
    }
    if rc != Z_OK {
        assert_eq!(
            verdict,
            wz_ext_e2e_verdict_t::default(),
            "e2e_receiver_judge: {rc} left a verdict"
        );
        return None;
    }
    hold_verdict(&verdict, frame.len(), keying);
    Some(verdict)
}

fn hold_verdict(v: &wz_ext_e2e_verdict_t, frame_len: usize, keying: u8) {
    assert!(
        v.status <= WZ_EXT_E2E_UNSLOTTED,
        "a status of no name: {}",
        v.status
    );
    let checks = WZ_EXT_E2E_FAILED_CRC
        | WZ_EXT_E2E_FAILED_IDENT
        | WZ_EXT_E2E_FAILED_LENGTH
        | WZ_EXT_E2E_FAILED_SHORT;
    assert_eq!(
        v.failed & !checks,
        0,
        "a failed check of no name: {:#x}",
        v.failed
    );
    if v.status == WZ_EXT_E2E_INTEGRITY {
        assert_ne!(v.failed, 0, "an integrity failure names no check");
    } else if v.status != WZ_EXT_E2E_UNSLOTTED {
        assert_eq!(
            v.failed, 0,
            "status {} names failed checks {:#x}",
            v.status, v.failed
        );
    }
    if v.status == WZ_EXT_E2E_UNSLOTTED {
        assert!(
            v.unslotted == WZ_EXT_E2E_NOT_LISTED || v.unslotted == WZ_EXT_E2E_SLOTS_FULL,
            "an unslotted frame says no reason: {}",
            v.unslotted
        );
    } else {
        assert_eq!(
            v.unslotted, WZ_EXT_E2E_SLOTTED,
            "a slotted frame with a reason"
        );
    }
    if keying == WZ_EXT_E2E_KEYING_INDEXED {
        assert_ne!(
            v.status, WZ_EXT_E2E_UNSLOTTED,
            "an indexed judge has no slots to miss"
        );
    }
    assert!(v.timeout <= 1, "a timeout flag of {}", v.timeout);
    for (bit, value) in [
        (WZ_EXT_E2E_HAS_COUNTER, v.counter),
        (WZ_EXT_E2E_HAS_STEP, v.step),
        (WZ_EXT_E2E_HAS_KIND, v.kind),
        (WZ_EXT_E2E_HAS_RESULT, v.result),
        (WZ_EXT_E2E_HAS_SENDER, v.sender),
        (WZ_EXT_E2E_HAS_SILENCE, v.silence_ms),
    ] {
        if v.has & bit == 0 {
            assert_eq!(value, 0, "a number without its has bit {bit:#x} is {value}");
        }
    }
    if v.has & WZ_EXT_E2E_HAS_STREAM == 0 {
        assert_eq!(v.stream, 0, "a stream without its has bit");
    }
    // An empty payload has no place to lie in: a frame shorter than its header reports none.
    if v.payload_len > 0 {
        let end = v.payload_offset.checked_add(v.payload_len);
        assert!(
            end.is_some_and(|end| end <= frame_len),
            "the payload at {} of {} bytes lies outside the frame of {frame_len}",
            v.payload_offset,
            v.payload_len
        );
    }
}

fn next_of(tx: &wz_ext_owned_e2e_sender_t, stream: usize) -> Option<u64> {
    let mut next = 0u64;
    // SAFETY: `tx` is an owned sender or the gravestone; `next` is writable.
    unsafe { wz_ext_e2e_sender_next(wz_ext_e2e_sender_loan(tx), stream, &mut next) }.then_some(next)
}

fn protect_and_judge(
    tx: &wz_ext_owned_e2e_sender_t,
    trip: &wz_ext_owned_e2e_receiver_t,
    stream: usize,
    payload: &[u8],
    now_ms: u64,
) {
    let loan = unsafe { wz_ext_e2e_sender_loan(tx) };
    let mut size = usize::MAX;
    // SAFETY: `loan` is a loaned sender or the gravestone; `size` is writable.
    let rc = unsafe { wz_ext_e2e_sender_frame_size(loan, payload.len(), &mut size) };
    if !unsafe { wz_ext_internal_e2e_sender_check(tx) } {
        assert_eq!(
            rc, Z_ERR_NULL,
            "e2e_sender_frame_size: the gravestone answered {rc}"
        );
        return;
    }
    assert_eq!(
        rc, Z_OK,
        "e2e_sender_frame_size: a live sender answered {rc}"
    );
    let before = next_of(tx, stream);

    // One byte short of the frame is refused before anything moves.
    if size > 0 {
        let mut short = vec![0u8; size - 1];
        let (mut written, mut counter) = (usize::MAX, u64::MAX);
        let mut refusal = empty_string();
        // SAFETY: `short` is writable for its length; the outs are writable.
        let rc = unsafe {
            wz_ext_e2e_sender_protect(
                loan,
                stream,
                payload.as_ptr(),
                payload.len(),
                short.as_mut_ptr(),
                short.len(),
                &mut written,
                &mut counter,
                &mut refusal,
            )
        };
        let _ = unsafe { take_string("e2e_sender_protect", &mut refusal) };
        assert_eq!(
            rc, Z_ERR_OVERFLOW,
            "e2e_sender_protect: a buffer one short answered {rc}"
        );
        assert_eq!(
            written, 0,
            "e2e_sender_protect: a refused frame wrote a length"
        );
        assert_eq!(
            next_of(tx, stream),
            before,
            "e2e_sender_protect: an overflow moved the counter"
        );
    }

    let mut frame = vec![0u8; size];
    let (mut written, mut counter) = (usize::MAX, u64::MAX);
    let mut refusal = empty_string();
    // SAFETY: `frame` is writable for `size` bytes; the outs are writable.
    let rc = unsafe {
        wz_ext_e2e_sender_protect(
            loan,
            stream,
            payload.as_ptr(),
            payload.len(),
            frame.as_mut_ptr(),
            frame.len(),
            &mut written,
            &mut counter,
            &mut refusal,
        )
    };
    let _ = unsafe { take_string("e2e_sender_protect", &mut refusal) };
    stated("e2e_sender_protect", rc, &[Z_OK, Z_EINVAL]);
    if rc != Z_OK {
        assert_eq!(written, 0, "e2e_sender_protect: {rc} wrote a length");
        assert_eq!(
            next_of(tx, stream),
            before,
            "e2e_sender_protect: {rc} consumed a counter value"
        );
        return;
    }
    assert_eq!(
        written, size,
        "e2e_sender_protect: a frame of {written} bytes, {size} stated"
    );
    if let Some(before) = before {
        assert_eq!(
            counter, before,
            "e2e_sender_protect: carried {counter}, the next was {before}"
        );
    }

    if !unsafe { wz_ext_internal_e2e_receiver_check(trip) } {
        return;
    }
    let mut verdict: wz_ext_e2e_verdict_t = unsafe { core::mem::zeroed() };
    // SAFETY: `trip` is a live owned receiver; `frame` is readable; `verdict` writable.
    let rc = unsafe {
        wz_ext_e2e_receiver_judge(
            wz_ext_e2e_receiver_loan(trip),
            stream,
            frame.as_ptr(),
            frame.len(),
            now_ms,
            &mut verdict,
        )
    };
    // The sender and this judge keep the same streams, so the stream the frame was built on is one
    // the judge has.
    assert_eq!(
        rc, Z_OK,
        "e2e_receiver_judge: a frame the sender built on stream {stream} answered {rc}"
    );
    hold_verdict(&verdict, frame.len(), WZ_EXT_E2E_KEYING_INDEXED);
    // The identifier is left out: it is judged against the expected values, which are the
    // sender's own text only by this target's choice.
    let intact = WZ_EXT_E2E_FAILED_CRC | WZ_EXT_E2E_FAILED_LENGTH | WZ_EXT_E2E_FAILED_SHORT;
    assert_eq!(
        verdict.failed & intact,
        0,
        "a frame the sender built fails checks {:#x}: {frame:02x?}",
        verdict.failed
    );
    if verdict.has & WZ_EXT_E2E_HAS_COUNTER != 0 {
        assert_eq!(
            verdict.counter, counter,
            "the judge read another counter than the sender wrote"
        );
    }
    let reported: &[u8] = if verdict.payload_len == 0 {
        &[]
    } else {
        &frame[verdict.payload_offset..verdict.payload_offset + verdict.payload_len]
    };
    assert_eq!(
        reported, payload,
        "the judge reports another payload than the sender protected"
    );
}

fn set_counter(tx: &wz_ext_owned_e2e_sender_t, stream: usize, rest: &[u8]) {
    let mut r = Reader::new(rest);
    let value = r.u64();
    // SAFETY: `tx` is an owned sender or the gravestone.
    let rc = unsafe { wz_ext_e2e_sender_set(wz_ext_e2e_sender_loan(tx), stream, value) };
    if !unsafe { wz_ext_internal_e2e_sender_check(tx) } {
        assert_eq!(
            rc, Z_ERR_NULL,
            "e2e_sender_set: the gravestone answered {rc}"
        );
        return;
    }
    stated("e2e_sender_set", rc, &[Z_OK, Z_EINVAL]);
    if rc == Z_OK {
        assert_eq!(
            next_of(tx, stream),
            Some(value),
            "e2e_sender_set: the next counter is not the one set"
        );
    }
}

fn drop_sender(tx: &mut wz_ext_owned_e2e_sender_t) {
    // SAFETY: an owned sender slot, dropped twice; the second is a documented no-op.
    unsafe {
        wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(tx));
        assert!(
            !wz_ext_internal_e2e_sender_check(tx),
            "a dropped sender is still held"
        );
        wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(tx));
    }
    assert_eq!(next_of(tx, 0), None, "a dropped sender gave a counter");
}

fn drop_receiver(rx: &mut wz_ext_owned_e2e_receiver_t) {
    // SAFETY: an owned receiver slot, dropped twice; the second is a documented no-op.
    unsafe {
        wz_ext_e2e_receiver_drop(wz_ext_e2e_receiver_move(rx));
        assert!(
            !wz_ext_internal_e2e_receiver_check(rx),
            "a dropped receiver is still held"
        );
        wz_ext_e2e_receiver_drop(wz_ext_e2e_receiver_move(rx));
    }
    assert!(
        judge(rx, 0, 1, WZ_EXT_E2E_KEYING_INDEXED, b"x", 0).is_none(),
        "a dropped receiver judged a frame"
    );
}
