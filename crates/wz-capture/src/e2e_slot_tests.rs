// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The per-slot judgement state, over SYNTHETIC profiles.
//!
//! The question here is not whether one stream is judged right: `e2e_judge`
//! holds that. It is whether a capture's frames reach the RIGHT stream, which a
//! single-sender test cannot show, because every wrong keying agrees with the
//! right one when there is only one slot. So each test that is about keying
//! drives two senders, two keys or two messages through the ledger in an order
//! that makes the wrong keying give a different verdict.
//!
//! The frames are built by `e2e_frame::build`, whose CRC engine is graded
//! against the published check values in `e2e_crc` and whose golden frames
//! `e2e_tests` holds; nothing here computes a CRC of its own.

use alloc::string::String;
use alloc::vec::Vec;

use crate::e2e_frame::{build, Values};
use crate::e2e_judge::CounterReason;
use crate::e2e_profile::{DocError, Profile};
use crate::e2e_slots::{Opened, Outcome, Reception, SlotLedger, SlotSender};

/// CRC first (CRC-32/AUTOSAR), a 2-byte counter that wraps at 65536, and an
/// identifier whose wire value is XORed. Messages are told apart by `ident`;
/// senders are kept apart.
const SLOT_A: &str = r#"{
  "name": "slot-a",
  "fields": [
    {"name": "crc", "bytes": 4},
    {"name": "length", "bytes": 2},
    {"name": "counter", "bytes": 2},
    {"name": "ident", "bytes": 4, "xor": "0x00FF00FF"}
  ],
  "crc": {"field": "crc", "width": 32, "poly": "0xF4ACFB13", "init": "0xFFFFFFFF",
          "refin": true, "refout": true, "xorout": "0xFFFFFFFF",
          "cover": ["length", "ident", "@payload", "counter"]},
  "length": {"field": "length", "counts": "frame"},
  "counter": {"field": "counter", "max_gap": 3, "timeout_ms": 100},
  "slot": {"message": ["ident"]}
}"#;

/// CRC LAST (CRC-64/XZ), a 4-byte counter, and NO sender separation: every
/// sender of a message shares its counter. The header is laid out unlike
/// `SLOT_A`'s, so a frame read at the other profile's offsets is wrong.
const SLOT_B: &str = r#"{
  "name": "slot-b",
  "fields": [
    {"name": "length", "bytes": 4},
    {"name": "counter", "bytes": 4},
    {"name": "tag", "bytes": 2},
    {"name": "crc", "bytes": 8}
  ],
  "crc": {"field": "crc", "width": 64, "poly": "0x42F0E1EBA9EA3693",
          "init": "0xFFFFFFFFFFFFFFFF", "refin": true, "refout": true,
          "xorout": "0xFFFFFFFFFFFFFFFF",
          "cover": ["counter", "@payload", "tag", "length"]},
  "length": {"field": "length", "counts": "frame"},
  "counter": {"field": "counter", "max_gap": 5, "timeout_ms": 50},
  "slot": {"message": ["tag"], "by_zid": false}
}"#;

const X: &[u8] = &[0x11, 0x22, 0x33, 0x44];
const Y: &[u8] = &[0x55, 0x66, 0x77, 0x88];

fn profile(text: &str) -> Profile {
    Profile::parse(text).expect("a synthetic profile reads")
}

/// A `slot-a` frame with this counter and message identifier.
fn frame_a(p: &Profile, counter: u64, ident: u64) -> Vec<u8> {
    let values = Values::new()
        .whole("counter", counter)
        .whole("ident", ident);
    // Long enough that the frame is also longer than the OTHER profile's header,
    // so a read under the wrong profile is a damaged frame and not a short one.
    build(p, &values, b"body-body").expect("builds").bytes
}

/// A `slot-b` frame.
fn frame_b(p: &Profile, counter: u64, tag: u64) -> Vec<u8> {
    let values = Values::new().whole("counter", counter).whole("tag", tag);
    build(p, &values, b"body-body").expect("builds").bytes
}

/// The same frame with its last body bit flipped: damaged, with a CRC that no
/// longer matches.
fn damaged(mut frame: Vec<u8>) -> Vec<u8> {
    let last = frame.len() - 1;
    frame[last] ^= 0x01;
    frame
}

/// One identity entry of a slot.
fn identity(name: &str, value: u64) -> (String, u64) {
    (String::from(name), value)
}

fn opened(outcome: Outcome) -> Opened {
    match outcome {
        Outcome::Opened(opened) => *opened,
        other => panic!("expected a frame that was read, got {other:?}"),
    }
}

/// Receive one frame for a sender under a key, with no clock.
fn receive(
    ledger: &mut SlotLedger,
    p: &Profile,
    key: &str,
    sender: Option<&[u8]>,
    frame: &[u8],
) -> Opened {
    opened(ledger.receive(&Reception {
        profile: p,
        keyexpr: key,
        payload: frame,
        sender,
        observed_at_ns: None,
    }))
}

/// Receive one frame at `ms` milliseconds of capture time.
fn receive_at(
    ledger: &mut SlotLedger,
    p: &Profile,
    key: &str,
    sender: Option<&[u8]>,
    frame: &[u8],
    ms: u64,
) -> Opened {
    opened(ledger.receive(&Reception {
        profile: p,
        keyexpr: key,
        payload: frame,
        sender,
        observed_at_ns: Some(ms * 1_000_000 + 345),
    }))
}

/// (counter error, reason) of a frame that was judged.
fn counter_verdict(o: &Opened) -> (bool, CounterReason) {
    let j = o.judgment.expect("the frame was judged");
    (j.counter_error, j.counter_reason)
}

#[test]
fn a_counter_that_repeats_skips_wraps_and_jumps_is_judged_within_its_slot() {
    let p = profile(SLOT_A);
    let mut ledger = SlotLedger::new();
    let key = "demo/a";
    let mut next = |counter: u64| {
        let f = frame_a(&p, counter, 7);
        counter_verdict(&receive(&mut ledger, &p, key, Some(X), &f))
    };
    // The first reception sets the baseline, whatever its value: here one step
    // short of the wrap.
    assert_eq!(next(65534), (false, CounterReason::None));
    // Consecutive, and the wrap itself is a step of one.
    assert_eq!(next(65535), (false, CounterReason::None));
    assert_eq!(next(0), (false, CounterReason::None));
    // The same counter again is a repetition and the baseline stays at 0.
    assert_eq!(next(0), (true, CounterReason::Repeat));
    // A skip inside the allowed gap (max_gap 3) is fine: 0 -> 3.
    assert_eq!(next(3), (false, CounterReason::None));
    // One past the gap is out of range: 3 -> 7 is a step of 4.
    assert_eq!(next(7), (true, CounterReason::OutOfRange));
    // The out-of-range frame MOVED the baseline, so 8 is consecutive and one
    // lost run does not condemn every frame after it.
    assert_eq!(next(8), (false, CounterReason::None));
}

#[test]
fn two_senders_publishing_one_key_keep_separate_counters() {
    let p = profile(SLOT_A);
    let mut ledger = SlotLedger::new();
    let key = "demo/a";
    // Interleaved, with counters a long way apart. A ledger that keyed on the
    // key alone would see 100 after 1 and call it out of range, and 2 after 100
    // and call it out of range again.
    let seq = [(X, 1u64), (Y, 100), (X, 2), (Y, 101), (X, 3), (Y, 102)];
    for (sender, counter) in seq {
        let f = frame_a(&p, counter, 7);
        let o = receive(&mut ledger, &p, key, Some(sender), &f);
        assert_eq!(
            counter_verdict(&o),
            (false, CounterReason::None),
            "sender {sender:02x?} counter {counter}"
        );
    }
    assert_eq!(ledger.slots(), 2, "one slot per sender");
}

#[test]
fn one_sender_publishing_two_keys_keeps_a_counter_per_key() {
    let p = profile(SLOT_A);
    let mut ledger = SlotLedger::new();
    // The same counters under two instances of a keyed message. Keyed by sender
    // alone, the second key's 5 after the first key's 5 is a repetition.
    for key in ["demo/a/1", "demo/a/2"] {
        for counter in [5u64, 6] {
            let f = frame_a(&p, counter, 7);
            let o = receive(&mut ledger, &p, key, Some(X), &f);
            assert_eq!(counter_verdict(&o), (false, CounterReason::None), "{key}");
        }
    }
    assert_eq!(ledger.slots(), 2);
}

#[test]
fn two_messages_on_one_key_keep_a_counter_each_and_the_identity_is_the_logical_value() {
    let p = profile(SLOT_A);
    let mut ledger = SlotLedger::new();
    let key = "demo/a";
    let f = frame_a(&p, 5, 0x1111);
    let first = receive(&mut ledger, &p, key, Some(X), &f);
    // The identifier's wire value is XORed with the profile's mask; the slot
    // names the LOGICAL value the sender supplied, not the wire's.
    assert_eq!(first.slot.identity, [identity("ident", 0x1111)]);
    let f = frame_a(&p, 5, 0x2222);
    let second = receive(&mut ledger, &p, key, Some(X), &f);
    // Counter 5 again, but of another message: not a repetition.
    assert_eq!(counter_verdict(&second), (false, CounterReason::None));
    assert_eq!(second.slot.identity, [identity("ident", 0x2222)]);
    // And the first message's own counter is untouched by the second's.
    let f = frame_a(&p, 5, 0x1111);
    let again = receive(&mut ledger, &p, key, Some(X), &f);
    assert_eq!(counter_verdict(&again), (true, CounterReason::Repeat));
    assert_eq!(ledger.slots(), 2);
}

#[test]
fn a_frame_with_a_bad_crc_is_not_counter_judged_and_leaves_the_baseline() {
    let p = profile(SLOT_A);
    let mut ledger = SlotLedger::new();
    let key = "demo/a";
    // First thing the slot ever receives is damaged: a CRC error, no counter
    // verdict, and no baseline set.
    let bad = receive(&mut ledger, &p, key, Some(X), &damaged(frame_a(&p, 50, 7)));
    assert!(!bad.frame.crc_ok);
    let j = bad.judgment.expect("judged");
    assert!(j.crc_error && !j.counter_error);
    // So the next VALID frame is a first reception, however far its counter is.
    let f = frame_a(&p, 9000, 7);
    let good = receive(&mut ledger, &p, key, Some(X), &f);
    assert_eq!(counter_verdict(&good), (false, CounterReason::None));
    // And a later damaged frame leaves 9000 as the baseline: 9001 is next.
    receive(&mut ledger, &p, key, Some(X), &damaged(frame_a(&p, 1, 7)));
    let f = frame_a(&p, 9001, 7);
    let next = receive(&mut ledger, &p, key, Some(X), &f);
    assert_eq!(counter_verdict(&next), (false, CounterReason::None));
}

#[test]
fn a_sender_the_capture_never_named_is_not_counter_judged_and_makes_no_slot() {
    let p = profile(SLOT_A);
    let mut ledger = SlotLedger::new();
    let key = "demo/a";
    for counter in [1u64, 1, 900] {
        let f = frame_a(&p, counter, 7);
        let o = receive(&mut ledger, &p, key, None, &f);
        // The CRC is stateless and is judged; the counter is stateful and has
        // no slot to be judged in, so it is not judged, rather than judged in a
        // slot shared with every other unnamed sender.
        assert!(o.frame.crc_ok);
        assert_eq!(o.slot.sender, SlotSender::Unknown);
        assert!(o.judgment.is_none(), "counter {counter}");
        assert!(!o.timed);
    }
    assert_eq!(ledger.slots(), 0, "nothing was kept for an unnamed sender");
    // A zid of nothing but zero bytes names nobody either.
    let f = frame_a(&p, 1, 7);
    let o = receive(&mut ledger, &p, key, Some(&[0u8, 0][..]), &f);
    assert_eq!(o.slot.sender, SlotSender::Unknown);
}

#[test]
fn a_profile_that_pools_senders_gives_them_one_counter() {
    let p = profile(SLOT_B);
    let mut ledger = SlotLedger::new();
    let key = "demo/b";
    let f = frame_b(&p, 5, 9);
    let first = receive(&mut ledger, &p, key, Some(X), &f);
    assert_eq!(first.slot.sender, SlotSender::Pooled);
    assert_eq!(counter_verdict(&first), (false, CounterReason::None));
    // The SAME counter from ANOTHER sender is a repetition in a pooled slot.
    // Judged per sender it would be a first reception and no error.
    let second = receive(&mut ledger, &p, key, Some(Y), &f);
    assert_eq!(counter_verdict(&second), (true, CounterReason::Repeat));
    // A pooled slot needs no zid, so an unnamed sender is judged too.
    let f = frame_b(&p, 6, 9);
    let third = receive(&mut ledger, &p, key, None, &f);
    assert_eq!(counter_verdict(&third), (false, CounterReason::None));
    assert_eq!(ledger.slots(), 1);
}

#[test]
fn the_header_is_read_at_the_offsets_of_the_profile_the_rule_names() {
    let a = profile(SLOT_A);
    let b = profile(SLOT_B);
    let mut ledger = SlotLedger::new();
    let fa = frame_a(&a, 12, 0x33);
    let fb = frame_b(&b, 777, 0x44);
    let oa = receive(&mut ledger, &a, "demo/a", Some(X), &fa);
    let ob = receive(&mut ledger, &b, "demo/b", Some(X), &fb);
    // Each one's CRC matches under its OWN layout, and its counter is what was
    // built in: read at the other profile's offsets, neither would be.
    assert!(oa.frame.crc_ok && ob.frame.crc_ok);
    assert_eq!(oa.frame.counter(&a), 12);
    assert_eq!(ob.frame.counter(&b), 777);
    assert_eq!(oa.slot.identity, [identity("ident", 0x33)]);
    assert_eq!(ob.slot.identity, [identity("tag", 0x44)]);
    // And a frame of one layout read under the other is damaged, which is what
    // the test above would look like if the rule named the wrong profile.
    let cross = receive(&mut ledger, &b, "demo/x", Some(X), &fa);
    assert!(!cross.frame.crc_ok);
}

#[test]
fn a_payload_shorter_than_the_header_is_not_a_frame_and_makes_no_slot() {
    let p = profile(SLOT_A);
    let mut ledger = SlotLedger::new();
    let short = alloc::vec![0u8; p.header_bytes() - 1];
    match ledger.receive(&Reception {
        profile: &p,
        keyexpr: "demo/a",
        payload: &short,
        sender: Some(X),
        observed_at_ns: Some(1),
    }) {
        Outcome::TooShort {
            payload_bytes,
            header_bytes,
        } => {
            assert_eq!(payload_bytes, short.len());
            assert_eq!(header_bytes, p.header_bytes());
        }
        other => panic!("expected TooShort, got {other:?}"),
    }
    assert_eq!(ledger.slots(), 0);
    // Exactly the header, with no body, is a frame.
    let f = build(
        &p,
        &Values::new().whole("counter", 1).whole("ident", 1),
        b"",
    )
    .expect("builds")
    .bytes;
    assert_eq!(f.len(), p.header_bytes());
    assert!(matches!(
        ledger.receive(&Reception {
            profile: &p,
            keyexpr: "demo/a",
            payload: &f,
            sender: Some(X),
            observed_at_ns: None,
        }),
        Outcome::Opened(_)
    ));
}

#[test]
fn the_timeout_is_judged_against_the_captures_clock_and_only_when_there_is_one() {
    let p = profile(SLOT_A);
    let mut ledger = SlotLedger::new();
    let key = "demo/a";
    // A valid frame at 0 ms, then a damaged one 150 ms later (the limit is 100):
    // the damaged frame moves nothing, so it is judged against the valid one's
    // instant and the silence has exceeded the limit.
    let f = frame_a(&p, 1, 7);
    let first = receive_at(&mut ledger, &p, key, Some(X), &f, 0);
    assert!(first.timed);
    assert_eq!(first.judgment.expect("judged").silence_ms, None);
    let late = receive_at(
        &mut ledger,
        &p,
        key,
        Some(X),
        &damaged(frame_a(&p, 2, 7)),
        150,
    );
    let j = late.judgment.expect("judged");
    assert!(j.crc_error && j.timeout_error);
    assert_eq!(j.silence_ms, Some(150));
    // A VALID frame after a long silence is not itself late: it ended the
    // silence.
    let f = frame_a(&p, 2, 7);
    let ok = receive_at(&mut ledger, &p, key, Some(X), &f, 500);
    assert!(!ok.judgment.expect("judged").timeout_error);
}

#[test]
fn a_frame_from_a_packet_with_no_timestamp_is_counter_judged_and_not_timed() {
    let p = profile(SLOT_A);
    let mut ledger = SlotLedger::new();
    let key = "demo/a";
    let f = frame_a(&p, 1, 7);
    receive_at(&mut ledger, &p, key, Some(X), &f, 0);
    // The next valid frame has no timestamp. Its counter is judged (a repeat
    // here), and its timeout is not.
    let f = frame_a(&p, 1, 7);
    let untimed = receive(&mut ledger, &p, key, Some(X), &f);
    assert!(!untimed.timed);
    assert_eq!(counter_verdict(&untimed), (true, CounterReason::Repeat));
    // A distinct frame, untimed, moves the baseline and FORGETS the instant of
    // the last timed one: a timed frame far later is then not charged with the
    // silence since a frame that is no longer the last.
    let f = frame_a(&p, 2, 7);
    let moved = receive(&mut ledger, &p, key, Some(X), &f);
    assert!(!moved.timed);
    assert_eq!(counter_verdict(&moved), (false, CounterReason::None));
    let later = receive_at(
        &mut ledger,
        &p,
        key,
        Some(X),
        &damaged(frame_a(&p, 3, 7)),
        100_000,
    );
    let j = later.judgment.expect("judged");
    assert!(j.crc_error);
    assert!(
        !j.timeout_error,
        "the instant of the last valid frame is unknown, so there is no silence to measure"
    );
}

#[test]
fn a_slot_may_not_be_keyed_on_a_field_that_changes_every_frame() {
    let with_slot = |slot: &str| -> DocError {
        let text = SLOT_A.replace(
            r#""slot": {"message": ["ident"]}"#,
            &alloc::format!(r#""slot": {slot}"#),
        );
        Profile::parse(&text).expect_err("refused")
    };
    for (slot, needle) in [
        (r#"{"message": ["counter"]}"#, "crc, length or counter"),
        (r#"{"message": ["crc"]}"#, "crc, length or counter"),
        (r#"{"message": ["length"]}"#, "crc, length or counter"),
        (r#"{"message": ["ident", "ident"]}"#, "listed twice"),
        (r#"{"message": ["nope"]}"#, "no field is called"),
        (r#"{"message": "ident"}"#, "expected an array"),
        (r#"{"by_zid": "yes"}"#, "expected true or false"),
        (r#"{"sender": true}"#, "unknown key"),
        (r#"[]"#, "expected an object"),
    ] {
        match with_slot(slot) {
            DocError::Invalid { path, reason } => {
                assert!(path.starts_with("/slot"), "{slot}: path {path}");
                assert!(reason.contains(needle), "{slot}: {reason}");
            }
            other => panic!("{slot}: {other:?}"),
        }
    }
    // And the default, with no `slot` at all, is one message per key and one
    // counter per sender.
    let text = SLOT_A.replace(",\n  \"slot\": {\"message\": [\"ident\"]}", "");
    assert_ne!(text, SLOT_A, "the slot key was removed");
    let bare = Profile::parse(&text).expect("reads");
    assert!(bare.slot().message.is_empty());
    assert!(bare.slot().by_zid);
}
