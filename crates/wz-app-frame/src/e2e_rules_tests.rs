// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Model tests of the rules a receiver judges by and a sender derives by, the
//! receiving judge kept per stream or per sender, and the sender's counter and
//! CRC cache, on SYNTHETIC profiles.
//!
//! The two layouts below differ in every axis the mechanism reads: the CRC's
//! width (32 and 64) and place (inside the header and first), the counter's
//! width (1 and 4 bytes) and place in the feeding order (last and first), the
//! length rule, the identifier (a split field XORed with a constant, and a
//! plain one), and the bit ranges of the message cell, whose sender part each
//! derives from the address under a mask of its own. The masks and constants
//! are made up. A real deployment's profile is checked only by an oracle lane
//! outside the repository, against frames a build of the deployed peer
//! exchanges with wz.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::e2e_frame::{build, logical_value, open, BuildError, Values, ADDRESS};
use crate::e2e_profile::{CounterErrors, DocError, JudgeRules, Profile};
use crate::e2e_receiver::{
    Keying, NewError, ReceiveError, Receiver, Status, Unslotted, FAILED_CRC, FAILED_IDENT,
    FAILED_LENGTH, FAILED_SHORT,
};
use crate::e2e_stream_sender::{Rollover, SendError, SenderOptions, StreamSender};

/// The counter first on the wire and LAST in the feeding order, a one-byte
/// counter, a 32-bit CRC inside the header, a split identifier XORed with a
/// constant, and every judging rule turned away from its default.
const LEFT: &str = r#"{
  "name": "syn-left",
  "fields": [
    {"name": "counter", "bytes": 1},
    {"name": "crc", "bytes": 4},
    {"name": "ident", "bytes": 4, "xor": "0x00C0FFEE",
     "split": [{"name": "sys", "lsb": 20, "width": 12},
               {"name": "mid", "lsb": 0, "width": 20}]},
    {"name": "length", "bytes": 2},
    {"name": "cell", "bytes": 4,
     "split": [{"name": "kind", "lsb": 30, "width": 2},
               {"name": "result", "lsb": 27, "width": 3},
               {"name": "sender", "lsb": 0, "width": 27,
                "derive": {"from": "address", "mask": "0x00FF0FF0", "xor": "0xA5A0"}}]}
  ],
  "crc": {"field": "crc", "width": 32, "poly": "0x1EDC6F41", "init": "0xFFFFFFFF",
          "refin": true, "refout": true, "xorout": "0xFFFFFFFF",
          "cover": ["ident", "cell", "@payload", "length", "counter"]},
  "length": {"field": "length", "counts": "frame"},
  "counter": {"field": "counter", "max_gap": 4, "timeout_ms": 500, "max_gap_ceiling": 12},
  "judge": {"ident": "ident", "length": true, "counter_errors": "joined",
            "out_of_range": "keeps_baseline"},
  "cell": {"field": "cell", "kind": "kind", "result": "result", "sender": "sender"}
}"#;

/// The CRC first on the wire and 64 bits wide, a four-byte counter FIRST in
/// the feeding order (so a CRC cache keeps nothing before it), a length that
/// leaves the CRC out, a plain identifier, and the default counter rules.
const RIGHT: &str = r#"{
  "name": "syn-right",
  "fields": [
    {"name": "crc", "bytes": 8},
    {"name": "counter", "bytes": 4},
    {"name": "length", "bytes": 4},
    {"name": "cell", "bytes": 4,
     "split": [{"name": "sender", "lsb": 8, "width": 24,
                "derive": {"from": "address", "mask": "0x00FFFF00", "xor": "0x123400"}},
               {"name": "kind", "lsb": 0, "width": 4}]},
    {"name": "ident", "bytes": 2}
  ],
  "crc": {"field": "crc", "width": 64, "poly": "0x1B", "init": "0xFFFFFFFFFFFFFFFF",
          "refin": true, "refout": true, "xorout": "0xFFFFFFFFFFFFFFFF",
          "cover": ["counter", "@payload", "length", "cell", "ident"]},
  "length": {"field": "length", "counts": "frame_minus", "fields": ["crc"]},
  "counter": {"field": "counter", "max_gap": 3, "timeout_ms": 100},
  "judge": {"ident": "ident"},
  "cell": {"field": "cell", "kind": "kind", "sender": "sender"}
}"#;

/// Three node addresses, read as the integers a deployment's address is. They
/// differ in bits both profiles' masks keep (bits 8 and 9, and bit 16), so each
/// gives each profile a sender identity of its own.
const ADDR_A: u64 = 0x0A1B_2C3D;
const ADDR_B: u64 = ADDR_A ^ 0x0000_0300;
const ADDR_C: u64 = ADDR_A ^ 0x0001_0000;
/// Bits the left profile's mask (0x00FF0FF0) drops.
const OUTSIDE_LEFT_MASK: u64 = 0xFF00_F00F;

fn left() -> Profile {
    Profile::parse(LEFT).expect("the left profile is valid")
}

fn right() -> Profile {
    Profile::parse(RIGHT).expect("the right profile is valid")
}

fn left_values(address: u64) -> Values {
    Values::new()
        .parts("ident", &[("sys", 0x5A1), ("mid", 0x0BEEF)])
        .parts("cell", &[("kind", 1), ("result", 2)])
        .address(address)
}

fn right_values(address: u64) -> Values {
    Values::new()
        .whole("ident", 0x7E57)
        .parts("cell", &[("kind", 9)])
        .address(address)
}

fn left_sender_id(address: u64) -> u64 {
    (address & 0x00FF_0FF0) ^ 0xA5A0
}

fn right_sender_id(address: u64) -> u64 {
    (address & 0x00FF_FF00) ^ 0x12_3400
}

/// A frame of `profile` with `counter`, built by the reference builder.
fn frame(profile: &Profile, values: &Values, counter: u64, payload: &[u8]) -> Vec<u8> {
    let name = &profile.fields()[profile.counter().field].name;
    build(profile, &values.clone().whole(name, counter), payload)
        .expect("the frame builds")
        .bytes
}

fn indexed(profile: Profile, expected: &Values, streams: usize) -> Receiver {
    Receiver::new(profile, expected, Keying::Indexed { streams }, None, 8).expect("made")
}

fn assert_refused(text: &str, path: &str, words: &str) {
    match Profile::parse(text) {
        Err(DocError::Invalid { path: p, reason }) => {
            assert_eq!(p, path, "the place of: {reason}");
            assert!(reason.contains(words), "`{reason}` says `{words}`");
        }
        other => panic!("expected a refusal at {path}, got {other:?}"),
    }
}

fn swap(text: &str, from: &str, to: &str) -> String {
    assert!(text.contains(from), "the profile has `{from}`");
    text.replacen(from, to, 1)
}

// ---------------------------------------------------------------- the profile

#[test]
fn the_judging_rules_and_the_cell_are_read_from_the_profile() {
    let p = left();
    let rules = p.rules();
    assert_eq!(rules.ident, p.field_index("ident"));
    assert!(rules.length);
    assert_eq!(rules.counter_errors, CounterErrors::Joined);
    assert!(!rules.out_of_range_moves_baseline);
    assert_eq!(p.counter().max_gap_ceiling, Some(12));
    assert_eq!(p.max_gap_limit(), 12);
    let cell = p.cell().expect("a cell");
    assert_eq!(Some(cell.field), p.field_index("cell"));
    assert_eq!(
        (cell.kind, cell.result, cell.sender),
        (Some(0), Some(1), Some(2))
    );
    let sender = &p.fields()[cell.field].parts[2];
    let derive = sender.derive.expect("derived");
    assert_eq!((derive.mask, derive.xor), (0x00FF_0FF0, 0xA5A0));

    let q = right();
    assert_eq!(q.rules().counter_errors, CounterErrors::Apart);
    assert!(q.rules().out_of_range_moves_baseline);
    assert!(!q.rules().length);
    assert_eq!(
        q.max_gap_limit(),
        0xFFFF_FFFF,
        "no ceiling: the counter's largest step"
    );
    assert_eq!(q.cell().expect("a cell").result, None);
}

#[test]
fn a_profile_that_states_no_rule_judges_as_the_judge_always_has() {
    let text = swap(
        LEFT,
        r#""judge": {"ident": "ident", "length": true, "counter_errors": "joined",
            "out_of_range": "keeps_baseline"},"#,
        "",
    );
    let p = Profile::parse(&text).expect("valid");
    assert_eq!(*p.rules(), JudgeRules::default());
    assert_eq!(JudgeRules::default().ident, None);
    assert!(!JudgeRules::default().length);
    assert_eq!(JudgeRules::default().counter_errors, CounterErrors::Apart);
    assert!(JudgeRules::default().out_of_range_moves_baseline);
    // The reader takes JSON5, so the comma the cell leaves behind is allowed.
    let text = swap(
        &text,
        r#""cell": {"field": "cell", "kind": "kind", "result": "result", "sender": "sender"}"#,
        "",
    );
    assert!(Profile::parse(&text).expect("valid").cell().is_none());
}

#[test]
fn a_derivation_is_refused_where_it_cannot_mean_what_it_says() {
    let derive = r#""derive": {"from": "address", "mask": "0x00FF0FF0", "xor": "0xA5A0"}"#;
    assert_refused(
        &swap(
            LEFT,
            derive,
            r#""derive": {"from": "clock", "mask": "0xFF"}"#,
        ),
        "/fields/4/split/2/derive/from",
        "not a source",
    );
    assert_refused(
        &swap(LEFT, derive, r#""derive": {"from": "address", "mask": 0}"#),
        "/fields/4/split/2/derive/mask",
        "takes nothing from the address",
    );
    assert_refused(
        &swap(
            LEFT,
            derive,
            r#""derive": {"from": "address", "mask": "0x08000000"}"#,
        ),
        "/fields/4/split/2/derive/mask",
        "does not fit the 27 bits",
    );
    assert_refused(
        &swap(
            LEFT,
            derive,
            r#""derive": {"from": "address", "mask": "0xFF", "xor": "0x08000000"}"#,
        ),
        "/fields/4/split/2/derive/xor",
        "does not fit the 27 bits",
    );
    assert_refused(
        &swap(
            LEFT,
            derive,
            r#""derive": {"from": "address", "mask": "0xFF", "shift": 2}"#,
        ),
        "/fields/4/split/2/derive/shift",
        "unknown key",
    );
    // A split field derives part by part; a field the mechanism fills derives nothing.
    assert_refused(
        &swap(
            LEFT,
            r#"{"name": "cell", "bytes": 4,"#,
            r#"{"name": "cell", "bytes": 4, "derive": {"from": "address", "mask": "0xFF"},"#,
        ),
        "/fields/4/derive",
        "derives a value part by part",
    );
    assert_refused(
        &swap(
            LEFT,
            r#"{"name": "counter", "bytes": 1}"#,
            r#"{"name": "counter", "bytes": 1, "derive": {"from": "address", "mask": "0xFF"}}"#,
        ),
        "/counter/field",
        "is derived from the address",
    );
}

#[test]
fn the_judging_rules_and_the_ceiling_are_validated() {
    assert_refused(
        &swap(LEFT, r#""max_gap_ceiling": 12"#, r#""max_gap_ceiling": 3"#),
        "/counter/max_gap",
        "above the profile's max_gap_ceiling 3",
    );
    assert_refused(
        &swap(
            LEFT,
            r#""max_gap_ceiling": 12"#,
            r#""max_gap_ceiling": 256"#,
        ),
        "/counter/max_gap_ceiling",
        "1 to 255",
    );
    assert_refused(
        &swap(
            LEFT,
            r#""judge": {"ident": "ident""#,
            r#""judge": {"ident": "counter""#,
        ),
        "/judge/ident",
        "crc, length or counter",
    );
    assert_refused(
        &swap(
            LEFT,
            r#""judge": {"ident": "ident""#,
            r#""judge": {"ident": "nothing""#,
        ),
        "/judge/ident",
        "no field is called",
    );
    assert_refused(
        &swap(
            LEFT,
            r#""counter_errors": "joined""#,
            r#""counter_errors": "merged""#,
        ),
        "/judge/counter_errors",
        "expected `apart` or `joined`",
    );
    assert_refused(
        &swap(
            LEFT,
            r#""out_of_range": "keeps_baseline""#,
            r#""out_of_range": "resets""#,
        ),
        "/judge/out_of_range",
        "moves_baseline",
    );
    assert_refused(
        &swap(LEFT, r#""length": true,"#, r#""length": "yes","#),
        "/judge/length",
        "true or false",
    );
}

#[test]
fn the_cell_names_parts_of_one_split_field() {
    let cell =
        r#""cell": {"field": "cell", "kind": "kind", "result": "result", "sender": "sender"}"#;
    assert_refused(
        &swap(
            LEFT,
            cell,
            r#""cell": {"field": "length", "sender": "sender"}"#,
        ),
        "/cell/field",
        "is not split",
    );
    assert_refused(
        &swap(
            LEFT,
            cell,
            r#""cell": {"field": "cell", "sender": "origin"}"#,
        ),
        "/cell/sender",
        "no part called `origin`",
    );
    assert_refused(
        &swap(
            LEFT,
            cell,
            r#""cell": {"field": "cell", "kind": "kind", "result": "kind"}"#,
        ),
        "/cell/result",
        "named twice",
    );
    assert_refused(
        &swap(LEFT, cell, r#""cell": {"field": "cell"}"#),
        "/cell",
        "at least one of",
    );
}

// ---------------------------------------------------------------- derived values

#[test]
fn a_derived_part_is_the_masked_address_xored_and_the_identifier_is_its_parts_xored() {
    let p = left();
    let built = build(&p, &left_values(ADDR_A).whole("counter", 7), b"\x01\x02").expect("built");
    let opened = open(&p, &built.bytes).expect("opens");
    let cell = &opened.fields[p.field_index("cell").expect("cell")];
    assert_eq!(cell.parts, vec![1, 2, left_sender_id(ADDR_A)]);
    // The identifier is composed of its parts at their bit positions, and the
    // wire carries it XORed with the profile's constant.
    let ident = &opened.fields[p.field_index("ident").expect("ident")];
    assert_eq!(ident.value, (0x5A1 << 20) | 0x0BEEF);
    assert_eq!(ident.raw, ident.value ^ 0x00C0_FFEE);
    assert_eq!(
        logical_value(
            &p,
            p.field_index("ident").expect("ident"),
            &left_values(ADDR_A)
        ),
        Ok(ident.value)
    );
    // Another address, another sender part, and nothing else of the header moves.
    let other = build(&p, &left_values(ADDR_B).whole("counter", 7), b"\x01\x02").expect("built");
    let opened_b = open(&p, &other.bytes).expect("opens");
    assert_eq!(
        opened_b.fields[p.field_index("cell").expect("cell")].parts[2],
        left_sender_id(ADDR_B)
    );
    assert_eq!(opened_b.fields[0].value, 7, "the counter is the same");
    assert_eq!(
        opened_b.fields[2], opened.fields[2],
        "the identifier is the same"
    );
    // Bits of the address outside the mask change nothing on the wire.
    let masked = build(
        &p,
        &left_values(ADDR_A ^ OUTSIDE_LEFT_MASK).whole("counter", 7),
        b"\x01\x02",
    )
    .expect("built");
    assert_eq!(masked.bytes, built.bytes);
}

#[test]
fn a_derived_value_needs_the_address_and_refuses_to_be_stated() {
    let p = left();
    let no_address = Values::new()
        .parts("ident", &[("sys", 1), ("mid", 2)])
        .parts("cell", &[("kind", 1), ("result", 2)])
        .whole("counter", 0);
    match build(&p, &no_address, &[]) {
        Err(BuildError::Values(DocError::Invalid { reason, .. })) => {
            assert!(reason.contains(ADDRESS), "{reason}");
            assert!(reason.contains("the part `sender` of `cell`"), "{reason}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    let stated = Values::new()
        .parts("ident", &[("sys", 1), ("mid", 2)])
        .parts("cell", &[("kind", 1), ("result", 2), ("sender", 5)])
        .whole("counter", 0)
        .address(ADDR_A);
    match build(&p, &stated, &[]) {
        Err(BuildError::Values(DocError::Invalid { path, reason })) => {
            assert_eq!(path, "/cell/sender");
            assert!(reason.contains("leave it out"), "{reason}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    // The values text states the address under its reserved member.
    let text = r#"{"ident": {"sys": 1, "mid": 2}, "cell": {"kind": 1, "result": 2},
                   "counter": 0, "@address": "0x0A1B2C3D"}"#;
    let parsed = Values::parse(text).expect("parsed");
    assert_eq!(parsed.stated_address(), Some(ADDR_A));
    assert!(build(&p, &parsed, &[]).is_ok());
    assert!(
        Values::parse(r#"{"@address": "ten"}"#).is_err(),
        "an address is an integer"
    );
}

// ---------------------------------------------------------------- the receiver

#[test]
fn the_first_intact_frame_is_the_baseline_and_the_next_are_judged_apart() {
    let p = right();
    let values = right_values(ADDR_A);
    let mut rx = indexed(p.clone(), &values, 2);
    let f = |c| frame(&p, &values, c, b"payload");
    let v = rx.receive(0, &f(40), 10).expect("judged");
    assert_eq!(
        (v.status, v.failed, v.stream, v.step),
        (Status::First, 0, Some(0), None)
    );
    let v = rx.receive(0, &f(41), 20).expect("judged");
    assert_eq!((v.status, v.step), (Status::Ok, Some(1)));
    assert_eq!(
        rx.receive(0, &f(41), 30).expect("judged").status,
        Status::Repeated
    );
    let v = rx.receive(0, &f(45), 40).expect("judged");
    assert_eq!((v.status, v.step), (Status::OutOfRange, Some(4)));
    // The default rule moved the baseline to 45, so 46 is the next.
    assert_eq!(
        rx.receive(0, &f(46), 50).expect("judged").status,
        Status::Ok
    );
    // Stream 1 is its own: its first frame is a baseline whatever stream 0 holds.
    assert_eq!(
        rx.receive(1, &f(46), 60).expect("judged").status,
        Status::First
    );
    // The cell's parts are reported, and the payload is always where it is.
    let v = rx.receive(1, &f(47), 70).expect("judged");
    assert_eq!(
        (v.kind, v.result, v.sender),
        (Some(9), None, Some(right_sender_id(ADDR_A)))
    );
    assert_eq!((v.payload_offset, v.payload_bytes), (p.header_bytes(), 7));
    assert_eq!(
        rx.receive(2, &f(48), 80),
        Err(ReceiveError::NoSuchStream {
            stream: 2,
            streams: 2
        })
    );
}

#[test]
fn joined_counter_errors_are_one_status_and_a_kept_baseline_judges_from_where_it_was() {
    let p = left();
    let values = left_values(ADDR_A);
    let mut rx = indexed(p.clone(), &values, 1);
    let f = |c| frame(&p, &values, c, b"xy");
    assert_eq!(
        rx.receive(0, &f(200), 0).expect("judged").status,
        Status::First
    );
    assert_eq!(
        rx.receive(0, &f(200), 1).expect("judged").status,
        Status::CounterError
    );
    assert_eq!(
        rx.receive(0, &f(210), 2).expect("judged").status,
        Status::CounterError
    );
    // `keeps_baseline`: 210 did not move it, so 201 is one step on from 200.
    assert_eq!(
        rx.receive(0, &f(201), 3).expect("judged").status,
        Status::Ok
    );
    // The one-byte counter wraps: 255 then 0 is a step of one.
    let mut rx = indexed(p.clone(), &values, 1);
    rx.receive(0, &f(255), 0).expect("judged");
    let v = rx.receive(0, &f(0), 1).expect("judged");
    assert_eq!((v.status, v.step), (Status::Ok, Some(1)));
}

#[test]
fn a_frame_that_fails_integrity_is_reported_moves_nothing_and_keeps_its_payload() {
    let p = left();
    let values = left_values(ADDR_A);
    let mut rx = indexed(p.clone(), &values, 1);
    let good = frame(&p, &values, 3, b"abc");
    rx.receive(0, &good, 0).expect("judged");
    // A damaged payload byte: the CRC.
    let mut damaged = frame(&p, &values, 4, b"abc");
    let last = damaged.len() - 1;
    damaged[last] ^= 0x40;
    let v = rx.receive(0, &damaged, 1).expect("judged");
    assert_eq!(
        (v.status, v.failed, v.stream),
        (Status::Integrity, FAILED_CRC, Some(0))
    );
    assert_eq!((v.payload_offset, v.payload_bytes), (p.header_bytes(), 3));
    // Another identifier, with a CRC that matches it: the identifier alone.
    let stranger = Values::new()
        .parts("ident", &[("sys", 0x5A1), ("mid", 0x0BEEE)])
        .parts("cell", &[("kind", 1), ("result", 2)])
        .address(ADDR_A);
    let v = rx
        .receive(0, &frame(&p, &stranger, 4, b"abc"), 2)
        .expect("judged");
    assert_eq!((v.status, v.failed), (Status::Integrity, FAILED_IDENT));
    // Neither moved the baseline: 4 is still one step on from 3.
    assert_eq!(
        rx.receive(0, &frame(&p, &values, 4, b"abc"), 3)
            .expect("judged")
            .status,
        Status::Ok
    );
    // A frame one byte longer than its length field says, CRC recomputed so only the length is off.
    let mut long = frame(&p, &values, 5, b"abc");
    long.push(0x99);
    let length_at = p.fields()[p.field_index("length").expect("length")].offset;
    let stated = u16::from_be_bytes([long[length_at], long[length_at + 1]]);
    assert_eq!(usize::from(stated) + 1, long.len());
    let refit = {
        let mut copy = long.clone();
        let crc = p.crc();
        let mut digest = crc.engine.start();
        for &item in &crc.cover {
            crate::e2e_frame::feed(&p, &mut digest, item, &copy);
        }
        let value = digest.finish();
        let at = p.fields()[crc.field].offset;
        copy[at..at + 4].copy_from_slice(&(value as u32).to_be_bytes());
        copy
    };
    let v = rx.receive(0, &refit, 4).expect("judged");
    assert_eq!((v.status, v.failed), (Status::Integrity, FAILED_LENGTH));
    // Shorter than the header: no fields, an empty payload, still judged in its stream.
    let v = rx.receive(0, &good[..4], 5).expect("judged");
    assert_eq!(
        (v.status, v.failed, v.counter),
        (Status::Integrity, FAILED_SHORT, None)
    );
    assert_eq!(
        (v.payload_offset, v.payload_bytes, v.stream),
        (4, 0, Some(0))
    );
    assert_eq!(
        rx.receive(0, &frame(&p, &values, 5, b"abc"), 6)
            .expect("judged")
            .status,
        Status::Ok
    );
}

/// An identifier word whose parts leave bits 12 to 15 and bit 7 to none, under a CRC that does not
/// cover the word, so a frame can carry other values in those bits and still verify.
const UNOWNED: &str = r#"{
  "name": "syn-unowned",
  "fields": [
    {"name": "ident", "bytes": 2, "xor": "0xC3A5",
     "split": [{"name": "hi", "lsb": 8, "width": 4}, {"name": "lo", "lsb": 0, "width": 7}]},
    {"name": "counter", "bytes": 1},
    {"name": "length", "bytes": 1},
    {"name": "crc", "bytes": 2}
  ],
  "crc": {"field": "crc", "width": 16, "poly": "0x8005", "init": "0x0000",
          "refin": true, "refout": true, "xorout": "0x0000",
          "cover": ["@payload", "counter", "length"]},
  "length": {"field": "length", "counts": "frame"},
  "counter": {"field": "counter", "max_gap": 2, "timeout_ms": 0},
  "judge": {"ident": "ident"}
}"#;

#[test]
fn a_split_identifier_is_judged_in_the_bits_its_parts_own() {
    let p = Profile::parse(UNOWNED).expect("valid");
    let ident = &p.fields()[p.field_index("ident").expect("ident")];
    assert_eq!(ident.owned_bits(), 0x0F7F);
    let counter = &p.fields()[p.field_index("counter").expect("counter")];
    assert_eq!(counter.owned_bits(), 0xFF, "a plain field owns every bit");

    let values = Values::new().parts("ident", &[("hi", 0x9), ("lo", 0x35)]);
    let mut rx = indexed(p.clone(), &values, 1);
    let first = frame(&p, &values, 1, b"xy");
    let v = rx.receive(0, &first, 0).expect("judged");
    assert_eq!((v.status, v.failed), (Status::First, 0));
    // Bits 12 to 15 are the first byte's high nibble and bit 7 the second byte's top bit: written
    // otherwise, they are no part of the identifier.
    let mut other = frame(&p, &values, 2, b"xy");
    other[0] ^= 0xF0;
    other[1] ^= 0x80;
    let v = rx.receive(0, &other, 1).expect("judged");
    assert_eq!((v.status, v.failed), (Status::Ok, 0));
    // A bit a part owns is: the frame names another identifier.
    let mut stranger = frame(&p, &values, 3, b"xy");
    stranger[1] ^= 0x01;
    let v = rx.receive(0, &stranger, 2).expect("judged");
    assert_eq!((v.status, v.failed), (Status::Integrity, FAILED_IDENT));
}

#[test]
fn a_profile_without_the_length_rule_does_not_judge_the_length() {
    let p = right();
    let values = right_values(ADDR_A);
    let mut rx = indexed(p.clone(), &values, 1);
    rx.receive(0, &frame(&p, &values, 1, b"q"), 0)
        .expect("judged");
    // `frame_minus` leaves the CRC out, and the profile states no length rule:
    // an extra byte the CRC covers is a CRC matter only, never a length one.
    let mut long = frame(&p, &values, 2, b"q");
    long.push(1);
    let v = rx.receive(0, &long, 1).expect("judged");
    assert_eq!(v.failed & FAILED_LENGTH, 0);
}

#[test]
fn senders_take_slots_in_arrival_order_only_with_an_intact_frame() {
    let p = right();
    let expected = right_values(ADDR_A);
    let mut rx = Receiver::new(
        p.clone(),
        &expected,
        Keying::Senders {
            slots: 2,
            bound: None,
        },
        None,
        8,
    )
    .expect("made");
    let of = |address, counter| frame(&p, &right_values(address), counter, b"s");
    // A damaged frame of a sender no slot holds is judged nowhere and takes no slot.
    let mut damaged = of(ADDR_A, 1);
    damaged[0] ^= 1;
    let v = rx.receive(0, &damaged, 0).expect("judged");
    assert_eq!(
        (v.status, v.stream, v.unslotted),
        (Status::Integrity, None, None)
    );
    assert_eq!(rx.slot_sender(0), None);
    // Two senders, two slots, each its own counter.
    assert_eq!(
        rx.receive(0, &of(ADDR_A, 10), 1).expect("judged").stream,
        Some(0)
    );
    assert_eq!(
        rx.receive(0, &of(ADDR_B, 500), 2).expect("judged").stream,
        Some(1)
    );
    assert_eq!(rx.slot_sender(0), Some(right_sender_id(ADDR_A)));
    assert_eq!(rx.slot_sender(1), Some(right_sender_id(ADDR_B)));
    assert_eq!(
        rx.receive(0, &of(ADDR_A, 11), 3).expect("judged").status,
        Status::Ok
    );
    assert_eq!(
        rx.receive(0, &of(ADDR_B, 501), 4).expect("judged").status,
        Status::Ok
    );
    // A damaged frame of a sender that holds a slot is judged in it.
    let mut damaged = of(ADDR_B, 502);
    damaged[0] ^= 1;
    let v = rx.receive(0, &damaged, 5).expect("judged");
    assert_eq!((v.status, v.stream), (Status::Integrity, Some(1)));
    // A third sender finds the table full: not judged, counted, payload still there.
    let v = rx.receive(0, &of(ADDR_C, 1), 6).expect("judged");
    assert_eq!(
        (v.status, v.unslotted, v.stream),
        (Status::Unslotted, Some(Unslotted::Full), None)
    );
    assert_eq!(v.payload_bytes, 1);
    assert_eq!(rx.counts().full, 1);
    assert_eq!(rx.counts().not_listed, 0);
    // The stream argument is the receiver's under sender keying.
    assert_eq!(
        rx.receive(1, &of(ADDR_A, 12), 7),
        Err(ReceiveError::NoSuchStream {
            stream: 1,
            streams: 1
        })
    );
}

#[test]
fn slots_bound_by_a_list_judge_the_listed_and_count_the_rest() {
    let p = left();
    let expected = left_values(ADDR_A);
    let bound = vec![left_sender_id(ADDR_B), left_sender_id(ADDR_A)];
    let mut rx = Receiver::new(
        p.clone(),
        &expected,
        Keying::Senders {
            slots: 4,
            bound: Some(bound),
        },
        None,
        4,
    )
    .expect("made");
    assert_eq!(rx.streams(), 2, "one slot per listed sender");
    let of = |address, counter| frame(&p, &left_values(address), counter, b"b");
    assert_eq!(
        rx.receive(0, &of(ADDR_A, 1), 0).expect("judged").stream,
        Some(1)
    );
    assert_eq!(
        rx.receive(0, &of(ADDR_B, 1), 0).expect("judged").stream,
        Some(0)
    );
    let v = rx.receive(0, &of(ADDR_C, 1), 0).expect("judged");
    assert_eq!(
        (v.status, v.unslotted),
        (Status::Unslotted, Some(Unslotted::NotListed))
    );
    assert_eq!(rx.counts().not_listed, 1);
}

#[test]
fn a_receiver_is_refused_by_name_when_it_cannot_judge_what_it_is_asked() {
    let one = || Keying::Indexed { streams: 1 };
    let left_new = |gap| Receiver::new(left(), &left_values(ADDR_A), one(), gap, 8).err();
    assert_eq!(
        left_new(Some(13)),
        Some(NewError::MaxGap {
            given: 13,
            limit: 12
        })
    );
    assert_eq!(
        left_new(Some(0)),
        Some(NewError::MaxGap {
            given: 0,
            limit: 12
        })
    );
    assert_eq!(left_new(Some(12)), None, "the ceiling itself is allowed");

    let values = right_values(ADDR_A);
    let senders = |slots| Keying::Senders { slots, bound: None };
    let new = |profile: Profile, keying: Keying, gap: Option<u64>, limit: usize| {
        Receiver::new(profile, &values, keying, gap, limit)
    };
    assert_eq!(
        new(right(), Keying::Indexed { streams: 0 }, None, 8).err(),
        Some(NewError::NoStreams)
    );
    assert_eq!(
        new(right(), senders(0), None, 8).err(),
        Some(NewError::NoStreams)
    );
    assert_eq!(
        new(right(), senders(9), None, 8).err(),
        Some(NewError::TooManySlots { slots: 9, limit: 8 })
    );
    let no_sender = swap(
        RIGHT,
        r#""cell": {"field": "cell", "kind": "kind", "sender": "sender"}"#,
        r#""cell": {"field": "cell", "kind": "kind"}"#,
    );
    let p = Profile::parse(&no_sender).expect("valid");
    assert_eq!(
        new(p, senders(2), None, 8).err(),
        Some(NewError::NoSenderInCell)
    );
    let twice = Keying::Senders {
        slots: 2,
        bound: Some(vec![5, 5]),
    };
    assert_eq!(
        new(right(), twice, None, 8).err(),
        Some(NewError::BadBoundList)
    );
    let too_many = Keying::Senders {
        slots: 1,
        bound: Some(vec![5, 6]),
    };
    assert_eq!(
        new(right(), too_many, None, 8).err(),
        Some(NewError::BadBoundList)
    );
    let too_wide = Keying::Senders {
        slots: 1,
        bound: Some(vec![1 << 24]),
    };
    assert_eq!(
        new(right(), too_wide, None, 8).err(),
        Some(NewError::BadBoundList)
    );
    // An identifier the profile judges must be expected.
    let none = Values::new();
    assert!(matches!(
        Receiver::new(right(), &none, Keying::Indexed { streams: 1 }, None, 8),
        Err(NewError::Expected(_))
    ));
    // A max_gap within the ceiling replaces the profile's own.
    let mut rx = Receiver::new(
        left(),
        &left_values(ADDR_A),
        Keying::Indexed { streams: 1 },
        Some(12),
        8,
    )
    .expect("made");
    let p = left();
    rx.receive(0, &frame(&p, &left_values(ADDR_A), 0, b""), 0)
        .expect("judged");
    assert_eq!(
        rx.receive(0, &frame(&p, &left_values(ADDR_A), 12, b""), 1)
            .expect("judged")
            .status,
        Status::Ok
    );
}

// ---------------------------------------------------------------- the sender

#[test]
fn the_sender_keeps_a_counter_per_stream_and_refuses_what_it_cannot_send() {
    let p = right();
    let options = SenderOptions {
        streams: 2,
        first_counter: 0xFFFF_FFFE,
        ..SenderOptions::default()
    };
    let mut tx = StreamSender::new(p.clone(), right_values(ADDR_A), options).expect("made");
    assert_eq!(tx.protect(0, b"a").expect("sent").counter, 0xFFFF_FFFE);
    assert_eq!(tx.protect(0, b"a").expect("sent").counter, 0xFFFF_FFFF);
    assert_eq!(
        tx.protect(0, b"a"),
        Err(SendError::Spent {
            stream: 0,
            max: 0xFFFF_FFFF
        })
    );
    assert_eq!(tx.next(0), Ok(None));
    assert_eq!(
        tx.protect(1, b"a").expect("sent").counter,
        0xFFFF_FFFE,
        "stream 1 is its own"
    );
    assert_eq!(
        tx.protect(2, b"a"),
        Err(SendError::NoSuchStream {
            stream: 2,
            streams: 2
        })
    );
    assert_eq!(
        tx.set(0, 1 << 32),
        Err(SendError::CounterDoesNotFit {
            value: 1 << 32,
            max: 0xFFFF_FFFF
        })
    );
    tx.set(0, 7).expect("set");
    assert_eq!(tx.protect(0, b"a").expect("sent").counter, 7);

    let wrap = SenderOptions {
        first_counter: 0xFFFF_FFFF,
        rollover: Rollover::Wrap,
        ..SenderOptions::default()
    };
    let mut tx = StreamSender::new(p.clone(), right_values(ADDR_A), wrap).expect("made");
    tx.protect(0, b"").expect("sent");
    assert_eq!(tx.next(0), Ok(Some(0)));

    let stated = right_values(ADDR_A).whole("counter", 3);
    assert_eq!(
        StreamSender::new(p.clone(), stated, SenderOptions::default()).err(),
        Some(SendError::CounterStated {
            field: String::from("counter")
        })
    );
    let missing = Values::new().whole("ident", 1).address(ADDR_A);
    assert!(matches!(
        StreamSender::new(p.clone(), missing, SenderOptions::default()),
        Err(SendError::Build(_))
    ));
    let none = SenderOptions {
        streams: 0,
        ..SenderOptions::default()
    };
    assert_eq!(
        StreamSender::new(p.clone(), right_values(ADDR_A), none).err(),
        Some(SendError::NoStreams)
    );
    let wide = SenderOptions {
        first_counter: 1 << 32,
        ..SenderOptions::default()
    };
    assert!(matches!(
        StreamSender::new(p, right_values(ADDR_A), wide),
        Err(SendError::CounterDoesNotFit { .. })
    ));
}

#[test]
fn a_sent_frame_is_the_reference_build_and_the_receiver_reads_it_back() {
    for (p, values) in [
        (left(), left_values(ADDR_A)),
        (right(), right_values(ADDR_B)),
    ] {
        let options = SenderOptions {
            first_counter: 5,
            crc_cache: true,
            ..SenderOptions::default()
        };
        let mut tx = StreamSender::new(p.clone(), values.clone(), options).expect("made");
        let mut rx = indexed(p.clone(), &values, 1);
        for (i, payload) in [&b"one"[..], b"one", b"two", b"", b"two"]
            .iter()
            .enumerate()
        {
            let sent = tx.protect(0, payload).expect("sent");
            assert_eq!(
                sent.bytes,
                frame(&p, &values, sent.counter, payload),
                "{}: frame {i}",
                p.name()
            );
            let v = rx.receive(0, &sent.bytes, i as u64).expect("judged");
            let want = if i == 0 { Status::First } else { Status::Ok };
            assert_eq!(
                (v.status, v.counter),
                (want, Some(sent.counter)),
                "{}: frame {i}",
                p.name()
            );
            assert_eq!(
                &sent.bytes[v.payload_offset..v.payload_offset + v.payload_bytes],
                *payload
            );
        }
    }
}

/// A small generator of test input, so the sweep is the same on every run.
struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// A profile with a CRC of `width` bits and the cover in `order`.
fn sweep_profile(width: u8, crc: &str, order: &[&str]) -> Profile {
    let cover: Vec<String> = order.iter().map(|n| format!("\"{n}\"")).collect();
    let text = format!(
        r#"{{"name": "sweep",
  "fields": [{{"name": "tag", "bytes": 3, "xor": "0x0F0E0D"}},
             {{"name": "counter", "bytes": 2}},
             {{"name": "crc", "bytes": {bytes}}},
             {{"name": "length", "bytes": 2}}],
  "crc": {{"field": "crc", "width": {width}, {crc}, "cover": [{cover}]}},
  "length": {{"field": "length", "counts": "frame"}},
  "counter": {{"field": "counter", "max_gap": 2, "timeout_ms": 10}}}}"#,
        bytes = width / 8,
        cover = cover.join(", "),
    );
    Profile::parse(&text).expect("the sweep profile is valid")
}

#[test]
fn the_crc_cache_gives_the_bytes_the_full_computation_gives() {
    // One published parameter set for each width the engine supports.
    let engines: [(u8, &str); 4] = [
        (
            8,
            r#""poly": "0x07", "init": "0x00", "refin": false, "refout": false, "xorout": "0x00""#,
        ),
        (
            16,
            r#""poly": "0x8005", "init": "0x0000", "refin": true, "refout": true, "xorout": "0x0000""#,
        ),
        (
            32,
            r#""poly": "0x1EDC6F41", "init": "0xFFFFFFFF", "refin": true, "refout": true, "xorout": "0xFFFFFFFF""#,
        ),
        (
            64,
            r#""poly": "0x1B", "init": "0xFFFFFFFFFFFFFFFF", "refin": true, "refout": true, "xorout": "0xFFFFFFFFFFFFFFFF""#,
        ),
    ];
    // The counter first, in the middle, last, and not covered at all.
    let orders: [&[&str]; 4] = [
        &["counter", "@payload", "tag", "length"],
        &["tag", "@payload", "counter", "length"],
        &["length", "tag", "@payload", "counter"],
        &["@payload", "tag", "length"],
    ];
    let mut rng = Xorshift(0x9E37_79B9_7F4A_7C15);
    for (width, params) in engines {
        for order in orders {
            let p = sweep_profile(width, params, order);
            let values = Values::new().whole("tag", 0x00AB_CDEF & 0xFF_FFFF);
            let options = SenderOptions {
                streams: 2,
                first_counter: 0xFFF0,
                rollover: Rollover::Wrap,
                crc_cache: true,
            };
            let mut tx = StreamSender::new(p.clone(), values.clone(), options).expect("made");
            let mut payloads: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
            let mut cached = 0;
            for _ in 0..200 {
                let stream = (rng.next() % 2) as usize;
                if rng.next() % 3 != 0 || payloads[stream].is_empty() {
                    let len = (rng.next() % 40) as usize;
                    payloads[stream] = (0..len).map(|_| rng.next() as u8).collect();
                }
                let sent = tx.protect(stream, &payloads[stream]).expect("sent");
                cached += usize::from(sent.from_cache);
                assert_eq!(
                    sent.bytes,
                    frame(&p, &values, sent.counter, &payloads[stream]),
                    "width {width}, order {order:?}, counter {}",
                    sent.counter
                );
            }
            assert!(
                cached > 0,
                "width {width}, order {order:?}: the cache was used"
            );
        }
    }
    // With the cache off, no frame comes from it.
    let p = right();
    let mut tx =
        StreamSender::new(p, right_values(ADDR_A), SenderOptions::default()).expect("made");
    tx.protect(0, b"same").expect("sent");
    assert!(!tx.protect(0, b"same").expect("sent").from_cache);
}
