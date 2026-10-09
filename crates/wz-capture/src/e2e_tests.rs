// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Tests of the end-to-end protection mechanism over SYNTHETIC profiles.
//!
//! None of the profiles here is any real protocol's: the names, widths, masks,
//! field orders and CRC choices are made up, and made to differ from one
//! another, so a test cannot pass by agreeing with one fixed layout. The golden
//! frames were computed once by an independent model written from the profile
//! description alone (a bitwise CRC, big-endian fields, parts OR-ed and then
//! XORed on build, the cover fed in its listed order); the CRC engine itself is
//! graded against published check values in `e2e_crc`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::e2e_frame::{build, open, BuildError, OpenError, Values};
use crate::e2e_json::{open_document, wrap_document};
use crate::e2e_judge::{CounterReason, Judge};
use crate::e2e_profile::{DocError, Profile, MAX_JSON_DEPTH};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "an even number of hex digits");
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

// ---------------------------------------------------------------- profiles

/// CRC first, 4-byte CRC, 2-byte counter; both an `xor` and a `split` on two
/// fields. The shape the brief sketches, with masks of its own.
const DEMO_A: &str = r#"{
  "name": "demo-a",
  "fields": [
    {"name": "crc", "bytes": 4},
    {"name": "length", "bytes": 2},
    {"name": "counter", "bytes": 2},
    {"name": "ident", "bytes": 4, "xor": "0x0F0F0F0F",
     "split": [{"name": "domain", "lsb": 24, "width": 8},
               {"name": "version", "lsb": 16, "width": 8},
               {"name": "msg", "lsb": 0, "width": 16}]},
    {"name": "cell", "bytes": 4, "xor": "0x01234567",
     "split": [{"name": "kind", "lsb": 30, "width": 2},
               {"name": "result", "lsb": 28, "width": 2},
               {"name": "sender", "lsb": 0, "width": 28}]}
  ],
  "crc": {"field": "crc", "width": 32, "poly": "0xF4ACFB13", "init": "0xFFFFFFFF",
          "refin": true, "refout": true, "xorout": "0xFFFFFFFF",
          "cover": ["length", "ident", "@payload", "cell", "counter"]},
  "length": {"field": "length", "counts": "frame"},
  "counter": {"field": "counter", "max_gap": 10, "timeout_ms": 1000}
}"#;

/// CRC LAST and 8 bytes wide, a 4-byte counter, a length that leaves one field
/// out, a field that is split with no `xor`, a field with an `xor` and no
/// split, and a field the CRC does not cover.
const DEMO_B: &str = r#"{
  "name": "demo-b",
  "fields": [
    {"name": "length", "bytes": 4},
    {"name": "counter", "bytes": 4},
    {"name": "ident", "bytes": 4,
     "split": [{"name": "sys", "lsb": 24, "width": 8},
               {"name": "rev", "lsb": 16, "width": 8},
               {"name": "id", "lsb": 0, "width": 16}]},
    {"name": "cell", "bytes": 4, "xor": "0xA5A5A5A5"},
    {"name": "crc", "bytes": 8}
  ],
  "crc": {"field": "crc", "width": 64, "poly": "0x42F0E1EBA9EA3693",
          "init": "0xFFFFFFFFFFFFFFFF", "refin": true, "refout": true,
          "xorout": "0xFFFFFFFFFFFFFFFF",
          "cover": ["counter", "@payload", "ident", "length"]},
  "length": {"field": "length", "counts": "frame_minus", "fields": ["cell"]},
  "counter": {"field": "counter", "max_gap": 5, "timeout_ms": 250}
}"#;

/// CRC in the MIDDLE, 16 bits and reflected, a 1-byte counter, a 3-byte length
/// and a 7-byte split field whose value can pass 2^53.
const DEMO_C: &str = r#"{
  "name": "demo-c",
  "fields": [
    {"name": "kind", "bytes": 1},
    {"name": "crc", "bytes": 2},
    {"name": "seq", "bytes": 1},
    {"name": "len", "bytes": 3},
    {"name": "tag", "bytes": 7, "xor": "0x01020304050607",
     "split": [{"name": "hi", "lsb": 32, "width": 24},
               {"name": "lo", "lsb": 0, "width": 32}]}
  ],
  "crc": {"field": "crc", "width": 16, "poly": "0x1021", "init": "0xFFFF",
          "refin": true, "refout": true, "xorout": "0x0000",
          "cover": ["kind", "tag", "@payload", "seq", "len"]},
  "length": {"field": "len", "counts": "frame"},
  "counter": {"field": "seq", "max_gap": 3, "timeout_ms": 40}
}"#;

/// An 8-bit CRC, one-byte length and counter, and an 8-byte field that is
/// XORed with all ones and split with bits left unassigned between the parts.
const DEMO_D: &str = r#"{
  "name": "demo-d",
  "fields": [
    {"name": "crc", "bytes": 1},
    {"name": "len", "bytes": 1},
    {"name": "seq", "bytes": 1},
    {"name": "stamp", "bytes": 8, "xor": "0xFFFFFFFFFFFFFFFF",
     "split": [{"name": "top", "lsb": 56, "width": 8},
               {"name": "mid", "lsb": 24, "width": 32},
               {"name": "low", "lsb": 0, "width": 8}]}
  ],
  "crc": {"field": "crc", "width": 8, "poly": "0x1D", "init": "0xFF",
          "refin": false, "refout": false, "xorout": "0xFF",
          "cover": ["stamp", "len", "@payload"]},
  "length": {"field": "len", "counts": "frame"},
  "counter": {"field": "seq", "max_gap": 1, "timeout_ms": 5}
}"#;

/// A CRC field WIDER than the CRC: 16 bits in a 3-byte field.
const DEMO_E: &str = r#"{
  "name": "demo-e",
  "fields": [
    {"name": "hdr", "bytes": 1},
    {"name": "crc", "bytes": 3},
    {"name": "seq", "bytes": 2},
    {"name": "len", "bytes": 2}
  ],
  "crc": {"field": "crc", "width": 16, "poly": "0x1021", "init": "0xFFFF",
          "refin": false, "refout": false, "xorout": "0x0000",
          "cover": ["hdr", "seq", "len", "@payload"]},
  "length": {"field": "len", "counts": "frame"},
  "counter": {"field": "seq", "max_gap": 10, "timeout_ms": 100}
}"#;

/// What one field must come to: its name, wire value, logical value, parts.
type FieldGold = (&'static str, u64, u64, &'static [u64]);

/// A golden frame, with the values it was built from.
struct Gold {
    profile: &'static str,
    values: &'static str,
    payload: &'static str,
    frame: &'static str,
    crc: u64,
    length: u64,
    fields: &'static [FieldGold],
}

/// Computed ONCE by an independent model (a script written from the profile
/// description alone: bitwise CRC, big-endian fields, parts OR-ed then XORed,
/// the cover fed in its listed order, the CRC field never fed). The script is
/// not part of the repository; its output is the literals below.
const GOLDS: &[Gold] = &[
    Gold {
        profile: DEMO_A,
        values: r#"{"counter": 258,
                    "ident": {"domain": 3, "version": 7, "msg": 4660},
                    "cell": {"kind": 1, "result": 0, "sender": "0x0ABCDEF"}}"#,
        payload: "deadbeef",
        frame: "c2bf56b4001401020c081d3b41888888deadbeef",
        crc: 0xc2bf_56b4,
        length: 20,
        fields: &[
            ("crc", 3_267_319_476, 3_267_319_476, &[]),
            ("length", 20, 20, &[]),
            ("counter", 258, 258, &[]),
            ("ident", 201_858_363, 50_795_060, &[3, 7, 4660]),
            ("cell", 1_099_466_888, 1_085_001_199, &[1, 0, 11_259_375]),
        ],
    },
    Gold {
        profile: DEMO_B,
        values: r#"{"counter": 4000000000,
                    "ident": {"sys": 9, "rev": 2, "id": 513},
                    "cell": "0x00C0FFEE"}"#,
        payload: "00112233445566778899",
        frame: "0000001eee6b280009020201a5655a4baf4f923dd5d1703400112233445566778899",
        crc: 0xaf4f_923d_d5d1_7034,
        length: 30,
        fields: &[
            ("length", 30, 30, &[]),
            ("counter", 4_000_000_000, 4_000_000_000, &[]),
            ("ident", 151_126_529, 151_126_529, &[9, 2, 513]),
            ("cell", 2_774_882_891, 12_648_430, &[]),
            (
                "crc",
                12_632_476_274_075_463_732,
                12_632_476_274_075_463_732,
                &[],
            ),
        ],
    },
    Gold {
        profile: DEMO_C,
        values: r#"{"kind": 77, "seq": 250,
                    "tag": {"hi": "0xFEDCBA", "lo": "0x12345678"}}"#,
        payload: "7a",
        frame: "4d6bc3fa00000fffdeb91631507f7a",
        crc: 0x6bc3,
        length: 15,
        fields: &[
            ("kind", 77, 77, &[]),
            ("crc", 27_587, 27_587, &[]),
            ("seq", 250, 250, &[]),
            ("len", 15, 15, &[]),
            (
                "tag",
                72_021_005_583_863_935,
                71_737_335_811_954_296,
                &[16_702_650, 305_419_896],
            ),
        ],
    },
    Gold {
        profile: DEMO_D,
        values: r#"{"seq": 0, "stamp": {"top": 171, "mid": "0x89ABCDEF", "low": 66}}"#,
        payload: "68656c6c6f",
        frame: "9f10005476543210ffffbd68656c6c6f",
        crc: 0x9f,
        length: 16,
        fields: &[
            ("crc", 159, 159, &[]),
            ("len", 16, 16, &[]),
            ("seq", 0, 0, &[]),
            (
                "stamp",
                6_086_144_520_448_114_621,
                12_360_599_553_261_436_994,
                &[171, 2_309_737_967, 66],
            ),
        ],
    },
    Gold {
        profile: DEMO_E,
        values: r#"{"hdr": 1, "seq": 65535}"#,
        payload: "010203",
        frame: "0100f80dffff000b010203",
        crc: 0xf80d,
        length: 11,
        fields: &[
            ("hdr", 1, 1, &[]),
            ("crc", 63_501, 63_501, &[]),
            ("seq", 65_535, 65_535, &[]),
            ("len", 11, 11, &[]),
        ],
    },
];

fn profile_of(text: &str) -> Profile {
    Profile::parse(text).unwrap_or_else(|e| panic!("a valid profile was refused: {e}\n{text}"))
}

fn values_of(text: &str) -> Values {
    Values::parse(text).unwrap_or_else(|e| panic!("valid values were refused: {e}\n{text}"))
}

/// Compare a report's fields against the golden table, by name.
fn assert_fields(profile: &Profile, got: &[crate::e2e_frame::FieldReport], want: &[FieldGold]) {
    assert_eq!(got.len(), want.len(), "the number of fields");
    for (report, (name, raw, value, parts)) in got.iter().zip(want) {
        assert_eq!(profile.fields()[report.index].name, *name);
        assert_eq!(report.raw, *raw, "{name}: wire value");
        assert_eq!(report.value, *value, "{name}: logical value");
        assert_eq!(report.parts, *parts, "{name}: parts");
    }
}

#[test]
fn golden_frames_build_to_the_independent_models_bytes_and_open_back() {
    for gold in GOLDS {
        let profile = profile_of(gold.profile);
        let payload = unhex(gold.payload);
        let built = build(&profile, &values_of(gold.values), &payload).expect("builds");
        assert_eq!(
            hex(&built.bytes),
            gold.frame,
            "{}: the frame",
            profile.name()
        );
        assert_eq!(built.crc, gold.crc, "{}: the CRC", profile.name());
        assert_eq!(built.length, gold.length, "{}: the length", profile.name());
        assert_eq!(built.payload_offset, profile.header_bytes());
        assert_eq!(built.payload_bytes, payload.len());
        assert_fields(&profile, &built.fields, gold.fields);

        let opened = open(&profile, &unhex(gold.frame)).expect("opens");
        assert!(opened.crc_ok, "{}: the golden CRC verifies", profile.name());
        assert_eq!(opened.crc_found, gold.crc);
        assert_eq!(opened.crc_computed, gold.crc);
        assert!(opened.length_matches_frame, "{}", profile.name());
        assert_eq!(opened.length_found, gold.length);
        assert_eq!(opened.length_expected, gold.length);
        assert_eq!(opened.payload_offset, profile.header_bytes());
        assert_eq!(opened.payload_bytes, payload.len());
        assert_fields(&profile, &opened.fields, gold.fields);
    }
}

// -------------------------------------------------------------- round trips

/// A small deterministic generator, so the random frames repeat.
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

fn random_values(profile: &Profile, rng: &mut Xorshift) -> Values {
    let mut values = Values::new();
    for (index, field) in profile.fields().iter().enumerate() {
        if index == profile.crc().field || index == profile.length().field {
            continue;
        }
        if field.parts.is_empty() {
            values = values.whole(&field.name, rng.next() & field.max_value());
        } else {
            let parts: Vec<(&str, u64)> = field
                .parts
                .iter()
                .map(|p| (p.name.as_str(), rng.next() & p.max_value()))
                .collect();
            values = values.parts(&field.name, &parts);
        }
    }
    values
}

#[test]
fn random_values_survive_a_build_and_an_open_under_every_synthetic_profile() {
    let mut rng = Xorshift(0xD1B5_4A32_D192_ED03);
    for gold in GOLDS {
        let profile = profile_of(gold.profile);
        for round in 0..60 {
            let len = (rng.next() % 41) as usize;
            let payload: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            let values = random_values(&profile, &mut rng);
            let built = build(&profile, &values, &payload).expect("builds");
            let opened = open(&profile, &built.bytes).expect("opens");
            let what = format!("{} round {round}", profile.name());
            assert_eq!(opened.fields, built.fields, "{what}: every field survives");
            assert!(opened.crc_ok, "{what}");
            assert_eq!(opened.crc_computed, built.crc, "{what}");
            assert!(opened.length_matches_frame, "{what}");
            assert_eq!(opened.length_found, built.length, "{what}");
            assert_eq!(opened.payload_offset, built.payload_offset, "{what}");
            assert_eq!(
                &built.bytes[opened.payload_offset..],
                payload.as_slice(),
                "{what}: the body is untouched"
            );
        }
    }
}

// ------------------------------------------------- what open reports, apart

/// Rebuild the golden frame of `DEMO_A` as bytes to damage.
fn demo_a_frame() -> (Profile, Vec<u8>) {
    let gold = &GOLDS[0];
    (profile_of(gold.profile), unhex(gold.frame))
}

#[test]
fn a_damaged_body_is_a_crc_failure_and_says_nothing_about_the_length() {
    let (profile, mut frame) = demo_a_frame();
    let last = frame.len() - 1;
    frame[last] ^= 0x01;
    let opened = open(&profile, &frame).expect("opens");
    assert!(!opened.crc_ok);
    assert_ne!(opened.crc_computed, opened.crc_found);
    assert!(
        opened.length_matches_frame,
        "the length is not what was damaged"
    );
}

#[test]
fn a_length_that_means_something_else_is_told_apart_from_a_damaged_frame() {
    // The sender counts the frame minus one field; the receiver's profile
    // counts the whole frame. Nothing was damaged on the wire.
    let sender = profile_of(&DEMO_A.replace(
        r#""length": {"field": "length", "counts": "frame"}"#,
        r#""length": {"field": "length", "counts": "frame_minus", "fields": ["cell"]}"#,
    ));
    let receiver = profile_of(DEMO_A);
    let gold = &GOLDS[0];
    let built = build(&sender, &values_of(gold.values), &unhex(gold.payload)).expect("builds");
    assert_eq!(built.length, 16, "20 less the 4-byte cell");

    let own = open(&sender, &built.bytes).expect("opens");
    assert!(
        own.crc_ok && own.length_matches_frame,
        "read by its own profile it is clean"
    );

    // The CRC is taken over the length field AS RECEIVED, so another profile's
    // counting rule cannot make a clean frame fail it: the difference shows in
    // the length facts alone.
    let other = open(&receiver, &built.bytes).expect("opens");
    assert!(
        other.crc_ok,
        "the CRC verifies over the length the sender wrote"
    );
    assert!(!other.length_matches_frame);
    assert_eq!(other.length_found, 16);
    assert_eq!(other.length_expected, 20);
    assert_eq!(other.crc_computed, own.crc_computed);
    assert_eq!(
        other.fields, own.fields,
        "the fields read the same either way"
    );

    // Damage is the other way round: the CRC fails and, when the length field
    // was not what was hit, the length facts stay clean. The pair of facts is
    // what tells "the sender counts differently" from "bytes were damaged".
    let mut damaged = built.bytes.clone();
    let last = damaged.len() - 1;
    damaged[last] ^= 0x01;
    let hit = open(&sender, &damaged).expect("opens");
    assert!(!hit.crc_ok && hit.length_matches_frame);
}

#[test]
fn a_wrong_length_field_alone_is_a_crc_failure_and_a_length_mismatch() {
    let (profile, mut frame) = demo_a_frame();
    // The length field is the two bytes after the 4-byte CRC.
    frame[5] ^= 0x04;
    let opened = open(&profile, &frame).expect("opens");
    assert!(!opened.crc_ok, "the length is covered");
    assert!(!opened.length_matches_frame);
    assert_eq!(opened.length_found, 16);
    assert_eq!(opened.length_expected, 20);
}

#[test]
fn the_body_is_what_follows_the_header_whatever_the_length_field_says() {
    let (profile, mut frame) = demo_a_frame();
    frame.extend_from_slice(&[0xAA, 0xBB]);
    let opened = open(&profile, &frame).expect("opens");
    assert_eq!(
        opened.payload_bytes, 6,
        "extent comes from the frame, not the field"
    );
    assert_eq!(opened.length_found, 20);
    assert_eq!(opened.length_expected, 22);
    assert!(!opened.length_matches_frame);
    assert!(!opened.crc_ok, "the CRC covers the body as received");
}

#[test]
fn a_frame_shorter_than_the_header_is_the_one_refusal() {
    let (profile, frame) = demo_a_frame();
    assert_eq!(profile.header_bytes(), 16);
    for len in [0usize, 1, 15] {
        assert_eq!(
            open(&profile, &frame[..len]).expect_err("short"),
            OpenError::ShortFrame {
                have: len,
                need: 16
            }
        );
    }
    let exact = open(&profile, &frame[..16]).expect("a header and an empty body opens");
    assert_eq!(exact.payload_bytes, 0);
    assert!(!exact.crc_ok, "its CRC was computed over a four-byte body");
}

#[test]
fn the_crc_field_is_never_part_of_what_is_fed() {
    // Replacing the CRC field with anything leaves the computed value alone, so
    // a frame whose CRC is wrong can still be told what the right one is.
    let (profile, frame) = demo_a_frame();
    let clean = open(&profile, &frame).expect("opens");
    for fill in [0x00u8, 0xFF, 0x5A] {
        let mut damaged = frame.clone();
        damaged[..4].fill(fill);
        let opened = open(&profile, &damaged).expect("opens");
        assert_eq!(opened.crc_computed, clean.crc_computed, "fill {fill:#x}");
        assert_eq!(opened.crc_found, u64::from(u32::from_be_bytes([fill; 4])));
        assert!(!opened.crc_ok);
    }
}

#[test]
fn a_crc_field_wider_than_the_crc_is_zero_extended_and_compared_whole() {
    let gold = &GOLDS[4];
    let profile = profile_of(gold.profile);
    let frame = unhex(gold.frame);
    assert_eq!(&frame[1..4], &[0x00, 0xF8, 0x0D], "zero in the high byte");
    assert!(open(&profile, &frame).expect("opens").crc_ok);
    let mut damaged = frame;
    damaged[1] = 0x01;
    let opened = open(&profile, &damaged).expect("opens");
    assert!(!opened.crc_ok, "a stray high byte is a mismatch");
    assert_eq!(
        opened.crc_computed, 0xF80D,
        "the low 16 bits are still right"
    );
}

#[test]
fn the_order_of_the_cover_is_part_of_the_answer() {
    let swapped = profile_of(&DEMO_A.replace(
        r#""cover": ["length", "ident", "@payload", "cell", "counter"]"#,
        r#""cover": ["length", "ident", "cell", "@payload", "counter"]"#,
    ));
    let gold = &GOLDS[0];
    let built = build(&swapped, &values_of(gold.values), &unhex(gold.payload)).expect("builds");
    assert_ne!(
        built.crc, gold.crc,
        "feeding the cell before the body is a different CRC"
    );
    // Frames built either way verify only under their own profile.
    let own = open(&swapped, &built.bytes).expect("opens");
    let wire_order = open(&profile_of(DEMO_A), &built.bytes).expect("opens");
    assert!(own.crc_ok);
    assert!(!wire_order.crc_ok);
}

#[test]
fn a_profile_builds_the_judge_its_counter_rules_describe() {
    // A 1-byte counter, a gap of 3 and a silence of 50 ms.
    let profile = profile_of(&DEMO_A.replace(
        r#""counter": {"field": "counter", "max_gap": 10, "timeout_ms": 1000}"#,
        r#""counter": {"field": "counter", "max_gap": 3, "timeout_ms": 50}"#,
    ));
    let mut judge = profile.judge();
    let feed = |judge: &mut Judge, counter: u64, now: u64| {
        judge.receive(true, counter, now).expect("fits two bytes")
    };
    assert!(!feed(&mut judge, 0xFFFE, 0).counter_error);
    assert!(
        !feed(&mut judge, 0x0001, 10).counter_error,
        "a step of 3 across the wrap"
    );
    assert_eq!(
        feed(&mut judge, 0x0005, 20).counter_reason,
        CounterReason::OutOfRange
    );
    assert!(judge.poll(20 + 51).timeout_error);
    assert!(!judge.poll(20 + 50).timeout_error);
}

#[test]
fn the_judge_reads_the_counter_an_open_frame_carries() {
    let profile = profile_of(DEMO_A);
    let gold = &GOLDS[0];
    let mut judge = profile.judge();
    let mut now = 0u64;
    let mut send = |counter: u64, damage: bool, judge: &mut Judge| {
        let values = values_of(&gold.values.replace("258", &counter.to_string()));
        let mut frame = build(&profile, &values, &unhex(gold.payload))
            .expect("builds")
            .bytes;
        if damage {
            frame[16] ^= 1;
        }
        let opened = open(&profile, &frame).expect("opens");
        assert_eq!(opened.counter(&profile), counter);
        now += 100;
        judge
            .receive(opened.crc_ok, opened.counter(&profile), now)
            .expect("the counter fits")
    };
    assert!(
        !send(7, false, &mut judge).counter_error,
        "the first frame sets the baseline"
    );
    let skipped = send(12, false, &mut judge);
    assert!(
        !skipped.counter_error,
        "a step of five is inside the gap of ten"
    );
    let repeat = send(12, false, &mut judge);
    assert_eq!(repeat.counter_reason, CounterReason::Repeat);
    let damaged = send(13, true, &mut judge);
    assert!(damaged.crc_error && !damaged.counter_error);
    let jumped = send(500, false, &mut judge);
    assert_eq!(jumped.counter_reason, CounterReason::OutOfRange);
}

// -------------------------------------------------------- profile refusals

const FIELDS: &str = r#"[
    {"name": "crc", "bytes": 4},
    {"name": "len", "bytes": 2},
    {"name": "seq", "bytes": 2},
    {"name": "id", "bytes": 2, "xor": "0xFF",
     "split": [{"name": "hi", "lsb": 8, "width": 8}, {"name": "lo", "lsb": 0, "width": 8}]}
]"#;
const CRC: &str = r#"{"field": "crc", "width": 32, "poly": "0xF4ACFB13", "init": "0xFFFFFFFF",
    "refin": true, "refout": true, "xorout": "0xFFFFFFFF",
    "cover": ["len", "id", "@payload", "seq"]}"#;
const LENGTH: &str = r#"{"field": "len", "counts": "frame"}"#;
const COUNTER: &str = r#"{"field": "seq", "max_gap": 10, "timeout_ms": 1000}"#;

/// The keys of the CRC description with their values, so one can be left out.
const CRC_KEYS: [(&str, &str); 8] = [
    ("field", r#""crc""#),
    ("width", "32"),
    ("poly", r#""0xF4ACFB13""#),
    ("init", r#""0xFFFFFFFF""#),
    ("refin", "true"),
    ("refout", "true"),
    ("xorout", r#""0xFFFFFFFF""#),
    ("cover", r#"["len", "id", "@payload", "seq"]"#),
];

/// The CRC description built from [`CRC_KEYS`], without `skip`.
fn crc_without(skip: Option<&str>) -> String {
    let members: Vec<String> = CRC_KEYS
        .iter()
        .filter(|(key, _)| Some(*key) != skip)
        .map(|(key, value)| format!("\"{key}\": {value}"))
        .collect();
    format!("{{{}}}", members.join(", "))
}

fn doc(fields: &str, crc: &str, length: &str, counter: &str) -> String {
    format!(
        r#"{{"name": "p", "fields": {fields}, "crc": {crc}, "length": {length}, "counter": {counter}}}"#
    )
}

/// `piece` with its one occurrence of `from` replaced. The occurrence is
/// asserted, so a typo in a test cannot turn a refusal test into a vacuous one.
fn swap(piece: &str, from: &str, to: &str) -> String {
    assert_eq!(
        piece.matches(from).count(),
        1,
        "`{from}` must occur once in the piece"
    );
    piece.replace(from, to)
}

fn base() -> String {
    doc(FIELDS, CRC, LENGTH, COUNTER)
}

#[test]
fn the_base_profile_is_valid() {
    let profile = profile_of(&base());
    assert_eq!(profile.header_bytes(), 10);
    assert_eq!(profile.name(), "p");
}

/// The refusal for `text`: it must be an `Invalid` at `path` whose reason
/// contains `reason`.
fn assert_refused(text: &str, path: &str, reason: &str) {
    match Profile::parse(text) {
        Ok(_) => panic!("accepted, expected a refusal at `{path}` saying `{reason}`:\n{text}"),
        Err(DocError::Invalid {
            path: got,
            reason: why,
        }) => {
            assert_eq!(got, path, "the place: {why}");
            assert!(why.contains(reason), "expected `{reason}` in `{why}`");
        }
        Err(other) => panic!("expected an Invalid refusal, got {other}"),
    }
}

#[test]
fn a_profile_that_is_not_json_is_refused_with_the_byte_it_stopped_at() {
    let text = base();
    let cut = &text[..text.find("\"crc\":").expect("present")];
    match Profile::parse(cut) {
        Err(DocError::Syntax { offset, .. }) => assert!(offset > 0 && offset <= cut.len()),
        other => panic!("expected a Syntax refusal, got {other:?}"),
    }
}

#[test]
fn the_shape_of_the_document_is_checked_before_its_content() {
    assert_refused("[]", "", "expected an object");
    assert_refused("7", "", "expected an object");
    assert_refused(
        &swap(&base(), r#""name": "p", "#, ""),
        "",
        "`name` is required",
    );
    assert_refused(
        &swap(&base(), r#""fields": "#, r#""extra": 1, "fields": "#),
        "/extra",
        "unknown key `extra`",
    );
    assert_refused(
        &doc(
            &swap(FIELDS, r#""bytes": 4}"#, r#""bytes": 4, "endian": "le"}"#),
            CRC,
            LENGTH,
            COUNTER,
        ),
        "/fields/0/endian",
        "unknown key",
    );
    assert_refused(
        &doc(
            &swap(
                FIELDS,
                r#"{"name": "crc", "bytes": 4}"#,
                r#"{"name": "crc", "name": "crc", "bytes": 4}"#,
            ),
            CRC,
            LENGTH,
            COUNTER,
        ),
        "/fields/0/name",
        "appears twice",
    );
    assert_refused(
        &doc(
            FIELDS,
            &swap(CRC, r#""width": 32"#, r#""width": "wide""#),
            LENGTH,
            COUNTER,
        ),
        "/crc/width",
        "is not an unsigned integer",
    );
    assert_refused(
        &doc("{}", CRC, LENGTH, COUNTER),
        "/fields",
        "expected an array",
    );
    assert_refused(
        &doc(FIELDS, "[]", LENGTH, COUNTER),
        "/crc",
        "expected an object",
    );
}

#[test]
fn nesting_past_the_bound_is_refused_before_the_reader_can_recurse_on_it() {
    // Far deeper than any stack could take, if the reader were let in: the
    // refusal comes at the byte that opens the first level past the bound.
    for open in ["[", "{\"a\":"] {
        let text = open.repeat(200_000);
        let want = DocError::Syntax {
            offset: MAX_JSON_DEPTH * open.len(),
            expected: "a shallower value",
        };
        assert_eq!(Profile::parse(&text).expect_err("refused"), want, "{open}");
        assert_eq!(Values::parse(&text).expect_err("refused"), want, "{open}");
    }
    // At the bound the text is JSON; it is simply not a profile.
    let at_bound = format!(
        "{}{}",
        "[".repeat(MAX_JSON_DEPTH),
        "]".repeat(MAX_JSON_DEPTH)
    );
    assert!(matches!(
        Profile::parse(&at_bound),
        Err(DocError::Invalid { .. })
    ));
    // Through the door the same refusal is a diagnosis with a byte offset.
    let doc = open_document(&"[".repeat(200_000), &[]);
    assert!(doc.contains("\"profile_offset\":8,"), "{doc}");
    assert!(doc.contains("expected a shallower value"), "{doc}");
}

#[test]
fn a_comment_in_the_profile_text_is_read_as_the_workspace_reader_reads_it() {
    // Documented: the text goes through the workspace's one JSON reader, so
    // what it admits is admitted; the document is then checked strictly.
    let text = swap(&base(), r#""name": "p","#, "// a note\n \"name\": \"p\",");
    assert!(Profile::parse(&text).is_ok());
}

#[test]
fn integers_are_checked_for_what_they_are() {
    for (bytes, reason) in [
        ("0", "1 to 8 bytes"),
        ("9", "1 to 8 bytes"),
        ("4.5", "not a plain unsigned decimal number"),
        ("-1", "not a plain unsigned decimal number"),
        ("007", "not a plain unsigned decimal number"),
        ("0x4", "not a plain unsigned decimal number"),
        ("\"0x\"", "not hexadecimal digits"),
        ("\"4 \"", "not an unsigned integer"),
        ("\"0x1FFFFFFFFFFFFFFFF\"", "does not fit in 64 bits"),
        ("true", "found a boolean"),
        ("null", "found null"),
    ] {
        let fields = swap(
            FIELDS,
            r#"{"name": "crc", "bytes": 4}"#,
            &format!(r#"{{"name": "crc", "bytes": {bytes}}}"#),
        );
        assert_refused(
            &doc(&fields, CRC, LENGTH, COUNTER),
            "/fields/0/bytes",
            reason,
        );
    }
    // The same widths spelled as strings are fine, which is the point of them.
    for spelled in ["\"4\"", "\"0x4\"", "\"0X4\""] {
        let fields = swap(
            FIELDS,
            r#"{"name": "crc", "bytes": 4}"#,
            &format!(r#"{{"name": "crc", "bytes": {spelled}}}"#),
        );
        assert!(
            Profile::parse(&doc(&fields, CRC, LENGTH, COUNTER)).is_ok(),
            "{spelled}"
        );
    }
}

#[test]
fn names_are_plain_and_bounded() {
    for (name, reason) in [
        ("", "cannot be empty"),
        ("a b", "has the character ' '"),
        ("a/b", "has the character '/'"),
        ("@payload", "has the character '@'"),
        ("é", "has the character 'é'"),
    ] {
        let fields = swap(FIELDS, r#""name": "len""#, &format!(r#""name": "{name}""#));
        assert_refused(
            &doc(&fields, CRC, LENGTH, COUNTER),
            "/fields/1/name",
            reason,
        );
    }
    let long = "n".repeat(65);
    let fields = swap(FIELDS, r#""name": "len""#, &format!(r#""name": "{long}""#));
    assert_refused(
        &doc(&fields, CRC, LENGTH, COUNTER),
        "/fields/1/name",
        "at most 64 bytes",
    );
    let fields = swap(FIELDS, r#""name": "len""#, r#""name": "seq""#);
    assert_refused(
        &doc(&fields, CRC, LENGTH, COUNTER),
        "/fields/2/name",
        "two fields are called `seq`",
    );
}

#[test]
fn the_number_of_fields_is_bounded() {
    assert_refused(
        &doc("[]", CRC, LENGTH, COUNTER),
        "/fields",
        "1 to 32 fields, this one has 0",
    );
    let many: Vec<String> = (0..33)
        .map(|i| format!(r#"{{"name": "f{i}", "bytes": 1}}"#))
        .collect();
    assert_refused(
        &doc(&format!("[{}]", many.join(",")), CRC, LENGTH, COUNTER),
        "/fields",
        "1 to 32 fields, this one has 33",
    );
}

#[test]
fn xor_and_split_must_fit_their_field_and_not_overlap() {
    // The field `id` is 2 bytes: 16 bits.
    for (xor, ok) in [("0xFFFF", true), ("0x10000", false)] {
        let fields = swap(FIELDS, r#""xor": "0xFF""#, &format!(r#""xor": "{xor}""#));
        let text = doc(&fields, CRC, LENGTH, COUNTER);
        if ok {
            assert!(Profile::parse(&text).is_ok(), "{xor}");
        } else {
            assert_refused(&text, "/fields/3/xor", "does not fit the field's 16 bits");
        }
    }
    let split = |parts: &str| {
        let fields = swap(
            FIELDS,
            r#""split": [{"name": "hi", "lsb": 8, "width": 8}, {"name": "lo", "lsb": 0, "width": 8}]"#,
            &format!(r#""split": {parts}"#),
        );
        doc(&fields, CRC, LENGTH, COUNTER)
    };
    assert_refused(
        &split(r#"[{"name": "a", "lsb": 4, "width": 8}, {"name": "b", "lsb": 0, "width": 8}]"#),
        "/fields/3/split/1",
        "overlaps an earlier part",
    );
    assert_refused(
        &split(r#"[{"name": "a", "lsb": 9, "width": 8}]"#),
        "/fields/3/split/0",
        "does not fit the field's 16 bits",
    );
    assert_refused(
        &split(r#"[{"name": "a", "lsb": 16, "width": 1}]"#),
        "/fields/3/split/0",
        "does not fit the field's 16 bits",
    );
    assert_refused(
        &split(r#"[{"name": "a", "lsb": 0, "width": 0}]"#),
        "/fields/3/split/0/width",
        "at least 1 bit",
    );
    assert_refused(
        &split(r#"[{"name": "a", "lsb": 0, "width": 4}, {"name": "a", "lsb": 8, "width": 4}]"#),
        "/fields/3/split/1/name",
        "two parts of one field are called `a`",
    );
    assert_refused(&split("[]"), "/fields/3/split", "1 to 64 parts");
    // The control: a split that stops exactly at the top of the field is fine.
    assert!(Profile::parse(&split(r#"[{"name": "a", "lsb": 8, "width": 8}]"#)).is_ok());
    assert!(Profile::parse(&split(r#"[{"name": "a", "lsb": 0, "width": 16}]"#)).is_ok());
}

#[test]
fn the_crc_description_is_validated_whole() {
    let crc = |from: &str, to: &str| doc(FIELDS, &swap(CRC, from, to), LENGTH, COUNTER);
    assert_refused(
        &crc(r#""width": 32"#, r#""width": 12"#),
        "/crc/width",
        "not supported",
    );
    assert_refused(
        &crc(r#""width": 32"#, r#""width": 24"#),
        "/crc/width",
        "not supported",
    );
    assert_refused(
        &crc(r#""width": 32"#, r#""width": 0"#),
        "/crc/width",
        "not supported",
    );
    assert_refused(
        &crc(r#""width": 32"#, r#""width": 300"#),
        "/crc/width",
        "not supported",
    );
    // 16 fits the 4-byte field; 8 does, with a poly that does not fit 8 bits.
    assert_refused(
        &crc(
            r#""width": 32, "poly": "0xF4ACFB13""#,
            r#""width": 8, "poly": "0x12F""#,
        ),
        "/crc/poly",
        "does not fit the 8-bit width",
    );
    assert_refused(
        &crc(r#""init": "0xFFFFFFFF""#, r#""init": "0x1FFFFFFFF""#),
        "/crc/init",
        "does not fit the 32-bit width",
    );
    assert_refused(
        &crc(r#""xorout": "0xFFFFFFFF""#, r#""xorout": "0x1FFFFFFFF""#),
        "/crc/xorout",
        "does not fit the 32-bit width",
    );
    // Every key of the description is required: none has a default, because a
    // default for `refin` or `xorout` would be a silent choice of algorithm.
    assert!(Profile::parse(&doc(FIELDS, &crc_without(None), LENGTH, COUNTER)).is_ok());
    for key in CRC_KEYS.map(|(k, _)| k) {
        assert_refused(
            &doc(FIELDS, &crc_without(Some(key)), LENGTH, COUNTER),
            "/crc",
            &format!("`{key}` is required"),
        );
    }
    assert_refused(
        &crc(r#""refin": true"#, r#""refin": "yes""#),
        "/crc/refin",
        "expected true or false",
    );
    // A CRC field narrower than the CRC.
    let narrow = swap(
        FIELDS,
        r#"{"name": "crc", "bytes": 4}"#,
        r#"{"name": "crc", "bytes": 3}"#,
    );
    assert_refused(
        &doc(&narrow, CRC, LENGTH, COUNTER),
        "/crc/field",
        "24 bits wide, narrower than the 32-bit CRC",
    );
    // The CRC field carries nothing but the CRC.
    let xored = swap(
        FIELDS,
        r#"{"name": "crc", "bytes": 4}"#,
        r#"{"name": "crc", "bytes": 4, "xor": "0x1"}"#,
    );
    assert_refused(
        &doc(&xored, CRC, LENGTH, COUNTER),
        "/crc/field",
        "carries an xor or a split",
    );
    assert_refused(
        &crc(r#""field": "crc""#, r#""field": "nope""#),
        "/crc/field",
        "no field is called `nope`",
    );
}

#[test]
fn the_cover_names_real_fields_once_and_never_the_crc() {
    let cover = |list: &str| {
        doc(
            FIELDS,
            &swap(CRC, r#"["len", "id", "@payload", "seq"]"#, list),
            LENGTH,
            COUNTER,
        )
    };
    assert_refused(
        &cover(r#"["len", "nope"]"#),
        "/crc/cover/1",
        "no field is called `nope`",
    );
    assert_refused(&cover(r#"["len", "crc"]"#), "/crc/cover/1", "never covered");
    assert_refused(&cover(r#"["len", "len"]"#), "/crc/cover/1", "covered twice");
    assert_refused(
        &cover(r#"["@payload", "@payload"]"#),
        "/crc/cover/1",
        "covered twice",
    );
    assert_refused(&cover(r#"[]"#), "/crc/cover", "take no input");
    assert_refused(&cover(r#"[1]"#), "/crc/cover/0", "expected a string");
    assert_refused(&cover(r#""len""#), "/crc/cover", "expected an array");
    // A cover without the body is a legal, if odd, description.
    assert!(Profile::parse(&cover(r#"["len"]"#)).is_ok());
}

#[test]
fn the_length_rule_is_validated() {
    let length = |text: &str| doc(FIELDS, CRC, text, COUNTER);
    assert_refused(
        &length(r#"{"field": "len", "counts": "payload"}"#),
        "/length/counts",
        "not a length rule",
    );
    assert_refused(
        &length(r#"{"field": "len", "counts": "frame_minus"}"#),
        "/length",
        "`frame_minus` needs `fields`",
    );
    assert_refused(
        &length(r#"{"field": "len", "counts": "frame", "fields": ["seq"]}"#),
        "/length/fields",
        "belongs to `frame_minus`",
    );
    assert_refused(
        &length(r#"{"field": "len", "counts": "frame_minus", "fields": []}"#),
        "/length/fields",
        "the list is empty",
    );
    assert_refused(
        &length(r#"{"field": "len", "counts": "frame_minus", "fields": ["seq", "seq"]}"#),
        "/length/fields/1",
        "listed twice",
    );
    assert_refused(
        &length(r#"{"field": "len", "counts": "frame_minus", "fields": ["nope"]}"#),
        "/length/fields/0",
        "no field is called `nope`",
    );
    assert_refused(
        &length(r#"{"field": "id", "counts": "frame"}"#),
        "/length/field",
        "carries an xor or a split",
    );
    assert_refused(
        &length(r#"{"field": "crc", "counts": "frame"}"#),
        "",
        "the crc and length are the same field",
    );
    assert_refused(
        &length(r#"{"field": "len", "counts": "frame", "unit": "bits"}"#),
        "/length/unit",
        "unknown key",
    );
}

#[test]
fn the_counter_rule_is_validated() {
    let counter = |text: &str| doc(FIELDS, CRC, LENGTH, text);
    assert_refused(
        &counter(r#"{"field": "seq", "max_gap": 0, "timeout_ms": 1000}"#),
        "/counter/max_gap",
        "max_gap is 1 to 65535",
    );
    assert_refused(
        &counter(r#"{"field": "seq", "max_gap": 65536, "timeout_ms": 1000}"#),
        "/counter/max_gap",
        "max_gap is 1 to 65535",
    );
    assert!(
        Profile::parse(&counter(
            r#"{"field": "seq", "max_gap": 65535, "timeout_ms": 1000}"#
        ))
        .is_ok(),
        "the largest step a 2-byte counter can take is allowed"
    );
    assert_refused(
        &counter(r#"{"field": "seq", "max_gap": 10, "timeout_ms": 0}"#),
        "/counter/timeout_ms",
        "at least 1",
    );
    assert_refused(
        &counter(r#"{"field": "len", "max_gap": 10, "timeout_ms": 1}"#),
        "",
        "the length and counter are the same field",
    );
    assert_refused(
        &counter(r#"{"field": "id", "max_gap": 10, "timeout_ms": 1}"#),
        "/counter/field",
        "carries an xor or a split",
    );
    assert_refused(
        &counter(r#"{"field": "crc", "max_gap": 10, "timeout_ms": 1}"#),
        "",
        "the crc and counter are the same field",
    );
    assert_refused(
        &counter(r#"{"field": "seq", "max_gap": 10}"#),
        "/counter",
        "`timeout_ms` is required",
    );
}

// ---------------------------------------------------------- build refusals

fn demo_a_values(edit: impl Fn(&str) -> String) -> String {
    edit(GOLDS[0].values)
}

fn assert_build_refused(values: &str, path: &str, reason: &str) {
    let profile = profile_of(DEMO_A);
    let values = match Values::parse(values) {
        Ok(v) => v,
        Err(e) => panic!("the values text must parse, the refusal is the build's: {e}"),
    };
    match build(&profile, &values, &[1, 2, 3]) {
        Ok(_) => panic!("built, expected a refusal at `{path}` saying `{reason}`"),
        Err(BuildError::Values(DocError::Invalid {
            path: got,
            reason: why,
        })) => {
            assert_eq!(got, path, "the place: {why}");
            assert!(why.contains(reason), "expected `{reason}` in `{why}`");
        }
        Err(other) => panic!("expected a values refusal, got {other}"),
    }
}

#[test]
fn a_value_that_does_not_fit_is_refused_never_truncated() {
    let edit = |from: &str, to: &str| demo_a_values(|v| swap(v, from, to));
    // The 8-bit part `domain`: 255 fits, 256 does not.
    assert!(build(
        &profile_of(DEMO_A),
        &values_of(&edit("\"domain\": 3", "\"domain\": 255")),
        &[]
    )
    .is_ok());
    assert_build_refused(
        &edit("\"domain\": 3", "\"domain\": 256"),
        "/ident/domain",
        "does not fit the 8-bit part `domain`",
    );
    assert_build_refused(
        &edit("\"msg\": 4660", "\"msg\": 65536"),
        "/ident/msg",
        "does not fit the 16-bit part `msg`",
    );
    assert_build_refused(
        &edit("\"sender\": \"0x0ABCDEF\"", "\"sender\": \"0x10000000\""),
        "/cell/sender",
        "does not fit the 28-bit part `sender`",
    );
    assert_build_refused(
        &edit("\"kind\": 1", "\"kind\": 4"),
        "/cell/kind",
        "does not fit the 2-bit part `kind`",
    );
    assert_build_refused(
        &edit("\"counter\": 258", "\"counter\": 65536"),
        "/counter",
        "does not fit the 2-byte field `counter`",
    );
}

#[test]
fn values_are_checked_against_the_profile_they_are_for() {
    let edit = |from: &str, to: &str| demo_a_values(|v| swap(v, from, to));
    assert_build_refused(
        &edit("\"counter\": 258,", "\"counter\": 258, \"extra\": 1,"),
        "/extra",
        "no field is called `extra`",
    );
    assert_build_refused(
        &edit("\"counter\": 258,", "\"counter\": 258, \"crc\": 1,"),
        "/crc",
        "the crc field `crc` is computed",
    );
    assert_build_refused(
        &edit("\"counter\": 258,", "\"counter\": 258, \"length\": 20,"),
        "/length",
        "the length field `length` is computed",
    );
    assert_build_refused(
        &edit("\"counter\": 258,", ""),
        "",
        "no value for the field `counter`",
    );
    assert_build_refused(
        &edit("\"counter\": 258", "\"counter\": {\"a\": 1}"),
        "/counter",
        "is not split: supply a number",
    );
    assert_build_refused(
        &edit(
            "\"ident\": {\"domain\": 3, \"version\": 7, \"msg\": 4660}",
            "\"ident\": 5",
        ),
        "/ident",
        "is split into parts: supply an object with domain, version, msg",
    );
    assert_build_refused(
        &edit("\"version\": 7, ", ""),
        "/ident",
        "no value for the part `version` of `ident`",
    );
    assert_build_refused(
        &edit("\"version\": 7", "\"version\": 7, \"rev\": 1"),
        "/ident/rev",
        "has no part called `rev`",
    );
}

#[test]
fn values_text_is_refused_for_what_it_is() {
    for (text, path, reason) in [
        ("[]", "", "expected an object"),
        (r#"{"a": 1, "a": 2}"#, "/a", "appears twice"),
        (r#"{"a": {"b": 1, "b": 2}}"#, "/a/b", "appears twice"),
        (r#"{"a": -1}"#, "/a", "not a plain unsigned decimal number"),
        (r#"{"a": 1.5}"#, "/a", "not a plain unsigned decimal number"),
        (r#"{"a": "x"}"#, "/a", "not an unsigned integer"),
        (r#"{"a": null}"#, "/a", "found null"),
        (r#"{"a": [1]}"#, "/a", "found an array"),
        (r#"{"a": {"b": {"c": 1}}}"#, "/a/b", "found an object"),
        (
            r#"{"a": "0x10000000000000000"}"#,
            "/a",
            "does not fit in 64 bits",
        ),
        (
            r#"{"a/b": -1}"#,
            "/a~1b",
            "not a plain unsigned decimal number",
        ),
    ] {
        match Values::parse(text) {
            Err(DocError::Invalid {
                path: got,
                reason: why,
            }) => {
                assert_eq!(got, path, "{text}: {why}");
                assert!(
                    why.contains(reason),
                    "{text}: expected `{reason}` in `{why}`"
                );
            }
            other => panic!("{text}: expected a refusal, got {other:?}"),
        }
    }
    assert!(matches!(
        Values::parse("{\"a\": "),
        Err(DocError::Syntax { .. })
    ));
    assert!(Values::parse(r#"{"a": 18446744073709551615, "b": "0xFFFFFFFFFFFFFFFF"}"#).is_ok());
}

#[test]
fn supplying_a_name_twice_through_the_builder_is_refused() {
    let profile = profile_of(DEMO_A);
    let values = Values::new()
        .whole("counter", 1)
        .whole("counter", 2)
        .parts("ident", &[("domain", 1), ("version", 1), ("msg", 1)])
        .parts("cell", &[("kind", 0), ("result", 0), ("sender", 0)]);
    match build(&profile, &values, &[]) {
        Err(BuildError::Values(DocError::Invalid { path, reason })) => {
            assert_eq!(path, "/counter");
            assert!(reason.contains("supplied twice"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
    let values = Values::new()
        .whole("counter", 1)
        .parts(
            "ident",
            &[("domain", 1), ("version", 1), ("msg", 1), ("msg", 2)],
        )
        .parts("cell", &[("kind", 0), ("result", 0), ("sender", 0)]);
    match build(&profile, &values, &[]) {
        Err(BuildError::Values(DocError::Invalid { path, reason })) => {
            assert_eq!(path, "/ident/msg");
            assert!(reason.contains("supplied twice"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_body_too_long_for_the_length_field_is_refused_with_the_numbers() {
    let profile = profile_of(DEMO_A);
    let values = values_of(GOLDS[0].values);
    // The length is header (16) plus body, in a 2-byte field.
    let fits = alloc::vec![0u8; 65535 - 16];
    let built = build(&profile, &values, &fits).expect("exactly the largest body");
    assert_eq!(built.length, 65535);
    let too_long = alloc::vec![0u8; 65535 - 16 + 1];
    match build(&profile, &values, &too_long) {
        Err(BuildError::PayloadTooLong {
            payload_bytes,
            length,
            field,
            field_bytes,
            max,
        }) => {
            assert_eq!(
                (payload_bytes, length, field.as_str(), field_bytes, max),
                (65520, 65536, "length", 2, 65535)
            );
        }
        other => panic!("{other:?}"),
    }
}

// ----------------------------------------------------------- the documents

// The golden text of revision 1, with the revision number the only change: a
// frame built from bytes is the document it was before the body could be
// described (`e2e_body_tests` holds the other half).
const WRAP_E: &str = concat!(
    r#"{"document":{"name":"e2e_wrap","revision":2},"ok":true,"profile":"demo-e","#,
    r#""frame":"0100f80dffff000b010203","payload_offset":8,"payload_bytes":3,"#,
    r#""fields":[{"name":"hdr","offset":0,"bytes":1,"raw":1,"value":1},"#,
    r#"{"name":"crc","offset":1,"bytes":3,"raw":63501,"value":63501},"#,
    r#"{"name":"seq","offset":4,"bytes":2,"raw":65535,"value":65535},"#,
    r#"{"name":"len","offset":6,"bytes":2,"raw":11,"value":11}],"#,
    r#""crc_computed":63501,"#,
    r#""crc_fed":[{"item":"hdr","bytes":1,"hex":"01"},{"item":"seq","bytes":2,"hex":"ffff"},"#,
    r#"{"item":"len","bytes":2,"hex":"000b"},{"item":"@payload","bytes":3}],"#,
    r#""length_field":11}"#
);

const OPEN_E: &str = concat!(
    r#"{"document":{"name":"e2e_open","revision":1},"ok":true,"profile":"demo-e","#,
    r#""payload_offset":8,"payload_bytes":3,"#,
    r#""fields":[{"name":"hdr","offset":0,"bytes":1,"raw":1,"value":1},"#,
    r#"{"name":"crc","offset":1,"bytes":3,"raw":63501,"value":63501},"#,
    r#"{"name":"seq","offset":4,"bytes":2,"raw":65535,"value":65535},"#,
    r#"{"name":"len","offset":6,"bytes":2,"raw":11,"value":11}],"#,
    r#""crc_ok":true,"crc_computed":63501,"#,
    r#""crc_fed":[{"item":"hdr","bytes":1,"hex":"01"},{"item":"seq","bytes":2,"hex":"ffff"},"#,
    r#"{"item":"len","bytes":2,"hex":"000b"},{"item":"@payload","bytes":3}],"#,
    r#""length_field":11,"length_expected":11,"length_matches_frame":true}"#
);

#[test]
fn the_wrap_document_is_pinned_byte_for_byte_on_a_small_profile() {
    let gold = &GOLDS[4];
    assert_eq!(
        wrap_document(gold.profile, gold.values, &unhex(gold.payload)),
        WRAP_E
    );
}

#[test]
fn the_open_document_is_pinned_byte_for_byte_on_a_small_profile() {
    let gold = &GOLDS[4];
    assert_eq!(open_document(gold.profile, &unhex(gold.frame)), OPEN_E);
}

#[test]
fn what_wrap_writes_open_reads_back_through_the_documents() {
    for gold in GOLDS {
        let wrapped = wrap_document(gold.profile, gold.values, &unhex(gold.payload));
        assert!(
            wrapped.contains(&format!("\"frame\":\"{}\"", gold.frame)),
            "{wrapped}"
        );
        let opened = open_document(gold.profile, &unhex(gold.frame));
        assert!(opened.contains("\"crc_ok\":true"), "{opened}");
        assert!(opened.contains("\"length_matches_frame\":true"), "{opened}");
    }
}

#[test]
fn an_integer_past_2_to_the_53_is_a_decimal_string_and_below_it_a_number() {
    // demo-c's `tag` is 7 bytes and its golden value is past 2^53; its `kind`
    // is a byte. demo-d's `stamp` is 8 bytes.
    let gold = &GOLDS[2];
    let wrapped = wrap_document(gold.profile, gold.values, &unhex(gold.payload));
    assert!(wrapped.contains(r#"{"name":"tag","offset":7,"bytes":7,"raw":"72021005583863935","value":"71737335811954296","parts":[{"name":"hi","value":16702650},{"name":"lo","value":305419896}]}"#), "{wrapped}");
    assert!(
        wrapped.contains(r#"{"name":"kind","offset":0,"bytes":1,"raw":77,"value":77}"#),
        "{wrapped}"
    );
    let gold = &GOLDS[3];
    let opened = open_document(gold.profile, &unhex(gold.frame));
    assert!(
        opened.contains(r#""raw":"6086144520448114621","value":"12360599553261436994""#),
        "{opened}"
    );
    // The CRC-64 of demo-b is past the line too.
    let gold = &GOLDS[1];
    let opened = open_document(gold.profile, &unhex(gold.frame));
    assert!(
        opened.contains(r#""crc_computed":"12632476274075463732""#),
        "{opened}"
    );
}

/// The value of `"key":N` or `"key":"N"` as digits, from the first occurrence.
fn number_after(doc: &str, key: &str) -> String {
    let rest = doc.split_once(&format!("\"{key}\":")).expect("the key").1;
    rest.trim_start_matches('"')
        .chars()
        .take_while(char::is_ascii_digit)
        .collect()
}

#[test]
fn a_profile_refusal_names_the_place_and_the_input_by_the_key_it_carries() {
    // Not JSON: an offset.
    let doc = wrap_document("{\"name\": ", "{}", &[]);
    assert!(
        doc.starts_with(
            r#"{"document":{"name":"e2e_wrap","revision":2},"ok":false,"profile_offset":"#
        ),
        "{doc}"
    );
    assert!(
        doc.contains(r#""reason":"the text is not JSON: expected "#),
        "{doc}"
    );
    assert!(
        !doc.contains("\"profile_path\"") && !doc.contains("\"values_"),
        "{doc}"
    );
    // Not a profile: a path.
    let bad = swap(DEMO_E, r#""bytes": 3"#, r#""bytes": 1"#);
    let doc = wrap_document(&bad, "{}", &[]);
    assert!(
        doc.contains(r#""ok":false,"profile_path":"/crc/field","reason":"#),
        "{doc}"
    );
    assert!(doc.contains(r#""message":"profile /crc/field: "#), "{doc}");
    assert!(!doc.contains("profile_offset"), "{doc}");
    // The same refusal from the other door, with its own revision.
    let doc = open_document(&bad, &[0u8; 16]);
    assert!(
        doc.starts_with(
            r#"{"document":{"name":"e2e_open","revision":1},"ok":false,"profile_path":"/crc/field""#
        ),
        "{doc}"
    );
    // A profile that is not an object: the root is the empty path.
    let doc = open_document("[]", &[]);
    assert!(doc.contains(r#""profile_path":"","reason":"expected an object, found an array","message":"profile: expected an object, found an array""#), "{doc}");
}

#[test]
fn a_values_refusal_is_named_by_values_keys_and_other_refusals_by_none() {
    let gold = &GOLDS[4];
    let doc = wrap_document(gold.profile, "{\"hdr\": ", &[]);
    assert!(doc.contains(r#""ok":false,"values_offset":"#), "{doc}");
    let doc = wrap_document(gold.profile, r#"{"hdr": 1, "seq": 70000}"#, &[]);
    assert!(doc.contains(r#""ok":false,"values_path":"/seq","reason":"70000 does not fit the 2-byte field `seq`","message":"values /seq: 70000 does not fit the 2-byte field `seq`""#), "{doc}");
    assert!(!doc.contains("profile_"), "{doc}");
    // A refusal about neither text.
    let doc = wrap_document(gold.profile, gold.values, &alloc::vec![0u8; 65536]);
    assert!(
        doc.contains(r#""ok":false,"reason":"a body of 65536 bytes makes the length 65544"#),
        "{doc}"
    );
    assert!(!doc.contains("_path") && !doc.contains("_offset"), "{doc}");
    let doc = open_document(gold.profile, &[1, 2, 3]);
    assert!(doc.contains(r#""ok":false,"reason":"the frame is 3 bytes and the header alone is 8","message":"the frame is 3 bytes and the header alone is 8""#), "{doc}");
    assert!(!doc.contains("profile"), "{doc}");
}

#[test]
fn no_document_ever_writes_a_null_and_every_one_opens_with_its_own_revision() {
    let gold = &GOLDS[0];
    let docs = [
        wrap_document(gold.profile, gold.values, &unhex(gold.payload)),
        wrap_document("{", "{}", &[]),
        wrap_document(gold.profile, "{", &[]),
        wrap_document(gold.profile, "{}", &[]),
        open_document(gold.profile, &unhex(gold.frame)),
        open_document("{", &[]),
        open_document(gold.profile, &[]),
    ];
    for doc in docs {
        assert!(!doc.contains("null"), "{doc}");
        assert!(
            doc.starts_with(r#"{"document":{"name":"e2e_wrap","revision":2}"#)
                || doc.starts_with(r#"{"document":{"name":"e2e_open","revision":1}"#),
            "{doc}"
        );
    }
}

// The documents of a frame built from bytes use the keys of revision 1 and no
// more: the keys revision 2 adds belong to a described body, and the test that
// reaches every one of them is in `e2e_body_tests`.
#[test]
fn the_documents_use_exactly_the_keys_the_registry_pins() {
    use crate::doc_revision::{key_set, E2E_OPEN, E2E_OPEN_R1_KEYS, E2E_WRAP, E2E_WRAP_R1_KEYS};
    let gold = &GOLDS[0];
    let split = &GOLDS[4];
    let bad_profile = swap(DEMO_E, r#""bytes": 3"#, r#""bytes": 1"#);
    let mut wrap: Vec<&str> = Vec::new();
    let mut open_keys: Vec<&str> = Vec::new();
    let wraps = [
        wrap_document(gold.profile, gold.values, &unhex(gold.payload)),
        wrap_document(split.profile, split.values, &unhex(split.payload)),
        wrap_document("{", "{}", &[]),
        wrap_document(&bad_profile, "{}", &[]),
        wrap_document(gold.profile, "{", &[]),
        wrap_document(gold.profile, "{\"a\": 1}", &[]),
        wrap_document(gold.profile, gold.values, &alloc::vec![0u8; 65536]),
    ];
    for doc in &wraps {
        wrap.extend(key_set(doc));
    }
    let opens = [
        open_document(gold.profile, &unhex(gold.frame)),
        open_document("{", &[]),
        open_document(&bad_profile, &[]),
        open_document(gold.profile, &[]),
    ];
    for doc in &opens {
        open_keys.extend(key_set(doc));
    }
    wrap.sort_unstable();
    wrap.dedup();
    open_keys.sort_unstable();
    open_keys.dedup();
    assert_eq!(wrap, E2E_WRAP_R1_KEYS, "{E2E_WRAP}");
    assert_eq!(open_keys, E2E_OPEN_R1_KEYS, "{E2E_OPEN}");
}

#[test]
fn the_fed_list_is_the_cover_in_its_own_order() {
    let gold = &GOLDS[0];
    let doc = wrap_document(gold.profile, gold.values, &unhex(gold.payload));
    let at = |needle: &str| {
        doc.find(needle)
            .unwrap_or_else(|| panic!("{needle} in {doc}"))
    };
    let fed = at("\"crc_fed\"");
    let order = [
        at("{\"item\":\"length\",\"bytes\":2,\"hex\":\"0014\"}"),
        at("{\"item\":\"ident\",\"bytes\":4,\"hex\":\"0c081d3b\"}"),
        at("{\"item\":\"@payload\",\"bytes\":4}"),
        at("{\"item\":\"cell\",\"bytes\":4,\"hex\":\"41888888\"}"),
        at("{\"item\":\"counter\",\"bytes\":2,\"hex\":\"0102\"}"),
    ];
    assert!(
        fed < order[0] && order.windows(2).all(|w| w[0] < w[1]),
        "{doc}"
    );
    assert_eq!(
        number_after(&doc, "crc_computed"),
        (0xc2bf_56b4u64).to_string()
    );
}
