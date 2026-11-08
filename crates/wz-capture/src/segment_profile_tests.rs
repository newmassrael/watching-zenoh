// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Tests of [`crate::segment_profile`], on a synthetic profile whose marks,
//! widths, orders and CRC are deliberately unlike any deployed header.

use alloc::string::String;
use alloc::vec::Vec;

use crate::e2e_profile::DocError;
use crate::segment_profile::{synthetic, Misplaced, SegmentProfile};

/// The synthetic profile ([`synthetic::PROFILE`]), under the name the tests
/// here use for it.
pub(crate) const DEMO: &str = synthetic::PROFILE;

/// The header width of [`DEMO`].
pub(crate) const DEMO_HEADER: usize = synthetic::HEADER_BYTES;

/// One piece of [`DEMO`] ([`synthetic::piece`]).
pub(crate) use synthetic::piece as demo_piece;

pub(crate) fn demo_profile() -> SegmentProfile {
    SegmentProfile::parse(DEMO).expect("the demo profile is valid")
}

fn refusal(text: &str) -> (String, String) {
    match SegmentProfile::parse(text) {
        Err(DocError::Invalid { path, reason }) => (path, reason),
        other => panic!("expected a refusal with a place, got {other:?}"),
    }
}

/// The demo profile with `from` replaced by `to`, which must occur once.
fn demo_with(from: &str, to: &str) -> String {
    assert_eq!(DEMO.matches(from).count(), 1, "`{from}` must occur once");
    DEMO.replacen(from, to, 1)
}

#[test]
fn the_profile_reads_its_fields_roles_and_header_width() {
    let p = demo_profile();
    assert_eq!(p.name(), "demo-split");
    assert_eq!(p.header_bytes(), DEMO_HEADER);
    let names: Vec<&str> = p.fields().iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["mark", "origin", "number", "size", "at", "check"]);
    assert_eq!(
        p.fields().iter().map(|f| f.offset).collect::<Vec<_>>(),
        [0, 2, 4, 5, 8, 11]
    );
    assert_eq!(
        (p.transfer(), p.total(), p.offset(), p.stream()),
        (2, 3, 4, &[1usize][..])
    );
    assert_eq!(p.crc().map(|c| c.field), Some(5));
    assert_eq!(p.total_max(), 4096);
    assert!(SegmentProfile::is_segment_profile(DEMO));
}

#[test]
fn a_piece_is_read_in_each_fields_own_byte_order_and_its_crc_matches() {
    let p = demo_profile();
    let bytes = demo_piece(0x1234, 7, 0x0A0B0C, 0x000102, b"chunk");
    let piece = p.recognise(&bytes).expect("a piece");
    assert_eq!(piece.values[..5], [0xA5C3, 0x1234, 7, 0x0A0B0C, 0x000102]);
    assert_eq!(piece.chunk, b"chunk");
    let crc = piece.crc.expect("the profile has a CRC");
    assert!(crc.matches(), "{crc:?}");
    // Little-endian means the first byte is the least significant: the wire
    // holds 34 12 for 0x1234.
    assert_eq!(&bytes[2..4], &[0x34, 0x12]);
}

#[test]
fn a_payload_without_the_marks_or_shorter_than_the_header_is_not_a_piece() {
    let p = demo_profile();
    let mut bytes = demo_piece(1, 1, 5, 0, b"abcde");
    bytes[0] ^= 0xFF;
    assert!(p.recognise(&bytes).is_none(), "a wrong mark");
    let bytes = demo_piece(1, 1, 5, 0, b"abcde");
    assert!(
        p.recognise(&bytes[..DEMO_HEADER - 1]).is_none(),
        "too short"
    );
    // Exactly the header is a piece with an empty chunk, which `place` refuses.
    let piece = p.recognise(&bytes[..DEMO_HEADER]).expect("a header alone");
    assert_eq!(p.place(&piece), Err(Misplaced::EmptyChunk));
}

#[test]
fn a_damaged_piece_with_its_marks_is_still_a_piece_and_says_its_crc_is_wrong() {
    let p = demo_profile();
    let mut bytes = demo_piece(1, 1, 5, 0, b"abcde");
    *bytes.last_mut().expect("a chunk") ^= 0x01;
    let piece = p.recognise(&bytes).expect("still a piece");
    let crc = piece.crc.expect("a CRC");
    assert!(!crc.matches(), "{crc:?}");
}

#[test]
fn without_marks_the_crc_is_what_makes_a_payload_a_piece() {
    let text = demo_with(r#","equals":"0xA5C3""#, "");
    let p = SegmentProfile::parse(&text).expect("valid without marks");
    let good = demo_piece(1, 1, 5, 0, b"abcde");
    assert!(p.recognise(&good).is_some());
    let mut bad = good.clone();
    *bad.last_mut().expect("a chunk") ^= 0x01;
    assert!(p.recognise(&bad).is_none(), "no mark and no matching CRC");
}

#[test]
fn place_refuses_a_whole_that_cannot_hold_the_chunk() {
    let p = demo_profile();
    let place = |size, at, chunk: &[u8]| {
        let bytes = demo_piece(1, 1, size, at, chunk);
        p.place(&p.recognise(&bytes).expect("a piece"))
    };
    assert_eq!(place(10, 4, b"abc"), Ok((10, 4)));
    assert_eq!(
        place(10, 7, b"abc"),
        Ok((10, 7)),
        "ends exactly at the total"
    );
    assert_eq!(place(10, 8, b"abc"), Err(Misplaced::PastTotal));
    assert_eq!(place(0, 0, b"abc"), Err(Misplaced::EmptyTotal));
    assert_eq!(place(4097, 0, b"abc"), Err(Misplaced::TotalPastMax));
}

#[test]
fn every_inconsistency_is_refused_at_its_place() {
    let cases: &[(&str, &str, &str)] = &[
        (
            r#""total_max":4096"#,
            r#""total_max":4096,"extra":1"#,
            "/segments/extra",
        ),
        (
            r#""transfer":"number""#,
            r#""transfer":"nothing""#,
            "/segments/transfer",
        ),
        (
            r#""total":"size""#,
            r#""total":"number""#,
            "/segments/total",
        ),
        (r#""offset":"at""#, r#""offset":"mark""#, "/segments/offset"),
        (
            r#""stream":["origin"]"#,
            r#""stream":["check"]"#,
            "/segments/stream/0",
        ),
        (
            r#""total_max":4096"#,
            r#""total_max":0"#,
            "/segments/total_max",
        ),
        (
            r#""total_max":4096"#,
            r#""total_max":67108865"#,
            "/segments/total_max",
        ),
        (
            r#"{"name":"at","bytes":3,"order":"little"}"#,
            r#"{"name":"at","bytes":3,"order":"middle"}"#,
            "/segments/fields/4/order",
        ),
        (
            r#""equals":"0xA5C3""#,
            r#""equals":"0x1A5C3""#,
            "/segments/fields/0/equals",
        ),
        (
            r#""cover":["mark","origin","number","size","at","@chunk"]"#,
            r#""cover":["mark","mark"]"#,
            "/segments/crc/cover/1",
        ),
        (
            r#""cover":["mark","origin","number","size","at","@chunk"]"#,
            r#""cover":["check"]"#,
            "/segments/crc/cover/0",
        ),
        (
            r#""field":"check""#,
            r#""field":"mark""#,
            "/segments/crc/field",
        ),
        (r#""width":16"#, r#""width":32"#, "/segments/crc/field"),
    ];
    for (from, to, path) in cases {
        let (at, reason) = refusal(&demo_with(from, to));
        assert_eq!(&at, path, "{to}: refused at {at}: {reason}");
    }
}

#[test]
fn a_profile_with_neither_marks_nor_a_crc_is_refused() {
    let text = demo_with(r#","equals":"0xA5C3""#, "");
    let start = text.find(r#""crc":"#).expect("a crc");
    let end = text.find(r#""stream""#).expect("a stream");
    let without = alloc::format!("{}{}", &text[..start], &text[end..]);
    let (at, reason) = refusal(&without);
    assert_eq!(at, "/segments", "{reason}");
}

#[test]
fn an_end_to_end_profile_is_not_a_segment_profile() {
    assert!(!SegmentProfile::is_segment_profile(
        r#"{"name":"demo-a","fields":[],"crc":{}}"#
    ));
    assert!(!SegmentProfile::is_segment_profile("not json"));
}
