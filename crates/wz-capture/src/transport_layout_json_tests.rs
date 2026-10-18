// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The layout door for bytes that already exist, held three ways, and the
//! honest limit of each.
//!
//! * AGAINST THE BUILD DOOR. Every unit the build door makes, fed back through
//!   this one with the same framing, must report the same rows byte for byte.
//!   The two doors share ONE function for the report (`transport_layout::layout`)
//!   and ONE renderer for its rows, so this proves the door's own plumbing (the
//!   prefix, the ring, no state between the bytes and the answer) and that the
//!   two documents cannot drift apart. It cannot prove the classification: a
//!   mutated table moves both answers together. That is what the next item is for.
//! * AGAINST BYTES AND ROWS TYPED BY HAND. Messages laid out from the upstream
//!   header rules, each with the rows a reader of the format expects, written
//!   out as a table here and not derived from the table in
//!   `transport_layout`. This is the oracle a mutated classification turns red.
//! * AGAINST BYTES THAT DO NOT READ. Every cut of every built unit, trailing
//!   bytes, every message id, a stream prefix that lies, and a few tens of
//!   thousands of garbage and mutated inputs: a clean refusal, or a report whose
//!   rows tile the body, and never a panic.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use std::eprintln;

use wz_session_core::json5::{self, Json5Value};
use wz_session_core::transport_compose::{vle_range, Framing};
use wz_session_core::wire_const;

use crate::doc_revision::{
    key_set, newest, TRANSPORT_BUILD, TRANSPORT_LAYOUT, TRANSPORT_LAYOUT_R1_KEYS,
};
use crate::transport_build::{build, RESOLUTION_WORDS};
use crate::transport_build_json::build_document;
use crate::transport_build_tests::corpus_descriptions;
use crate::transport_layout::{
    layout, Encoding, Kind, LayoutError, RelativeTo, Row, COVERED_MESSAGES,
};
use crate::transport_layout_json::{layout_document, ring_max_of};

// ---------------------------------------------------------------- helpers

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The text of a string-valued member of a document this library wrote.
fn member(doc: &str, key: &str) -> String {
    let marker = format!("\"{key}\":\"");
    let start = doc
        .find(&marker)
        .unwrap_or_else(|| panic!("no `{key}` in {doc}"))
        + marker.len();
    let len = doc[start..].find('"').expect("a string closes");
    doc[start..start + len].to_string()
}

/// The `"layout":[...]` member of a document, as text. It is the last member of
/// both documents, so it runs to the closing brace.
fn layout_member(doc: &str) -> &str {
    let start = doc
        .find("\"layout\":[")
        .unwrap_or_else(|| panic!("no layout in {doc}"));
    &doc[start..doc.len() - 1]
}

fn is_refusal(doc: &str) -> bool {
    doc.starts_with(r#"{"document":{"name":"transport_layout","revision":1},"ok":false,"reason":""#)
}

/// A refusal is a value of one shape: the envelope, `ok:false`, a reason and its
/// one-line message, and no layout, no counts, no position and no null.
fn assert_refusal(doc: &str, what: &str) {
    assert!(is_refusal(doc), "{what}: not a refusal: {doc}");
    assert!(!doc.contains("\"layout\""), "{what}: {doc}");
    assert!(!doc.contains("null"), "{what}: a top-level null: {doc}");
    let Json5Value::Object(top) = json5::parse(doc).expect("a refusal is JSON") else {
        panic!("{what}: a document is an object")
    };
    let keys: Vec<&str> = top.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, ["document", "ok", "reason", "message"], "{what}");
}

fn reason(doc: &str) -> String {
    member(doc, "reason")
}

/// Every document the layout door writes over the units the build door makes:
/// the population the carries gate in `fields_json` measures the three
/// families against, with the refusals beside them.
pub(crate) fn documents_for_the_carries_gate() -> Vec<String> {
    let mut docs = Vec::new();
    for (_, json, ring) in corpus_descriptions() {
        for framing in Framing::ALL {
            let b = build(&json, framing).expect("the corpus builds");
            docs.push(layout_document(&b.unit, framing, ring));
        }
    }
    docs.push(layout_document(&[0x03], Framing::Datagram, None));
    docs
}

/// A frame with a payload that is a whole network message, laid by hand.
const FRAME_WITH_A_PUSH: [u8; 8] = [0x25, 0x05, 0x1D, 0x00, 0x01, 0x00, 0x00, 0x00];

// ---------------------------------------------- 1. against the build door

/// For every message the build door can make, in every framing: the unit it
/// returns, read back through this door with the same framing and the ring the
/// description named, reports the rows the build door reported.
#[test]
fn the_layout_of_every_built_unit_is_the_builds_own_layout() {
    let (mut units, mut rows, mut sequence_rows) = (0usize, 0usize, 0usize);
    let mut messages: Vec<String> = Vec::new();
    for (label, json, ring) in corpus_descriptions() {
        for framing in Framing::ALL {
            let built_doc = build_document(&json, framing);
            let unit = unhex(&member(&built_doc, "unit"));
            let read = layout_document(&unit, framing, ring);
            assert!(read.contains("\"ok\":true"), "{label}: {read}");
            assert_eq!(
                layout_member(&read),
                layout_member(&built_doc),
                "{label} as {}",
                framing.name()
            );
            // The envelope is the one place the two differ, by name.
            assert!(
                read.starts_with(
                    r#"{"document":{"name":"transport_layout","revision":1},"ok":true,"#
                ),
                "{read}"
            );
            let b = build(&json, framing).expect("builds");
            assert!(read.contains(&format!("\"prefix_bytes\":{}", b.prefix_bytes)));
            assert!(read.contains(&format!("\"body_bytes\":{}", b.body.len())));
            // And the library function agrees with the document's rows.
            assert_eq!(layout(&unit, framing, ring).expect("rows"), b.layout);
            units += 1;
            rows += b.layout.len();
            sequence_rows += b
                .layout
                .iter()
                .filter(|r| r.kind == Kind::SequenceNumber)
                .count();
            if framing == Framing::Datagram {
                messages.push(label.clone());
            }
        }
    }
    eprintln!("equality oracle: {units} units, {rows} rows, {sequence_rows} sequence rows");
    assert_eq!(units, corpus_descriptions().len() * Framing::ALL.len());
    assert!(units >= 200, "only {units} units compared");
    assert!(rows >= 2_000, "only {rows} rows compared");
    assert!(sequence_rows >= 100, "only {sequence_rows} sequence rows");
    // Every message kind the build door supports is in the population.
    for kind in [
        "init_syn",
        "init_ack",
        "open_syn",
        "open_ack",
        "frame",
        "fragment",
        "keep_alive",
        "close",
    ] {
        assert!(
            messages.iter().any(|l| l.starts_with(kind)),
            "no `{kind}` case among {messages:?}"
        );
    }
}

/// A VLE of every width the format has, in every field that takes one: the
/// sequence number of a Frame, the initial sequence number and the lease of an
/// Open, and the body of a numeric extension.
#[test]
fn every_vle_width_from_one_to_nine_reads_back_to_the_builds_row() {
    let mut widths_seen: Vec<usize> = Vec::new();
    for width in 1..=9usize {
        let (lo, hi) = vle_range(width).expect("a width the format has");
        for value in [lo, hi] {
            let v = if value > (1 << 53) {
                format!("\"{value}\"")
            } else {
                value.to_string()
            };
            for (what, json, field) in [
                (
                    "frame sn",
                    format!(r#"{{"message":"frame","reliable":true,"sn":{v},"payload":"00"}}"#),
                    "sn",
                ),
                (
                    "fragment sn",
                    format!(
                        r#"{{"message":"fragment","reliable":false,"more":true,"sn":{v},"payload":"00"}}"#
                    ),
                    "sn",
                ),
                (
                    "open initial_sn",
                    format!(
                        r#"{{"message":"open_ack","lease_ms":0,"lease_unit":"ms","initial_sn":{v}}}"#
                    ),
                    "initial_sn",
                ),
                (
                    "open lease",
                    format!(
                        r#"{{"message":"open_ack","lease_ms":{v},"lease_unit":"ms","initial_sn":1}}"#
                    ),
                    "lease",
                ),
                (
                    "extension z64 body",
                    format!(
                        r#"{{"message":"open_ack","lease_ms":0,"lease_unit":"ms","initial_sn":1,
                           "extensions":[{{"id":7,"z64":{v}}}]}}"#
                    ),
                    "extensions[0].value",
                ),
            ] {
                for framing in Framing::ALL {
                    let b = build(&json, framing).unwrap_or_else(|e| panic!("{what}: {e:?}"));
                    let built_doc = build_document(&json, framing);
                    let read = layout_document(&b.unit, framing, None);
                    assert_eq!(layout_member(&read), layout_member(&built_doc), "{what}");
                    let row = b
                        .layout
                        .iter()
                        .find(|r| r.name == field)
                        .unwrap_or_else(|| panic!("{what}: no `{field}` row"));
                    assert_eq!(row.width, width, "{what} of {value}");
                    assert_eq!(row.encoding, Encoding::Vle);
                    assert_eq!((row.min, row.max), (Some(lo), Some(hi)));
                    widths_seen.push(width);
                }
            }
        }
    }
    let per_width: Vec<usize> = (1..=9usize)
        .map(|w| widths_seen.iter().filter(|seen| **seen == w).count())
        .collect();
    eprintln!("vle widths 1..9, units per width: {per_width:?}");
    for (i, seen) in per_width.iter().enumerate() {
        assert!(*seen >= 20, "width {} measured {seen} times", i + 1);
    }
}

/// The ring the caller names reaches the sequence-number rows exactly as the
/// build door's `sn_resolution` does, for each of the four rings.
#[test]
fn a_named_ring_reaches_the_sequence_rows_as_the_build_doors_does() {
    let mut named = 0usize;
    for word in RESOLUTION_WORDS {
        let ring = ring_max_of(word).expect("a resolution word");
        for body in [
            r#""message":"frame","reliable":true,"sn":5,"payload":"dead""#,
            r#""message":"fragment","reliable":false,"more":false,"sn":9,"payload":"01""#,
            r#""message":"open_syn","lease_ms":1500,"initial_sn":3,"cookie":"01""#,
            r#""message":"open_ack","lease_ms":0,"initial_sn":1"#,
        ] {
            let json = format!(r#"{{{body},"sn_resolution":"{word}"}}"#);
            for framing in Framing::ALL {
                let built_doc = build_document(&json, framing);
                let unit = unhex(&member(&built_doc, "unit"));
                let read = layout_document(&unit, framing, Some(ring));
                assert_eq!(layout_member(&read), layout_member(&built_doc), "{json}");
                assert!(
                    read.contains(&format!("\"ring_max\":{}", cell(ring))),
                    "{word}: {read}"
                );
                // Without the ring the same bytes carry null, and nothing else moves.
                let unnamed = layout_document(&unit, framing, None);
                assert_eq!(
                    layout_member(&unnamed),
                    layout_member(&read)
                        .replace(&format!("\"ring_max\":{}", cell(ring)), "\"ring_max\":null")
                        .replace(
                            &format!("\"ring_max_width\":{}", vle_len(ring)),
                            "\"ring_max_width\":null"
                        )
                );
                named += 1;
            }
        }
    }
    assert_eq!(named, 4 * 4 * 3);
    assert_eq!(ring_max_of("7bit"), None);
    assert_eq!(ring_max_of(""), None);
    assert_eq!(ring_max_of("8BIT"), None);
}

fn cell(v: u64) -> String {
    if v > (1 << 53) {
        format!("\"{v}\"")
    } else {
        v.to_string()
    }
}

fn vle_len(v: u64) -> usize {
    wz_session_core::transport_compose::vle_width(v)
}

/// A sequence number above the ring the caller named is a fact about the
/// session, reported as the bytes hold it.
#[test]
fn a_sequence_number_beyond_the_named_ring_is_reported_not_refused() {
    let b = build(
        r#"{"message":"frame","reliable":true,"sn":300,"payload":"00"}"#,
        Framing::Datagram,
    )
    .expect("builds with no ring named");
    let read = layout_document(&b.unit, Framing::Datagram, ring_max_of("8bit"));
    assert!(read.contains("\"ok\":true"), "{read}");
    assert!(
        read.contains(r#""value":300,"min":128,"max":16383,"bit_mask":null,"carrier":null,"stored":null,"measures":null,"ring_max":127,"ring_max_width":1"#),
        "{read}"
    );
}

// ------------------------------------- 2. against rows typed by hand

/// What a reader of the format expects of one row, typed from the upstream
/// header rules and not taken from the classification table.
struct Want {
    name: &'static str,
    kind: Kind,
    offset: usize,
    width: usize,
    relative_to: RelativeTo,
    encoding: Encoding,
    value: Option<u64>,
    min: Option<u64>,
    max: Option<u64>,
    bit_mask: Option<u8>,
    carrier: Option<&'static str>,
    stored: Option<u64>,
    measures: Option<&'static str>,
}

/// A row that owns bytes: a fixed integer, or a byte string when `value` is `None`.
fn fixed(name: &'static str, kind: Kind, offset: usize, width: usize, value: Option<u64>) -> Want {
    let (min, max) = match value {
        Some(_) => (Some(0), Some((1u64 << (8 * width)) - 1)),
        None => (None, None),
    };
    Want {
        name,
        kind,
        offset,
        width,
        relative_to: RelativeTo::Body,
        encoding: Encoding::Fixed,
        value,
        min,
        max,
        bit_mask: None,
        carrier: None,
        stored: None,
        measures: None,
    }
}

/// A VLE row of `width` bytes, which keeps its width for `min..=max`.
fn vle(
    name: &'static str,
    kind: Kind,
    offset: usize,
    width: usize,
    value: u64,
    (min, max): (u64, u64),
    measures: Option<&'static str>,
) -> Want {
    Want {
        name,
        kind,
        offset,
        width,
        relative_to: RelativeTo::Body,
        encoding: Encoding::Vle,
        value: Some(value),
        min: Some(min),
        max: Some(max),
        bit_mask: None,
        carrier: None,
        stored: None,
        measures,
    }
}

/// A bit-field or flag of the byte at `offset` that the row `carrier` names.
fn bits(
    name: &'static str,
    kind: Kind,
    offset: usize,
    carrier: &'static str,
    mask: u8,
    stored: u64,
) -> Want {
    Want {
        name,
        kind,
        offset,
        width: 1,
        relative_to: RelativeTo::Body,
        encoding: Encoding::Fixed,
        value: Some(stored),
        min: Some(0),
        max: Some(u64::from(mask >> mask.trailing_zeros())),
        bit_mask: Some(mask),
        carrier: Some(carrier),
        stored: Some(stored),
        measures: None,
    }
}

fn unit_length(width: usize, value: u64) -> Want {
    Want {
        name: "unit_length",
        kind: Kind::Length,
        offset: 0,
        width,
        relative_to: RelativeTo::Unit,
        encoding: Encoding::Fixed,
        value: Some(value),
        min: Some(0),
        max: Some((1u64 << (8 * width)) - 1),
        bit_mask: None,
        carrier: None,
        stored: None,
        measures: Some("body"),
    }
}

fn assert_rows(label: &str, got: &[Row], want: &[Want]) {
    let got_names: Vec<&str> = got.iter().map(|r| r.name.as_str()).collect();
    let want_names: Vec<&str> = want.iter().map(|w| w.name).collect();
    assert_eq!(got_names, want_names, "{label}: the rows, in wire order");
    for (g, w) in got.iter().zip(want) {
        let at = format!("{label}: row `{}`", w.name);
        assert_eq!(g.kind, w.kind, "{at} kind");
        assert_eq!((g.offset, g.width), (w.offset, w.width), "{at} place");
        assert_eq!(g.relative_to, w.relative_to, "{at} relative_to");
        assert_eq!(g.encoding, w.encoding, "{at} encoding");
        assert_eq!(g.value, w.value, "{at} value");
        assert_eq!((g.min, g.max), (w.min, w.max), "{at} min and max");
        assert_eq!(g.bit_mask, w.bit_mask, "{at} bit_mask");
        assert_eq!(g.carrier.as_deref(), w.carrier, "{at} carrier");
        assert_eq!(g.stored, w.stored, "{at} stored");
        assert_eq!(g.measures.as_deref(), w.measures, "{at} measures");
        assert_eq!((g.ring_max, g.ring_max_width), (None, None), "{at} ring");
    }
}

use Kind::{Flag, Length, Other, Reserved, SequenceNumber};

/// Bytes laid by hand, rows written by hand. Each message is one the format's
/// header rules give: a header byte of the message id in its low five bits and
/// the flags above it, then the fields in order.
#[test]
fn bytes_laid_by_hand_report_the_rows_a_reader_of_the_format_expects() {
    // FRAME, reliable (R = 0x20), sn 5, payload dead.
    let frame = [0x25u8, 0x05, 0xDE, 0xAD];
    let frame_rows = vec![
        fixed("header", Other, 0, 1, Some(0x25)),
        bits("mid", Other, 0, "header", 0x1F, 5),
        bits("z", Flag, 0, "header", 0x80, 0),
        bits("r", Flag, 0, "header", 0x20, 1),
        bits("header_reserved", Reserved, 0, "header", 0x40, 0),
        vle("sn", SequenceNumber, 1, 1, 5, (0, 127), None),
        fixed("payload", Other, 2, 2, None),
    ];
    let rows = layout(&frame, Framing::Datagram, None).expect("a frame");
    assert_rows("frame", &rows, &frame_rows);

    // The same frame behind a 16-bit stream prefix: one row more, relative to
    // the unit, and every other row at the same place in the body.
    let mut streamed = vec![4u8, 0];
    streamed.extend_from_slice(&frame);
    let mut with_prefix = vec![unit_length(2, 4)];
    with_prefix.extend(frame_rows);
    let rows = layout(&streamed, Framing::TcpStream, None).expect("a streamed frame");
    assert_rows("tcp frame", &rows, &with_prefix);

    // KEEP_ALIVE is a header and nothing else.
    let rows = layout(&[0x04], Framing::Datagram, None).expect("a keep alive");
    assert_rows(
        "keep_alive",
        &rows,
        &[
            fixed("header", Other, 0, 1, Some(0x04)),
            bits("mid", Other, 0, "header", 0x1F, 4),
            bits("z", Flag, 0, "header", 0x80, 0),
            bits("header_reserved", Reserved, 0, "header", 0x60, 0),
        ],
    );

    // CLOSE, S = 0x20 (the whole session), reason 2.
    let rows = layout(&[0x23, 0x02], Framing::Datagram, None).expect("a close");
    assert_rows(
        "close",
        &rows,
        &[
            fixed("header", Other, 0, 1, Some(0x23)),
            bits("mid", Other, 0, "header", 0x1F, 3),
            bits("z", Flag, 0, "header", 0x80, 0),
            bits("s", Flag, 0, "header", 0x20, 1),
            bits("header_reserved", Reserved, 0, "header", 0x40, 0),
            fixed("reason", Other, 1, 1, Some(2)),
        ],
    );

    // INIT, syn: version 5, a peer (1) with a 4-byte zid, so the zid length
    // stored beside the role is 3.
    let init = [0x01u8, 0x05, 0x31, 0xB0, 0xB1, 0xB2, 0xB3];
    let rows = layout(&init, Framing::Datagram, None).expect("an init");
    assert_rows(
        "init_syn",
        &rows,
        &[
            fixed("header", Other, 0, 1, Some(0x01)),
            bits("mid", Other, 0, "header", 0x1F, 1),
            bits("z", Flag, 0, "header", 0x80, 0),
            bits("a", Flag, 0, "header", 0x20, 0),
            bits("s", Flag, 0, "header", 0x40, 0),
            fixed("version", Other, 1, 1, Some(5)),
            fixed("cbyte", Other, 2, 1, Some(0x31)),
            bits("whatami", Other, 2, "cbyte", 0x03, 1),
            Want {
                value: Some(4),
                measures: Some("zid"),
                ..bits("zid_len", Length, 2, "cbyte", 0xF0, 3)
            },
            bits("cbyte_reserved", Reserved, 2, "cbyte", 0x0C, 0),
            fixed("zid", Other, 3, 4, None),
        ],
    );

    // INIT with the extension chain (Z = 0x80): one numeric extension, id 7,
    // body 1. The entry's header is its id (low four bits), M (0x10), the two
    // encoding bits (0x60, z64 = 1) and the chain bit (0x80).
    let init_ext = [0x81u8, 0x05, 0x31, 0xB0, 0xB1, 0xB2, 0xB3, 0x27, 0x01];
    let rows = layout(&init_ext, Framing::Datagram, None).expect("an init with a chain");
    let tail = &rows[rows.len() - 6..];
    assert_rows(
        "init_syn extension",
        tail,
        &[
            fixed("extensions[0].header", Other, 7, 1, Some(0x27)),
            bits(
                "extensions[0].ext_id",
                Other,
                7,
                "extensions[0].header",
                0x0F,
                7,
            ),
            bits("extensions[0].m", Flag, 7, "extensions[0].header", 0x10, 0),
            bits(
                "extensions[0].encoding",
                Other,
                7,
                "extensions[0].header",
                0x60,
                1,
            ),
            bits("extensions[0].z", Flag, 7, "extensions[0].header", 0x80, 0),
            vle("extensions[0].value", Other, 8, 1, 1, (0, 127), None),
        ],
    );

    // OPEN, syn, lease in seconds (T = 0x40): lease 10, initial sn 7, a cookie.
    let open = [0x42u8, 0x0A, 0x07, 0x02, 0xAA, 0xBB];
    let rows = layout(&open, Framing::Datagram, None).expect("an open");
    assert_rows(
        "open_syn",
        &rows,
        &[
            fixed("header", Other, 0, 1, Some(0x42)),
            bits("mid", Other, 0, "header", 0x1F, 2),
            bits("z", Flag, 0, "header", 0x80, 0),
            bits("a", Flag, 0, "header", 0x20, 0),
            bits("t", Flag, 0, "header", 0x40, 1),
            vle("lease", Other, 1, 1, 10, (0, 127), None),
            vle("initial_sn", SequenceNumber, 2, 1, 7, (0, 127), None),
            vle("cookie_len", Length, 3, 1, 2, (0, 127), Some("cookie")),
            fixed("cookie", Other, 4, 2, None),
        ],
    );

    // FRAGMENT, R and M (0x20 and 0x40), sn 300 (two VLE bytes), payload beef.
    let fragment = [0x66u8, 0xAC, 0x02, 0xBE, 0xEF];
    let rows = layout(&fragment, Framing::Datagram, None).expect("a fragment");
    assert_rows(
        "fragment",
        &rows,
        &[
            fixed("header", Other, 0, 1, Some(0x66)),
            bits("mid", Other, 0, "header", 0x1F, 6),
            bits("z", Flag, 0, "header", 0x80, 0),
            bits("r", Flag, 0, "header", 0x20, 1),
            bits("m", Flag, 0, "header", 0x40, 1),
            vle("sn", SequenceNumber, 1, 2, 300, (128, 16_383), None),
            fixed("payload", Other, 3, 2, None),
        ],
    );
}

/// The report of the header's own worked example, as the header prints it.
#[test]
fn the_headers_worked_example_is_what_the_door_writes() {
    let doc = layout_document(
        &[0x04, 0x00, 0x25, 0x05, 0xDE, 0xAD],
        Framing::TcpStream,
        None,
    );
    assert!(
        doc.starts_with(concat!(
            r#"{"document":{"name":"transport_layout","revision":1},"ok":true,"#,
            r#""prefix_bytes":2,"body_bytes":4,"layout":["#,
            r#"{"name":"unit_length","kind":"length","offset":0,"width":2,"#,
            r#""relative_to":"unit","encoding":"fixed","value":4,"min":0,"max":65535,"#,
            r#""bit_mask":null,"carrier":null,"stored":null,"measures":"body","#,
            r#""ring_max":null,"ring_max_width":null},"#
        )),
        "{doc}"
    );
}

/// A network message carried in a Frame is ONE row, whatever the bytes in it.
#[test]
fn a_network_message_inside_a_frame_is_one_payload_row() {
    let rows = layout(&FRAME_WITH_A_PUSH, Framing::Datagram, None).expect("a frame");
    let payload: Vec<&Row> = rows.iter().filter(|r| r.name == "payload").collect();
    assert_eq!(payload.len(), 1);
    assert_eq!(
        (payload[0].offset, payload[0].width, payload[0].kind),
        (2, 6, Kind::Other)
    );
    assert_eq!(rows.last().map(|r| r.name.as_str()), Some("payload"));
    assert!(rows.iter().all(|r| !r.name.starts_with("payload.")));
}

// -------------------------------------------- 3. the bytes that do not read

/// Cut a built unit at every byte. A stream framing's prefix then announces more
/// than is there, so every cut is refused; a datagram of a message that has no
/// tail is refused at every cut; a Frame or Fragment cut inside its payload is
/// a shorter message and reports as one. None panics, and a refusal is one shape.
#[test]
fn a_unit_cut_at_every_byte_is_refused_or_reported_never_a_panic() {
    let (mut cuts, mut refused, mut shorter) = (0usize, 0usize, 0usize);
    for (label, json, _) in corpus_descriptions() {
        let tail_kind = label.starts_with("frame") || label.starts_with("fragment");
        for framing in Framing::ALL {
            let b = build(&json, framing).expect("builds");
            for cut in 0..b.unit.len() {
                let doc = layout_document(&b.unit[..cut], framing, None);
                cuts += 1;
                let datagram_payload_cut = framing == Framing::Datagram
                    && tail_kind
                    && cut >= b.unit.len() - payload_len(&b.layout);
                if datagram_payload_cut {
                    // Inside the payload: a shorter message of the same kind.
                    assert!(doc.contains("\"ok\":true"), "{label} cut {cut}: {doc}");
                    let rows = layout(&b.unit[..cut], framing, None).expect("rows");
                    let last = rows.last().expect("a row");
                    assert_eq!(last.name, "payload", "{label} cut {cut}");
                    assert_eq!(last.offset + last.width, cut, "{label} cut {cut}");
                    shorter += 1;
                } else {
                    assert_refusal(&doc, &format!("{label} as {} cut {cut}", framing.name()));
                    refused += 1;
                }
            }
        }
    }
    eprintln!("cuts: {cuts}, refused {refused}, shorter frames reported {shorter}");
    assert_eq!(cuts, refused + shorter);
    assert!(cuts > 2_000, "only {cuts} cuts");
    assert!(refused > 1_500, "only {refused} refusals");
    assert!(shorter > 50, "only {shorter} shorter frames");
}

fn payload_len(rows: &[Row]) -> usize {
    rows.iter()
        .find(|r| r.name == "payload")
        .map_or(0, |r| r.width)
}

/// Bytes after the message: a message with a tail takes them into its payload; a
/// message without refuses them, and says so; a stream prefix that does not
/// announce them refuses with both numbers.
#[test]
fn bytes_after_the_message_are_refused_unless_the_message_has_a_tail() {
    let (mut refused, mut absorbed) = (0usize, 0usize);
    for (label, json, _) in corpus_descriptions() {
        let tail_kind = label.starts_with("frame") || label.starts_with("fragment");
        let b = build(&json, Framing::Datagram).expect("builds");
        for extra in [1usize, 2, 7] {
            let mut unit = b.unit.clone();
            unit.extend(core::iter::repeat_n(0xEE, extra));
            let doc = layout_document(&unit, Framing::Datagram, None);
            if tail_kind {
                assert!(doc.contains("\"ok\":true"), "{label}: {doc}");
                let rows = layout(&unit, Framing::Datagram, None).expect("rows");
                assert_eq!(
                    rows.last().map(|r| r.width),
                    Some(payload_len(&b.layout) + extra),
                    "{label}"
                );
                absorbed += 1;
            } else {
                assert_refusal(&doc, &label);
                assert!(
                    reason(&doc).contains("bytes follow the message"),
                    "{label}: {doc}"
                );
                refused += 1;
            }
        }
        // Behind a stream prefix that does not announce them: refused for the
        // prefix, whichever message it is.
        let s = build(&json, Framing::TcpStream).expect("builds");
        let mut unit = s.unit.clone();
        unit.push(0xEE);
        let doc = layout_document(&unit, Framing::TcpStream, None);
        assert_refusal(&doc, &label);
        assert!(
            reason(&doc).contains(&format!(
                "announces {} bytes and {} follow it",
                s.body.len(),
                s.body.len() + 1
            )),
            "{label}: {doc}"
        );
    }
    assert!(refused > 30 && absorbed > 30, "{refused} {absorbed}");
}

/// A stream prefix is held to the bytes behind it, in both framings.
#[test]
fn a_stream_prefix_must_announce_what_follows_it() {
    let body = [0x25u8, 0x05, 0xDE, 0xAD];
    for (framing, width) in [(Framing::TcpStream, 2usize), (Framing::LowLatencyStream, 4)] {
        let mut ok = vec![4u8];
        ok.resize(width, 0);
        ok.extend_from_slice(&body);
        let doc = layout_document(&ok, framing, None);
        assert!(doc.contains("\"ok\":true"), "{doc}");
        assert!(doc.contains(&format!("\"prefix_bytes\":{width},\"body_bytes\":4")));
        assert!(doc.contains(&format!(
            r#"{{"name":"unit_length","kind":"length","offset":0,"width":{width},"relative_to":"unit","encoding":"fixed","value":4,"#
        )));
        for announced in [0u8, 3, 5, 255] {
            let mut lie = ok.clone();
            lie[0] = announced;
            let doc = layout_document(&lie, framing, None);
            assert_refusal(&doc, "a prefix that lies");
            assert!(
                reason(&doc).contains(&format!("announces {announced} bytes and 4 follow it")),
                "{doc}"
            );
        }
        // Too short to hold the prefix at all, including the empty unit.
        for len in 0..width {
            let doc = layout_document(&ok[..len], framing, None);
            assert_refusal(&doc, "no room for the prefix");
            assert!(reason(&doc).contains("has no room"), "{doc}");
        }
        // A prefix that announces nothing, and nothing behind it, is a message
        // that is not there.
        let empty = vec![0u8; width];
        assert_refusal(&layout_document(&empty, framing, None), "an empty body");
    }
    // The same message as a datagram, for the caller whose capture is cut.
    assert!(layout_document(&body, Framing::Datagram, None).contains("\"ok\":true"));
    assert_refusal(&layout_document(&[], Framing::Datagram, None), "no bytes");
}

/// Every message id: the six the report covers read, and every other id (Join,
/// Oam and the ids the transport space does not name) is refused by name and
/// number. A refusal, never a default and never a guess at their fields.
#[test]
fn a_message_id_the_report_does_not_cover_is_refused_by_number() {
    use wire_const::{
        T_MID_CLOSE, T_MID_FRAGMENT, T_MID_FRAME, T_MID_INIT, T_MID_KEEP_ALIVE, T_MID_OPEN,
    };
    let covered = [
        T_MID_INIT,
        T_MID_OPEN,
        T_MID_CLOSE,
        T_MID_KEEP_ALIVE,
        T_MID_FRAME,
        T_MID_FRAGMENT,
    ];
    let (mut read, mut refused_named, mut refused_unnamed) = (0usize, 0usize, 0usize);
    for mid in 0u8..32 {
        for flags in [0x00u8, 0x20, 0x40, 0x60] {
            // A body of zeros, which every message the walker reads (Join and
            // Oam included, in every flag combination used here) reads to its end.
            let mut bytes = vec![mid | flags];
            bytes.extend(core::iter::repeat_n(0u8, 48));
            let doc = layout_document(&bytes, Framing::Datagram, None);
            if covered.contains(&mid) {
                // The body is arbitrary, so the message may or may not read;
                // what must hold is that it is never refused as uncovered.
                assert!(
                    !doc.contains("does not cover") && !doc.contains("names"),
                    "mid {mid}: {doc}"
                );
                read += 1;
            } else {
                assert_refusal(&doc, &format!("mid {mid}"));
                let why = reason(&doc);
                assert!(why.contains(&format!("message id {mid}")), "{why}");
                for word in COVERED_MESSAGES {
                    assert!(why.contains(word), "{why}");
                }
                if why.contains("which the report does not cover") {
                    refused_named += 1;
                } else {
                    assert!(why.contains("not one the transport space names"), "{why}");
                    refused_unnamed += 1;
                }
            }
        }
    }
    assert_eq!(read, 6 * 4);
    // Join and Oam are named messages the report does not cover.
    assert_eq!(refused_named, 2 * 4);
    assert_eq!(refused_unnamed, (32 - 8) * 4);
}

/// The list of messages the refusal names is the dissector's own words for the
/// six the table classifies.
#[test]
fn the_covered_messages_are_the_ones_the_table_has_a_scope_for() {
    use wz_session_core::dissect::MessageName;
    let words: Vec<&str> = [
        MessageName::Init,
        MessageName::Open,
        MessageName::Close,
        MessageName::KeepAlive,
        MessageName::Frame,
        MessageName::Fragment,
    ]
    .iter()
    .map(|m| m.name())
    .collect();
    assert_eq!(words, COVERED_MESSAGES);
}

/// A VLE that is not the shortest encoding of its value is read by the format
/// and cannot be reported (min and max would lie about its width): refused, by
/// field, with the width it has and the width its value needs.
#[test]
fn a_padded_vle_is_refused_by_field() {
    // sn 5 written in two bytes: 0x85 0x00.
    let doc = layout_document(&[0x25, 0x85, 0x00, 0xDE], Framing::Datagram, None);
    assert_refusal(&doc, "a padded sn");
    let why = reason(&doc);
    assert!(
        why.contains("`sn` is a VLE of 2 bytes and its value needs 1"),
        "{why}"
    );
}

/// Bytes that end inside a field say so in words, and the walker's own error
/// name does not leak as the whole reason.
#[test]
fn a_message_that_ends_inside_a_field_says_so() {
    let doc = layout_document(&[0x01, 0x05, 0x31, 0xB0], Framing::Datagram, None);
    assert_refusal(&doc, "a short init");
    assert!(
        reason(&doc).contains("end inside a field of the message"),
        "{doc}"
    );
}

/// Every way the report can fail has a sentence of its own, and the document a
/// failure becomes is the refusal shape.
#[test]
fn every_layout_error_renders_to_a_refusal() {
    use crate::transport_layout_json::refusal_for;
    let errors = [
        LayoutError::Unreadable(String::from("InvalidUtf8")),
        LayoutError::Unreadable(String::from("NeedMoreBytes")),
        LayoutError::NotCovered {
            name: String::from("Join"),
            mid: 7,
        },
        LayoutError::NotCovered {
            name: String::from("Unknown"),
            mid: 20,
        },
        LayoutError::Unclassified {
            name: String::from("never_seen"),
        },
        LayoutError::Untiled { at: 3 },
        LayoutError::NonCanonicalVle {
            name: String::from("sn"),
            width: 2,
            canonical: 1,
        },
    ];
    let mut reasons: Vec<String> = Vec::new();
    for error in &errors {
        let doc = refusal_for(error, 9);
        assert_refusal(&doc, &format!("{error:?}"));
        reasons.push(reason(&doc));
    }
    reasons.sort();
    reasons.dedup();
    assert_eq!(reasons.len(), errors.len(), "a sentence per error");
    // The classification gap names the field and says the table is the cause.
    assert!(reasons
        .iter()
        .any(|r| r.contains("`never_seen`") && r.contains("does not classify")));
}

// ------------------------------------------------------------------ fuzz

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*: a fixed seed, so a failure is the same failure on every host.
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// What every answer must satisfy, for any input: a document of the envelope that
/// parses; a refusal of one shape; or a report whose rows lie inside the unit,
/// tile the body, and are the rows `layout` returns.
fn check_answer(unit: &[u8], framing: Framing, doc: &str) -> bool {
    assert!(
        doc.starts_with(r#"{"document":{"name":"transport_layout","revision":1},"ok":"#),
        "{unit:02x?}: {doc}"
    );
    json5::parse(doc).unwrap_or_else(|e| panic!("{unit:02x?}: not JSON ({e:?}): {doc}"));
    if is_refusal(doc) {
        assert_refusal(doc, &format!("{unit:02x?}"));
        return false;
    }
    let rows = layout(unit, framing, None).expect("a report implies rows");
    let prefix = framing.prefix_bytes();
    let mut next = 0usize;
    for row in &rows {
        let base = match row.relative_to {
            RelativeTo::Unit => 0,
            RelativeTo::Body => prefix,
        };
        assert!(
            base + row.offset + row.width <= unit.len(),
            "{unit:02x?}: `{}` reaches past the unit",
            row.name
        );
        if row.relative_to == RelativeTo::Body && row.carrier.is_none() {
            assert_eq!(row.offset, next, "{unit:02x?}: a gap before `{}`", row.name);
            next += row.width;
        }
    }
    assert_eq!(next + prefix, unit.len(), "{unit:02x?}: rows stop short");
    true
}

/// Garbage, headers biased to the messages the report covers, and mutated built
/// units: a few tens of thousands of inputs and no panic.
#[test]
fn garbage_and_mutated_units_never_panic() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let (mut inputs, mut reported, mut refused) = (0usize, 0usize, 0usize);
    let mids = [
        wire_const::T_MID_INIT,
        wire_const::T_MID_OPEN,
        wire_const::T_MID_CLOSE,
        wire_const::T_MID_KEEP_ALIVE,
        wire_const::T_MID_FRAME,
        wire_const::T_MID_FRAGMENT,
    ];
    for round in 0..9_000usize {
        let len = rng.below(97);
        let mut bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        if round % 2 == 0 && !bytes.is_empty() {
            // Aim at the messages the report covers, with random flags.
            bytes[0] = mids[rng.below(mids.len())] | (rng.next() as u8 & 0xE0);
        }
        for framing in Framing::ALL {
            let mut unit = bytes.clone();
            let prefix = framing.prefix_bytes();
            if round % 3 == 0 && unit.len() >= prefix {
                // A prefix that tells the truth, so the message itself is reached.
                let body = (unit.len() - prefix) as u32;
                unit[..prefix].copy_from_slice(&body.to_le_bytes()[..prefix]);
            }
            let doc = layout_document(&unit, framing, Some(rng.next()));
            inputs += 1;
            if check_answer_with_ring(&unit, framing, &doc) {
                reported += 1;
            } else {
                refused += 1;
            }
        }
    }
    for (label, json, _) in corpus_descriptions() {
        for framing in Framing::ALL {
            let built = build(&json, framing).expect("builds").unit;
            for _ in 0..25 {
                let mut unit = built.clone();
                match rng.below(4) {
                    0 => {
                        // Flip one to three bytes.
                        for _ in 0..=rng.below(3) {
                            let at = rng.below(unit.len());
                            unit[at] ^= (rng.next() as u8) | 1;
                        }
                    }
                    1 => unit.truncate(rng.below(unit.len() + 1)),
                    2 => unit.extend((0..=rng.below(9)).map(|_| rng.next() as u8)),
                    _ => {
                        // Every byte after the prefix replaced at one position.
                        let at = rng.below(unit.len());
                        unit[at] = rng.next() as u8;
                    }
                }
                let doc = layout_document(&unit, framing, None);
                inputs += 1;
                if check_answer(&unit, framing, &doc) {
                    reported += 1;
                } else {
                    refused += 1;
                }
                let _ = &label;
            }
        }
    }
    eprintln!("fuzz: {inputs} inputs, {reported} reported, {refused} refused");
    assert!(inputs > 30_000, "only {inputs} inputs");
    assert!(reported > 2_000, "only {reported} reports");
    assert!(refused > 10_000, "only {refused} refusals");
}

/// The invariant check for a ring that was named: the same answer as without it
/// except in the two ring cells, which `check_answer` does not read.
fn check_answer_with_ring(unit: &[u8], framing: Framing, doc: &str) -> bool {
    let reported = check_answer(unit, framing, doc);
    let unnamed = layout_document(unit, framing, None);
    assert_eq!(is_refusal(doc), is_refusal(&unnamed), "{unit:02x?}");
    reported
}

// ------------------------------------------------------- the registry

/// One reading of the document's keys and vocabularies, and that they are the
/// build document's.
#[test]
fn the_layout_documents_vocabularies_are_the_build_documents() {
    let layout_shape = newest(TRANSPORT_LAYOUT).expect("a registered document");
    let build_shape = newest(TRANSPORT_BUILD).expect("a registered document");
    let words = |shape: &crate::doc_revision::DocumentShape| -> Vec<(String, Vec<String>)> {
        shape
            .families
            .iter()
            .map(|f| {
                (
                    f.key.to_string(),
                    f.values.iter().map(|v| v.to_string()).collect(),
                )
            })
            .collect()
    };
    assert_eq!(words(layout_shape), words(build_shape), "the same families");
    assert_eq!(
        layout_shape
            .carries
            .iter()
            .map(|c| (
                c.key,
                matches!(c.shape, crate::doc_revision::CarriesShape::Passenger)
            ))
            .collect::<Vec<_>>(),
        build_shape
            .carries
            .iter()
            .map(|c| (
                c.key,
                matches!(c.shape, crate::doc_revision::CarriesShape::Passenger)
            ))
            .collect::<Vec<_>>(),
        "the same carries verdicts"
    );
    // And the words are the report's own types', walked.
    let family = |key: &str| -> Vec<&'static str> {
        layout_shape
            .families
            .iter()
            .find(|f| f.key == key)
            .expect("a family")
            .values
            .to_vec()
    };
    let sorted = |mut v: Vec<&'static str>| {
        v.sort_unstable();
        v
    };
    assert_eq!(family("kind"), sorted(Kind::names()));
    assert_eq!(family("encoding"), sorted(Encoding::names()));
    assert_eq!(family("relative_to"), sorted(RelativeTo::names()));

    // The row keys of the two documents are the same, in the same order.
    let b = build(
        r#"{"message":"frame","reliable":true,"sn":5,"payload":"dead"}"#,
        Framing::TcpStream,
    )
    .expect("builds");
    let first_row = |doc: &str| -> Vec<String> {
        let Json5Value::Object(top) = json5::parse(doc).expect("JSON") else {
            panic!("an object")
        };
        let Some((_, Json5Value::Array(rows))) = top.iter().find(|(k, _)| k == "layout") else {
            panic!("a layout")
        };
        match &rows[0] {
            Json5Value::Object(entries) => entries.iter().map(|(k, _)| k.clone()).collect(),
            other => panic!("a row is an object: {other:?}"),
        }
    };
    assert_eq!(
        first_row(&layout_document(&b.unit, Framing::TcpStream, None)),
        first_row(&build_document(
            r#"{"message":"frame","reliable":true,"sn":5,"payload":"dead"}"#,
            Framing::TcpStream
        ))
    );
}

#[test]
fn the_document_uses_exactly_the_keys_the_registry_pins() {
    let mut docs = documents_for_the_carries_gate();
    docs.push(layout_document(&[], Framing::TcpStream, None));
    docs.push(layout_document(&[0x1F, 0], Framing::Datagram, None));
    let mut keys: Vec<&str> = Vec::new();
    for doc in &docs {
        keys.extend(key_set(doc));
    }
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys, TRANSPORT_LAYOUT_R1_KEYS, "{TRANSPORT_LAYOUT}");
    assert!(docs.iter().any(|d| d.contains("\"ok\":true")));
    assert!(docs.iter().any(|d| d.contains("\"ok\":false")));
}

/// The integer rule: a cell past 2^53 is a string, in this document as in the
/// build document, because one function writes both.
#[test]
fn a_cell_past_two_to_the_fifty_third_is_a_string() {
    let b = build(
        &format!(
            r#"{{"message":"frame","reliable":true,"sn":"{}"}}"#,
            u64::MAX
        ),
        Framing::Datagram,
    )
    .expect("builds");
    let doc = layout_document(&b.unit, Framing::Datagram, ring_max_of("64bit"));
    assert!(
        doc.contains(
            r#""width":9,"relative_to":"body","encoding":"vle","value":"18446744073709551615","min":"72057594037927936","max":"18446744073709551615""#
        ),
        "{doc}"
    );
    assert!(
        doc.contains(r#""ring_max":"9223372036854775807","ring_max_width":9"#),
        "{doc}"
    );
}

/// The hex of a unit the way `transport_build` prints it, round-tripped here so
/// the helpers above are held to the document they read.
#[test]
fn the_helpers_read_the_build_documents_unit() {
    let b = build(r#"{"message":"keep_alive"}"#, Framing::TcpStream).expect("builds");
    let doc = build_document(r#"{"message":"keep_alive"}"#, Framing::TcpStream);
    assert_eq!(unhex(&member(&doc, "unit")), b.unit);
    assert_eq!(hex(&b.unit), member(&doc, "unit"));
    assert_eq!(vle_len(127), 1);
    assert_eq!(vle_len(128), 2);
}
