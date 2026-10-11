// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_dissect_transport_layout` across the boundary.
//!
//! The mechanism is held where it lives (`wz-capture`'s
//! `transport_layout_json_tests`: the build-door equality, the rows typed by
//! hand, every cut, the fuzz). What this crate adds is the boundary, so that is
//! what is held here: raw pointers in, an owned string out, a caller's bug as an
//! error code and bytes that do not read as a refusal VALUE, and the unit the
//! build door makes through this ABI reported by this door through this ABI.

use super::*;

/// Drive the door the way C does.
pub(super) fn call(bytes: &[u8], framing: c_int, ring: Option<&str>) -> Result<String, c_int> {
    let ring = ring.map(|w| CString::new(w).expect("no interior NUL"));
    let mut out: *mut c_char = core::ptr::null_mut();
    let rc = unsafe {
        wz_dissect_transport_layout(
            bytes.as_ptr(),
            bytes.len(),
            framing,
            ring.as_ref().map_or(core::ptr::null(), |r| r.as_ptr()),
            &mut out,
        )
    };
    if rc != WZ_DISSECT_OK {
        assert!(out.is_null(), "an error must not hand back a string");
        return Err(rc);
    }
    assert!(!out.is_null(), "OK must come with a string");
    let s = unsafe { std::ffi::CStr::from_ptr(out) }
        .to_str()
        .expect("utf8")
        .to_string();
    unsafe { wz_dissect_string_free(out) };
    Ok(s)
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// One document of each shape the door writes: a report in each framing, a
/// refusal for bytes that end inside a field, one for a prefix that lies, and
/// one for a message the report does not cover.
pub(super) fn documents() -> Vec<String> {
    vec![
        call(
            &[0x04, 0x00, 0x25, 0x05, 0xDE, 0xAD],
            WZ_DISSECT_FRAMING_TCP_STREAM,
            None,
        ),
        call(
            &[0x01, 0x05, 0x31, 0xB0, 0xB1, 0xB2, 0xB3],
            WZ_DISSECT_FRAMING_DATAGRAM,
            None,
        ),
        call(
            &[0x02, 0x00, 0x00, 0x00, 0x23, 0x02],
            WZ_DISSECT_FRAMING_LOWLATENCY_STREAM,
            Some("16bit"),
        ),
        call(&[0x01, 0x05], WZ_DISSECT_FRAMING_DATAGRAM, None),
        call(&[0x09, 0x00, 0x25], WZ_DISSECT_FRAMING_TCP_STREAM, None),
        call(&[0x07, 0, 0, 0, 0, 0], WZ_DISSECT_FRAMING_DATAGRAM, None),
    ]
    .into_iter()
    .map(|r| r.expect("bytes are always answered"))
    .collect()
}

/// A message built through the build door, through this ABI, is reported by this
/// door to the rows the build door reported: the same `layout` text.
#[test]
fn a_built_unit_is_reported_to_the_rows_the_build_door_gave() {
    let mut checked = 0usize;
    for (description, framing, ring) in [
        (
            r#"{"message":"frame","reliable":true,"sn":5,"priority":3,"payload":"dead"}"#,
            WZ_DISSECT_FRAMING_TCP_STREAM,
            None,
        ),
        (
            r#"{"message":"init_ack","version":5,"whatami":"client","zid":"a0a1","cookie":"c0c1c2"}"#,
            WZ_DISSECT_FRAMING_DATAGRAM,
            None,
        ),
        (
            r#"{"message":"open_syn","lease_ms":10000,"initial_sn":7,"cookie":"01","sn_resolution":"32bit"}"#,
            WZ_DISSECT_FRAMING_LOWLATENCY_STREAM,
            Some("32bit"),
        ),
        (
            r#"{"message":"fragment","reliable":false,"more":true,"sn":300,"first":true,"payload":"beef"}"#,
            WZ_DISSECT_FRAMING_TCP_STREAM,
            None,
        ),
        (
            r#"{"message":"close","reason":7,"session":false}"#,
            WZ_DISSECT_FRAMING_DATAGRAM,
            None,
        ),
        (
            r#"{"message":"keep_alive"}"#,
            WZ_DISSECT_FRAMING_TCP_STREAM,
            None,
        ),
    ] {
        let built = super::transport_build::call(description, framing).expect("answers");
        let unit = unhex(&json_string(&built, "unit"));
        let read = call(&unit, framing, ring).expect("answers");
        let layout_of = |doc: &str| doc[doc.find("\"layout\":[").expect("a layout")..].to_string();
        assert!(read.contains("\"ok\":true"), "{description}: {read}");
        // The build document ends `...]}` and so does this one.
        assert_eq!(layout_of(&read), layout_of(&built), "{description}");
        checked += 1;
    }
    assert_eq!(checked, 6);
}

/// What is the caller's bug is an error code and no string; what a link delivered
/// is a document.
#[test]
fn a_callers_bug_is_a_code_and_unreadable_bytes_are_a_refusal() {
    let unit = [0x25u8, 0x05, 0xDE, 0xAD];
    for framing in [3, -1, 99] {
        assert_eq!(
            call(&unit, framing, None),
            Err(WZ_DISSECT_ERR_INVALID_ARG),
            "{framing}"
        );
    }
    // A ring that is not one of the four words, in any spelling.
    for ring in ["7bit", "", "8BIT", "16 bit", "64bit "] {
        assert_eq!(
            call(&unit, WZ_DISSECT_FRAMING_DATAGRAM, Some(ring)),
            Err(WZ_DISSECT_ERR_INVALID_ARG),
            "{ring:?}"
        );
    }
    let mut out: *mut c_char = core::ptr::null_mut();
    assert_eq!(
        unsafe {
            wz_dissect_transport_layout(
                unit.as_ptr(),
                unit.len(),
                WZ_DISSECT_FRAMING_DATAGRAM,
                core::ptr::null(),
                core::ptr::null_mut(),
            )
        },
        WZ_DISSECT_ERR_INVALID_ARG
    );
    // Null bytes with a length is a bug; null bytes with none is an empty unit.
    assert_eq!(
        unsafe {
            wz_dissect_transport_layout(
                core::ptr::null(),
                4,
                WZ_DISSECT_FRAMING_DATAGRAM,
                core::ptr::null(),
                &mut out,
            )
        },
        WZ_DISSECT_ERR_INVALID_ARG
    );
    assert!(out.is_null());
    let bad_utf8 = CString::new(vec![b'8', 0xFF]).expect("no NUL");
    assert_eq!(
        unsafe {
            wz_dissect_transport_layout(
                unit.as_ptr(),
                unit.len(),
                WZ_DISSECT_FRAMING_DATAGRAM,
                bad_utf8.as_ptr(),
                &mut out,
            )
        },
        WZ_DISSECT_ERR_INVALID_ARG
    );
    assert!(out.is_null());
    let rc = unsafe {
        wz_dissect_transport_layout(
            core::ptr::null(),
            0,
            WZ_DISSECT_FRAMING_DATAGRAM,
            core::ptr::null(),
            &mut out,
        )
    };
    assert_eq!(rc, WZ_DISSECT_OK);
    let empty = unsafe { std::ffi::CStr::from_ptr(out) }
        .to_str()
        .expect("utf8")
        .to_string();
    unsafe { wz_dissect_string_free(out) };
    assert!(
        empty.starts_with(
            r#"{"document":{"name":"transport_layout","revision":1},"ok":false,"reason":""#
        ),
        "{empty}"
    );
    assert!(!empty.contains("\"layout\""), "{empty}");

    // Every cut of a unit is answered, and a refusal is one shape.
    let mut refused = 0usize;
    for framing in [
        WZ_DISSECT_FRAMING_DATAGRAM,
        WZ_DISSECT_FRAMING_TCP_STREAM,
        WZ_DISSECT_FRAMING_LOWLATENCY_STREAM,
    ] {
        let built = super::transport_build::call(
            r#"{"message":"open_syn","lease_ms":10000,"initial_sn":7,"cookie":"aabb"}"#,
            framing,
        )
        .expect("answers");
        let whole = unhex(&json_string(&built, "unit"));
        for cut in 0..whole.len() {
            let doc = call(&whole[..cut], framing, None).expect("a cut unit is answered");
            assert!(
                doc.contains("\"ok\":false") && !doc.contains("\"layout\""),
                "cut {cut}: {doc}"
            );
            refused += 1;
        }
        assert!(call(&whole, framing, None)
            .expect("answers")
            .contains("\"ok\":true"));
    }
    assert!(refused > 15, "{refused}");
}

/// The boundary adds nothing to the library call it wraps.
#[test]
fn the_boundary_adds_nothing_to_the_library_call() {
    use wz_session_core::transport_compose::Framing;
    let unit = [0x42u8, 0x0A, 0x07, 0x02, 0xAA, 0xBB];
    for (framing, abi) in [
        (Framing::Datagram, WZ_DISSECT_FRAMING_DATAGRAM),
        (Framing::TcpStream, WZ_DISSECT_FRAMING_TCP_STREAM),
        (
            Framing::LowLatencyStream,
            WZ_DISSECT_FRAMING_LOWLATENCY_STREAM,
        ),
    ] {
        let ring = wz_capture::transport_layout_json::ring_max_of("16bit");
        assert_eq!(
            call(&unit, abi, Some("16bit")).expect("answers"),
            wz_capture::transport_layout_json::layout_document(&unit, framing, ring)
        );
    }
}

/// The header's worked example is what the door writes: the opening of the
/// document and its first row, and the refusal, as `wz_dissect.h` prints them.
/// An example nothing runs is a number in a comment, and this header has been
/// found stale about its examples before.
#[test]
fn the_headers_example_is_what_the_door_writes() {
    const HEADER: &str = include_str!("../../include/wz_dissect.h");
    let flat: String = HEADER
        .lines()
        .map(|l| l.trim_start().trim_start_matches('*').trim())
        .collect::<Vec<_>>()
        .join("");
    let flat: String = flat.split_whitespace().collect();

    let doc = call(
        &[0x04, 0x00, 0x25, 0x05, 0xDE, 0xAD],
        WZ_DISSECT_FRAMING_TCP_STREAM,
        None,
    )
    .expect("answers");
    let first_row_end = doc.find("},{").expect("a second row");
    let opening: String = doc[..=first_row_end].split_whitespace().collect();
    assert!(
        flat.contains(&opening),
        "the header's example no longer opens the way the door writes it:\n{opening}"
    );

    let refused = call(
        &[0x04, 0x00, 0x25, 0x05, 0xDE],
        WZ_DISSECT_FRAMING_TCP_STREAM,
        None,
    )
    .expect("answers");
    let reason = json_string(&refused, "reason");
    assert!(
        HEADER.contains(&format!("\"reason\":\"{reason}\"")),
        "the header's refusal example no longer carries the reason the door writes: {reason}"
    );
}
