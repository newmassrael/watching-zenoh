// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_dissect_transport_build` across the boundary.
//!
//! The mechanism is held where it lives (`wz-capture`'s `transport_build_tests`:
//! the independent oracle, the dissector round trip, the report replacements).
//! What this crate adds is the boundary, so that is what is held here: raw
//! pointers in, an owned string out, a caller's bug as an error code and a
//! refused description as a diagnosis, and a built message that reads back
//! through the OTHER door, `wz_dissect_transport_message`, which is the door
//! the claim pairs this one with.

use super::*;

/// Drive the door the way C does.
pub(super) fn call(description: &str, framing: c_int) -> Result<String, c_int> {
    let text = CString::new(description).expect("no interior NUL");
    let mut out: *mut c_char = core::ptr::null_mut();
    let rc = unsafe { wz_dissect_transport_build(text.as_ptr(), framing, &mut out) };
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

/// One document of each shape the door writes: a built message in each framing,
/// a description that is not JSON, one refused at a key, one refused for a
/// value, and a body the framing cannot hold.
pub(super) fn documents() -> Vec<String> {
    let long = "ab".repeat(70_000);
    vec![
        call(
            r#"{"message":"frame","reliable":true,"sn":5,"priority":3,"payload":"dead"}"#,
            WZ_DISSECT_FRAMING_TCP_STREAM,
        ),
        call(
            r#"{"message":"init_syn","version":5,"whatami":"peer","zid":"b0b1b2b3"}"#,
            WZ_DISSECT_FRAMING_DATAGRAM,
        ),
        call(
            r#"{"message":"close","reason":2,"session":true}"#,
            WZ_DISSECT_FRAMING_LOWLATENCY_STREAM,
        ),
        call("{\"message\":", WZ_DISSECT_FRAMING_TCP_STREAM),
        call(r#"{"message":"scout"}"#, WZ_DISSECT_FRAMING_TCP_STREAM),
        call(
            r#"{"message":"frame","reliable":true,"sn":300,"sn_resolution":"8bit"}"#,
            WZ_DISSECT_FRAMING_TCP_STREAM,
        ),
        call(
            &format!(r#"{{"message":"frame","reliable":true,"sn":1,"payload":"{long}"}}"#),
            WZ_DISSECT_FRAMING_TCP_STREAM,
        ),
    ]
    .into_iter()
    .map(|r| r.expect("a description is always answered"))
    .collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// A message built through this door reads back through the reading door, to
/// the fields it was given, and the unit is the framing's prefix then the body.
#[test]
fn a_built_message_reads_back_through_the_reading_door() {
    for (description, framing, expect) in [
        (
            r#"{"message":"frame","reliable":true,"sn":5,"payload":"dead"}"#,
            WZ_DISSECT_FRAMING_TCP_STREAM,
            vec!["\"name\":\"sn\",\"start\":1,\"end\":2,\"kind\":\"uint\",\"value\":5"],
        ),
        (
            r#"{"message":"init_ack","version":5,"whatami":"client","zid":"a0a1","cookie":"c0c1c2"}"#,
            WZ_DISSECT_FRAMING_DATAGRAM,
            vec![
                "\"name\":\"whatami\",\"start\":2,\"end\":3,\"kind\":\"bits\",\"value\":2",
                "\"name\":\"cookie_len\"",
                "\"name\":\"cookie\"",
            ],
        ),
        (
            r#"{"message":"open_syn","lease_ms":10000,"initial_sn":7,"cookie":"01"}"#,
            WZ_DISSECT_FRAMING_LOWLATENCY_STREAM,
            vec![
                "\"name\":\"lease\",\"start\":1,\"end\":2,\"kind\":\"uint\",\"value\":10",
                "\"name\":\"initial_sn\",\"start\":2,\"end\":3,\"kind\":\"uint\",\"value\":7",
            ],
        ),
        (
            r#"{"message":"fragment","reliable":false,"more":true,"sn":300,"first":true,"payload":"beef"}"#,
            WZ_DISSECT_FRAMING_TCP_STREAM,
            vec![
                "\"name\":\"m\",\"start\":0,\"end\":1,\"kind\":\"flag\",\"value\":true",
                "\"name\":\"sn\",\"start\":1,\"end\":3,\"kind\":\"uint\",\"value\":300",
            ],
        ),
        (
            r#"{"message":"close","reason":7,"session":false}"#,
            WZ_DISSECT_FRAMING_DATAGRAM,
            vec![
                "\"name\":\"s\",\"start\":0,\"end\":1,\"kind\":\"flag\",\"value\":false",
                "\"name\":\"reason\",\"start\":1,\"end\":2,\"kind\":\"uint\",\"value\":7",
            ],
        ),
        (
            r#"{"message":"keep_alive"}"#,
            WZ_DISSECT_FRAMING_TCP_STREAM,
            vec!["\"name\":\"KeepAlive\""],
        ),
    ] {
        let doc = call(description, framing).expect("answers");
        assert!(doc.contains("\"ok\":true"), "{description}: {doc}");
        let body = unhex(&json_string(&doc, "body"));
        let unit = unhex(&json_string(&doc, "unit"));
        let prefix = json_count(&doc, "prefix_bytes");
        assert_eq!(unit.len(), prefix + body.len(), "{description}");
        assert_eq!(&unit[prefix..], &body[..], "{description}");
        let announced = unit[..prefix]
            .iter()
            .rev()
            .fold(0usize, |acc, b| acc << 8 | *b as usize);
        if prefix > 0 {
            assert_eq!(announced, body.len(), "{description}");
        }
        let read = call_transport(&body).expect("the reading door reads what was built");
        for needle in expect {
            assert!(
                read.contains(needle),
                "{description}: `{needle}` not in {read}"
            );
        }
    }
}

/// The header's worked example is what the door writes: the opening of the
/// document and its first row, and the refusal, as `wz_dissect.h` prints them.
/// An example nothing runs is a number in a comment, and this header has been
/// found stale about its examples before.
#[test]
fn the_headers_example_is_what_the_door_writes() {
    const HEADER: &str = include_str!("../../include/wz_dissect.h");
    // The header's comment markers and line breaks are not part of a document.
    let flat: String = HEADER
        .lines()
        .map(|l| l.trim_start().trim_start_matches('*').trim())
        .collect::<Vec<_>>()
        .join("");
    let flat: String = flat.split_whitespace().collect();

    let doc = call(
        r#"{"message":"frame","reliable":true,"sn":5,"priority":3,"payload":"dead"}"#,
        WZ_DISSECT_FRAMING_TCP_STREAM,
    )
    .expect("answers");
    // Up to and including the first row, which is the stream prefix.
    let first_row_end = doc.find("},{").expect("a second row");
    let opening: String = doc[..=first_row_end].split_whitespace().collect();
    assert!(
        flat.contains(&opening),
        "the header's example no longer opens the way the door writes it:\n{opening}"
    );

    let refused = call(
        r#"{"message":"frame","reliable":true,"sn":300,"sn_resolution":"8bit"}"#,
        WZ_DISSECT_FRAMING_DATAGRAM,
    )
    .expect("answers");
    let reason = json_string(&refused, "reason");
    assert!(
        HEADER.contains(&format!("\"reason\":\"{reason}\"")),
        "the header's refusal example no longer carries the reason the door writes: {reason}"
    );
}

#[test]
fn the_prefix_of_each_framing_is_its_width() {
    for (framing, width) in [
        (WZ_DISSECT_FRAMING_DATAGRAM, 0),
        (WZ_DISSECT_FRAMING_TCP_STREAM, 2),
        (WZ_DISSECT_FRAMING_LOWLATENCY_STREAM, 4),
    ] {
        let doc = call(r#"{"message":"keep_alive"}"#, framing).expect("answers");
        assert_eq!(json_count(&doc, "prefix_bytes"), width, "{doc}");
    }
}

/// What is the caller's bug is an error code and no string; what a person
/// typed is a diagnosis.
#[test]
fn a_callers_bug_is_a_code_and_a_refused_description_is_a_diagnosis() {
    let ok = r#"{"message":"keep_alive"}"#;
    for framing in [3, -1, 99] {
        assert_eq!(
            call(ok, framing),
            Err(WZ_DISSECT_ERR_INVALID_ARG),
            "{framing}"
        );
    }
    let mut out: *mut c_char = core::ptr::null_mut();
    let text = CString::new(ok).expect("no NUL");
    assert_eq!(
        unsafe {
            wz_dissect_transport_build(core::ptr::null(), WZ_DISSECT_FRAMING_DATAGRAM, &mut out)
        },
        WZ_DISSECT_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe {
            wz_dissect_transport_build(
                text.as_ptr(),
                WZ_DISSECT_FRAMING_DATAGRAM,
                core::ptr::null_mut(),
            )
        },
        WZ_DISSECT_ERR_INVALID_ARG
    );
    let bad_utf8 = CString::new(vec![b'{', 0xFF, b'}']).expect("no NUL");
    assert_eq!(
        unsafe {
            wz_dissect_transport_build(bad_utf8.as_ptr(), WZ_DISSECT_FRAMING_DATAGRAM, &mut out)
        },
        WZ_DISSECT_ERR_INVALID_ARG
    );
    assert!(out.is_null());

    let refused = call(
        r#"{"message":"frame","reliable":true,"sn":300,"sn_resolution":"8bit"}"#,
        WZ_DISSECT_FRAMING_DATAGRAM,
    )
    .expect("a refused description is answered");
    assert!(
        refused.contains("\"ok\":false,\"description_path\":\"/sn\""),
        "{refused}"
    );
    let text = call("{\"message\":", WZ_DISSECT_FRAMING_DATAGRAM).expect("answered");
    assert!(text.contains("\"description_offset\""), "{text}");
}

/// The boundary adds nothing to the library call it wraps.
#[test]
fn the_boundary_adds_nothing_to_the_library_call() {
    use wz_session_core::transport_compose::Framing;
    let description = r#"{"message":"open_ack","lease_ms":0,"initial_sn":1}"#;
    for (framing, abi) in [
        (Framing::Datagram, WZ_DISSECT_FRAMING_DATAGRAM),
        (Framing::TcpStream, WZ_DISSECT_FRAMING_TCP_STREAM),
        (
            Framing::LowLatencyStream,
            WZ_DISSECT_FRAMING_LOWLATENCY_STREAM,
        ),
    ] {
        assert_eq!(
            call(description, abi).expect("answers"),
            wz_capture::transport_build_json::build_document(description, framing)
        );
    }
}
