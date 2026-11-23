// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_dissect_live_open_with` across the boundary: the sized options a live
//! handle is opened under, the refusals of options this library cannot honour,
//! and a serial line declared through them read as a session.
//!
//! The serial reader is held where it lives (`wz-capture`'s `serial` module
//! and the session table's tests); what this file holds is that a declaration
//! made through the ABI reaches it, and what each document then says.

use super::*;

/// The options a test opens a handle under: `limits` and nothing else set,
/// with `size` the size this crate was compiled against.
fn options(limits: c_int) -> WzDissectLiveOptions {
    WzDissectLiveOptions {
        size: core::mem::size_of::<WzDissectLiveOptions>(),
        limits,
        ..WzDissectLiveOptions::ZERO
    }
}

/// `wz_dissect_live_open_with` the way C calls it, with the refusal code when
/// it refuses.
fn open_with(options: *const WzDissectLiveOptions) -> Result<*mut live::LiveDissection, c_int> {
    let mut handle: *mut live::LiveDissection = core::ptr::null_mut();
    let rc = unsafe { wz_dissect_live_open_with(options, &mut handle) };
    if rc != WZ_DISSECT_OK {
        assert!(handle.is_null(), "a refused open handed back a handle");
        return Err(rc);
    }
    assert!(!handle.is_null(), "OK came back with no handle");
    Ok(handle)
}

/// `wz_dissect_live_session_table` the way C calls it.
fn session_table_of(handle: *const live::LiveDissection) -> String {
    let mut out: *mut c_char = core::ptr::null_mut();
    let rc = unsafe { wz_dissect_live_session_table(handle, &mut out) };
    assert_eq!(rc, WZ_DISSECT_OK, "live session table rc");
    let doc = unsafe { std::ffi::CStr::from_ptr(out) }
        .to_str()
        .expect("utf8")
        .to_string();
    unsafe { wz_dissect_string_free(out) };
    doc
}

/// A file read through a handle the way the header tells a caller to read one
/// with options: the whole file followed, all of it consumed, then the end.
fn read_file(handle: *mut live::LiveDissection, file: &[u8]) {
    assert_eq!(follow(handle, file), WZ_DISSECT_OK, "the file reads");
    let mut consumed = usize::MAX;
    let rc = unsafe { wz_dissect_live_followed(handle, &mut consumed) };
    assert_eq!(rc, WZ_DISSECT_OK);
    assert_eq!(consumed, file.len(), "a whole file is consumed whole");
    unsafe { wz_dissect_live_end(handle) };
}

/// THE LAYOUT IS THE ONE THE HEADER DECLARES on a 64-bit target, with no
/// padding inside it, and the first published size is the whole of it.
#[cfg(target_pointer_width = "64")]
#[test]
fn the_options_layout_is_the_one_the_header_declares() {
    use core::mem::{offset_of, size_of};
    type O = WzDissectLiveOptions;
    assert_eq!(offset_of!(O, size), 0);
    assert_eq!(offset_of!(O, limits), 8);
    assert_eq!(offset_of!(O, serial_link_type_count), 12);
    assert_eq!(offset_of!(O, serial_link_types), 16);
    assert_eq!(offset_of!(O, frames_per_flow), 24);
    assert_eq!(offset_of!(O, frames_total), 32);
    assert_eq!(
        LIVE_OPTIONS_FIRST_SIZE, 40,
        "the six fields the first published struct holds"
    );
    assert!(size_of::<O>() >= LIVE_OPTIONS_FIRST_SIZE);
}

/// EVERY OPTION THIS LIBRARY CANNOT HONOUR IS REFUSED, and none quietly
/// becomes a handle that ignores what was asked.
///
/// A null pointer either side, a size below the first published struct, an
/// unknown preset, a link-type count with no list, and a byte past this
/// library's struct that a newer header set. Zero bytes past it are a caller
/// compiled against a longer struct that set nothing this library does not
/// know, and open.
#[test]
fn the_options_door_refuses_what_it_cannot_honour() {
    let mut handle: *mut live::LiveDissection = core::ptr::null_mut();
    assert_eq!(
        unsafe { wz_dissect_live_open_with(core::ptr::null(), &mut handle) },
        WZ_DISSECT_ERR_INVALID_ARG,
        "a null options"
    );
    let none = options(WZ_DISSECT_LIMITS_NONE);
    assert_eq!(
        unsafe { wz_dissect_live_open_with(&none, core::ptr::null_mut()) },
        WZ_DISSECT_ERR_INVALID_ARG,
        "a null out"
    );

    let short = WzDissectLiveOptions {
        size: LIVE_OPTIONS_FIRST_SIZE - 1,
        ..options(WZ_DISSECT_LIMITS_NONE)
    };
    assert_eq!(
        open_with(&short),
        Err(WZ_DISSECT_ERR_INVALID_ARG),
        "a short size"
    );
    let zero = WzDissectLiveOptions {
        size: 0,
        ..options(WZ_DISSECT_LIMITS_NONE)
    };
    assert_eq!(
        open_with(&zero),
        Err(WZ_DISSECT_ERR_INVALID_ARG),
        "no size at all"
    );
    assert_eq!(
        open_with(&options(7)),
        Err(WZ_DISSECT_ERR_INVALID_ARG),
        "a preset this build does not know"
    );
    let listless = WzDissectLiveOptions {
        serial_link_type_count: 1,
        ..options(WZ_DISSECT_LIMITS_NONE)
    };
    assert_eq!(
        open_with(&listless),
        Err(WZ_DISSECT_ERR_INVALID_ARG),
        "a count with no list"
    );

    // A caller compiled against a longer struct than this library's: the
    // options at the front of a buffer, the size one word past this library's
    // struct, and that word the field this library does not know.
    let longer = |later: u64| {
        let known = core::mem::size_of::<WzDissectLiveOptions>();
        let mut words = [0u64; 16];
        let front = WzDissectLiveOptions {
            size: known + 8,
            ..options(WZ_DISSECT_LIMITS_NONE)
        };
        // SAFETY: the buffer is 128 bytes, 8-aligned, and the struct is smaller.
        unsafe { core::ptr::write(words.as_mut_ptr().cast::<WzDissectLiveOptions>(), front) };
        words[known / 8] = later;
        words
    };
    let set = longer(1);
    assert_eq!(
        open_with(set.as_ptr().cast()),
        Err(WZ_DISSECT_ERR_INVALID_ARG),
        "a field this library cannot honour"
    );
    let unset = longer(0);
    let handle =
        open_with(unset.as_ptr().cast()).expect("nothing past this library's struct is set");
    unsafe { wz_dissect_live_close(handle) };
}

/// THE OPTIONS DOOR IS THE TWO OPEN DOORS WITH THE OTHER FIELDS ZERO: the preset
/// alone opens what `wz_dissect_live_open` opens, and the two frame ceilings
/// arrive in `caps` and bite as `wz_dissect_live_open_bounded`'s do. Twelve
/// keep-alives over three flows under a per-flow ceiling of 4 and a total of 5
/// leave five held and seven taken.
#[test]
fn the_options_door_is_the_two_open_doors_with_the_other_fields_zero() {
    let preset = open_with(&options(WZ_DISSECT_LIMITS_LIVE_TAP)).expect("the preset opens");
    let doc = live_retention(preset).expect("a fresh handle");
    assert_eq!(
        in_group(&doc, "frames_per_flow", "frames_per_flow"),
        "10000",
        "{doc}"
    );
    assert_eq!(
        in_group(&doc, "frames_per_flow", "frames_total"),
        "100000",
        "{doc}"
    );
    unsafe { wz_dissect_live_close(preset) };

    let none = open_with(&options(WZ_DISSECT_LIMITS_NONE)).expect("the preset opens");
    let doc = live_retention(none).expect("a fresh handle");
    assert_eq!(
        in_group(&doc, "frames_per_flow", "frames_per_flow"),
        "null",
        "{doc}"
    );
    assert_eq!(
        in_group(&doc, "frames_per_flow", "frames_total"),
        "null",
        "{doc}"
    );
    unsafe { wz_dissect_live_close(none) };

    let bounded = open_with(&WzDissectLiveOptions {
        frames_per_flow: 4,
        frames_total: 5,
        ..options(WZ_DISSECT_LIMITS_LIVE_TAP)
    })
    .expect("the ceilings open");
    for i in 0..12u8 {
        let at = (i % 3) * 2;
        let packet = udp_packet(
            [10, 0, 0, 1 + at],
            7447,
            [10, 0, 0, 2 + at],
            7447,
            &KEEPALIVE,
        );
        push_live(bounded, WZ_DISSECT_NO_TIMESTAMP, &packet);
    }
    let doc = live_retention(bounded).expect("a fed handle");
    assert_eq!(
        in_group(&doc, "frames_per_flow", "frames_per_flow"),
        "4",
        "{doc}"
    );
    assert_eq!(
        in_group(&doc, "frames_per_flow", "frames_total"),
        "5",
        "{doc}"
    );
    assert_eq!(
        in_group(&doc, "stream_flows", "frames"),
        "5",
        "held in all: {doc}"
    );
    assert_eq!(
        in_group(&doc, "scout_askers", "frames"),
        "7",
        "taken: {doc}"
    );
    unsafe { wz_dissect_live_close(bounded) };
}

/// A SERIAL CAPTURE OPENED WITH ITS LINK TYPE DECLARED READS ITS SESSION AS
/// RECORDS, and the same capture opened without the declaration is skipped
/// packet by packet, as it was before the door existed.
///
/// The capture's two interfaces are the line's two wires and its first two
/// frames the line's own handshake, which names interface 0 the initiator's:
/// so the five zenoh messages are an Init and an Open each way and a
/// keep-alive, `a` from interface 0 and `b` from interface 1, each anchored at
/// the packet that carried its frame.
#[test]
fn a_declared_serial_capture_reads_as_records_and_an_undeclared_one_is_skipped() {
    let file = wz_capture::serial::line_capture(2, true);
    let link_types = [wz_capture::serial::FIXTURE_LINK_TYPE];
    let declared = open_with(&WzDissectLiveOptions {
        serial_link_type_count: 1,
        serial_link_types: link_types.as_ptr(),
        ..options(WZ_DISSECT_LIMITS_NONE)
    })
    .expect("a declaration opens");
    read_file(declared, &file);
    let records = drain_all(declared);
    // WZ_DISSECT_KIND_INIT, _OPEN and _KEEPALIVE, as literals: the numbers a C
    // consumer switches on.
    assert_eq!(
        records.iter().map(|r| r.kind).collect::<Vec<_>>(),
        vec![1, 1, 2, 2, 4],
        "{records:?}"
    );
    assert!(
        records.iter().all(|r| r.origin == 5 && r.anchor_space == 0),
        "every record is the serial line's (WZ_DISSECT_ORIGIN_SERIAL), anchored at \
         a packet: {records:?}"
    );
    assert_eq!(
        records.iter().map(|r| r.direction).collect::<Vec<_>>(),
        vec![0, 1, 0, 1, 0],
        "the handshake named interface 0 the initiator's"
    );
    assert_eq!(
        records.iter().map(|r| r.anchor).collect::<Vec<_>>(),
        vec![2, 3, 4, 5, 6],
        "the two handshake frames are packets 0 and 1 and carry no message"
    );
    let table = session_table_of(declared);
    assert!(table.contains("\"link\":\"serial\""), "{table}");
    assert!(
        table.contains("\"direction_basis\":\"handshake\""),
        "{table}"
    );
    let health = live_health(declared).expect("a handle");
    assert!(
        !health.contains("\"link_type\":147"),
        "a declared link type is read, not skipped: {health}"
    );
    unsafe { wz_dissect_live_close(declared) };

    let undeclared = open_live(WZ_DISSECT_LIMITS_NONE).expect("the preset opens");
    read_file(undeclared, &file);
    assert!(
        drain_all(undeclared).is_empty(),
        "nothing on the undeclared link type is read as serial"
    );
    let health = live_health(undeclared).expect("a handle");
    assert!(
        health.contains("\"interface\":0,\"link_type\":147,\"packets\":4")
            && health.contains("\"interface\":1,\"link_type\":147,\"packets\":3"),
        "every packet of the undeclared line is skipped, per interface: {health}"
    );
    unsafe { wz_dissect_live_close(undeclared) };
}

/// ONE INTERFACE CANNOT SEPARATE THE WIRES, and the session table says so in its
/// own word: the records all read `a` and the flow's `direction_basis` is
/// `unknown`.
#[test]
fn a_serial_capture_on_one_interface_says_its_directions_are_unknown() {
    let file = wz_capture::serial::line_capture(1, false);
    let link_types = [wz_capture::serial::FIXTURE_LINK_TYPE];
    let handle = open_with(&WzDissectLiveOptions {
        serial_link_type_count: 1,
        serial_link_types: link_types.as_ptr(),
        ..options(WZ_DISSECT_LIMITS_NONE)
    })
    .expect("a declaration opens");
    read_file(handle, &file);
    let records = drain_all(handle);
    assert_eq!(records.len(), 5, "{records:?}");
    assert!(records.iter().all(|r| r.direction == 0), "{records:?}");
    let table = session_table_of(handle);
    assert!(
        table.contains("\"direction_basis\":\"unknown\""),
        "one interface separates nothing: {table}"
    );
    unsafe { wz_dissect_live_close(handle) };
}
