// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_dissect_pcap_session_table` and `wz_dissect_live_session_table` across
//! the boundary.
//!
//! The mechanism is held where it lives (`wz-capture`'s `session_table_tests`:
//! the oracle against the census and the field document, the retention
//! invariance, every reason a cell can carry, the refusals by cause). What this
//! crate adds is the boundary, so that is what is held here: raw pointers in, an
//! owned string out, a caller's bug as an error code and a container that does
//! not read as a document, the two halves writing one document, and the ceiling
//! saying what it cost.

use super::*;

/// Drive the container door the way C does.
pub(super) fn call_pcap(bytes: &[u8], limits: c_int) -> Result<String, c_int> {
    let mut out: *mut c_char = core::ptr::null_mut();
    let rc =
        unsafe { wz_dissect_pcap_session_table(bytes.as_ptr(), bytes.len(), limits, &mut out) };
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

/// Drive the handle door the way C does.
fn call_live(handle: *const live::LiveDissection) -> Result<String, c_int> {
    let mut out: *mut c_char = core::ptr::null_mut();
    let rc = unsafe { wz_dissect_live_session_table(handle, &mut out) };
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

const ZID_A: [u8; 4] = [0xA1; 4];
const ZID_B: [u8; 4] = [0xB2; 4];
/// 1.7e9 seconds: a real clock, which is past 2^53 nanoseconds.
const EPOCH_S: u32 = 1_700_000_000;

fn init(zid: &[u8], ack: bool) -> Vec<u8> {
    let mut wire = vec![
        wz_session_core::wire_const::T_MID_INIT | if ack { 0x20 } else { 0 },
        0x09,
        (((zid.len() as u8) - 1) << 4) | 0x02,
    ];
    wire.extend_from_slice(zid);
    if ack {
        wire.push(0);
    }
    wire
}

fn keepalive() -> Vec<u8> {
    vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE]
}

/// A capture of UDP datagrams, one transport message each, microseconds apart.
fn udp_capture(sport: u16, messages: &[(bool, Vec<u8>)]) -> Vec<u8> {
    let packets: Vec<Vec<u8>> = messages
        .iter()
        .map(|(from_dialer, wire)| {
            if *from_dialer {
                udp_packet([10, 0, 0, 1], sport, [10, 0, 0, 2], 7447, wire)
            } else {
                udp_packet([10, 0, 0, 2], 7447, [10, 0, 0, 1], sport, wire)
            }
        })
        .collect();
    let rows: Vec<(u32, u32, &[u8])> = packets
        .iter()
        .enumerate()
        .map(|(i, p)| (EPOCH_S, (i as u32 + 1) * 1_000, p.as_slice()))
        .collect();
    wz_capture::pcap::write(LINKTYPE_ETHERNET, &rows)
}

/// A session from its start: an InitSyn, an InitAck and `n` keep-alives.
fn session(n: usize) -> Vec<u8> {
    let mut messages = vec![(true, init(&ZID_A, false)), (false, init(&ZID_B, true))];
    messages.extend((0..n).map(|i| (i % 2 == 0, keepalive())));
    udp_capture(43210, &messages)
}

/// The same flow joined after its handshake.
fn midstream(n: usize) -> Vec<u8> {
    let messages: Vec<(bool, Vec<u8>)> = (0..n).map(|i| (i % 2 == 0, keepalive())).collect();
    udp_capture(43210, &messages)
}

/// One document of each shape the doors write: a session, a flow joined after
/// its handshake, a QUIC flow nobody decrypted, and a refusal of each kind the
/// bytes can earn.
pub(super) fn documents() -> Vec<String> {
    let quic = {
        let mut initial = vec![
            0xC0, 0, 0, 0, 1, 4, 1, 2, 3, 4, 4, 5, 6, 7, 8, 0, 0x40, 0x10,
        ];
        initial.resize(64, 0);
        let packet = udp_packet([10, 0, 0, 1], 4433, [10, 0, 0, 2], 7447, &initial);
        wz_capture::pcap::write(LINKTYPE_ETHERNET, &[(EPOCH_S, 1_000, packet.as_slice())])
    };
    let full = session(3);
    let cut = &full[..full.len() - 5];
    [
        call_pcap(&full, WZ_DISSECT_LIMITS_NONE),
        call_pcap(&midstream(2), WZ_DISSECT_LIMITS_NONE),
        call_pcap(&quic, WZ_DISSECT_LIMITS_NONE),
        call_pcap(
            b"this is not a capture, and not close to one",
            WZ_DISSECT_LIMITS_NONE,
        ),
        call_pcap(cut, WZ_DISSECT_LIMITS_NONE),
    ]
    .into_iter()
    .map(|r| r.expect("a document, whatever the bytes"))
    .collect()
}

/// A SESSION CROSSES THE BOUNDARY with the cells a consumer maps, the zids in the
/// census's own spelling, and the instants as strings (a real clock is past 2^53).
#[test]
fn a_session_crosses_the_boundary_with_every_cell_stated() {
    let doc = call_pcap(&session(4), WZ_DISSECT_LIMITS_NONE).expect("answers");
    let a = wz_session_core::zid_hex::zid_to_zenoh_hex(&ZID_A);
    let b = wz_session_core::zid_hex::zid_to_zenoh_hex(&ZID_B);
    assert!(
        doc.starts_with(&format!(
            "{{\"document\":{{\"name\":\"session_table\",\"revision\":1}},\"ok\":true,\
             \"sessions\":[{{\"initiator\":\"{a}\",\"acceptor\":\"{b}\",\"link\":\"udp\",\
             \"phase\":\"init_complete\",\"encrypted\":\"clear\","
        )),
        "{doc}"
    );
    // Six datagrams, one message each, and the payload bytes of each.
    let want_bytes = init(&ZID_A, false).len() + init(&ZID_B, true).len() + 4;
    assert!(
        doc.contains(&format!(
            "\"frames\":6,\"bytes\":{want_bytes},\"unstated\":[],\"flows\":["
        )),
        "{doc}"
    );
    assert!(
        doc.contains("\"first_seen_ts_ns\":\"1700000000001000000\",\"last_seen_ts_ns\":\"1700000000006000000\""),
        "an instant on a real clock is a string: {doc}"
    );
}

/// THE TWO HALVES WRITE ONE DOCUMENT, for the same packets at the same instants,
/// under either preset: the handle door is the container door over the handle's
/// dissection, and anything else would be a second reader of the same facts.
#[test]
fn the_two_halves_write_one_document() {
    for file in [session(5), midstream(3)] {
        for limits in [WZ_DISSECT_LIMITS_NONE, WZ_DISSECT_LIMITS_LIVE_TAP] {
            let from_container = call_pcap(&file, limits).expect("answers");
            let handle = replay(&file, limits).expect("the capture reads");
            let from_handle = call_live(handle);
            unsafe { wz_dissect_live_close(handle) };
            assert_eq!(
                from_handle.expect("answers"),
                from_container,
                "limits {limits}: the handle and the container must agree"
            );
        }
    }
}

/// A HANDLE FED PACKET BY PACKET gives the document a container of the same
/// packets gives, which is what lets a consumer move between the halves.
#[test]
fn a_handle_fed_by_push_agrees_with_the_container() {
    let messages = vec![
        (true, init(&ZID_A, false)),
        (false, init(&ZID_B, true)),
        (true, keepalive()),
    ];
    let file = udp_capture(43210, &messages);
    let mut handle: *mut live::LiveDissection = core::ptr::null_mut();
    assert_eq!(
        unsafe { wz_dissect_live_open(WZ_DISSECT_LIMITS_NONE, &mut handle) },
        WZ_DISSECT_OK
    );
    for (i, (from_dialer, wire)) in messages.iter().enumerate() {
        let packet = if *from_dialer {
            udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, wire)
        } else {
            udp_packet([10, 0, 0, 2], 7447, [10, 0, 0, 1], 43210, wire)
        };
        let ts_ns = u64::from(EPOCH_S) * 1_000_000_000 + (i as u64 + 1) * 1_000_000;
        assert_eq!(
            unsafe {
                wz_dissect_live_push(
                    handle,
                    LINKTYPE_ETHERNET,
                    ts_ns,
                    packet.as_ptr(),
                    packet.len(),
                )
            },
            WZ_DISSECT_OK
        );
    }
    let pushed = call_live(handle).expect("answers");
    unsafe { wz_dissect_live_close(handle) };
    assert_eq!(
        pushed,
        call_pcap(&file, WZ_DISSECT_LIMITS_NONE).expect("answers")
    );
}

/// A PACKET PUSHED WITH NO TIMESTAMP leaves both instants unstated, and says why.
#[test]
fn a_packet_with_no_timestamp_is_no_clock() {
    let mut handle: *mut live::LiveDissection = core::ptr::null_mut();
    assert_eq!(
        unsafe { wz_dissect_live_open(WZ_DISSECT_LIMITS_NONE, &mut handle) },
        WZ_DISSECT_OK
    );
    let packet = udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &keepalive());
    assert_eq!(
        unsafe {
            wz_dissect_live_push(
                handle,
                LINKTYPE_ETHERNET,
                WZ_DISSECT_NO_TIMESTAMP,
                packet.as_ptr(),
                packet.len(),
            )
        },
        WZ_DISSECT_OK
    );
    let doc = call_live(handle).expect("answers");
    unsafe { wz_dissect_live_close(handle) };
    assert!(
        doc.contains("\"first_seen_ts_ns\":null,\"last_seen_ts_ns\":null"),
        "{doc}"
    );
    assert!(
        doc.contains("{\"cell\":\"first_seen_ts_ns\",\"reason\":\"no_clock\"}"),
        "{doc}"
    );
}

/// A BOUND THAT BITES IS SAID, and a flow it evicts has no row.
///
/// One capture of more flows than the live-tap ceiling holds, through both
/// presets: the unbounded table carries every flow and a group that reports no
/// bite, the bounded one carries one flow fewer and says one was dropped.
#[test]
fn a_session_table_can_be_bounded_and_says_what_the_bound_cost() {
    let file = capture_one_flow_past_the_tap_cap();
    let unbounded = call_pcap(&file, WZ_DISSECT_LIMITS_NONE).expect("answers");
    assert!(
        unbounded.contains(NO_CAPS_NO_BITE),
        "the unbounded table must carry the group and report no bite: {unbounded}"
    );
    let bounded = call_pcap(&file, WZ_DISSECT_LIMITS_LIVE_TAP).expect("answers");
    assert!(
        bounded.contains(LIVE_TAP_ONE_FLOW_BIT),
        "the live-tap flow cap must bite and the table must say so: {bounded}"
    );
    let rows = |doc: &str| doc.matches("{\"initiator\":").count();
    assert_eq!(rows(&unbounded), OVER_TAP_CAP, "a row per flow");
    assert_eq!(
        rows(&bounded),
        OVER_TAP_CAP - 1,
        "the flow the ceiling evicted has no row, and dropped_by_limits is where that is said"
    );
}

/// A container that does not read is a DOCUMENT, a refusal by name, and never an
/// error code or a panic; a caller's bug is a code and no string.
#[test]
fn a_bad_container_is_a_refusal_and_a_callers_bug_is_a_code() {
    let full = session(3);
    for (bytes, word) in [
        (
            &b"this is not a capture, and not close to one"[..],
            "not_a_capture",
        ),
        (&full[..full.len() - 5], "truncated"),
        (&full[..10], "truncated"),
        (&[][..], "truncated"),
    ] {
        let doc = call_pcap(bytes, WZ_DISSECT_LIMITS_NONE).expect("a refusal is answered");
        assert!(
            doc.starts_with(&format!(
                "{{\"document\":{{\"name\":\"session_table\",\"revision\":1}},\"ok\":false,\
                 \"refusal\":\"{word}\",\"message\":"
            )),
            "{doc}"
        );
        assert!(
            !doc.contains("\"sessions\""),
            "a refusal carries no rows: {doc}"
        );
    }

    // The caller's own bugs.
    assert_eq!(
        call_pcap(&full, 9),
        Err(WZ_DISSECT_ERR_INVALID_ARG),
        "an unknown preset"
    );
    assert_eq!(call_pcap(&full, -1), Err(WZ_DISSECT_ERR_INVALID_ARG));
    let mut out: *mut c_char = core::ptr::null_mut();
    assert_eq!(
        unsafe {
            wz_dissect_pcap_session_table(core::ptr::null(), 0, WZ_DISSECT_LIMITS_NONE, &mut out)
        },
        WZ_DISSECT_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe {
            wz_dissect_pcap_session_table(
                full.as_ptr(),
                full.len(),
                WZ_DISSECT_LIMITS_NONE,
                core::ptr::null_mut(),
            )
        },
        WZ_DISSECT_ERR_INVALID_ARG
    );
    assert!(out.is_null());
    assert_eq!(
        call_live(core::ptr::null()),
        Err(WZ_DISSECT_ERR_INVALID_ARG)
    );
    let mut handle: *mut live::LiveDissection = core::ptr::null_mut();
    assert_eq!(
        unsafe { wz_dissect_live_open(WZ_DISSECT_LIMITS_NONE, &mut handle) },
        WZ_DISSECT_OK
    );
    assert_eq!(
        unsafe { wz_dissect_live_session_table(handle, core::ptr::null_mut()) },
        WZ_DISSECT_ERR_INVALID_ARG
    );
    // An EMPTY handle answers with an empty table: nothing was seen, and that is
    // a document and not an error.
    let empty = call_live(handle).expect("an empty handle answers");
    unsafe { wz_dissect_live_close(handle) };
    assert!(empty.contains("\"sessions\":[]"), "{empty}");
}

/// The boundary adds nothing to the library call it wraps.
#[test]
fn the_boundary_adds_nothing_to_the_library_call() {
    let file = session(2);
    let dissection =
        Dissection::from_capture_bounded(&file, wz_capture::DissectionLimits::default())
            .expect("reads");
    assert_eq!(
        call_pcap(&file, WZ_DISSECT_LIMITS_NONE).expect("answers"),
        wz_capture::session_table_json::session_table_json(&dissection)
    );
}

/// THE ABI'S TWO DOORS ARE LISTED where the library says which door is current.
#[test]
fn the_container_door_is_in_the_doors_walk_and_joins_nothing() {
    let catalogue = call_readable_surfaces();
    assert!(
        catalogue.contains("{\"name\":\"wz_dissect_pcap_session_table\",\"subsumed_by\":null}"),
        "{catalogue}"
    );
}
