// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_dissect_live_follow_next` across the boundary: one capture written as two
//! containers, read by one handle, says what the capture read as one container
//! says, and a handle that moved on reads no container again.
//!
//! The walk that numbers on and names sections apart is held in `wz-capture`
//! (`CaptureCursor::next_container`); what this file holds is the door, and
//! the documents a consumer reads from the handle it moved.

use super::*;

/// A stream link's framing unit: the message's length as two little-endian
/// bytes, then the message.
fn stream_unit(wire: &[u8]) -> Vec<u8> {
    let mut out = (wire.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(wire);
    out
}

/// A zenoh session over TCP from its first message, and a datagram flow beside
/// it: the dialler's InitSyn and OpenSyn and the acceptor's InitAck and OpenAck
/// are the first four packets, then keep-alives each way with a datagram
/// keep-alive between them. A capture cut after the fourth packet puts the
/// session's start in one container and all its traffic in the next.
fn session_packets() -> Vec<Vec<u8>> {
    let init_syn = stream_unit(&[0x01, 0x09, 0x32, 0xA1, 0xA1, 0xA1, 0xA1]);
    let init_ack = stream_unit(&[0x21, 0x09, 0x32, 0xB2, 0xB2, 0xB2, 0xB2, 0x00]);
    let open_syn = stream_unit(&[0x02, 10, 0, 0]);
    let open_ack = stream_unit(&[0x22, 10, 0]);
    let keepalive = stream_unit(&KEEPALIVE);
    let (mut a, mut b) = (1000u32, 5000u32);
    let mut packets = Vec::new();
    for (from_dialler, wire) in [
        (true, &init_syn),
        (false, &init_ack),
        (true, &open_syn),
        (false, &open_ack),
    ] {
        if from_dialler {
            packets.push(tcp_packet(a, wire));
            a += wire.len() as u32;
        } else {
            packets.push(tcp_packet_reverse(b, wire));
            b += wire.len() as u32;
        }
    }
    for _ in 0..3 {
        packets.push(tcp_packet(a, &keepalive));
        a += keepalive.len() as u32;
        packets.push(udp_packet(
            [10, 0, 0, 3],
            7447,
            [10, 0, 0, 4],
            7447,
            &KEEPALIVE,
        ));
        packets.push(tcp_packet_reverse(b, &keepalive));
        b += keepalive.len() as u32;
    }
    packets
}

/// A classic pcap of `packets[from..to]`, each at the instant it has in the
/// whole capture, so two containers cut from one capture carry its clock.
fn container(packets: &[Vec<u8>], from: usize, to: usize) -> Vec<u8> {
    let rows: Vec<(u32, u32, &[u8])> = packets[from..to]
        .iter()
        .zip(from as u32..)
        .map(|(p, i)| (0u32, i * 1_000, p.as_slice()))
        .collect();
    wz_capture::pcap::write(1, &rows)
}

/// `wz_dissect_live_follow_next` the way C calls it: the code and the number
/// the next container's first packet took.
fn follow_next(handle: *mut live::LiveDissection, bytes: &[u8]) -> (c_int, u64) {
    let mut first_packet = u64::MAX;
    let rc = unsafe {
        wz_dissect_live_follow_next(handle, bytes.as_ptr(), bytes.len(), &mut first_packet)
    };
    (rc, first_packet)
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

/// ONE CAPTURE READ AS TWO CONTAINERS SAYS WHAT IT SAYS READ AS ONE: the same
/// records, the same session table and the same census, with the session's
/// handshake in the first container and every message of its traffic in the
/// second. The second container's first packet takes the number after the
/// first container's last, and the handle's walk counts the second
/// container's bytes.
#[test]
fn a_capture_read_as_two_containers_says_what_it_says_read_as_one() {
    let packets = session_packets();
    let whole = container(&packets, 0, packets.len());
    let first = container(&packets, 0, 4);
    let second = container(&packets, 4, packets.len());

    let one = open_live(WZ_DISSECT_LIMITS_NONE).expect("the preset opens");
    assert_eq!(
        follow(one, &whole),
        WZ_DISSECT_OK,
        "the whole capture reads"
    );
    unsafe { wz_dissect_live_end(one) };

    let two = open_live(WZ_DISSECT_LIMITS_NONE).expect("the preset opens");
    assert_eq!(
        follow(two, &first),
        WZ_DISSECT_OK,
        "the first container reads"
    );
    assert_eq!(
        follow_next(two, &second),
        (WZ_DISSECT_OK, 4),
        "the next container's first packet is the fifth of the capture"
    );
    let mut consumed = usize::MAX;
    assert_eq!(
        unsafe { wz_dissect_live_followed(two, &mut consumed) },
        WZ_DISSECT_OK
    );
    assert_eq!(consumed, second.len(), "the walk is the next container's");
    unsafe { wz_dissect_live_end(two) };

    let records = drain_all(two);
    assert_eq!(records, drain_all(one), "the records");
    assert!(
        records.iter().any(|r| r.kind == 4 && r.anchor_space == 1),
        "the second container's stream keep-alives are records: {records:?}"
    );
    let table = session_table_of(two);
    assert_eq!(table, session_table_of(one), "the session table");
    assert!(
        table.contains("\"phase\":\"established\""),
        "the session the first container opened goes on in the second: {table}"
    );
    assert_eq!(
        call_live_census(two, "").expect("the planes render"),
        call_live_census(one, "").expect("the planes render"),
        "the census"
    );
    unsafe { wz_dissect_live_close(one) };
    unsafe { wz_dissect_live_close(two) };
}

/// A HANDLE THAT MOVED ON READS NO CONTAINER AGAIN AND IS LENT NONE: its packet
/// numbers count across containers, so the field document ignores the
/// container it is handed and says so, and lending one is refused. A handle
/// that read one container still reads it again.
#[test]
fn a_moved_handle_reads_no_container_again_and_is_lent_none() {
    let packets = session_packets();
    let whole = container(&packets, 0, packets.len());
    let first = container(&packets, 0, 4);
    let second = container(&packets, 4, packets.len());

    let one = open_live(WZ_DISSECT_LIMITS_NONE).expect("the preset opens");
    assert_eq!(follow(one, &whole), WZ_DISSECT_OK);
    let doc = live_fields(one, &whole);
    assert!(
        doc.contains("\"capture_reread\":true"),
        "a handle on its first container reads it again: {doc}"
    );
    unsafe { wz_dissect_live_close(one) };

    let two = open_live(WZ_DISSECT_LIMITS_NONE).expect("the preset opens");
    assert_eq!(follow(two, &first), WZ_DISSECT_OK);
    assert_eq!(follow_next(two, &second).0, WZ_DISSECT_OK);
    let doc = live_fields(two, &second);
    assert!(
        doc.contains("\"capture_reread\":false"),
        "a moved handle reads no container again: {doc}"
    );
    assert_eq!(
        unsafe { wz_dissect_live_follow_lent(two, second.as_ptr(), second.len()) },
        WZ_DISSECT_ERR_INVALID_ARG,
        "a moved handle is lent no container"
    );
    unsafe { wz_dissect_live_close(two) };
}

/// A HANDLE THAT HAS READ NOTHING IS NOT MOVED: the door is then the follow
/// door, the first packet is number 0, and the container is read again by the
/// field document. A null argument is refused.
#[test]
fn a_handle_that_has_read_nothing_is_not_moved_and_nulls_are_refused() {
    let packets = session_packets();
    let whole = container(&packets, 0, packets.len());
    let h = open_live(WZ_DISSECT_LIMITS_NONE).expect("the preset opens");
    assert_eq!(follow_next(h, &whole), (WZ_DISSECT_OK, 0));
    let doc = live_fields(h, &whole);
    assert!(
        doc.contains("\"capture_reread\":true"),
        "an unmoved handle reads its container again: {doc}"
    );

    let mut first_packet = 0u64;
    assert_eq!(
        unsafe {
            wz_dissect_live_follow_next(core::ptr::null_mut(), whole.as_ptr(), 1, &mut first_packet)
        },
        WZ_DISSECT_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { wz_dissect_live_follow_next(h, core::ptr::null(), 0, &mut first_packet) },
        WZ_DISSECT_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe {
            wz_dissect_live_follow_next(h, whole.as_ptr(), whole.len(), core::ptr::null_mut())
        },
        WZ_DISSECT_ERR_INVALID_ARG
    );
    unsafe { wz_dissect_live_close(h) };
}
