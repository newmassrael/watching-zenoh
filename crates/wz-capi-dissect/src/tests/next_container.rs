// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_dissect_live_follow_next` across the boundary: one capture written as two
//! containers, read by one handle, says what the capture read as one container
//! says, and a handle that moved on reads the container it follows now again.
//! The same capture lent as two containers reads as it does handed over, and
//! the handle says which containers it still reads.
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

/// `wz_dissect_live_follow_lent` the way C calls it.
fn follow_lent(handle: *mut live::LiveDissection, bytes: &[u8]) -> c_int {
    unsafe { wz_dissect_live_follow_lent(handle, bytes.as_ptr(), bytes.len()) }
}

/// `wz_dissect_live_follow_next_lent` the way C calls it: the code and the
/// number the next container's first packet took.
fn follow_next_lent(handle: *mut live::LiveDissection, bytes: &[u8]) -> (c_int, u64) {
    let mut first_packet = u64::MAX;
    let rc = unsafe {
        wz_dissect_live_follow_next_lent(handle, bytes.as_ptr(), bytes.len(), &mut first_packet)
    };
    (rc, first_packet)
}

/// `wz_dissect_live_oldest_container` the way C calls it: `(oldest, current)`.
fn oldest_container(handle: *const live::LiveDissection) -> (u64, u64) {
    let (mut oldest, mut current) = (u64::MAX, u64::MAX);
    let rc = unsafe { wz_dissect_live_oldest_container(handle, &mut oldest, &mut current) };
    assert_eq!(rc, WZ_DISSECT_OK, "the oldest container door");
    (oldest, current)
}

/// Each record's bytes as the handle answers them, written out so two handles'
/// answers compare whatever holds the bytes.
fn bytes_of(handle: *const live::LiveDissection, records: &[WzDissectRecord]) -> Vec<String> {
    records
        .iter()
        .map(|r| format!("{:?}", unsafe { (*handle).message_bytes(r) }))
        .collect()
}

/// A classic pcap of `n` datagram keep-alives from one flow, each at the
/// instant its place in a capture of them gives, numbered from `from`.
fn keepalives(from: usize, n: usize) -> Vec<u8> {
    let packets: Vec<Vec<u8>> = (0..from + n)
        .map(|_| udp_packet([10, 0, 0, 3], 7447, [10, 0, 0, 4], 7447, &KEEPALIVE))
        .collect();
    container(&packets, from, from + n)
}

/// The datagram flows of a field document: from its `datagram_flows` key to
/// the `capture_reread` key the document writes after them.
fn datagram_flows_of(doc: &str) -> &str {
    let from = doc.find("\"datagram_flows\":").expect("datagram flows");
    let to = doc.find("\"capture_reread\":").expect("the reread verdict");
    &doc[from..to]
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

/// A HANDLE THAT MOVED ON READS THE CONTAINER IT FOLLOWS NOW AGAIN: its packet
/// numbers count across containers, and the field document finds the next
/// container's packets by them, so every datagram row of the capture, all of
/// them in the second container, comes out as a handle that read the capture as
/// one container writes it. It may be lent the container it follows.
#[test]
fn a_moved_handle_rereads_the_container_it_follows_and_may_be_lent_it() {
    let packets = session_packets();
    let whole = container(&packets, 0, packets.len());
    let first = container(&packets, 0, 4);
    let second = container(&packets, 4, packets.len());

    let one = open_live(WZ_DISSECT_LIMITS_NONE).expect("the preset opens");
    assert_eq!(follow(one, &whole), WZ_DISSECT_OK);
    let whole_doc = live_fields(one, &whole);
    assert!(
        whole_doc.contains("\"capture_reread\":true"),
        "a handle on its first container reads it again: {whole_doc}"
    );
    unsafe { wz_dissect_live_close(one) };

    let two = open_live(WZ_DISSECT_LIMITS_NONE).expect("the preset opens");
    assert_eq!(follow(two, &first), WZ_DISSECT_OK);
    assert_eq!(follow_next(two, &second).0, WZ_DISSECT_OK);
    let doc = live_fields(two, &second);
    assert!(
        doc.contains("\"capture_reread\":true"),
        "a moved handle reads the container it follows again: {doc}"
    );
    let datagrams = datagram_flows_of(&doc);
    assert!(
        datagrams.contains("\"messages\":[{"),
        "the second container's datagram keep-alives are rows: {doc}"
    );
    assert_eq!(
        datagrams,
        datagram_flows_of(&whole_doc),
        "the datagram rows, packet numbers and frame offsets included"
    );
    assert_eq!(
        follow_lent(two, &second),
        WZ_DISSECT_OK,
        "a moved handle is lent the container it follows"
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

/// ONE CAPTURE LENT AS TWO CONTAINERS READS AS IT DOES HANDED OVER: the same
/// records, the same bytes for every record (the session's handshake read from
/// the first container after the handle moved on to the second), the same
/// session table and census, and no copy of a stream's bytes kept. The handle
/// still reads the first container, and one that copied both reads neither.
#[test]
fn a_capture_lent_as_two_containers_reads_as_it_does_handed_over() {
    let packets = session_packets();
    let first = container(&packets, 0, 4);
    let second = container(&packets, 4, packets.len());

    let copied = open_live(WZ_DISSECT_LIMITS_NONE).expect("the preset opens");
    assert_eq!(follow(copied, &first), WZ_DISSECT_OK);
    assert_eq!(follow_next(copied, &second), (WZ_DISSECT_OK, 4));
    unsafe { wz_dissect_live_end(copied) };

    let lent = open_live(WZ_DISSECT_LIMITS_NONE).expect("the preset opens");
    assert_eq!(follow_lent(lent, &first), WZ_DISSECT_OK);
    assert_eq!(oldest_container(lent), (0, 0), "one container, read");
    assert_eq!(follow_next_lent(lent, &second), (WZ_DISSECT_OK, 4));
    unsafe { wz_dissect_live_end(lent) };

    let records = drain_all(lent);
    assert_eq!(records, drain_all(copied), "the records");
    assert!(
        records.iter().any(|r| r.anchor_space == 1 && r.anchor == 0),
        "the handshake's first stream message is a record: {records:?}"
    );
    assert_eq!(
        bytes_of(lent, &records),
        bytes_of(copied, &records),
        "every record's bytes, the first container's among them"
    );
    assert_eq!(session_table_of(lent), session_table_of(copied));
    assert_eq!(
        call_live_census(lent, "").expect("the planes render"),
        call_live_census(copied, "").expect("the planes render"),
        "the census"
    );
    let kept = |h: *const live::LiveDissection| unsafe { (*h).memory() }.dissection.stream_kept;
    assert_eq!(kept(lent), 0, "a lent stream keeps no copy of its bytes");
    assert!(
        kept(copied) > 0,
        "anti-vacuity: the copying handle keeps them"
    );
    assert_eq!(
        oldest_container(lent),
        (0, 1),
        "the handshake's bytes are still read from the first container"
    );
    assert_eq!(
        oldest_container(copied),
        (1, 1),
        "a handle that copied reads no container"
    );
    unsafe { wz_dissect_live_close(lent) };
    unsafe { wz_dissect_live_close(copied) };
}

/// THE OLDEST CONTAINER MOVES ON AS A CEILING LETS GO OF THE EARLIER ONE: with
/// two messages held per flow, once the second container's datagrams are read
/// the first container's are gone, the handle reads only the second, and what it
/// holds is read there. With no ceiling the first container is still read.
#[test]
fn the_oldest_container_moves_on_as_a_ceiling_lets_go_of_the_first() {
    let (first, second) = (keepalives(0, 3), keepalives(3, 3));

    let mut bounded: *mut live::LiveDissection = core::ptr::null_mut();
    assert_eq!(
        unsafe { wz_dissect_live_open_bounded(2, 0, &mut bounded) },
        WZ_DISSECT_OK
    );
    assert_eq!(follow_lent(bounded, &first), WZ_DISSECT_OK);
    assert_eq!(follow_next_lent(bounded, &second), (WZ_DISSECT_OK, 3));
    assert_eq!(
        oldest_container(bounded),
        (1, 1),
        "the first container's datagrams were let go of"
    );
    let records = drain_all(bounded);
    assert_eq!(records.len(), 2, "two held: {records:?}");
    // The census decodes every message held again, each from the container
    // its place names.
    assert!(
        call_live_census(bounded, "").is_ok(),
        "what is held is read from the second container"
    );

    let whole = open_live(WZ_DISSECT_LIMITS_NONE).expect("the preset opens");
    assert_eq!(follow_lent(whole, &first), WZ_DISSECT_OK);
    assert_eq!(follow_next_lent(whole, &second), (WZ_DISSECT_OK, 3));
    assert_eq!(
        oldest_container(whole),
        (0, 1),
        "control: with every datagram held the first container is still read"
    );
    unsafe { wz_dissect_live_close(bounded) };
    unsafe { wz_dissect_live_close(whole) };
}

/// The two doors refuse a null argument, and a handle that has read nothing is
/// not moved by the lending one.
#[test]
fn the_lending_next_door_and_the_oldest_door_refuse_nulls() {
    let first = keepalives(0, 1);
    let h = open_live(WZ_DISSECT_LIMITS_NONE).expect("the preset opens");
    let (mut n, mut m) = (0u64, 0u64);
    assert_eq!(
        unsafe {
            wz_dissect_live_follow_next_lent(h, first.as_ptr(), first.len(), core::ptr::null_mut())
        },
        WZ_DISSECT_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { wz_dissect_live_follow_next_lent(h, core::ptr::null(), 0, &mut n) },
        WZ_DISSECT_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { wz_dissect_live_oldest_container(core::ptr::null(), &mut n, &mut m) },
        WZ_DISSECT_ERR_INVALID_ARG
    );
    assert_eq!(
        unsafe { wz_dissect_live_oldest_container(h, core::ptr::null_mut(), &mut n) },
        WZ_DISSECT_ERR_INVALID_ARG
    );
    assert_eq!(follow_next_lent(h, &first), (WZ_DISSECT_OK, 0), "not moved");
    assert_eq!(oldest_container(h), (0, 0));
    unsafe { wz_dissect_live_close(h) };
}
