// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a RECORD'S TIME is, where it comes from, and how finely it is kept.
//!
//! Two consumer claims met in one mechanism and are graded together here.
//!
//! # Claim A: a record behind a hole in a byte stream took the capture's end
//!
//! A TCP segment that arrives ahead of a missing one is held; it is decoded when
//! the hole fills, when it has been waited on long enough, or when the capture
//! ends. The record decoded out of it used to be stamped with the observer's
//! clock AS OF THAT MOMENT, which is the clock of whichever packet was pushed
//! last, so every record that waited behind a hole read the instant the capture
//! stopped. On a real capture 62 of 98 stream records did, and `elapsed > 1000`
//! was true of rows nowhere near a second from their predecessors.
//!
//! The rule these tests hold down is that a record's time is the capture time of
//! the packet that carried its FIRST byte, the byte its `stream_offset` names and
//! the packet its row's `first_byte.packet` names. It is a property of the
//! record and of the capture, and not of when this reader got round to decoding
//! the bytes.
//!
//! # Claim B: the clock kept milliseconds
//!
//! Both ends of an interval were truncated to their millisecond before they were
//! subtracted, so a 0.575 ms round trip read 0 ms or 1 ms depending on where the
//! millisecond boundary fell. The clock now keeps the nanosecond, and every
//! millisecond figure is that divided down, rounded down: the `*_ms` keys keep
//! the values they had, and the nanosecond keys beside them are the same samples
//! unrounded.

use alloc::vec::Vec;

use wz_session_core::inbound::InboundFrame;
use wz_session_core::passive::{Direction, NANOS_PER_MILLI};

use crate::datagram_tests::{
    framed_frame, framed_keepalive, tcp_packet, tcp_packet_reverse, udp_packet,
};
use crate::link::LINKTYPE_ETHERNET;
use crate::Dissection;

/// An epoch instant in nanoseconds, well past 2^53 as a real clock is.
const T0: u64 = 1_700_000_000_000_000_000;

/// The gap between consecutive packets of these captures: not a whole
/// millisecond and not a whole microsecond, so a stamp that kept only one of
/// those would differ from the packet's own.
const STEP: u64 = 1_234_567;

/// The instant packet `index` of these captures was taken at.
fn at(index: usize) -> u64 {
    T0 + index as u64 * STEP
}

/// A TCP conversation built packet by packet, remembering when each was taken.
///
/// A lost segment is never pushed and takes no packet index, because a capture
/// file does not number what it does not hold: the packet after a hole is the
/// next index, and that is the numbering a row's `first_byte.packet` uses.
struct Wire {
    d: Dissection,
    /// Next sequence number low to high, then high to low.
    next_seq: [u32; 2],
    /// The instant of each packet pushed, by packet index.
    instants: Vec<Option<u64>>,
    /// The bytes of each packet pushed, by packet index, so the capture can be
    /// written out as a file and read back through the document doors.
    packets: Vec<Vec<u8>>,
}

impl Wire {
    fn new() -> Self {
        Self {
            d: Dissection::new(),
            next_seq: [1000, 5000],
            instants: Vec::new(),
            packets: Vec::new(),
        }
    }

    /// The packets so far as a classic pcap, each at its own instant to the
    /// microsecond (the file's resolution), which is the capture the document
    /// doors re-read.
    #[cfg(feature = "dissect")]
    fn file(&self) -> Vec<u8> {
        let rows: Vec<(u32, u32, &[u8])> = self
            .packets
            .iter()
            .zip(&self.instants)
            .map(|(bytes, ns)| {
                let ns = ns.expect("these captures are fully timed");
                (
                    (ns / 1_000_000_000) as u32,
                    ((ns % 1_000_000_000) / 1_000) as u32,
                    bytes.as_slice(),
                )
            })
            .collect();
        crate::pcap::write(LINKTYPE_ETHERNET, &rows)
    }

    /// Low to high, in order.
    fn send(&mut self, bytes: &[u8]) {
        let seq = self.next_seq[0];
        self.next_seq[0] += bytes.len() as u32;
        self.put(seq, bytes, false, true);
    }

    /// High to low, in order.
    fn reply(&mut self, bytes: &[u8]) {
        let seq = self.next_seq[1];
        self.next_seq[1] += bytes.len() as u32;
        self.put(seq, bytes, true, true);
    }

    /// Low to high, in order, with the packet carrying no timestamp.
    fn send_untimed(&mut self, bytes: &[u8]) {
        let seq = self.next_seq[0];
        self.next_seq[0] += bytes.len() as u32;
        self.put(seq, bytes, false, false);
    }

    /// Low to high: the bytes existed on the wire and the capture missed them.
    fn lose(&mut self, bytes: &[u8]) {
        self.next_seq[0] += bytes.len() as u32;
    }

    /// Push one packet at an explicit sequence number, taking the next packet
    /// index and the next instant.
    fn put(&mut self, seq: u32, bytes: &[u8], reverse: bool, timed: bool) {
        let index = self.instants.len();
        let ns = timed.then(|| at(index));
        self.instants.push(ns);
        let packet = if reverse {
            tcp_packet_reverse(seq, bytes)
        } else {
            tcp_packet(seq, bytes)
        };
        self.d
            .push_packet_at_nanos(LINKTYPE_ETHERNET, index, ns, &packet);
        self.packets.push(packet);
    }

    /// The sequence number the next in-order low-to-high byte will carry.
    fn seq(&self) -> u32 {
        self.next_seq[0]
    }

    /// Advance past bytes that were sent out of order and have since been put.
    fn skip(&mut self, len: usize) {
        self.next_seq[0] += len as u32;
    }
}

/// `n` one-frame units, numbered by their `sn`.
fn units(n: u8) -> Vec<Vec<u8>> {
    (0..n).map(framed_frame).collect()
}

/// The `sn` of a decoded `Frame`, which is how a test names a unit.
fn sn_of(frame: &wz_session_core::passive::PassiveFrame) -> u64 {
    match &frame.frame {
        Ok(InboundFrame::Frame { sn, .. }) => *sn,
        other => panic!("not a Frame: {other:?}"),
    }
}

/// THE ORACLE OF CLAIM A, applied to every record of every stream flow: its
/// time is the capture time of the packet its first byte is in, found by the
/// lookup its own row uses, and its millisecond reading is that divided down.
///
/// The packet is NOT taken from the record: it is asked of the run map, so the
/// expectation is independent of the code that stamps. And the map is asked
/// through `packet_for`, the function `first_byte.packet` is written from, so
/// "the record's time" and "the packet its row names" cannot be two things.
fn assert_each_record_is_stamped_by_the_packet_of_its_first_byte(
    d: &Dissection,
    instants: &[Option<u64>],
) {
    let mut checked = 0usize;
    for flow in d.flows() {
        for frame in flow.frames.iter() {
            // The byte the row's `first_byte` names: past the length prefix and
            // whatever of the batch stands ahead of the message.
            let first_byte = crate::FlowDissection::message_at(frame);
            let packet = flow
                .packet_for(frame.direction, first_byte)
                .unwrap_or_else(|| panic!("no packet holds offset {first_byte}"));
            let want = instants[packet];
            assert_eq!(
                frame.observed_at_ns, want,
                "the record whose first byte is at offset {first_byte} ({:?}) begins in packet {packet}",
                frame.direction
            );
            assert_eq!(
                frame.observed_at_ms,
                want.map(|ns| ns / NANOS_PER_MILLI),
                "and its millisecond reading is that, divided down"
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "the oracle graded nothing");
}

// ---------------------------------------------------------------------------
// Claim A
// ---------------------------------------------------------------------------

/// THE CONSUMER'S SHAPE: a segment is lost, the segments behind it are held
/// until the capture ends, and `finish` delivers them.
///
/// Forty one-frame packets, the sixth lost, each captured at its own instant.
/// Before the fix every record behind the hole read the instant of the LAST
/// packet (33 of the 39 wrong, measured), and the five before it and the last
/// were right, which is why the defect hid in a capture's middle.
#[test]
fn records_behind_a_hole_are_stamped_by_their_own_packets_when_the_capture_ends() {
    let units = units(40);
    let mut wire = Wire::new();
    for (i, unit) in units.iter().enumerate() {
        if i == 5 {
            wire.lose(unit);
        } else {
            wire.send(unit);
        }
    }
    assert_eq!(
        wire.d.flows()[0].frames.len(),
        5,
        "the hole is still open, so only what came before it has been decoded"
    );
    wire.d.finish();

    let flow = &wire.d.flows()[0];
    assert_eq!(
        flow.frames.len(),
        39,
        "five before the hole, thirty-four after"
    );
    assert_each_record_is_stamped_by_the_packet_of_its_first_byte(&wire.d, &wire.instants);

    // The same thing said without the helper, on the records the defect hit.
    let sns: Vec<u64> = flow.frames.iter().map(sn_of).collect();
    assert!(!sns.contains(&5), "the lost unit left no record: {sns:?}");
    let sixth_after = flow
        .frames
        .iter()
        .find(|f| sn_of(f) == 10)
        .expect("unit 10");
    assert_eq!(
        sixth_after.observed_at_ns,
        Some(at(9)),
        "unit 10 is the tenth packet pushed (index 9), and not the last"
    );
    assert_ne!(
        sixth_after.observed_at_ns,
        flow.frames.iter().last().unwrap().observed_at_ns
    );
}

/// The hole is stepped over on PATIENCE, mid-capture, and not at its end. A
/// different caller of the same delivery, with a different clock: the segment
/// that runs the patience out is the one whose packet had been the clock.
#[test]
fn records_behind_a_hole_stepped_over_on_patience_are_stamped_by_their_own_packets() {
    let units = units(40);
    let mut wire = Wire::new();
    wire.d.set_gap_patience(Some(8));
    for (i, unit) in units.iter().enumerate() {
        if i == 5 {
            wire.lose(unit);
        } else {
            wire.send(unit);
        }
    }
    let held = wire.d.flows()[0].frames.len();
    assert!(
        held > 5,
        "the patience ran out before the capture ended, so records behind the hole \
         were already decoded: {held}"
    );
    assert_each_record_is_stamped_by_the_packet_of_its_first_byte(&wire.d, &wire.instants);
    wire.d.finish();
    assert_each_record_is_stamped_by_the_packet_of_its_first_byte(&wire.d, &wire.instants);
}

/// A segment that arrives AHEAD of its predecessor is held until the
/// predecessor comes, and is then released by a packet that is NOT its own.
/// Unit 3 is captured before unit 2 here; stamped by the clock at release it
/// would read unit 2's later instant.
#[test]
fn a_segment_released_by_a_late_neighbour_keeps_the_instant_it_was_captured_at() {
    let units = units(5);
    let mut wire = Wire::new();
    wire.send(&units[0]);
    wire.send(&units[1]);
    let at_unit_2 = wire.seq();
    let at_unit_3 = at_unit_2 + units[2].len() as u32;
    wire.put(at_unit_3, &units[3], false, true); // captured third, held
    wire.put(at_unit_2, &units[2], false, true); // captured fourth, releases both
    wire.skip(units[2].len() + units[3].len());
    wire.send(&units[4]);

    let flow = &wire.d.flows()[0];
    let by_sn: Vec<(u64, Option<u64>)> = flow
        .frames
        .iter()
        .map(|f| (sn_of(f), f.observed_at_ns))
        .collect();
    assert_eq!(
        by_sn,
        [
            (0, Some(at(0))),
            (1, Some(at(1))),
            (2, Some(at(3))),
            (3, Some(at(2))),
            (4, Some(at(4))),
        ],
        "unit 3 was captured BEFORE unit 2, whose arrival released it"
    );
    assert_each_record_is_stamped_by_the_packet_of_its_first_byte(&wire.d, &wire.instants);
}

/// A unit that spans two packets is stamped with the FIRST one, and the list
/// holds records in the order their units COMPLETED. Both are stated rules and
/// this is where they are pinned together, because the second is the cost of
/// the first: a unit that began earlier can be listed after one that began
/// later, so a list's times are not monotone and a consumer wanting capture
/// order sorts by time.
#[test]
fn a_unit_spanning_two_packets_is_stamped_by_its_first_and_listed_when_it_completes() {
    let units = units(2);
    let (head, tail) = units[1].split_at(3);
    let mut wire = Wire::new();
    wire.send(&units[0]); // packet 0
    wire.send(head); // packet 1: the first byte of unit 1
    wire.reply(&framed_keepalive()); // packet 2, the other direction, whole
    wire.send(tail); // packet 3: unit 1 completes

    let flow = &wire.d.flows()[0];
    let listed: Vec<(Direction, Option<u64>)> = flow
        .frames
        .iter()
        .map(|f| (f.direction, f.observed_at_ns))
        .collect();
    assert_eq!(
        listed,
        [
            (Direction::A, Some(at(0))),
            (Direction::B, Some(at(2))),
            (Direction::A, Some(at(1))),
        ],
        "unit 1 began in packet 1 and completed in packet 3, after the keepalive of packet 2"
    );
    assert_each_record_is_stamped_by_the_packet_of_its_first_byte(&wire.d, &wire.instants);
}

/// Two messages of ONE batch that arrive in different packets are each stamped
/// by the packet of their own first byte: the unit began in packet 0, and its
/// second message in packet 1. A stamp taken once per unit gives both packet 0's.
#[test]
fn two_messages_of_one_batch_in_different_packets_each_take_their_own() {
    let keepalive = wz_session_core::wire_const::T_MID_KEEP_ALIVE;
    let mut unit = 2u16.to_le_bytes().to_vec();
    unit.extend_from_slice(&[keepalive, keepalive]);
    let mut wire = Wire::new();
    wire.send(&unit[..3]); // packet 0: the prefix and the first message
    wire.send(&unit[3..]); // packet 1: the second message

    let stamps: Vec<(usize, Option<u64>)> = wire.d.flows()[0]
        .frames
        .iter()
        .map(|f| (f.batch_index, f.observed_at_ns))
        .collect();
    assert_eq!(stamps, [(0, Some(at(0))), (1, Some(at(1)))]);
    assert_each_record_is_stamped_by_the_packet_of_its_first_byte(&wire.d, &wire.instants);
}

/// A unit that STRADDLES the hole is never produced, so no record has its
/// first byte in the hole.
///
/// The brief asks what time such a record gets; the answer is that there is no
/// such record. The hole is announced to the reader, which drops the bytes it
/// holds on the near side (they are "on the wrong side of a boundary this
/// reader can no longer place") and scans for a boundary its depth confirms. The
/// records that follow begin in packets the capture HAS, and are stamped by them.
#[test]
fn a_unit_split_by_the_hole_leaves_no_record_and_the_ones_after_it_keep_their_packets() {
    let units = units(20);
    let mut wire = Wire::new();
    for unit in &units[..5] {
        wire.send(unit);
    }
    let (kept, lost) = units[5].split_at(4);
    wire.send(kept);
    wire.lose(lost);
    for unit in &units[6..] {
        wire.send(unit);
    }
    wire.d.finish();

    let flow = &wire.d.flows()[0];
    let sns: Vec<u64> = flow.frames.iter().map(sn_of).collect();
    assert!(
        !sns.contains(&5),
        "the straddling unit must not be reported as a record: {sns:?}"
    );
    assert_eq!(sns.len(), 19, "every other unit survived: {sns:?}");
    assert_each_record_is_stamped_by_the_packet_of_its_first_byte(&wire.d, &wire.instants);
}

/// A packet with no timestamp inherits the flow's clock, as it always has: a
/// source that stamps some packets and not others must not un-know a time it
/// was told. The run map records what the CLOCK said at each packet, so a record
/// read out of an unstamped packet takes the earlier stamp -- and one read late
/// still does.
#[test]
fn a_record_in_an_unstamped_packet_takes_the_flows_clock_as_of_that_packet() {
    let units = units(4);
    let mut wire = Wire::new();
    wire.send(&units[0]); // stamped
    wire.send(&units[1]); // stamped
    wire.send_untimed(&units[2]); // no timestamp
    wire.send(&units[3]); // stamped again

    let stamps: Vec<Option<u64>> = wire.d.flows()[0]
        .frames
        .iter()
        .map(|f| f.observed_at_ns)
        .collect();
    assert_eq!(
        stamps,
        [Some(at(0)), Some(at(1)), Some(at(1)), Some(at(3))],
        "the unstamped packet reports the instant the clock stood at"
    );

    // And a capture with no stamp anywhere has no instant on any record: the
    // run map must not invent one.
    let mut none = Dissection::new();
    let mut seq = 1000u32;
    for unit in &units {
        none.push_packet_at_nanos(LINKTYPE_ETHERNET, 0, None, &tcp_packet(seq, unit));
        seq += unit.len() as u32;
    }
    assert!(
        none.flows()[0]
            .frames
            .iter()
            .all(|f| f.observed_at_ns.is_none() && f.observed_at_ms.is_none()),
        "a capture nobody timed has no time on any record"
    );
}

/// The flow's FIRST bytes can be held while the reader decides what the flow
/// is, and a hole in that opening is answered at the end of the capture. The
/// records released then are read long after their packets and must still say
/// when they were captured: this is the replay path of the same stamp.
#[test]
fn records_released_after_a_lost_opening_are_stamped_by_their_own_packets() {
    let units = units(12);
    let mut wire = Wire::new();
    // Two bytes that are the start of an HTTP upgrade, so the flow stays
    // undecided, and then a hole that takes the rest of the opening.
    wire.send(b"GE");
    wire.lose(&[0u8; 8]);
    for unit in &units {
        wire.send(unit);
    }
    wire.d.finish();

    let flow = &wire.d.flows()[0];
    assert_eq!(
        flow.frames.len(),
        12,
        "the lost opening was settled as a stream and its tail was read: {:?}",
        wire.d.framing_health()
    );
    assert_each_record_is_stamped_by_the_packet_of_its_first_byte(&wire.d, &wire.instants);
}

/// A clean capture is stamped exactly as it always was: the millisecond reading
/// of every record is the millisecond of its packet, whether the packets were
/// handed over in milliseconds or in nanoseconds with digits to spare.
///
/// This is the CONTROL for everything above and below: the change was meant to
/// move records behind holes and the digits of the clock, and nothing else.
#[test]
fn a_clean_capture_reads_the_same_millisecond_whichever_way_it_was_fed() {
    let units = units(30);
    let mut by_ms = Dissection::new();
    let mut by_ns = Dissection::new();
    let mut seq = 1000u32;
    for (i, unit) in units.iter().enumerate() {
        let ns = at(i);
        by_ms.push_packet_at(
            LINKTYPE_ETHERNET,
            i,
            Some(ns / NANOS_PER_MILLI),
            &tcp_packet(seq, unit),
        );
        by_ns.push_packet_at_nanos(LINKTYPE_ETHERNET, i, Some(ns), &tcp_packet(seq, unit));
        seq += unit.len() as u32;
    }
    by_ms.finish();
    by_ns.finish();
    let a: Vec<_> = by_ms.flows()[0]
        .frames
        .iter()
        .map(|f| f.observed_at_ms)
        .collect();
    let b: Vec<_> = by_ns.flows()[0]
        .frames
        .iter()
        .map(|f| f.observed_at_ms)
        .collect();
    assert_eq!(a.len(), 30);
    assert_eq!(a, b, "the millisecond column does not depend on the digits");
    for (i, f) in by_ns.flows()[0].frames.iter().enumerate() {
        assert_eq!(
            f.observed_at_ns,
            Some(at(i)),
            "and the nanosecond one keeps them"
        );
    }
}

/// Fewer records behind a hole than the resync depth are not confirmed as a
/// boundary and are not produced -- the consumer's "five or fewer", which is a
/// SEPARATE condition from the stamp and is pinned here only so it is named.
///
/// [`wz_session_core::passive::DEFAULT_RESYNC_DEPTH`] chained frames must follow
/// a hole before the reader trusts the boundary it found (R311y609: it measured
/// 45-68% of frames after a hole mis-framed with no corroboration). With fewer
/// the bytes stay in the scan; the loss is visible as a desync that never
/// recovered, and in what the session still holds. What this does NOT show is a
/// count of the records those bytes held, and that is the open part.
#[test]
fn behind_a_hole_fewer_records_than_the_resync_depth_are_held_unconfirmed() {
    let depth = wz_session_core::passive::DEFAULT_RESYNC_DEPTH;
    for behind in 1..=depth + 2 {
        let all = units(1 + 1 + behind as u8);
        let mut wire = Wire::new();
        wire.send(&all[0]);
        wire.lose(&all[1]);
        for unit in &all[2..] {
            wire.send(unit);
        }
        wire.d.finish();

        let flow = &wire.d.flows()[0];
        let health = wire.d.framing_health();
        if behind < depth {
            assert_eq!(
                flow.frames.len(),
                1,
                "{behind} behind the hole: nothing confirmed, only the unit before it"
            );
            assert_eq!(
                (health.desyncs, health.recoveries),
                (1, 0),
                "{behind} behind the hole: the desync never recovered"
            );
            assert_eq!(
                flow.session.buffered(Direction::A),
                behind * 8,
                "{behind} behind the hole: their bytes are still in the scan"
            );
        } else {
            assert_eq!(flow.frames.len(), 1 + behind, "{behind} behind the hole");
            assert_eq!((health.desyncs, health.recoveries), (1, 1));
        }
    }
}

// ---------------------------------------------------------------------------
// Claim B
// ---------------------------------------------------------------------------

/// A source that knows the nanosecond keeps it, on a datagram link and a stream
/// link alike, and the millisecond reading is that divided down. The instant is
/// past 2^53 so a path that squeezed it through a double or a float loses digits
/// the assertion can see.
#[test]
fn the_clock_keeps_every_digit_the_source_gave_on_both_link_kinds() {
    let instant = 1_700_000_000_123_456_789u64;

    let mut d = Dissection::new();
    let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
    d.push_packet_at_nanos(
        LINKTYPE_ETHERNET,
        0,
        Some(instant),
        &udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &keepalive),
    );
    d.push_packet_at_nanos(
        LINKTYPE_ETHERNET,
        1,
        Some(instant + 1),
        &tcp_packet(1000, &framed_keepalive()),
    );
    let datagram = &d.datagram_flows()[0].frames[0];
    assert_eq!(datagram.observed_at_ns, Some(instant));
    assert_eq!(datagram.observed_at_ms, Some(1_700_000_000_123));
    let stream = &d.flows()[0].frames[0];
    assert_eq!(stream.observed_at_ns, Some(instant + 1));
    assert_eq!(stream.observed_at_ms, Some(1_700_000_000_123));
}

/// A classic pcap's microsecond digits, and a pcapng's at each resolution it is
/// written in, reach the records. The oracle is arithmetic on the numbers the
/// FILE was written from, not a call into the reader that is being graded.
#[test]
fn a_capture_files_sub_millisecond_digits_reach_the_records() {
    let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
    let packet = udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &keepalive);

    // Classic pcap: seconds and microseconds.
    let file = crate::pcap::write(
        LINKTYPE_ETHERNET,
        &[
            (1_700_000_000, 123_456, &packet),
            (1_700_000_000, 123_999, &packet),
        ],
    );
    let d = Dissection::from_pcap(&file).expect("reads");
    let ns: Vec<_> = d.datagram_flows()[0]
        .frames
        .iter()
        .map(|f| f.observed_at_ns)
        .collect();
    assert_eq!(
        ns,
        [
            Some(1_700_000_000_123_456_000),
            Some(1_700_000_000_123_999_000)
        ],
        "microseconds widened to nanoseconds, none dropped"
    );

    // pcapng at nanosecond (9), microsecond (6) and millisecond (3) resolution:
    // the same instant written as ticks of each.
    for (resolution, ticks, want_ns) in [
        (
            9u8,
            1_700_000_000_123_456_789u64,
            1_700_000_000_123_456_789u64,
        ),
        (6, 1_700_000_000_123_456, 1_700_000_000_123_456_000),
        (3, 1_700_000_000_123, 1_700_000_000_123_000_000),
    ] {
        let file = crate::pcapng::write(
            &[(LINKTYPE_ETHERNET, resolution)],
            &[(0, ticks, packet.as_slice())],
        );
        let d = Dissection::from_pcapng(&file).expect("reads");
        let frame = &d.datagram_flows()[0].frames[0];
        assert_eq!(
            frame.observed_at_ns,
            Some(want_ns),
            "if_tsresol {resolution}"
        );
        assert_eq!(
            frame.observed_at_ms,
            Some(1_700_000_000_123),
            "if_tsresol {resolution}: the millisecond reading is the same"
        );
    }
}

/// One exchange: a request, a reply `reply_us` later, a close `close_us` later,
/// the request captured at `request_us` microseconds past a whole second.
#[cfg(feature = "network-codecs")]
fn exchange_at(request_us: u64, reply_us: u64, close_us: u64) -> Dissection {
    use crate::exchange::tests as fx;
    let base_ns = |us: u64| 5_000_000_000 + us * 1_000;
    let records: [(bool, Option<u64>, Vec<u8>); 3] = [
        (
            true,
            Some(base_ns(request_us)),
            fx::request_query(1, fx::sender_space(0, Some("q/one"))),
        ),
        (
            false,
            Some(base_ns(request_us + reply_us)),
            fx::response_reply(1, fx::sender_space(0, Some("q/one")), b"v"),
        ),
        (
            false,
            Some(base_ns(request_us + close_us)),
            fx::response_final(1),
        ),
    ];
    dissect_ns(&records)
}

/// `exchange::tests::dissect`, with nanosecond stamps: one record per UDP
/// datagram, through the whole pipeline.
#[cfg(feature = "network-codecs")]
fn dissect_ns(records: &[(bool, Option<u64>, Vec<u8>)]) -> Dissection {
    use crate::datagram_tests::frame_carrying;
    let mut d = Dissection::new();
    for (i, (from_low, ns, record)) in records.iter().enumerate() {
        let wire = frame_carrying(record);
        let packet = if *from_low {
            udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &wire)
        } else {
            udp_packet([10, 0, 0, 2], 7447, [10, 0, 0, 1], 43210, &wire)
        };
        d.push_packet_at_nanos(LINKTYPE_ETHERNET, i, *ns, &packet);
    }
    d
}

/// THE CONSUMER'S NUMBER. A round trip of 575 microseconds read 1 ms, or 0 ms,
/// by where it fell in a millisecond. The nanosecond total is 575 000 at every
/// phase; the millisecond total is what it always was, and still flips, because
/// the `*_ms` keys keep their meaning.
#[cfg(feature = "network-codecs")]
#[test]
fn a_round_trip_of_575_microseconds_reads_575000_ns_at_every_phase() {
    let mut seen_ms = alloc::collections::BTreeSet::new();
    for phase_us in (0..1000u64).step_by(37) {
        let d = exchange_at(phase_us, 200, 575);
        let table = crate::exchange::exchanges(&d);
        assert_eq!(table.completed(), 1, "phase {phase_us}");
        let (first_reply, completion) = table.totals();
        assert_eq!(completion.total_ns(), 575_000, "phase {phase_us}");
        assert_eq!(completion.mean_ns(), Some(575_000));
        assert_eq!(completion.min_ns(), Some(575_000));
        assert_eq!(completion.max_ns(), Some(575_000));
        assert_eq!(first_reply.total_ns(), 200_000, "phase {phase_us}");
        // The legacy column: each end truncated to its millisecond, then
        // subtracted. It is 1 exactly when the close crosses a boundary.
        let crosses = u64::from(phase_us + 575 >= 1000);
        assert_eq!(completion.total_ms(), crosses, "phase {phase_us}");
        seen_ms.insert(completion.total_ms());
    }
    assert_eq!(
        seen_ms.len(),
        2,
        "the sweep reached both sides of a boundary, so the control means something"
    );
}

/// The mean of two intervals is taken from the unrounded intervals: 379 and 575
/// microseconds average 477, where two rounded readings average 0 or 1.
#[cfg(feature = "network-codecs")]
#[test]
fn a_mean_over_exchanges_is_taken_from_the_unrounded_intervals() {
    use crate::exchange::tests as fx;
    let at_us = |us: u64| Some(7_000_000_000 + us * 1_000);
    let d = dissect_ns(&[
        (
            true,
            at_us(100),
            fx::request_query(1, fx::sender_space(0, Some("q/a"))),
        ),
        (false, at_us(100 + 379), fx::response_final(1)),
        (
            true,
            at_us(5_100),
            fx::request_query(2, fx::sender_space(0, Some("q/a"))),
        ),
        (false, at_us(5_100 + 575), fx::response_final(2)),
    ]);
    let table = crate::exchange::exchanges(&d);
    let completion = table.row("q/a").expect("row").completion;
    assert_eq!(completion.count(), 2);
    assert_eq!(completion.total_ns(), 954_000);
    assert_eq!(completion.mean_ns(), Some(477_000));
    assert_eq!(completion.min_ns(), Some(379_000));
    assert_eq!(completion.max_ns(), Some(575_000));
}

/// On a capture whose stamps are whole milliseconds, the nanosecond figures are
/// the millisecond figures times a million: the two columns are one measurement
/// at two granularities and agree wherever the granularity allows. The control
/// for the exchange plane's pre-existing tests.
#[cfg(feature = "network-codecs")]
#[test]
fn on_whole_millisecond_stamps_the_two_columns_agree() {
    use crate::exchange::tests as fx;
    let d = fx::dissect(&[
        (
            true,
            Some(1_000),
            fx::request_query(7, fx::sender_space(0, Some("demo/**"))),
        ),
        (
            false,
            Some(1_030),
            fx::response_reply(7, fx::sender_space(0, Some("demo/a")), b"first"),
        ),
        (false, Some(1_050), fx::response_final(7)),
    ]);
    let (first_reply, completion) = crate::exchange::exchanges(&d).totals();
    assert_eq!(first_reply.total_ms(), 30);
    assert_eq!(first_reply.total_ns(), 30_000_000);
    assert_eq!(completion.total_ms(), 50);
    assert_eq!(completion.total_ns(), 50_000_000);
    assert_eq!(completion.mean_ns(), Some(50_000_000));
}

/// An exchange whose reply is stamped a few hundred microseconds BEFORE its
/// request, inside one millisecond, is the 0 ms sample it always was and a
/// 0 ns one -- and one that runs backwards by a whole millisecond is still
/// refused and counted. The `non_monotonic` gap counter keeps its meaning.
#[cfg(feature = "network-codecs")]
#[test]
fn a_reply_stamped_inside_the_requests_millisecond_is_a_zero_sample_not_a_refusal() {
    use crate::exchange::tests as fx;
    let inside = dissect_ns(&[
        (
            true,
            Some(5_000_900_000),
            fx::request_query(1, fx::sender_space(0, Some("q/x"))),
        ),
        (false, Some(5_000_400_000), fx::response_final(1)),
    ]);
    let table = crate::exchange::exchanges(&inside);
    let completion = table.totals().1;
    assert_eq!(
        table.gaps().non_monotonic,
        0,
        "same millisecond: not backwards"
    );
    assert_eq!(
        (
            completion.count(),
            completion.total_ms(),
            completion.total_ns()
        ),
        (1, 0, 0)
    );

    let across = dissect_ns(&[
        (
            true,
            Some(5_001_100_000),
            fx::request_query(1, fx::sender_space(0, Some("q/x"))),
        ),
        (false, Some(5_000_900_000), fx::response_final(1)),
    ]);
    let table = crate::exchange::exchanges(&across);
    assert_eq!(
        table.gaps().non_monotonic,
        1,
        "an earlier millisecond: backwards"
    );
    assert!(table.totals().1.is_empty());
}

/// The census document: every latency object says its figures twice, the
/// millisecond ones as they were and the nanosecond ones beside them, and a
/// nanosecond figure past 2^53 is a string, by the integer rule every 64-bit
/// clock cell here follows.
#[cfg(feature = "network-codecs")]
#[test]
fn the_census_latency_object_carries_both_columns_and_follows_the_integer_rule() {
    let d = exchange_at(300, 200, 575);
    let doc = crate::census_json::census_json(&d);
    assert!(
        doc.contains(
            "\"completion\":{\"count\":1,\"min_ms\":0,\"max_ms\":0,\"mean_ms\":0,\"total_ms\":0,\
             \"min_ns\":575000,\"max_ns\":575000,\"mean_ns\":575000,\"total_ns\":575000}"
        ),
        "{doc}"
    );
    assert!(
        doc.contains(
            "\"first_reply\":{\"count\":1,\"min_ms\":0,\"max_ms\":0,\"mean_ms\":0,\"total_ms\":0,\
             \"min_ns\":200000,\"max_ns\":200000,\"mean_ns\":200000,\"total_ns\":200000}"
        ),
        "{doc}"
    );

    // Nothing measured: null, never a fabricated zero, and a total of 0.
    use crate::exchange::tests as fx;
    let unanswered = dissect_ns(&[(
        true,
        Some(5_000_000_000),
        fx::request_query(1, fx::sender_space(0, Some("q/none"))),
    )]);
    let doc = crate::census_json::census_json(&unanswered);
    assert!(
        doc.contains(
            "\"completion\":{\"count\":0,\"min_ms\":null,\"max_ms\":null,\"mean_ms\":null,\
             \"total_ms\":0,\"min_ns\":null,\"max_ns\":null,\"mean_ns\":null,\"total_ns\":0}"
        ),
        "{doc}"
    );

    // 2^53 + 1 nanoseconds is 104 days: a capture with a wild stamp, and the
    // only way a latency reaches the line. One more than the exact bound.
    let line = (1u64 << 53) + 1;
    let wild = dissect_ns(&[
        (
            true,
            Some(1_000_000_000),
            fx::request_query(1, fx::sender_space(0, Some("q/wild"))),
        ),
        (false, Some(1_000_000_000 + line), fx::response_final(1)),
    ]);
    let doc = crate::census_json::census_json(&wild);
    assert!(
        doc.contains(
            "\"min_ns\":\"9007199254740993\",\"max_ns\":\"9007199254740993\",\
             \"mean_ns\":\"9007199254740993\",\"total_ns\":\"9007199254740993\"}"
        ),
        "{doc}"
    );
}

/// `elapsed` is still a MILLISECOND term. A request 1000.9 ms after the capture
/// began has elapsed 1000, exactly as it had before the clock kept nanoseconds,
/// and `elapsed > 1000` does not select it: the selector's unit is part of the
/// language, and a record's digits do not leak into it.
#[cfg(feature = "network-codecs")]
#[test]
fn the_elapsed_term_stays_a_millisecond_term() {
    use crate::exchange::tests as fx;
    let origin = 9_000_000_000u64;
    let d = dissect_ns(&[
        (
            true,
            Some(origin),
            fx::request_query(1, fx::sender_space(0, Some("q/first"))),
        ),
        (
            true,
            Some(origin + 1_000_900_000),
            fx::request_query(2, fx::sender_space(0, Some("q/second"))),
        ),
        (
            true,
            Some(origin + 1_001_000_000),
            fx::request_query(3, fx::sender_space(0, Some("q/third"))),
        ),
    ]);
    let count = |selector: &str| {
        let filter = crate::filter::Filter::parse(selector).expect("parses");
        crate::exchange::exchanges_where(&d, &filter).requests()
    };
    assert_eq!(count("elapsed == 1000"), 1, "1000.9 ms reads 1000");
    assert_eq!(count("elapsed > 1000"), 1, "only the one at 1001.0 ms");
    assert_eq!(count("elapsed < 1000"), 1, "only the origin itself");
}

/// An Init and a leased Open on one datagram flow, captured 888 ns apart, and
/// the capture file that holds them: the shape that gives a flow a retained
/// instant and a last-seen instant with digits to lose.
fn an_init_and_an_open_888_nanoseconds_apart() -> (Dissection, Vec<u8>) {
    use crate::datagram_tests::{init_datagram, open_datagram_leased};
    let first = 1_700_000_000_000_000_111u64;
    let second = 1_700_000_000_000_000_999u64;
    let packets = [
        (
            first,
            udp_packet(
                [10, 0, 0, 1],
                7447,
                [10, 0, 0, 2],
                7447,
                &init_datagram(false, &[]),
            ),
        ),
        (
            second,
            udp_packet(
                [10, 0, 0, 1],
                7447,
                [10, 0, 0, 2],
                7447,
                &open_datagram_leased(false, 5_000),
            ),
        ),
    ];
    let mut d = Dissection::new();
    let mut rows: Vec<(u32, u32, &[u8])> = Vec::new();
    for (i, (ns, packet)) in packets.iter().enumerate() {
        d.push_packet_at_nanos(LINKTYPE_ETHERNET, i, Some(*ns), packet);
        rows.push((
            (*ns / 1_000_000_000) as u32,
            ((*ns % 1_000_000_000) / 1_000) as u32,
            packet.as_slice(),
        ));
    }
    let file = crate::pcap::write(LINKTYPE_ETHERNET, &rows);
    (d, file)
}

/// The retention document's earliest instant is the figure a record carries,
/// with every digit: 111 ns past a microsecond, which the millisecond clock
/// would have read as a whole millisecond.
#[test]
fn retention_carries_the_digits_a_record_carries() {
    let (d, _) = an_init_and_an_open_888_nanoseconds_apart();
    let retention = crate::retention_json::retention_json(&d);
    assert!(
        retention.contains("\"oldest_ts_ns\":\"1700000000000000111\""),
        "{retention}"
    );
    assert_eq!(
        crate::retention_json::Retention::of(&d).oldest_ms,
        Some(1_700_000_000_000),
        "and the millisecond reading is that divided down"
    );
}

/// A direction's last-seen instant is the instant of the LAST record it
/// produced, nanoseconds and all.
#[cfg(feature = "dissect")]
#[test]
fn a_directions_last_seen_instant_carries_the_digits_a_record_carries() {
    let (d, file) = an_init_and_an_open_888_nanoseconds_apart();
    let fields = crate::fields_json::fields_json(&d, &file, None, None);
    assert!(
        fields.contains("\"last_seen_ts_ns\":\"1700000000000000999\""),
        "{fields}"
    );
    let half = d.datagram_flows()[0].half(Direction::A);
    assert_eq!(
        (half.last_seen_ms, half.last_seen_ns),
        (Some(1_700_000_000_000), Some(1_700_000_000_000_000_999))
    );
}

// ---------------------------------------------------------------------------
// Row order
// ---------------------------------------------------------------------------

/// A stream flow whose decode order is NOT its capture order.
///
/// A's unit begins in packet 0 and ends in packet 2; B's keepalive sits wholly
/// in packet 1 and is decoded first. The session lists [B, A]; the capture saw A
/// begin first.
#[cfg(feature = "dissect")]
fn a_unit_that_completes_after_one_that_began_later() -> Wire {
    let unit = framed_frame(7);
    let (head, tail) = unit.split_at(3);
    let mut wire = Wire::new();
    wire.send(head); // packet 0: A's unit begins
    wire.reply(&framed_keepalive()); // packet 1: B's whole message
    wire.send(tail); // packet 2: A's unit completes
    wire
}

/// The packets the rows of a field document name, in document order.
#[cfg(feature = "dissect")]
fn first_byte_packets(doc: &str) -> Vec<u64> {
    doc.match_indices("\"first_byte\":{\"packet\":")
        .map(|(at, key)| {
            let digits: alloc::string::String = doc[at + key.len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            digits.parse().expect("a packet number")
        })
        .collect()
}

/// `(packet, payload_offset)` of each row's `first_byte`, in document order.
#[cfg(feature = "dissect")]
fn first_byte_places(doc: &str) -> Vec<(u64, u64)> {
    const KEY: &str = "\"first_byte\":{\"packet\":";
    doc.match_indices(KEY)
        .map(|(at, key)| {
            let number = |from: usize| -> (u64, usize) {
                let digits: alloc::string::String = doc[from..]
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect();
                (digits.parse().expect("a number"), from + digits.len())
            };
            let (packet, end) = number(at + key.len());
            let offset_key = ",\"payload_offset\":";
            assert!(
                doc[end..].starts_with(offset_key),
                "{}",
                &doc[end..end + 40]
            );
            let (offset, _) = number(end + offset_key.len());
            (packet, offset)
        })
        .collect()
}

/// A numbering that numbers every list and issues no row numbers.
#[cfg(feature = "dissect")]
struct EveryListNumbered;

#[cfg(feature = "dissect")]
impl crate::fields_json::RowCoordinates for EveryListNumbered {
    fn list_id(&self, list: usize) -> Option<u64> {
        Some(list as u64)
    }

    fn scouting_list_id(&self, _flow: &crate::link::FlowKey) -> Option<u64> {
        None
    }
}

/// THE ORDER OF A STREAM FLOW'S ROWS IS THE ORDER THE CAPTURE SAW THEM BEGIN.
///
/// The premise is asserted first -- the session decoded B before A -- because a
/// fixture whose two orders coincide would pass any order.
#[cfg(feature = "dissect")]
#[test]
fn a_stream_flows_rows_come_out_in_capture_order() {
    let wire = a_unit_that_completes_after_one_that_began_later();
    let flow = &wire.d.flows()[0];
    let decoded: Vec<Direction> = flow.frames.iter().map(|f| f.direction).collect();
    assert_eq!(
        decoded,
        [Direction::B, Direction::A],
        "premise: the unit that began first completed last"
    );
    assert_eq!(flow.capture_order(), [1, 0], "A (position 1) began first");

    let doc = crate::fields_json::fields_json(&wire.d, &wire.file(), None, None);
    assert_eq!(
        first_byte_packets(&doc),
        [0, 1],
        "rows come out by the packet of their first byte: {doc}"
    );
}

/// Rows of ONE packet are in the order of their bytes in it: the tiebreak is the
/// place in the packet, and it is never anything that varies between runs.
///
/// Three units in one segment share a packet, so the packet cannot order them
/// and only the stated tiebreak does. The assertion is on the places the rows
/// themselves report, which the document derives from the bytes and not from the
/// order the rows were listed in.
#[cfg(feature = "dissect")]
#[test]
fn rows_of_one_packet_are_in_the_order_of_their_bytes() {
    let units = units(3);
    let mut wire = Wire::new();
    wire.send(&units.concat());
    let doc = crate::fields_json::fields_json(&wire.d, &wire.file(), None, None);
    let prefix = 2u64;
    let unit_len = units[0].len() as u64;
    assert_eq!(
        first_byte_places(&doc),
        [
            (0, prefix),
            (0, unit_len + prefix),
            (0, 2 * unit_len + prefix)
        ],
        "{doc}"
    );
    assert_eq!(wire.d.flows()[0].capture_order(), [0, 1, 2]);
}

/// The ceiling counts from the front of capture order, so the row it holds back
/// is the one the capture took last.
#[cfg(feature = "dissect")]
#[test]
fn a_row_ceiling_keeps_the_rows_the_capture_saw_first() {
    let wire = a_unit_that_completes_after_one_that_began_later();
    let doc = crate::fields_json::fields_json(&wire.d, &wire.file(), Some(1), None);
    assert_eq!(first_byte_packets(&doc), [0], "{doc}");
    assert!(doc.contains("\"shown\":1,\"omitted\":1"), "{doc}");
}

/// The selection document's rows are the field document's, in the same order:
/// one function orders both.
#[cfg(all(feature = "dissect", feature = "network-codecs"))]
#[test]
fn the_selection_document_lists_rows_in_the_field_documents_order() {
    let wire = a_unit_that_completes_after_one_that_began_later();
    let filter = crate::filter::Filter::parse("").expect("an empty selector parses");
    let doc = crate::selection_json::selection_json_where_coordinated(
        &wire.d,
        &filter,
        &EveryListNumbered,
    );
    let directions: Vec<&str> = doc
        .match_indices("\"direction\":\"")
        .map(|(at, key)| &doc[at + key.len()..at + key.len() + 1])
        .collect();
    assert_eq!(directions, ["a", "b"], "A began first: {doc}");
}

/// A capture that needs no reordering reads exactly as it did: the identity.
/// The control for the three tests above, and the reason the revision row can
/// say a capture without a hole or a spanning unit is unchanged.
#[cfg(feature = "dissect")]
#[test]
fn a_capture_whose_orders_coincide_is_not_reordered() {
    let units = units(6);
    let mut wire = Wire::new();
    for (i, unit) in units.iter().enumerate() {
        if i % 2 == 0 {
            wire.send(unit);
        } else {
            wire.reply(&framed_keepalive());
        }
    }
    let flow = &wire.d.flows()[0];
    assert_eq!(flow.capture_order(), (0..6).collect::<Vec<usize>>());
    let doc = crate::fields_json::fields_json(&wire.d, &wire.file(), None, None);
    assert_eq!(first_byte_packets(&doc), [0, 1, 2, 3, 4, 5], "{doc}");
}

/// The records behind a hole are listed in capture order too, which is also
/// the order of their instants: after the hole is stepped over, the rows read
/// by packet and each row's record carries that packet's instant, so the two
/// orders a consumer might sort by agree.
#[cfg(feature = "dissect")]
#[test]
fn rows_behind_a_hole_are_in_capture_order_and_their_instants_agree_with_it() {
    let units = units(20);
    let mut wire = Wire::new();
    for (i, unit) in units.iter().enumerate() {
        if i == 3 {
            wire.lose(unit);
        } else {
            wire.send(unit);
        }
    }
    wire.d.finish();
    let flow = &wire.d.flows()[0];
    let order = flow.capture_order();
    let instants: Vec<Option<u64>> = order
        .iter()
        .map(|&p| flow.frames[p].observed_at_ns)
        .collect();
    assert!(
        instants.windows(2).all(|w| w[0] < w[1]),
        "capture order is ascending in time, strictly, on a clock that ticks: {instants:?}"
    );
    let doc = crate::fields_json::fields_json(&wire.d, &wire.file(), None, None);
    let packets = first_byte_packets(&doc);
    assert_eq!(packets.len(), 19);
    assert!(packets.windows(2).all(|w| w[0] < w[1]), "{packets:?}");
}
