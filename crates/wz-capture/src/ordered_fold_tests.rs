// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE RESUMED CENSUS IS THE CENSUS, and what it did to get there.
//!
//! Two things are held, and neither is a clock.
//!
//! **Equality.** At every step of a growing capture, the document a kept memory
//! writes is the document a fresh fold writes, byte for byte, for the same
//! selector. That is the whole correctness claim: a fold that continued where it
//! must not would write a different table, and the equality is what would show it.
//!
//! **Work.** [`crate::FoldStats`] says how many messages a memory folded and how
//! many times it began again. A step that adds `n` messages to a capture the fold
//! may continue across must fold exactly `n` per plane, and begin nothing; a step
//! that breaks one of the conditions must begin every plane once. Equality alone
//! would pass a memory that restarted every time, which is the old cost under a
//! new name.
//!
//! Each capture below is built to break ONE condition and only that one, because a
//! capture that broke two would pass for either.

use alloc::vec::Vec;

use crate::census_json::{census_json_where, census_json_where_resumable};
use crate::datagram_tests::{
    frame_carrying, framed_keepalive, push, sender_space, tcp_packet_on, tcp_packet_reverse,
    udp_packet,
};
use crate::exchange::tests::{declare_kexpr, request_query, response_final, response_reply};
use crate::filter::Filter;
use crate::link::LINKTYPE_ETHERNET;
use crate::{CensusMemory, Dissection, DissectionLimits, FoldStats};

const LOW: [u8; 4] = [10, 0, 0, 1];
const HIGH: [u8; 4] = [10, 0, 0, 2];
const ZID_A: &[u8] = &[0xA1, 0xA1, 0xA1, 0xA1];
const ZID_B: &[u8] = &[0xB2, 0xB2, 0xB2, 0xB2];

/// How many planes a memory folds each message through.
const PLANES: u64 = 4;

/// A transport INIT naming `zid`: what makes a node, and two of them a link.
fn init_wire(zid: &[u8]) -> Vec<u8> {
    let mut wire = alloc::vec![
        wz_session_core::wire_const::T_MID_INIT,
        0x09,
        (((zid.len() as u8) - 1) << 4) | 0x02,
    ];
    wire.extend_from_slice(zid);
    wire
}

/// A capture grown one packet at a time, and the memory kept beside it.
struct Growing {
    d: Dissection,
    packets: usize,
    memory: CensusMemory,
    filter: Filter,
}

impl Growing {
    fn new(d: Dissection, selector: &str) -> Self {
        Self {
            d,
            packets: 0,
            memory: CensusMemory::new(),
            filter: Filter::parse(selector).expect("the selector parses"),
        }
    }

    fn messages(&self) -> u64 {
        self.d
            .message_lists()
            .map(|(_, frames)| frames.len() as u64)
            .sum()
    }

    /// One UDP datagram carrying `record` in a transport Frame, from `from_low`
    /// on the link `(sport, dport)`.
    fn udp(&mut self, from_low: bool, sport: u16, dport: u16, record: &[u8]) {
        self.udp_wire(from_low, sport, dport, &frame_carrying(record));
    }

    fn udp_wire(&mut self, from_low: bool, sport: u16, dport: u16, wire: &[u8]) {
        let packet = if from_low {
            udp_packet(LOW, sport, HIGH, dport, wire)
        } else {
            udp_packet(HIGH, dport, LOW, sport, wire)
        };
        self.d.push_packet(LINKTYPE_ETHERNET, self.packets, &packet);
        self.packets += 1;
    }

    fn raw(&mut self, packet: &[u8]) {
        self.d.push_packet(LINKTYPE_ETHERNET, self.packets, packet);
        self.packets += 1;
    }

    /// Ask both ways and require the same bytes; hand back what the memory did.
    fn ask(&mut self, step: &str) -> (FoldStats, FoldStats) {
        let before = self.memory.stats();
        let fresh = census_json_where(&self.d, &self.filter);
        let resumed = census_json_where_resumable(&self.d, &self.filter, &mut self.memory);
        assert_eq!(
            resumed, fresh,
            "{step}: the resumed census is not the census a fresh fold writes"
        );
        (before, self.memory.stats())
    }
}

fn delta(before: FoldStats, after: FoldStats) -> FoldStats {
    FoldStats {
        messages_folded: after.messages_folded - before.messages_folded,
        restarts: after.restarts - before.restarts,
        resumes: after.resumes - before.resumes,
    }
}

/// The records a session carries once it is up: a declaration, a put under the
/// declared alias, a query and its answer.
fn session_records() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    out.push(declare_kexpr(7, "demo/temp"));
    for round in 0..6u64 {
        out.push(push(sender_space(7, None), &[round as u8; 12]));
        out.push(request_query(round + 1, sender_space(0, Some("demo/q"))));
        out.push(response_reply(
            round + 1,
            sender_space(0, Some("demo/q")),
            b"ok",
        ));
        out.push(response_final(round + 1));
    }
    out
}

/// THE CASE THE DOOR IS FOR: one session, handshaken, then traffic that only
/// appends. Every step after the handshake continues every plane and folds
/// exactly the messages that arrived.
#[test]
fn a_session_that_only_grows_is_continued_not_refolded() {
    let mut g = Growing::new(Dissection::new(), "");
    g.udp_wire(true, 40000, 7447, &init_wire(ZID_A));
    g.ask("first INIT");
    g.udp_wire(false, 40000, 7447, &init_wire(ZID_B));
    g.ask("second INIT, the link");

    let mut continued = 0u64;
    for (i, record) in session_records().iter().enumerate() {
        let from_low = i % 2 == 0;
        let held = g.messages();
        g.udp(from_low, 40000, 7447, record);
        let arrived = g.messages() - held;
        assert!(arrived > 0, "record {i} produced no message to fold");
        let nodes_before = g.memory.node_stats();
        let (before, after) = g.ask(&alloc::format!("record {i}"));
        let work = delta(before, after);
        // The node census, which the grouping every plane is folded against is
        // derived from, continues too and takes only what arrived.
        let nodes_after = g.memory.node_stats();
        assert_eq!(
            (
                nodes_after.restarts - nodes_before.restarts,
                nodes_after.resumes - nodes_before.resumes,
                nodes_after.messages_folded - nodes_before.messages_folded,
            ),
            (0, 1, arrived),
            "record {i}: the node census must continue and fold the {arrived} new message(s) only"
        );
        assert_eq!(
            work.restarts, 0,
            "record {i}: a capture that only appended must not begin again, {work:?}"
        );
        assert_eq!(work.resumes, PLANES, "record {i}: {work:?}");
        // The work is the messages that arrived this step and nothing else, which
        // is what makes the cost follow the new traffic and not the capture.
        assert_eq!(
            work.messages_folded,
            PLANES * arrived,
            "record {i}: {arrived} message(s) arrived and each of {PLANES} planes \
             folds each once, {work:?}"
        );
        continued += 1;
    }
    assert!(
        continued >= 20,
        "the capture is too short to say a fold continued: {continued} steps"
    );
}

/// ANTI-VACUITY for the work counter: a handshake that arrives after the traffic
/// it names changes who owns every earlier message, so the fold cannot continue,
/// and the counter must say it began again.
#[test]
fn a_handshake_that_arrives_late_begins_every_plane_again() {
    let mut g = Growing::new(Dissection::new(), "");
    for (i, record) in session_records().iter().take(6).enumerate() {
        g.udp(i % 2 == 0, 40000, 7447, record);
        g.ask(&alloc::format!("traffic {i}"));
    }
    g.udp_wire(true, 40000, 7447, &init_wire(ZID_A));
    g.ask("first INIT");
    g.udp_wire(false, 40000, 7447, &init_wire(ZID_B));
    let (before, after) = g.ask("second INIT, the link");
    let work = delta(before, after);
    assert_eq!(
        work.restarts, PLANES,
        "the link changes the grouping every plane was folded against: {work:?}"
    );
    // And once it has begun again it continues.
    g.udp(true, 40000, 7447, &push(sender_space(7, None), &[1u8; 12]));
    let (before, after) = g.ask("traffic after the link");
    let work = delta(before, after);
    assert_eq!((work.restarts, work.resumes), (0, PLANES), "{work:?}");
}

/// The node census begins again exactly when a message that arrived names a node,
/// and continues otherwise, including when a datagram flow it has not seen
/// appears (a new list after the others).
#[test]
fn the_node_census_begins_again_only_when_a_message_names_a_node() {
    let mut g = Growing::new(Dissection::new(), "");
    g.udp_wire(true, 40000, 7447, &init_wire(ZID_A));
    g.udp_wire(false, 40000, 7447, &init_wire(ZID_B));
    g.ask("handshaken");
    let base = g.memory.node_stats();

    g.udp(
        true,
        40000,
        7447,
        &push(sender_space(0, Some("demo/a")), &[1u8; 12]),
    );
    g.ask("traffic");
    // A second datagram flow with traffic and no handshake: a new list, after the
    // others, naming nobody.
    g.udp(
        true,
        41000,
        7447,
        &push(sender_space(0, Some("demo/b")), &[2u8; 12]),
    );
    g.ask("a second datagram flow");
    let mid = g.memory.node_stats();
    assert_eq!(mid.restarts, base.restarts, "{base:?} then {mid:?}");
    assert_eq!(mid.resumes, base.resumes + 2, "{base:?} then {mid:?}");

    // A handshake on the second flow names the two nodes there: begin again.
    g.udp_wire(true, 41000, 7447, &init_wire(ZID_A));
    g.udp_wire(false, 41000, 7447, &init_wire(ZID_B));
    g.ask("the second flow is handshaken");
    let end = g.memory.node_stats();
    assert_eq!(end.restarts, mid.restarts + 1, "{mid:?} then {end:?}");
}

/// A new STREAM flow is a new list in front of every datagram list, which moves
/// the position a list is known by, so the fold begins again; a new DATAGRAM flow
/// lands after the others and does not.
#[test]
fn a_new_stream_flow_begins_again_and_a_new_datagram_flow_does_not() {
    let mut g = Growing::new(Dissection::new(), "");
    g.udp_wire(true, 40000, 7447, &init_wire(ZID_A));
    g.udp_wire(false, 40000, 7447, &init_wire(ZID_B));
    g.udp(true, 40000, 7447, &declare_kexpr(7, "demo/temp"));
    g.ask("settled");
    g.udp(true, 40000, 7447, &push(sender_space(7, None), &[1u8; 12]));
    let (before, after) = g.ask("continued");
    assert_eq!(delta(before, after).restarts, 0);

    // A second datagram flow: after the first one in the enumeration.
    g.udp(
        true,
        41000,
        7447,
        &push(sender_space(0, Some("demo/b")), &[2u8; 12]),
    );
    let (before, after) = g.ask("a second datagram flow");
    assert_eq!(
        delta(before, after).restarts,
        0,
        "a datagram flow appended after the others keeps every position"
    );

    // A stream flow: in front of every datagram list.
    g.raw(&tcp_packet_on(2222, 0, &framed_keepalive()));
    let (before, after) = g.ask("a stream flow appeared");
    assert_eq!(
        delta(before, after).restarts,
        PLANES,
        "a stream flow moves the position of every datagram list"
    );
    g.udp(true, 40000, 7447, &push(sender_space(7, None), &[3u8; 12]));
    let (before, after) = g.ask("after it");
    let work = delta(before, after);
    assert_eq!((work.restarts, work.resumes), (0, PLANES), "{work:?}");
}

/// A message decoded AFTER a packet that followed it: bytes of a stream that
/// arrived behind a gap are held until the gap fills, so the message they carry
/// sorts before a message another flow already contributed. The fold has no place
/// for it and begins again.
#[test]
fn a_message_that_sorts_before_one_already_folded_begins_again() {
    let mut g = Growing::new(Dissection::new(), "");
    // Packet 0: the first stream bytes, which fix where the stream begins.
    g.raw(&tcp_packet_on(1111, 0, &framed_keepalive()));
    g.ask("the stream begins");
    // Packet 1: a segment three bytes ahead of where the stream has reached. The
    // bytes between are missing, so it is held and decodes nothing yet.
    let held = g.messages();
    g.raw(&tcp_packet_on(1111, 6, &framed_keepalive()));
    assert_eq!(g.messages(), held, "a segment behind a gap decodes nothing");
    g.ask("a held segment");
    // Packet 2: a datagram message, folded.
    g.udp(
        true,
        40000,
        7447,
        &push(sender_space(0, Some("demo/a")), &[1u8; 12]),
    );
    g.ask("a datagram message");
    g.udp(
        true,
        40000,
        7447,
        &push(sender_space(0, Some("demo/a")), &[2u8; 12]),
    );
    let (before, after) = g.ask("continued");
    assert_eq!(delta(before, after).restarts, 0);
    // The three bytes that were missing. The segment held at packet 1 decodes now,
    // so a message of packet 1 appears behind a message of packet 3.
    let held = g.messages();
    g.raw(&tcp_packet_on(1111, 3, &framed_keepalive()));
    assert!(
        g.messages() >= held + 2,
        "the gap filling releases the held segment"
    );
    let (before, after) = g.ask("the gap fills");
    assert_eq!(
        delta(before, after).restarts,
        PLANES,
        "a message that sorts before the last one folded cannot be fed to a fold"
    );
}

/// A ceiling on the frames a flow keeps trims the front, which renumbers every
/// position behind it, so the fold begins again at each trim and still writes the
/// document a fresh fold writes.
#[test]
fn a_trimmed_list_begins_again_and_still_equals() {
    let limits = DissectionLimits {
        frames_per_flow: Some(6),
        ..DissectionLimits::default()
    };
    let mut g = Growing::new(Dissection::with_limits(limits), "");
    for (i, record) in session_records().iter().enumerate() {
        g.udp(i % 2 == 0, 40000, 7447, record);
        g.ask(&alloc::format!("record {i}"));
    }
    // The list is trimmed from the sixth message on, so the later steps begin
    // again each time; the earlier ones continued.
    let stats = g.memory.stats();
    assert!(stats.restarts > PLANES, "{stats:?}");
    assert!(stats.resumes > 0, "{stats:?}");
}

/// A memory is for ONE selector: the same one continues, another begins again,
/// and each answer equals a fresh fold under its own selector.
#[test]
fn another_selector_begins_again_and_the_same_one_continues() {
    let mut g = Growing::new(Dissection::new(), "key == demo/**");
    g.udp_wire(true, 40000, 7447, &init_wire(ZID_A));
    g.udp_wire(false, 40000, 7447, &init_wire(ZID_B));
    for (i, record) in session_records().iter().take(8).enumerate() {
        g.udp(i % 2 == 0, 40000, 7447, record);
        g.ask(&alloc::format!("under the first selector, {i}"));
    }
    let (before, after) = g.ask("again under the first selector");
    assert_eq!(delta(before, after).restarts, 0);

    g.filter = Filter::parse("kind == query").expect("the selector parses");
    let (before, after) = g.ask("under another selector");
    assert_eq!(
        delta(before, after).restarts,
        PLANES,
        "another selector is another memory"
    );
    g.filter = Filter::parse("key == demo/**").expect("the selector parses");
    let (before, after) = g.ask("back to the first selector");
    assert_eq!(delta(before, after).restarts, PLANES);
}

/// A capture with traffic in both directions of a stream flow and a datagram
/// flow, asked after every packet with a selector that reads a `zid` prefix: the
/// grouping the selector is read against changes as nodes are named, and the
/// fold must follow it.
#[test]
fn a_zid_selector_follows_the_nodes_the_capture_names() {
    let mut g = Growing::new(Dissection::new(), "zid == a1a1a1a1");
    let mut seq_low = 0u32;
    let mut seq_high = 0u32;
    let init_a = framed(&init_wire(ZID_A));
    let init_b = framed(&init_wire(ZID_B));
    g.raw(&tcp_packet_on(1111, seq_low, &init_a));
    seq_low += init_a.len() as u32;
    g.ask("first INIT, stream");
    g.raw(&tcp_packet_reverse(seq_high, &init_b));
    seq_high += init_b.len() as u32;
    g.ask("second INIT, stream");
    for round in 0..8u64 {
        let record = push(sender_space(0, Some("demo/z")), &[round as u8; 12]);
        let wire = framed(&frame_carrying(&record));
        if round % 2 == 0 {
            g.raw(&tcp_packet_on(1111, seq_low, &wire));
            seq_low += wire.len() as u32;
        } else {
            g.raw(&tcp_packet_reverse(seq_high, &wire));
            seq_high += wire.len() as u32;
        }
        g.ask(&alloc::format!("stream traffic {round}"));
    }
    g.udp_wire(
        true,
        40000,
        7447,
        &init_wire(&[0xA1, 0xA1, 0xA1, 0xA1, 0x77]),
    );
    g.ask("another node whose zid begins like the first");
}

/// A stream message: its length as a little-endian u16, then the message.
fn framed(message: &[u8]) -> Vec<u8> {
    let mut out = (message.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(message);
    out
}

/// The walk the fold continues is the walk the planes always made: from nothing
/// remembered, [`Dissection::capture_order_since`] hands back every message in the
/// order [`Dissection::message_frames_in_capture_order`] does, and from a mark it
/// hands back the tail of that order.
#[test]
fn the_walk_from_nothing_is_the_whole_walk_and_from_a_mark_is_its_tail() {
    let mut g = Growing::new(Dissection::new(), "");
    g.udp_wire(true, 40000, 7447, &init_wire(ZID_A));
    g.udp_wire(false, 40000, 7447, &init_wire(ZID_B));
    for (i, record) in session_records().iter().take(10).enumerate() {
        g.udp(i % 2 == 0, 40000, 7447, record);
    }
    g.raw(&tcp_packet_on(2222, 0, &framed_keepalive()));
    let whole: Vec<(usize, usize)> =
        g.d.message_frames_in_capture_order()
            .into_iter()
            .map(|(_, list, packet, _)| (list, packet))
            .collect();
    let (frames, marks) = g.d.capture_order_since(None).expect("a first walk");
    let first: Vec<(usize, usize)> = frames
        .into_iter()
        .map(|(_, list, packet, _)| (list, packet))
        .collect();
    assert_eq!(first, whole);
    assert!(!whole.is_empty(), "the walk is over nothing");

    // Nothing new: an empty tail, and the same marks.
    let (tail, again) =
        g.d.capture_order_since(Some(&marks))
            .expect("still a prefix");
    assert!(tail.is_empty());
    assert_eq!(again, marks);

    // Two datagram messages more: exactly those two, in order, and they are the
    // last two of the whole walk.
    g.udp(
        true,
        40000,
        7447,
        &push(sender_space(0, Some("demo/t")), &[1u8; 12]),
    );
    g.udp(
        true,
        40000,
        7447,
        &push(sender_space(0, Some("demo/t")), &[2u8; 12]),
    );
    let whole: Vec<(usize, usize)> =
        g.d.message_frames_in_capture_order()
            .into_iter()
            .map(|(_, list, packet, _)| (list, packet))
            .collect();
    let (tail, _) =
        g.d.capture_order_since(Some(&marks))
            .expect("a prefix with two more");
    let tail: Vec<(usize, usize)> = tail
        .into_iter()
        .map(|(_, list, packet, _)| (list, packet))
        .collect();
    assert_eq!(tail.len(), 2, "{tail:?}");
    assert_eq!(tail, whole[whole.len() - 2..]);

    // A second stream flow goes in front of every datagram list, which moves
    // their positions: the mark taken before it is no longer a prefix.
    g.raw(&tcp_packet_on(3333, 0, &framed_keepalive()));
    assert!(g.d.capture_order_since(Some(&marks)).is_none());
}
