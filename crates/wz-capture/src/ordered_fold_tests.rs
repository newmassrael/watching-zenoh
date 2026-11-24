// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
const ZID_C: &[u8] = &[0xC3, 0xC3, 0xC3, 0xC3];
const ZID_D: &[u8] = &[0xD4, 0xD4, 0xD4, 0xD4];

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
    for round in 0..6u32 {
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

/// The node census continues across a message that names a node as across any
/// other, including when a datagram flow it has not seen appears (a new list
/// after the others), and folds only what arrived.
#[test]
fn the_node_census_continues_across_a_message_that_names_a_node() {
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

    // A handshake on the second flow names the two nodes there: the census
    // takes the two INITs and credits the flow's earlier bytes by them.
    g.udp_wire(true, 41000, 7447, &init_wire(ZID_A));
    g.udp_wire(false, 41000, 7447, &init_wire(ZID_B));
    g.ask("the second flow is handshaken");
    let end = g.memory.node_stats();
    assert_eq!(end.restarts, mid.restarts, "{mid:?} then {end:?}");
    assert_eq!(end.resumes, mid.resumes + 1, "{mid:?} then {end:?}");
    assert_eq!(
        end.messages_folded,
        mid.messages_folded + 2,
        "the two INITs and nothing else: {mid:?} then {end:?}"
    );
}

/// Ask after a packet pushed when the capture held `held` messages, and require
/// the memory to have continued every plane and the node census over exactly
/// the messages that packet added.
fn require_continued(g: &mut Growing, held: u64, step: &str) {
    let arrived = g.messages() - held;
    assert!(
        arrived > 0,
        "{step}: the packet produced no message to fold"
    );
    let nodes_before = g.memory.node_stats();
    let (before, after) = g.ask(step);
    let work = delta(before, after);
    let nodes_after = g.memory.node_stats();
    assert_eq!(
        (
            nodes_after.restarts - nodes_before.restarts,
            nodes_after.messages_folded - nodes_before.messages_folded,
        ),
        (0, arrived),
        "{step}: the node census must go on and fold the {arrived} new message(s)"
    );
    assert_eq!(
        (work.restarts, work.resumes, work.messages_folded),
        (0, PLANES, PLANES * arrived),
        "{step}: every plane must go on and fold the {arrived} new message(s)"
    );
}

/// SESSIONS THAT OPEN ONE AFTER ANOTHER ARE FOLDED ACROSS, NOT AGAIN: each new
/// datagram flow's two INITs name two nodes no flow named before and give its
/// list a session of its own. At every step the census is the census a fresh
/// fold writes (`Growing::ask`), and from the second step on every plane and
/// the node census go on and fold only the messages that arrived, the INITs
/// included: a call costs what arrived since.
#[test]
fn sessions_that_open_one_after_another_are_folded_across_not_again() {
    let pairs: [[&[u8]; 2]; 3] = [
        [ZID_A, ZID_B],
        [ZID_C, ZID_D],
        [&[0xE5, 0xE5, 0xE5, 0xE5], &[0xF6, 0xF6, 0xF6, 0xF6]],
    ];
    let mut g = Growing::new(Dissection::new(), "");
    g.udp_wire(true, 40000, 7447, &init_wire(pairs[0][0]));
    g.ask("the first INIT");
    let mut steps = 0u32;
    for (session, pair) in pairs.iter().enumerate() {
        let sport = 40000 + session as u16;
        if session > 0 {
            let held = g.messages();
            g.udp_wire(true, sport, 7447, &init_wire(pair[0]));
            require_continued(&mut g, held, &alloc::format!("session {session}: INIT"));
            steps += 1;
        }
        let held = g.messages();
        g.udp_wire(false, sport, 7447, &init_wire(pair[1]));
        require_continued(&mut g, held, &alloc::format!("session {session}: the link"));
        steps += 1;
        for (i, record) in session_records().iter().enumerate() {
            let held = g.messages();
            g.udp(i % 2 == 0, sport, 7447, record);
            require_continued(
                &mut g,
                held,
                &alloc::format!("session {session}: record {i}"),
            );
            steps += 1;
        }
    }
    assert!(steps >= 70, "too few steps to say a fold went on: {steps}");
    assert_eq!(
        g.memory.node_stats().restarts,
        1,
        "the node census began once, at the first call"
    );
    assert_eq!(
        crate::node::session_grouping(&g.d).sessions(),
        3,
        "anti-vacuity: the capture holds three sessions"
    );
}

/// A HANDSHAKE THAT ARRIVES LATE ON AN EARLIER LIST: a fresh census numbers that
/// list's nodes before the ones a later list named, and so does the memory
/// (`Growing::ask` holds the two documents equal), without folding a message
/// again. The planes begin again, because that list's traffic was folded
/// before its session was known.
#[test]
fn a_late_handshake_on_an_earlier_list_renumbers_without_folding_again() {
    let mut g = Growing::new(Dissection::new(), "");
    for (i, record) in session_records().iter().take(4).enumerate() {
        g.udp(i % 2 == 0, 40000, 7447, record);
    }
    g.ask("traffic on the first flow, no handshake");
    g.udp_wire(true, 41000, 7447, &init_wire(ZID_C));
    g.udp_wire(false, 41000, 7447, &init_wire(ZID_D));
    g.ask("the second flow's session");
    let nodes_before = g.memory.node_stats();

    g.udp_wire(true, 40000, 7447, &init_wire(ZID_A));
    g.udp_wire(false, 40000, 7447, &init_wire(ZID_B));
    let (before, after) = g.ask("the first flow says who it is, late");
    let nodes_after = g.memory.node_stats();
    assert_eq!(
        (
            nodes_after.restarts - nodes_before.restarts,
            nodes_after.messages_folded - nodes_before.messages_folded,
        ),
        (0, 2),
        "the node census takes the two INITs and folds nothing again"
    );
    assert_eq!(
        crate::node::nodes(&g.d).nodes()[0].zid,
        ZID_A,
        "anti-vacuity: the late handshake's node is numbered first"
    );
    assert_eq!(
        delta(before, after).restarts,
        PLANES,
        "the first flow's traffic was folded before its session was known"
    );
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
    // An exact key and not `demo/**`: a selector carrying a wildcard is a parse
    // error in a build without the wildcard feature, and this lib is also run
    // with default features off.
    let mut g = Growing::new(Dissection::new(), "key == demo/temp");
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
    g.filter = Filter::parse("key == demo/temp").expect("the selector parses");
    let (before, after) = g.ask("back to the first selector");
    assert_eq!(delta(before, after).restarts, PLANES);
}

/// With two memories, two selectors asked in turn each CONTINUE their own folds:
/// only the first ask of each begins, every later ask folds just the messages that
/// arrived since that selector was last asked, and every answer equals a fresh fold.
#[test]
fn two_memories_let_two_selectors_alternate_without_beginning_again() {
    let mut g = Growing::new(Dissection::new(), "key == demo/temp");
    assert_eq!(g.memory.set_selector_memories(2), 2);
    let first = Filter::parse("key == demo/temp").expect("the selector parses");
    let second = Filter::parse("kind == query").expect("the selector parses");
    g.udp_wire(true, 40000, 7447, &init_wire(ZID_A));
    g.udp_wire(false, 40000, 7447, &init_wire(ZID_B));
    let mut restarts = 0;
    for (i, record) in session_records().iter().take(8).enumerate() {
        g.udp(i % 2 == 0, 40000, 7447, record);
        for (name, filter) in [("first", &first), ("second", &second)] {
            g.filter = filter.clone();
            let (before, after) = g.ask(&alloc::format!("{name} selector, step {i}"));
            restarts += delta(before, after).restarts;
        }
    }
    assert_eq!(
        restarts,
        2 * PLANES,
        "each selector begins its planes once and continues them after"
    );
}

/// TWO SELECTORS ASKED IN TURN, FROM THE SECOND ROUND ON, EACH FOLD ONLY WHAT
/// ARRIVED since that selector was last asked: a call's cost follows the new
/// traffic whichever selector it is under, not the capture.
#[test]
fn two_selectors_in_turn_fold_only_what_arrived_since_each_was_asked() {
    let mut g = Growing::new(Dissection::new(), "key == demo/temp");
    assert_eq!(g.memory.set_selector_memories(2), 2);
    let selectors = [
        Filter::parse("key == demo/temp").expect("the selector parses"),
        Filter::parse("kind == query").expect("the selector parses"),
    ];
    g.udp_wire(true, 40000, 7447, &init_wire(ZID_A));
    g.udp_wire(false, 40000, 7447, &init_wire(ZID_B));
    let mut continued = 0u64;
    for (i, record) in session_records().iter().enumerate() {
        let held = g.messages();
        g.udp(i % 2 == 0, 40000, 7447, record);
        let arrived = g.messages() - held;
        for filter in &selectors {
            g.filter = filter.clone();
            let (before, after) = g.ask(&alloc::format!("record {i}"));
            if i == 0 {
                continue;
            }
            let work = delta(before, after);
            assert_eq!(work.restarts, 0, "record {i}: {work:?}");
            assert_eq!(
                work.messages_folded,
                PLANES * arrived,
                "record {i}: {arrived} message(s) arrived since this selector was \
                 last asked, {work:?}"
            );
            continued += 1;
        }
    }
    assert!(
        continued >= 40,
        "too few steps to say two selectors continued: {continued}"
    );
}

/// A third selector takes the place of the least recently used one, and that one
/// begins again when it is next asked; the one asked more recently is kept.
#[test]
fn the_least_recently_used_selector_gives_up_its_memory() {
    let mut g = Growing::new(Dissection::new(), "key == demo/temp");
    g.memory.set_selector_memories(2);
    let a = Filter::parse("key == demo/temp").expect("the selector parses");
    let b = Filter::parse("kind == query").expect("the selector parses");
    let c = Filter::parse("kind == reply").expect("the selector parses");
    g.udp_wire(true, 40000, 7447, &init_wire(ZID_A));
    g.udp_wire(false, 40000, 7447, &init_wire(ZID_B));
    for filter in [&a, &b, &a, &c] {
        g.filter = filter.clone();
        g.ask("filling the memories");
    }
    // `a` was used after `b`, so `c` took `b`'s place.
    assert_eq!(g.memory.selector_evictions(), 1, "c took b's place");
    assert_eq!(g.memory.selectors_in_use(), 2, "two memories, both in use");
    g.filter = a.clone();
    let (before, after) = g.ask("a is still kept");
    assert_eq!(delta(before, after).restarts, 0);
    g.filter = c.clone();
    let (before, after) = g.ask("c is still kept");
    assert_eq!(delta(before, after).restarts, 0);
    g.filter = b.clone();
    let (before, after) = g.ask("b was given up");
    assert_eq!(delta(before, after).restarts, PLANES);
    assert_eq!(
        g.memory.selector_evictions(),
        2,
        "b came back and took the place of the one asked longest ago"
    );
}

/// The count is held to what a handle may keep, and lowering it gives up the
/// least recently used first.
#[test]
fn the_count_of_memories_is_held_to_its_bounds() {
    let mut memory = CensusMemory::new();
    assert_eq!(memory.selector_memories(), 1, "one is the default");
    assert_eq!(memory.set_selector_memories(0), 1, "none is held to one");
    assert_eq!(
        memory.set_selector_memories(usize::MAX),
        crate::MAX_SELECTOR_MEMORIES
    );
    assert_eq!(memory.set_selector_memories(3), 3);
    assert_eq!(memory.selector_memories(), 3);
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
    assert_eq!(tail.iter().len(), 0);
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

/// A FLOW'S WORD THAT MOVES BEGINS A FOLD THAT READ IT, AND NO OTHER.
///
/// The flow carries records and no handshake, and each Frame's SN is one after
/// the last one's: a step weighs about eight bits toward zenoh (a varint equals
/// a given value with chance `2^-8`), so with two steps the word is still
/// `undecided` and the third crosses `yes`, where the word latches. Nothing else
/// a fold is judged by moves, which is what isolates the word. A selector that
/// reads `zenoh` judged the flow's earlier messages by the old word and must
/// begin again (and writes the same document a fresh fold does); one that does
/// not continues, and folds exactly the one message that arrived.
#[test]
fn a_flow_word_that_moves_begins_a_fold_that_reads_it_and_no_other() {
    let frame = |sn: u8, record: Vec<u8>| {
        let mut wire = alloc::vec![wz_session_core::wire_const::T_MID_FRAME, sn];
        wire.extend_from_slice(&record);
        wire
    };
    for (selector, begins) in [("zenoh == undecided", true), ("kind == put", false)] {
        let mut g = Growing::new(Dissection::new(), selector);
        g.udp_wire(true, 40000, 7447, &frame(1, declare_kexpr(7, "demo/temp")));
        g.udp_wire(
            true,
            40000,
            7447,
            &frame(2, push(sender_space(7, None), &[1u8; 12])),
        );
        g.ask("settled");
        g.udp_wire(
            true,
            40000,
            7447,
            &frame(3, push(sender_space(7, None), &[2u8; 12])),
        );
        let (before, after) = g.ask("continued");
        assert_eq!(delta(before, after).restarts, 0, "{selector}: an append");

        g.udp_wire(
            true,
            40000,
            7447,
            &frame(4, push(sender_space(7, None), &[3u8; 12])),
        );
        let (before, after) = g.ask("the third step");
        let moved = delta(before, after);
        if begins {
            assert_eq!(moved.restarts, PLANES, "{selector}: {moved:?}");
        } else {
            assert_eq!(moved.restarts, 0, "{selector}: {moved:?}");
            assert_eq!(moved.messages_folded, PLANES, "{selector}: {moved:?}");
        }
    }
}

/// Two captures fed the same packets on one datagram flow: one that keeps
/// `per_flow` messages and one that keeps every message.
#[cfg(feature = "dissect")]
struct Twin {
    bounded: Dissection,
    whole: Dissection,
    packets: usize,
}

#[cfg(feature = "dissect")]
impl Twin {
    fn new(per_flow: usize) -> Self {
        Self {
            bounded: Dissection::with_limits(DissectionLimits {
                frames_per_flow: Some(per_flow),
                ..DissectionLimits::default()
            }),
            whole: Dissection::new(),
            packets: 0,
        }
    }

    fn wire(&mut self, from_low: bool, wire: &[u8]) {
        let packet = if from_low {
            udp_packet(LOW, 40000, HIGH, 7447, wire)
        } else {
            udp_packet(HIGH, 7447, LOW, 40000, wire)
        };
        self.bounded
            .push_packet(LINKTYPE_ETHERNET, self.packets, &packet);
        self.whole
            .push_packet(LINKTYPE_ETHERNET, self.packets, &packet);
        self.packets += 1;
    }

    /// Messages the bounded capture ever decoded.
    fn produced(&self) -> u64 {
        self.bounded
            .message_lists()
            .map(|(_, frames)| frames.produced())
            .sum()
    }

    /// Messages the bounded capture holds now.
    fn held(&self) -> u64 {
        self.bounded
            .message_lists()
            .map(|(_, frames)| frames.len() as u64)
            .sum()
    }
}

/// The planes of a census document: what every census of the same messages
/// writes alike, without `observed` and `dropped_by_limits`, which say what one
/// capture holds and lost.
#[cfg(feature = "dissect")]
fn planes_of(doc: &str) -> &str {
    let from = doc.find(",\"keyexprs\":").expect("the planes");
    let to = doc.find(",\"dropped_by_limits\":").expect("the losses");
    &doc[from..to]
}

/// The raw value of `key` in a census document's `observed` object.
#[cfg(feature = "dissect")]
fn observed_value<'d>(doc: &'d str, key: &str) -> &'d str {
    let open = "\"observed\":{";
    let at = doc.find(open).expect("the observed object") + open.len();
    let marker = alloc::format!("\"{key}\":");
    let start = at + doc[at..].find(&marker).expect("the key") + marker.len();
    let rest = &doc[start..];
    // The interval is an object of scalars; every other value is a scalar.
    let end = if rest.starts_with('{') {
        rest.find('}').expect("the interval closes") + 1
    } else {
        rest.find([',', '}']).expect("the value ends")
    };
    &rest[..end]
}

/// A CENSUS OVER ITS HISTORY GOES ON ACROSS FRONT TRIMS and is the census of
/// every message it observed: at every step its planes are the planes of a
/// capture that kept every message, a step after a trim folds only what
/// arrived, and the declaration a ceiling took first still names the records
/// after it, where a census of what is held calls them unresolved.
#[cfg(feature = "dissect")]
#[test]
fn a_history_census_goes_on_across_trims_and_counts_everything_observed() {
    let mut t = Twin::new(6);
    let mut memory = CensusMemory::over_history();
    let any = Filter::any();
    t.wire(true, &init_wire(ZID_A));
    t.wire(false, &init_wire(ZID_B));
    t.wire(true, &frame_carrying(&declare_kexpr(7, "demo/temp")));
    let first = census_json_where_resumable(&t.bounded, &any, &mut memory);
    assert_eq!(
        planes_of(&first),
        planes_of(&census_json_where(&t.whole, &any))
    );

    let mut trimmed_steps = 0;
    for round in 0..30u8 {
        let produced = t.produced();
        t.wire(
            true,
            &frame_carrying(&push(sender_space(7, None), &[round; 12])),
        );
        let arrived = t.produced() - produced;
        assert!(arrived > 0, "round {round} produced no message to fold");
        let before = memory.stats();
        let history = census_json_where_resumable(&t.bounded, &any, &mut memory);
        let work = delta(before, memory.stats());
        let whole = census_json_where(&t.whole, &any);
        assert_eq!(
            planes_of(&history),
            planes_of(&whole),
            "round {round}: the census over its history is not the census of \
             every message it observed"
        );
        for key in ["messages", "interval"] {
            assert_eq!(
                observed_value(&history, key),
                observed_value(&whole, key),
                "round {round}: {key}"
            );
        }
        assert_eq!(observed_value(&whole, "trimmed"), "0", "{whole}");
        let trimmed = t.produced() - t.held();
        assert_eq!(
            observed_value(&history, "trimmed"),
            alloc::format!("{trimmed}"),
            "round {round}: {history}"
        );
        assert_eq!(
            (work.restarts, work.resumes, work.messages_folded),
            (0, PLANES, PLANES * arrived),
            "round {round}: a step folds what arrived, trimmed list or not ({work:?})"
        );
        if trimmed > 0 {
            trimmed_steps += 1;
        }
    }
    assert!(
        trimmed_steps > 20,
        "the ceiling must trim on most steps, or nothing went on across a trim: \
         {trimmed_steps}"
    );

    let history = census_json_where_resumable(&t.bounded, &any, &mut memory);
    let held_only = census_json_where(&t.bounded, &any);
    assert!(
        planes_of(&history).contains("\"demo/temp\""),
        "the records keep the key their trimmed declaration gave: {history}"
    );
    assert!(
        !planes_of(&held_only).contains("\"demo/temp\""),
        "a census of what is held must have lost the declaration, or this \
         fixture never trimmed it: {held_only}"
    );
}

/// A MESSAGE A TRIM TAKES BEFORE ANY CALL FOLDS IT is counted `unobserved`: a
/// caller asking once per twenty pushes on a list that holds six reads the hole,
/// exactly, and one asking at every push, or a census over the capture, reads
/// none.
#[cfg(feature = "dissect")]
#[test]
fn a_history_census_counts_what_left_before_it_was_folded() {
    let any = Filter::any();
    let record = |round: u8| frame_carrying(&push(sender_space(7, None), &[round; 12]));

    let mut slow = Twin::new(6);
    let mut memory = CensusMemory::over_history();
    slow.wire(true, &frame_carrying(&declare_kexpr(7, "demo/temp")));
    let first = census_json_where_resumable(&slow.bounded, &any, &mut memory);
    assert_eq!(observed_value(&first, "unobserved"), "0", "{first}");
    let folded_through = slow.produced();
    for round in 0..20u8 {
        slow.wire(true, &record(round));
    }
    let first_held = slow.produced() - slow.held();
    assert!(
        first_held > folded_through,
        "the fixture must trim past what the first call folded"
    );
    let after = census_json_where_resumable(&slow.bounded, &any, &mut memory);
    assert_eq!(
        observed_value(&after, "unobserved"),
        alloc::format!("{}", first_held - folded_through),
        "the messages trimmed between the two calls: {after}"
    );
    assert_eq!(
        observed_value(&after, "messages"),
        alloc::format!("{}", folded_through + slow.held()),
        "{after}"
    );
    assert_eq!(
        memory.stats().restarts,
        PLANES,
        "the planes went on across the hole: {:?}",
        memory.stats()
    );
    let over_the_capture = census_json_where(&slow.bounded, &any);
    assert_eq!(
        observed_value(&over_the_capture, "unobserved"),
        "0",
        "{over_the_capture}"
    );

    let mut fast = Twin::new(6);
    let mut memory = CensusMemory::over_history();
    fast.wire(true, &frame_carrying(&declare_kexpr(7, "demo/temp")));
    census_json_where_resumable(&fast.bounded, &any, &mut memory);
    for round in 0..20u8 {
        fast.wire(true, &record(round));
        let doc = census_json_where_resumable(&fast.bounded, &any, &mut memory);
        assert_eq!(
            observed_value(&doc, "unobserved"),
            "0",
            "push {round}: {doc}"
        );
    }
    assert!(
        fast.produced() > fast.held(),
        "the fast caller's list was trimmed too, so its 0 is not for want of a trim"
    );
}

/// A census over its history gives up what its planes keep of the rows no list
/// holds, and its document does not move for it: the entries kept stay near
/// what the lists hold, where every row ever folded would be kept otherwise.
#[cfg(feature = "dissect")]
#[test]
fn a_history_census_gives_up_the_rows_no_list_holds() {
    let mut t = Twin::new(6);
    let mut memory = CensusMemory::over_history();
    let any = Filter::any();
    t.wire(true, &frame_carrying(&declare_kexpr(7, "demo/temp")));
    census_json_where_resumable(&t.bounded, &any, &mut memory);
    const PUSHES: u32 = 1_500;
    for round in 0..PUSHES {
        t.wire(
            true,
            &frame_carrying(&push(sender_space(7, None), &round.to_le_bytes())),
        );
        // Asked at every push, as a tap asks at every beat: a message a ceiling
        // takes before any call folds it is never observed, so a census asked
        // less often than the list turns over is not the untrimmed twin's.
        let history = census_json_where_resumable(&t.bounded, &any, &mut memory);
        if round % 100 == 99 {
            assert_eq!(
                planes_of(&history),
                planes_of(&census_json_where(&t.whole, &any)),
                "push {round}: giving rows up moved the document"
            );
        }
    }
    assert_eq!(
        memory.stats().restarts,
        PLANES,
        "the planes began once and went on: {:?}",
        memory.stats()
    );
    let kept = memory.kept_entries();
    assert!(
        kept < 1_000,
        "{kept} entries kept for {PUSHES} records folded and 6 held: the rows no \
         list holds were not given up"
    );
}

/// A census over its history whose exchanges still open alone outgrow four
/// times what the lists hold begins its planes again over what is held, and
/// says so: `trimmed` is 0 and the planes are a census of what is held.
#[cfg(feature = "dissect")]
#[test]
fn a_history_census_whose_open_exchanges_outgrow_the_holding_begins_again() {
    let mut t = Twin::new(6);
    let mut memory = CensusMemory::over_history();
    let any = Filter::any();
    t.wire(
        true,
        &frame_carrying(&push(sender_space(0, Some("demo/a")), &[1u8; 4])),
    );
    census_json_where_resumable(&t.bounded, &any, &mut memory);
    // Asked at every query, so every message is observed (see the test above):
    // the planes go on, and the call after the open exchanges pass the bound
    // begins them again.
    let mut began_again = None;
    for n in 0..1_200u32 {
        t.wire(
            true,
            &frame_carrying(&request_query(n + 1, sender_space(0, Some("demo/q")))),
        );
        let outgrown = 4 * t.held() as usize + 1024;
        let kept = memory.kept_entries();
        let before = memory.stats();
        let doc = census_json_where_resumable(&t.bounded, &any, &mut memory);
        let work = delta(before, memory.stats());
        if work.restarts > 0 {
            assert!(
                kept > outgrown,
                "query {n}: the planes began again with {kept} entries against a \
                 bound of {outgrown} ({work:?})"
            );
            began_again = Some((doc, work));
            break;
        }
        if n % 100 == 99 {
            assert_eq!(
                planes_of(&doc),
                planes_of(&census_json_where(&t.whole, &any)),
                "query {n}: before the bound is passed the census is the history's"
            );
        }
    }
    let (again, work) = began_again.expect("the open exchanges never outgrew the holding");
    assert_eq!(work.restarts, PLANES, "the planes begin again: {work:?}");
    // Every plane, the node plane included: the node census begins again with
    // the planes, so the bytes it credits are the held messages' too.
    assert_eq!(
        planes_of(&again),
        planes_of(&census_json_where(&t.bounded, &any)),
        "begun again, every plane is a census of what is held"
    );
    assert_eq!(observed_value(&again, "trimmed"), "0", "{again}");
    assert_eq!(
        observed_value(&again, "messages"),
        alloc::format!("{}", t.held()),
        "{again}"
    );
}

/// A census over its history whose nodes say who they are again goes on: the
/// node census takes the two INITs, the grouping they leave is the one the
/// planes were folded under, and the planes go on across the trims they have
/// already gone on across, still counting what the lists no longer hold.
#[cfg(feature = "dissect")]
#[test]
fn a_history_census_goes_on_when_its_nodes_say_who_they_are_again() {
    let mut t = Twin::new(6);
    let mut memory = CensusMemory::over_history();
    let any = Filter::any();
    t.wire(true, &init_wire(ZID_A));
    t.wire(false, &init_wire(ZID_B));
    t.wire(true, &frame_carrying(&declare_kexpr(7, "demo/temp")));
    census_json_where_resumable(&t.bounded, &any, &mut memory);
    for round in 0..10u8 {
        t.wire(
            true,
            &frame_carrying(&push(sender_space(7, None), &[round; 12])),
        );
        census_json_where_resumable(&t.bounded, &any, &mut memory);
    }
    assert!(
        t.produced() > t.held(),
        "the ceiling must have trimmed, or nothing is history yet"
    );

    // The same two nodes say who they are again.
    t.wire(true, &init_wire(ZID_A));
    t.wire(false, &init_wire(ZID_B));
    let (nodes_before, before) = (memory.node_stats(), memory.stats());
    let again = census_json_where_resumable(&t.bounded, &any, &mut memory);
    let work = delta(before, memory.stats());
    assert_eq!(
        memory.node_stats().restarts - nodes_before.restarts,
        0,
        "a message that names a node is folded like any other"
    );
    assert_eq!(
        (work.restarts, work.messages_folded),
        (0, 2 * PLANES),
        "the planes go on and fold the two INITs: {work:?}"
    );
    assert_ne!(
        observed_value(&again, "trimmed"),
        "0",
        "the census still counts what the lists no longer hold: {again}"
    );
}
