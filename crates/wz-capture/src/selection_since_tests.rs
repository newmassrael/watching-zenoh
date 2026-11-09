// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE SELECTION SINCE DOCUMENT OF A MEMORY THAT GOES ON IS THE ONE A MEMORY THAT
//! BEGINS AGAIN WRITES, and what the first did to get there.
//!
//! Two things are held, as for the census's memory (`crate::ordered_fold_tests`),
//! and neither is a clock.
//!
//! **Equality.** At every step of a growing capture, asked from the cursor the
//! last document gave, the document a kept memory writes is the document a memory
//! that judges from the first message and reads every row writes
//! ([`SelectionMemory::begin_again`] before each call), byte for byte, with the
//! same words remembered. That memory is what every call was before the planes
//! were kept, so the equality is the claim that keeping them changed no word, no
//! row, no `revised` entry and no order.
//!
//! **Work.** [`SelectionWork`] says how many messages the planes folded, how often
//! they began again, how many rows were read and how many calls read every row. A
//! capture that only grows must fold each message once and read every row only on
//! the first call; equality alone would pass a memory that walked everything every
//! time, which is the cost this memory exists to remove.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::datagram_tests::{
    frame_carrying, framed_keepalive, push, sender_space, tcp_packet_on, tcp_packet_reverse,
    udp_packet,
};
use crate::exchange::tests::{request_query, response_final, response_reply};
use crate::fields_json::RowCoordinates;
use crate::filter::Filter;
use crate::link::{FlowKey, LINKTYPE_ETHERNET};
use crate::selection_json::{
    selection_since_json_coordinated, SelectionMemory, SelectionWindow, SelectionWork,
};
use crate::{Dissection, DissectionLimits};

const LOW: [u8; 4] = [10, 0, 0, 1];
const HIGH: [u8; 4] = [10, 0, 0, 2];

/// Row numbers handed out as a handle hands them: every row a list produced and
/// the numbering has not seen takes the next number, in list order, at each
/// drain. A list is known by its place, so a fixture adds its stream flows before
/// its datagram flows, as a capture whose places do not move does.
#[derive(Default)]
struct Numbering {
    rows: BTreeMap<(usize, u64), u64>,
    reached: Vec<u64>,
    scouting: BTreeMap<(FlowKey, u64), u64>,
    scouting_reached: BTreeMap<FlowKey, u64>,
    issued: u64,
}

impl Numbering {
    fn drain(&mut self, d: &Dissection) {
        for (list, (_, _, frames)) in d.message_lists_with_origin().enumerate() {
            if self.reached.len() <= list {
                self.reached.resize(list + 1, 0);
            }
            let first = frames.produced() - frames.len() as u64;
            for produced in self.reached[list].max(first)..frames.produced() {
                self.issued += 1;
                self.rows.insert((list, produced), self.issued);
            }
            self.reached[list] = frames.produced();
        }
        for flow in d.datagram_flows() {
            let scouting = flow.scouting();
            let reached = self.scouting_reached.entry(flow.flow).or_insert(0);
            let first = scouting.produced() - scouting.len() as u64;
            for produced in (*reached).max(first)..scouting.produced() {
                self.issued += 1;
                self.scouting.insert((flow.flow, produced), self.issued);
            }
            *reached = scouting.produced();
        }
    }
}

impl RowCoordinates for Numbering {
    fn list_id(&self, list: usize) -> Option<u64> {
        Some(list as u64)
    }

    fn scouting_list_id(&self, _flow: &FlowKey) -> Option<u64> {
        Some(1_000)
    }

    fn row_seq(&self, list: usize, produced: u64) -> Option<u64> {
        self.rows.get(&(list, produced)).copied()
    }

    fn scouting_row_seq(&self, flow: &FlowKey, produced: u64) -> Option<u64> {
        self.scouting.get(&(*flow, produced)).copied()
    }
}

/// A capture grown one packet at a time, a memory that goes on beside it, and
/// one that begins again at every call.
struct Growing {
    d: Dissection,
    packets: usize,
    numbering: Numbering,
    filter: Filter,
    kept: SelectionMemory,
    again: SelectionMemory,
    /// The cursor the last document gave.
    cursor: u64,
}

impl Growing {
    fn new(d: Dissection, selector: &str) -> Self {
        Self {
            d,
            packets: 0,
            numbering: Numbering::default(),
            filter: Filter::parse(selector).expect("the selector parses"),
            kept: SelectionMemory::default(),
            again: SelectionMemory::default(),
            cursor: 0,
        }
    }

    fn raw_at(&mut self, at: Option<u64>, packet: &[u8]) {
        self.d
            .push_packet_at(LINKTYPE_ETHERNET, self.packets, at, packet);
        self.packets += 1;
    }

    fn udp_at(&mut self, at: Option<u64>, from_low: bool, sport: u16, record: &[u8]) {
        let wire = frame_carrying(record);
        let packet = if from_low {
            udp_packet(LOW, sport, HIGH, 7447, &wire)
        } else {
            udp_packet(HIGH, 7447, LOW, sport, &wire)
        };
        self.raw_at(at, &packet);
    }

    fn udp(&mut self, from_low: bool, record: &[u8]) {
        self.udp_at(None, from_low, 43210, record);
    }

    /// One UDP datagram carrying the transport message `wire` as it is.
    fn udp_wire(&mut self, from_low: bool, wire: &[u8]) {
        let packet = if from_low {
            udp_packet(LOW, 43210, HIGH, 7447, wire)
        } else {
            udp_packet(HIGH, 7447, LOW, 43210, wire)
        };
        self.raw_at(None, &packet);
    }

    /// Ask both memories from `after` and require the same bytes; hand back the
    /// document and what the kept memory did for it.
    fn ask_from(&mut self, after: u64, step: &str) -> (String, SelectionWork) {
        self.numbering.drain(&self.d);
        let window = SelectionWindow {
            after_seq: after,
            through_seq: self.numbering.issued,
        };
        let before = self.kept.work();
        let kept = selection_since_json_coordinated(
            &self.d,
            &self.filter,
            &self.numbering,
            window,
            &mut self.kept,
        );
        self.again.begin_again();
        let again = selection_since_json_coordinated(
            &self.d,
            &self.filter,
            &self.numbering,
            window,
            &mut self.again,
        );
        assert_eq!(
            kept, again,
            "{step}: the memory that went on wrote another document than one that \
             began again"
        );
        self.cursor = window.through_seq;
        (kept, delta(before, self.kept.work()))
    }

    /// Ask from the cursor the last document gave.
    fn ask(&mut self, step: &str) -> (String, SelectionWork) {
        self.ask_from(self.cursor, step)
    }
}

fn delta(before: SelectionWork, after: SelectionWork) -> SelectionWork {
    SelectionWork {
        fold: crate::FoldStats {
            messages_folded: after.fold.messages_folded - before.fold.messages_folded,
            restarts: after.fold.restarts - before.fold.restarts,
            resumes: after.fold.resumes - before.fold.resumes,
        },
        rows_read: after.rows_read - before.rows_read,
        continued: after.continued - before.continued,
        whole: after.whole - before.whole,
    }
}

/// The selectors the planes answer differently: by kind, key and direction at
/// the record, by the outcome at the exchange's close, by a message's name at
/// the row, and none.
const SELECTORS: [&str; 10] = [
    "",
    "kind == query",
    "kind == put or kind == del",
    "key == demo/**",
    "dir == b",
    "closed == no",
    "closed == yes",
    "replies >= 1",
    "msg == ResponseFinal",
    "not kind == put",
];

/// THE CASE THE DOOR IS FOR, on forty generated captures: requests that close,
/// stay open, are opened again before they closed, closes of requests the
/// capture never held, replies and pushes, one packet at a time, asked from the
/// cursor each time. Every document equals the one a memory that begins again
/// writes, and the kept memory folded each message once and read every row only
/// on its first call.
#[test]
fn a_memory_that_goes_on_writes_what_one_that_begins_again_writes() {
    for seed in 0..40 {
        let (records, _) = crate::selection_json::tests::generated(seed);
        for selector in SELECTORS {
            let mut g = Growing::new(Dissection::new(), selector);
            let mut revised = 0usize;
            for (i, (from_low, at, record)) in records.iter().enumerate() {
                g.udp_at(*at, *from_low, 43210, record);
                let (doc, _) = g.ask(&alloc::format!("seed {seed}, {selector}, record {i}"));
                revised += doc.matches("\"was\":").count();
            }
            let work = g.kept.work();
            assert_eq!(work.whole, 1, "seed {seed}, {selector}: {work:?}");
            assert_eq!(
                work.continued,
                records.len() as u64 - 1,
                "seed {seed}, {selector}: {work:?}"
            );
            assert_eq!(work.fold.restarts, 1, "seed {seed}, {selector}: {work:?}");
            assert_eq!(
                work.fold.messages_folded,
                records.len() as u64,
                "seed {seed}, {selector}: each message is folded once"
            );
            // ANTI-VACUITY: the outcome terms move a request's word when its
            // exchange closes, so the comparison above met revised rows.
            if selector == "closed == no" && seed == 0 {
                assert!(revised > 0, "the generated capture revised no row");
            }
        }
    }
}

/// THE ROWS READ ARE THE NEW ONES AND THE OPEN REQUESTS. A session of queries
/// each closed before the next opens: every call reads the rows that arrived,
/// and the request still open, once.
#[test]
fn a_call_reads_what_arrived_and_the_requests_still_open() {
    let mut g = Growing::new(Dissection::new(), "closed == no");
    let mut open_before = 0u64;
    let mut calls = 0u64;
    for round in 1..=6u64 {
        for (from_low, record, open_after) in [
            (
                true,
                request_query(round, sender_space(0, Some("demo/q"))),
                1,
            ),
            (
                false,
                response_reply(round, sender_space(0, Some("demo/q")), b"ok"),
                1,
            ),
            (false, response_final(round), 0),
            (
                true,
                push(sender_space(0, Some("demo/p")), &[round as u8; 4]),
                0,
            ),
        ] {
            g.udp(from_low, &record);
            let (_, work) = g.ask(&alloc::format!("round {round}"));
            calls += 1;
            // The first call reads its one row whole; every later one goes on.
            assert_eq!(work.whole, u64::from(calls == 1), "round {round}: {work:?}");
            assert_eq!(
                work.rows_read,
                1 + open_before,
                "round {round}: the row that arrived and each request open before it"
            );
            open_before = open_after;
        }
    }
    assert_eq!(g.kept.work().whole, 1, "{:?}", g.kept.work());
}

/// A STREAM AND A DATAGRAM FLOW, with a selector that reads a `zid`: the grouping
/// changes as the handshakes name nodes, and again when a datagram node whose zid
/// begins like the first is named. Each of those begins the planes again and
/// reads every row; the stream traffic between continues in its capture order,
/// and every document equals one that begins again.
#[test]
fn a_zid_selector_follows_the_nodes_and_the_stream_order() {
    let mut g = Growing::new(Dissection::new(), "zid == a1a1a1a1");
    let mut seq_low = 0u32;
    let mut seq_high = 0u32;
    let init_a = framed(&init_wire(&[0xA1, 0xA1, 0xA1, 0xA1]));
    let init_b = framed(&init_wire(&[0xB2, 0xB2, 0xB2, 0xB2]));
    g.raw_at(None, &tcp_packet_on(1111, seq_low, &init_a));
    seq_low += init_a.len() as u32;
    g.ask("first INIT, stream");
    g.raw_at(None, &tcp_packet_reverse(seq_high, &init_b));
    seq_high += init_b.len() as u32;
    g.ask("second INIT, stream");
    let whole_after_handshake = g.kept.work().whole;
    for round in 0..8u64 {
        let record = push(sender_space(0, Some("demo/z")), &[round as u8; 12]);
        let wire = framed(&frame_carrying(&record));
        if round % 2 == 0 {
            g.raw_at(None, &tcp_packet_on(1111, seq_low, &wire));
            seq_low += wire.len() as u32;
        } else {
            g.raw_at(None, &tcp_packet_reverse(seq_high, &wire));
            seq_high += wire.len() as u32;
        }
        let (_, work) = g.ask(&alloc::format!("stream traffic {round}"));
        assert_eq!(work.whole, 0, "round {round}: {work:?}");
        assert_eq!(work.fold.messages_folded, 1, "round {round}: {work:?}");
    }
    assert_eq!(g.kept.work().whole, whole_after_handshake);
    g.udp_wire(true, &init_wire(&[0xA1, 0xA1, 0xA1, 0xA1, 0x77]));
    let (_, work) = g.ask("another node whose zid begins like the first");
    assert_eq!(work.whole, 1, "{work:?}");
}

/// A STREAM MESSAGE DECODED AFTER A PACKET THAT FOLLOWED IT (a segment held
/// behind a gap) sorts before a row already written: the planes begin again and
/// every row is read, and the document still equals one that begins again.
#[test]
fn a_message_held_behind_a_gap_reads_every_row_again() {
    let mut g = Growing::new(Dissection::new(), "msg == KeepAlive");
    g.raw_at(None, &tcp_packet_on(1111, 0, &framed_keepalive()));
    g.ask("the stream begins");
    g.raw_at(None, &tcp_packet_on(1111, 6, &framed_keepalive()));
    g.ask("a held segment");
    g.udp(true, &push(sender_space(0, Some("demo/a")), &[1u8; 12]));
    g.ask("a datagram message");
    g.udp(true, &push(sender_space(0, Some("demo/a")), &[2u8; 12]));
    let (_, work) = g.ask("continued");
    assert_eq!(work.whole, 0, "{work:?}");
    g.raw_at(None, &tcp_packet_on(1111, 3, &framed_keepalive()));
    let (_, work) = g.ask("the gap fills");
    assert_eq!(work.whole, 1, "{work:?}");
}

/// A CURSOR BELOW THE ONE THE LAST DOCUMENT GAVE reads every row, since the rows
/// between were never written by the memory's reckoning; the planes still go on.
#[test]
fn a_cursor_below_the_last_one_reads_every_row_and_folds_nothing_again() {
    let mut g = Growing::new(Dissection::new(), "closed == no");
    for round in 1..=4u64 {
        g.udp(true, &request_query(round, sender_space(0, Some("demo/q"))));
        g.ask(&alloc::format!("request {round}"));
    }
    g.udp(false, &response_final(2));
    // Behind the last cursor (4), and at the request the close revises (2).
    let (doc, work) = g.ask_from(2, "a cursor behind");
    assert_eq!(work.whole, 1, "{work:?}");
    assert_eq!(work.fold.restarts, 0, "{work:?}");
    assert_eq!(work.fold.messages_folded, 1, "{work:?}");
    assert!(
        doc.contains("\"was\":\"yes\""),
        "the closed request is revised: {doc}"
    );
    let (_, work) = g.ask("from the cursor again");
    assert_eq!(work.whole, 0, "{work:?}");
}

/// A CEILING THAT TRIMS THE FRONT does not begin the planes again: they go on
/// across the trim, so a call after it folds what arrived, and the rows the
/// ceiling took are in no document. The words of the held rows can differ from a
/// walk over what is held where they depended on what was taken (that is the
/// point of going on), so this holds the rows and the work, not the bytes.
#[test]
fn a_ceiling_that_trims_the_front_does_not_begin_the_planes_again() {
    let limits = DissectionLimits {
        frames_per_flow: Some(6),
        ..DissectionLimits::default()
    };
    let mut d = Dissection::with_limits(limits);
    let filter = Filter::parse("kind == query").expect("parses");
    let mut numbering = Numbering::default();
    let mut memory = SelectionMemory::default();
    let mut cursor = 0u64;
    for (packets, round) in (1..=30u64).enumerate() {
        let record = if round % 3 == 0 {
            response_final(round - 1)
        } else {
            request_query(round, sender_space(0, Some("demo/q")))
        };
        let wire = frame_carrying(&record);
        let packet = if round % 3 == 0 {
            udp_packet(HIGH, 7447, LOW, 43210, &wire)
        } else {
            udp_packet(LOW, 43210, HIGH, 7447, &wire)
        };
        d.push_packet(LINKTYPE_ETHERNET, packets, &packet);
        numbering.drain(&d);
        let through = numbering.issued;
        let doc = selection_since_json_coordinated(
            &d,
            &filter,
            &numbering,
            SelectionWindow {
                after_seq: cursor,
                through_seq: through,
            },
            &mut memory,
        );
        // The one new row, and only it: a query's word does not move at its close.
        assert!(
            doc.contains(&alloc::format!("\"rows\":[{{\"seq\":{through},")),
            "round {round}: {doc}"
        );
        assert_eq!(doc.matches("\"seq\":").count(), 1, "round {round}: {doc}");
        cursor = through;
    }
    let work = memory.work();
    assert_eq!(work.whole, 1, "{work:?}");
    assert_eq!(work.fold.restarts, 1, "{work:?}");
    assert_eq!(work.fold.messages_folded, 30, "{work:?}");
}

/// A transport INIT naming `zid`.
fn init_wire(zid: &[u8]) -> Vec<u8> {
    let mut wire = alloc::vec![
        wz_session_core::wire_const::T_MID_INIT,
        0x09,
        (((zid.len() as u8) - 1) << 4) | 0x02,
    ];
    wire.extend_from_slice(zid);
    wire
}

/// A stream message: its length as a little-endian u16, then the message.
fn framed(message: &[u8]) -> Vec<u8> {
    let mut out = (message.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(message);
    out
}
