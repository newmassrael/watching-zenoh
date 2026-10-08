// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a dissection still HOLDS, beside the ceilings that decide how much it
//! may.
//!
//! # The question, and why it had no answer
//!
//! A consumer rendering a live tap shows a window: "the last 40 seconds", "the
//! oldest message still here is from 12:04:31". Every ceiling it could read
//! (`dropped_by_limits.caps`) says how much this reader MAY keep, every
//! counter (`dropped_by_limits.frames` and the rest) says how much it has
//! already thrown away, and nothing said what it holds NOW. A viewer that
//! wants to say "you are looking at the last N messages, older ones are gone"
//! had to count rows of a document it had rendered for another purpose.
//!
//! # There is no single window, and the document says so
//!
//! The request that led here was written against one ring buffer with one byte
//! budget. This library has none. Retention is several ceilings, each over its
//! own scope, and a number that summed them would compare against none of
//! them:
//!
//! * `frames_per_flow` bounds a TCP flow's decoded messages, one list;
//! * on a datagram flow the SAME ceiling is one budget shared by the cleartext
//!   list, the scouting list and the recovered QUIC datagram list
//!   ([`crate::DatagramDissection::budgeted_messages`]), and every QUIC stream
//!   is bounded apart, in its own coordinate space;
//! * `stream_bytes_per_direction` bounds the reassembled bytes of each
//!   DIRECTION of each TCP flow;
//! * `max_flows_per_table` bounds each of the two flow tables.
//!
//! So the `held` group reports two things for the axes where the scope
//! matters: the TOTAL a reader would want for a caption, and the FULLEST
//! scope, which is the one that answers "is a ceiling about to bite" because
//! it is the one thing comparable to a cap. A total of 40,000 messages under a
//! cap of 10,000 per flow is a healthy handle with four busy flows, and the
//! same 40,000 in one flow is a bug; only the fullest scope tells them apart.
//!
//! # What is counted, and what is not
//!
//! `frames` is decoded transport messages retained, whether or not a drain has
//! handed their records out: a drain reads the lists and removes nothing, so
//! this is not the count of records still to drain and it is not the count of
//! bytes anything holds. `scouting` is the same for scouting datagrams, which
//! a record door also hands out one record each. The reassembled stream is the
//! one place this library holds BYTES, and `stream_bytes` is those; a datagram
//! flow holds decoded messages only, and this document does not invent a byte
//! figure for them.
//!
//! The serial line is counted in `frames` and named apart in `serial_frames`,
//! because no ceiling bounds it: it is excluded from `fullest_window`, whose
//! whole meaning is "comparable to a cap", and a reader who sees `frames` far
//! above `fullest_window.messages` with a `serial_frames` to account for it
//! has been told why.
//!
//! # `oldest_ts_ns`
//!
//! The capture instant of the oldest retained message, in the unit and on the
//! clock a drained record's `ts_ns` uses, so the two compare directly: it is
//! the minimum over EVERY retained message and scouting datagram, not over the
//! head of each list, because a capture merged from two taps can carry a later
//! message ahead of an earlier one and "how far back can I read" is a question
//! about the earliest instant held. `null` when nothing retained has a clock —
//! a source with no clock, or nothing held yet — which is a different fact from
//! a clock reading zero.
//!
//! Since retention revision 3 the instant carries every digit the capture
//! recorded. It was a whole number of milliseconds widened to nanoseconds
//! before, and a record's `ts_ns` was too, so the two agreed by being rounded
//! alike; they now agree by being the same figure unrounded, and a consumer
//! comparing them is comparing the capture's own timestamps.
//!
//! # Not in it
//!
//! `scout_askers`: the set that ceiling bounds is private to the scouting
//! observer and has no accessor, so this document reports the cumulative drop
//! the shared ceilings group already carries and no held figure. Named rather
//! than approximated.

use alloc::string::String;
use core::fmt::Write as _;

use wz_session_core::passive::NANOS_PER_MILLI;

use crate::Dissection;

/// What one [`Dissection`] holds at the moment it was measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// Decoded transport messages retained, over every list the dissection
    /// enumerates for a record door, the serial line included.
    pub frames: usize,
    /// Scouting datagrams retained.
    pub scouting: usize,
    /// The part of [`Self::frames`] that is the serial line, which no ceiling
    /// bounds.
    pub serial_frames: usize,
    /// Entries in the skipped-packet list.
    pub skipped: usize,
    /// Reassembled bytes retained, over both directions of every TCP flow.
    pub stream_bytes: usize,
    /// TCP flows in the stream table.
    pub stream_flows: usize,
    /// Datagram flows in the datagram table.
    pub datagram_flows: usize,
    /// The fullest single scope `frames_per_flow` bounds; see the module doc
    /// for which scopes those are.
    pub fullest_window_messages: usize,
    /// The fullest single direction of a TCP flow, the scope
    /// `stream_bytes_per_direction` bounds.
    pub fullest_window_stream_bytes: usize,
    /// The earliest capture instant among retained messages, in this reader's
    /// milliseconds; `None` when none has a clock.
    pub oldest_ms: Option<u64>,
    /// The same instant to the nanosecond: [`Self::oldest_ms`] is this divided
    /// by a million, rounded down, and `None` exactly when it is. This is the
    /// figure the document's `oldest_ts_ns` carries.
    pub oldest_ns: Option<u64>,
}

impl Retention {
    /// Measure `d`. Reads the lists in place and allocates nothing.
    pub fn of(d: &Dissection) -> Self {
        // The total goes through the one enumeration a record door drains, so a
        // list added there reaches this count with no edit here.
        let frames: usize = d
            .message_lists_with_origin()
            .map(|(_, _, list)| list.len())
            .sum();
        let oldest_of_frames = d
            .message_lists_with_origin()
            .flat_map(|(_, _, list)| list.iter())
            .filter_map(|frame| frame.observed_at_ns)
            .min();
        let scouting_lists = || d.datagram_flows().iter().map(|flow| &flow.scouting);
        let scouting: usize = scouting_lists().map(|list| list.len()).sum();
        let oldest_of_scouting = scouting_lists()
            .flat_map(|list| list.iter())
            .filter_map(|datagram| datagram.observed_at_ns)
            .min();
        let oldest_ns = [oldest_of_frames, oldest_of_scouting]
            .into_iter()
            .flatten()
            .min();

        // Each scope against the ceiling that bounds it. A stream flow's list
        // is its own scope; a datagram flow's budget is shared by three lists;
        // a QUIC stream is bounded where it is fed, apart from both.
        let stream_messages = d.flows().iter().map(|flow| flow.frames.len());
        let datagram_messages = d
            .datagram_flows()
            .iter()
            .map(crate::DatagramDissection::budgeted_messages);
        let quic_stream_messages = d
            .datagram_flows()
            .iter()
            .flat_map(|flow| flow.quic_streams.iter().map(|stream| stream.frames.len()));
        let fullest_window_messages = stream_messages
            .chain(datagram_messages)
            .chain(quic_stream_messages)
            .max()
            .unwrap_or(0);

        // The bytes RETAINED, which is `stream().len()`. `len()` is the
        // absolute count reassembled and never goes backwards when a trim
        // reclaims memory, so summing it would report a handle that had trimmed
        // everything as full.
        let directions = || {
            d.flows()
                .iter()
                .flat_map(|flow| [&flow.low_to_high, &flow.high_to_low])
                .map(|assembler| assembler.stream().len())
        };

        Self {
            frames,
            scouting,
            serial_frames: d.serial_frames().len(),
            skipped: d.skipped().len(),
            stream_bytes: directions().sum(),
            stream_flows: d.flows().len(),
            datagram_flows: d.datagram_flows().len(),
            fullest_window_messages,
            fullest_window_stream_bytes: directions().max().unwrap_or(0),
            oldest_ms: oldest_ns.map(|ns| ns / NANOS_PER_MILLI),
            oldest_ns,
        }
    }
}

/// The retention document: what is held, then the ceilings and losses that
/// explain why it is that much.
///
/// `dropped_by_limits` is the SAME group every other document carries, from the
/// same emitter, so a reader comparing `held.fullest_window.messages` with
/// `dropped_by_limits.caps.frames_per_flow` compares two values taken from one
/// dissection at one instant.
pub fn retention_json(d: &Dissection) -> String {
    let held = Retention::of(d);
    let mut out = String::from("{");
    crate::doc_revision::envelope_into(crate::doc_revision::RETENTION, &mut out);
    let _ = write!(
        out,
        ",\"held\":{{\"frames\":{},\"scouting\":{},\"serial_frames\":{},\
         \"skipped\":{},\"stream_bytes\":{},\"stream_flows\":{},\
         \"datagram_flows\":{},\"fullest_window\":{{\"messages\":{},\
         \"stream_bytes\":{}}},\"oldest_ts_ns\":",
        held.frames,
        held.scouting,
        held.serial_frames,
        held.skipped,
        held.stream_bytes,
        held.stream_flows,
        held.datagram_flows,
        held.fullest_window_messages,
        held.fullest_window_stream_bytes,
    );
    // An instant in nanoseconds since 1970 is about 1.7e18: past 2^53, which a
    // reader on doubles cannot hold, and under 2^63. Written through the shared
    // `u64` door, so it is a number while it is exact and a string once it is
    // not, by the same rule as a protocol field's value.
    match held.oldest_ns {
        Some(ns) => wz_session_core::json::u64_into(ns, &mut out),
        None => out.push_str("null"),
    }
    out.push_str("},\"dropped_by_limits\":");
    out.push_str(&crate::report::dropped_by_limits_json(d));
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datagram_tests::{
        framed_keepalive, scout_message, tcp_packet, tcp_packet_reverse, udp_packet, SCOUT_GROUP,
    };
    use crate::link::LINKTYPE_ETHERNET;
    use crate::DissectionLimits;
    use alloc::vec::Vec;

    const SCOUT_PORT: u16 = 7446;

    /// The raw JSON values of the object that holds `key`, read by the library's
    /// own scope walker so a test never reads a nested group as its parent.
    fn scope_holding<'a>(doc: &'a str, key: &str) -> Vec<(&'a str, &'a str)> {
        crate::doc_revision::object_scopes(doc)
            .into_iter()
            .find(|scope| scope.iter().any(|(k, _)| *k == key))
            .unwrap_or_else(|| panic!("no object holds `{key}`: {doc}"))
    }

    fn value<'a>(scope: &[(&'a str, &'a str)], key: &str) -> &'a str {
        scope
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| *v)
            .unwrap_or_else(|| panic!("no `{key}` in {scope:?}"))
    }

    /// One keepalive per packet on the stream flow, so the number of messages
    /// held is the number of packets pushed and the fixture, not the library,
    /// is the oracle for it.
    fn push_stream_keepalives(d: &mut Dissection, times_ms: &[Option<u64>]) {
        for (i, at) in times_ms.iter().enumerate() {
            d.push_packet_at(
                LINKTYPE_ETHERNET,
                i,
                *at,
                &tcp_packet(1000 + 3 * i as u32, &framed_keepalive()),
            );
        }
    }

    #[test]
    fn an_empty_dissection_renders_zero_held_and_no_ceiling() {
        let doc = retention_json(&Dissection::new());
        assert_eq!(
            doc,
            "{\"document\":{\"name\":\"retention\",\"revision\":3},\
             \"held\":{\"frames\":0,\"scouting\":0,\"serial_frames\":0,\"skipped\":0,\
             \"stream_bytes\":0,\"stream_flows\":0,\"datagram_flows\":0,\
             \"fullest_window\":{\"messages\":0,\"stream_bytes\":0},\"oldest_ts_ns\":null},\
             \"dropped_by_limits\":{\"frames\":0,\"stream_bytes\":0,\"skipped\":0,\"flows\":0,\
             \"scouting\":0,\"scout_askers\":0,\"caps\":{\"frames_per_flow\":null,\
             \"stream_bytes_per_direction\":null,\"skipped_packets\":null,\
             \"max_flows_per_table\":null,\"max_scout_askers\":null}}}"
        );
    }

    /// The totals over an unbounded dissection are the messages the fixture
    /// sent, and the fullest window is a datagram flow's SHARED budget: no
    /// single list of it is the biggest number in the document.
    #[test]
    fn the_totals_are_what_was_sent_and_a_datagram_flows_budget_is_one_sum() {
        let mut d = Dissection::new();
        // Stream flow: two messages. Datagram flow A: one. Datagram flow B, the
        // scouting group: three scouts and two transport messages.
        push_stream_keepalives(&mut d, &[None, None]);
        let keepalive = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        d.push_packet(
            LINKTYPE_ETHERNET,
            10,
            &udp_packet([10, 0, 0, 1], 7447, [10, 0, 0, 2], 7447, &keepalive),
        );
        let scout = scout_message();
        for i in 0..3usize {
            d.push_packet(
                LINKTYPE_ETHERNET,
                20 + i,
                &udp_packet([10, 0, 0, 9], 43210, SCOUT_GROUP, SCOUT_PORT, &scout),
            );
        }
        for i in 0..2usize {
            d.push_packet(
                LINKTYPE_ETHERNET,
                30 + i,
                &udp_packet([10, 0, 0, 9], 43210, SCOUT_GROUP, SCOUT_PORT, &keepalive),
            );
        }

        let held = Retention::of(&d);
        assert_eq!(held.frames, 2 + 1 + 2, "transport messages, every list");
        assert_eq!(held.scouting, 3);
        assert_eq!(held.stream_flows, 1);
        assert_eq!(held.datagram_flows, 2);
        assert_eq!(held.serial_frames, 0);
        assert_eq!(
            held.fullest_window_messages, 5,
            "flow B holds two transport messages and three scouts under ONE ceiling; \
             counting a single list would say 3"
        );

        let doc = retention_json(&d);
        let group = scope_holding(&doc, "serial_frames");
        assert_eq!(value(&group, "frames"), "5");
        assert_eq!(value(&group, "scouting"), "3");
        let window = scope_holding(&doc, "messages");
        assert_eq!(value(&window, "messages"), "5");
    }

    /// The reason the document has a fullest scope at all: two datagram flows
    /// each at the ceiling hold twice the ceiling between them, and only the
    /// scope says the ceiling is what is being met.
    #[test]
    fn a_total_over_the_ceiling_is_not_a_ceiling_bitten_twice() {
        const CAP: usize = 4;
        let mut d = Dissection::with_limits(DissectionLimits {
            frames_per_flow: Some(CAP),
            ..DissectionLimits::default()
        });
        let keepalive = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let scout = scout_message();
        for (flow, source) in [[10, 0, 0, 1], [10, 0, 0, 2]].into_iter().enumerate() {
            for i in 0..10usize {
                d.push_packet(
                    LINKTYPE_ETHERNET,
                    flow * 100 + i * 2,
                    &udp_packet(source, 43210, SCOUT_GROUP, SCOUT_PORT, &scout),
                );
                d.push_packet(
                    LINKTYPE_ETHERNET,
                    flow * 100 + i * 2 + 1,
                    &udp_packet(source, 43210, SCOUT_GROUP, SCOUT_PORT, &keepalive),
                );
            }
        }
        assert_eq!(
            d.datagram_flows().len(),
            2,
            "two flows, or nothing is shown"
        );
        assert!(
            d.drops().frames > 0 && d.drops().scouting > 0,
            "both bitten"
        );

        let held = Retention::of(&d);
        assert_eq!(
            held.frames + held.scouting,
            2 * CAP,
            "the total is twice it"
        );
        assert_eq!(
            held.fullest_window_messages, CAP,
            "the scope is the ceiling"
        );
    }

    /// The two QUIC lists count where the ceiling counts them: recovered
    /// datagrams share the flow's budget with its cleartext and scouting
    /// lists, and every QUIC stream is a scope of its own.
    #[test]
    fn a_quic_flow_counts_its_datagrams_in_the_budget_and_each_stream_apart() {
        use crate::Direction;
        let mut d = Dissection::new();
        // A flow to hang QUIC on: one packet and no decoded message.
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &udp_packet([10, 0, 0, 1], 4433, [10, 0, 0, 2], 7447, &[]),
        );
        let flow = d.datagram_flows()[0].flow;
        let unit = framed_keepalive();
        let keepalive = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        // Stream 7 gets four messages and stream 9 gets one; two recovered
        // datagrams land in the flow's own budget.
        for _ in 0..4 {
            d.feed_quic_stream(flow, Direction::A, 7, false, &unit);
        }
        d.feed_quic_stream(flow, Direction::A, 9, false, &unit);
        for at in 1..=2usize {
            d.feed_quic_datagram(flow, Direction::A, at, &keepalive);
        }
        let dg = &d.datagram_flows()[0];
        assert_eq!(
            dg.quic_streams.len(),
            2,
            "the fixture must open two streams"
        );
        assert_eq!(dg.quic_datagrams.len(), 2, "and recover two datagrams");

        let held = Retention::of(&d);
        assert_eq!(held.frames, 4 + 1 + 2, "every list counts toward the total");
        assert_eq!(
            held.fullest_window_messages, 4,
            "stream 7 is the fullest scope; the flow's budget holds only the two \
             datagrams, and summing the streams into it would say 7"
        );

        // Two more datagrams make the flow's budget the fuller scope.
        for at in 3..=5usize {
            d.feed_quic_datagram(flow, Direction::A, at, &keepalive);
        }
        assert_eq!(Retention::of(&d).fullest_window_messages, 5);
    }

    /// Bytes RETAINED are what a trim leaves, not the absolute count the
    /// assembler keeps for offsets: after a trim the two differ, and reporting
    /// the second would call a handle that had reclaimed everything full.
    #[test]
    fn stream_bytes_are_the_bytes_kept_and_not_the_bytes_ever_reassembled() {
        const KEEP: usize = 64;
        let mut d = Dissection::with_limits(DissectionLimits {
            stream_bytes_per_direction: Some(KEEP),
            ..DissectionLimits::default()
        });
        // 300 bytes one way and 10 the other, on one connection.
        let forward: Vec<u8> = (0..100).flat_map(|_| framed_keepalive()).collect();
        let back: Vec<u8> = (0..3).flat_map(|_| framed_keepalive()).chain([0]).collect();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &forward));
        d.push_packet(LINKTYPE_ETHERNET, 1, &tcp_packet_reverse(5000, &back));

        let flow = &d.flows()[0];
        let absolute = flow.low_to_high.len().max(flow.high_to_low.len());
        assert!(
            absolute > KEEP,
            "the fixture must reassemble past the ceiling or `len()` and the kept \
             bytes are the same number and this test proves nothing: {absolute}"
        );
        let held = Retention::of(&d);
        assert_eq!(held.fullest_window_stream_bytes, KEEP);
        assert_eq!(
            held.stream_bytes,
            KEEP + back.len(),
            "both directions, kept"
        );
    }

    /// The oldest instant is the minimum over everything held — the scouting
    /// list included, and not the head of each list.
    #[test]
    fn the_oldest_instant_is_the_earliest_capture_time_held() {
        // A scout at 1500 ms is older than any transport message (2000, 3000)
        // and lives in a list a walk of the message lists never reads.
        let mut d = Dissection::new();
        push_stream_keepalives(&mut d, &[Some(2_000), Some(3_000)]);
        let scout = scout_message();
        d.push_packet_at(
            LINKTYPE_ETHERNET,
            10,
            Some(1_500),
            &udp_packet([10, 0, 0, 9], 43210, SCOUT_GROUP, SCOUT_PORT, &scout),
        );
        assert_eq!(Retention::of(&d).oldest_ms, Some(1_500));
        assert!(
            retention_json(&d).contains("\"oldest_ts_ns\":1500000000}"),
            "in the unit a drained record's ts_ns uses: {}",
            retention_json(&d)
        );
    }

    /// A capture whose clock steps back holds a later message AHEAD of an
    /// earlier one, so the head of the list is not the oldest instant held.
    #[test]
    fn a_list_whose_clock_stepped_back_does_not_hide_its_oldest_behind_its_head() {
        let mut d = Dissection::new();
        push_stream_keepalives(&mut d, &[Some(5_000), Some(4_000)]);
        let flow = &d.flows()[0];
        assert_eq!(
            flow.frames[0].observed_at_ms,
            Some(5_000),
            "the fixture must put the LATER instant at the head"
        );
        assert_eq!(Retention::of(&d).oldest_ms, Some(4_000));
    }

    /// A trim from the front moves the oldest instant with it: what the window
    /// reaches back to is what is still held.
    #[test]
    fn a_trim_from_the_front_moves_the_oldest_instant() {
        let mut d = Dissection::with_limits(DissectionLimits {
            frames_per_flow: Some(2),
            ..DissectionLimits::default()
        });
        push_stream_keepalives(
            &mut d,
            &[Some(1_000), Some(2_000), Some(3_000), Some(4_000)],
        );
        assert_eq!(d.drops().frames, 2, "two went, so the window moved");
        assert_eq!(Retention::of(&d).oldest_ms, Some(3_000));
    }

    /// No clock is `null`, a different fact from a clock that reads zero.
    #[test]
    fn a_source_with_no_clock_has_no_oldest_instant() {
        let mut d = Dissection::new();
        push_stream_keepalives(&mut d, &[None, None]);
        assert_eq!(Retention::of(&d).oldest_ms, None);
        assert!(retention_json(&d).contains("\"oldest_ts_ns\":null"));

        let mut zero = Dissection::new();
        push_stream_keepalives(&mut zero, &[Some(0)]);
        assert_eq!(Retention::of(&zero).oldest_ms, Some(0));
        assert!(retention_json(&zero).contains("\"oldest_ts_ns\":0}"));
    }

    /// A real capture clock, in nanoseconds since 1970, is past 2^53: written
    /// bare, a reader on doubles loses its low bits and says nothing. From
    /// revision 2 it is a string once it is not exact, and a number below the
    /// line, which is also what the one value a test clock usually is (a few
    /// seconds) keeps being.
    #[test]
    fn an_instant_past_the_exact_integer_line_is_a_string() {
        // 1_700_000_000_000 ms is 1.7e18 ns: 2^53 is 9.007e15.
        let mut d = Dissection::new();
        push_stream_keepalives(&mut d, &[Some(1_700_000_000_000)]);
        assert_eq!(Retention::of(&d).oldest_ms, Some(1_700_000_000_000));
        let doc = retention_json(&d);
        assert!(
            doc.contains("\"oldest_ts_ns\":\"1700000000000000000\"}"),
            "a real-clock instant is the digits in a string: {doc}"
        );
        assert!(doc.contains("\"revision\":3"), "{doc}");

        // The last millisecond that stays a number: 9_007_199_254 ms is 9.007e15 ns
        // and under the line; one more is over it.
        let mut under = Dissection::new();
        push_stream_keepalives(&mut under, &[Some(9_007_199_254)]);
        assert!(retention_json(&under).contains("\"oldest_ts_ns\":9007199254000000}"));
        let mut over = Dissection::new();
        push_stream_keepalives(&mut over, &[Some(9_007_199_255)]);
        assert!(retention_json(&over).contains("\"oldest_ts_ns\":\"9007199255000000\"}"));
    }

    /// The skipped-packet list is bounded by its own ceiling and counted
    /// against it.
    #[test]
    fn skipped_packets_are_counted_against_their_own_ceiling() {
        let mut d = Dissection::with_limits(DissectionLimits {
            skipped_packets: Some(2),
            ..DissectionLimits::default()
        });
        for i in 0..5usize {
            // A link type nothing reads: recorded as skipped, not decoded.
            d.push_packet(0xFFFF, i, &[0u8; 20]);
        }
        assert_eq!(d.drops().skipped, 3, "the fixture must bite the ceiling");
        assert_eq!(Retention::of(&d).skipped, 2);
    }
}
