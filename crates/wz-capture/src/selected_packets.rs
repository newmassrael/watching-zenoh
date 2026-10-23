// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The capture PACKETS that carried the messages a selector picked, and the
//! counts that say how complete that list is.
//!
//! # What a consumer writing a file of picked messages was missing
//!
//! The selection document says, per row, the word a selector said and the
//! coordinates that join the row to a record. A datagram row's anchor is a
//! packet, but a stream row's is a byte offset in its flow's stream, and the one
//! packet the field document names for a stream row is the packet of its FIRST
//! byte. A message that spans segments, a WebSocket message split into frames
//! and a unit inside TLS records are all carried by packets that no published
//! coordinate names, so a consumer that wanted to write the picked messages to a
//! file had to re-derive the stream layout this crate already holds, and the
//! only door that hands a packet back by number reads the container to it on
//! every call.
//!
//! This is the list, from the rows of [`crate::selection_json`] (the same
//! enumeration, so the same rows) and the run maps their bytes came out of.
//!
//! # Which packets carry a row
//!
//! A datagram or scouting row: the packet it came in. A stream row: every
//! packet that carried a byte of the framing unit it was read from, from the
//! unit's anchor to [`wz_session_core::passive::PassiveFrame::wire_end`]
//! ([`crate::FlowDissection::packets_carrying`] says what that is for a plain,
//! a WebSocket and a TLS unit). The list is sorted and holds each packet once,
//! however many picked rows it carried.
//!
//! # Context
//!
//! Reading a message again needs more than its own bytes when the capture is
//! cut to the picked packets. Measured on this reader: the compression and
//! low-latency agreement and the sequence-number ring come from the Init and
//! Open exchange; a numeric key expression resolves through the Declare that
//! defined it; a fragmented message is joined from the fragments before it; a
//! WebSocket stream is recognised from its opening, and a TLS record is opened
//! by a key found through the handshake and at a sequence number counted from
//! the first record of its direction. With context asked for, the list also
//! holds, for every flow that has a picked row:
//!
//! - the packets of its Init and Open rows and of every row carrying a Declare;
//! - the packets of every row of a fragment chain a picked row belongs to;
//! - in each direction, the packets of the stream ahead of its first message;
//!   and on a TLS flow, every packet of a direction up to the end of its last
//!   picked unit, because each record's sequence number depends on all before
//!   it.
//!
//! Every Declare of the flow and not only the one a picked row resolves through:
//! the resolution is the key-expression plane's, and asking it which declaration
//! a row used would be a second reading of that plane. The summary says how many
//! packets context added, so a consumer sees what this costs.
//!
//! A `ResponseFinal` and its `Request` are one exchange judged once, so a picked
//! final's request is picked with it and needs no context of its own.
//!
//! # What the counts say
//!
//! [`SelectedPacketsSummary`](crate::selected_packets::SelectedPacketsSummary)
//! counts the rows by the word they got, the rows the
//! message ceilings took before this walk (so a list made short is never read as
//! whole), the picked rows whose bytes are no longer held, and what context
//! added and could not place. An empty selector asks nothing: every row is
//! counted `unjudged` and no packet is named.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use wz_session_core::inbound::InboundFrame;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::passive::{Carried, Direction, PassiveFrame};
use wz_session_core::passive_messages::MessageList;

use crate::fields_json::{judged_by, RowCoordinates, RowVerdict};
use crate::selection_json::{for_each_row, RowSource};

/// The packets a selector's picked rows came in, and the counts beside them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SelectedPackets {
    /// Capture packet numbers, ascending, each once.
    pub packets: Vec<u64>,
    /// How complete [`Self::packets`] is, and what made it.
    pub summary: SelectedPacketsSummary,
}

/// What [`selected_packets_coordinated`] walked, and what it could not reach.
///
/// The four row counts partition the rows the selection document has; the rest
/// are about rows and packets outside that partition.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SelectedPacketsSummary {
    /// Rows the selector said `yes` of: the picked rows.
    pub rows_yes: u64,
    /// Rows it said `no` of.
    pub rows_no: u64,
    /// Rows whose records were judged and the capture did not carry what
    /// deciding needed.
    pub rows_undecided: u64,
    /// Rows carrying no record a selector can speak of, and every row when the
    /// selector is empty or ambiguous in this capture.
    pub rows_unjudged: u64,
    /// Messages the message ceilings discarded before this walk, scouting
    /// messages included: rows this walk never saw. `0` on a handle whose
    /// ceilings have not bitten.
    pub rows_trimmed: u64,
    /// Flows the flow ceiling evicted before this walk, with every row they
    /// held.
    pub flows_evicted: u64,
    /// Picked rows whose packets cannot be named: the stream bytes they were
    /// read from were given back to a retention ceiling.
    pub rows_unplaced: u64,
    /// Packets in the list, context included.
    pub packets: u64,
    /// Packets in the list only because context asked for them. `0` when
    /// context was not asked for.
    pub context_packets: u64,
    /// Rows and stream ranges context needed whose packets cannot be named,
    /// for the reason [`Self::rows_unplaced`] gives.
    pub context_unplaced: u64,
}

/// The packets that carried the rows `filter` picks, over the rows of the
/// selection document with each row numbered by `coordinates`, and with the
/// context the module doc names when `context` is set.
pub fn selected_packets_coordinated(
    d: &crate::Dissection,
    filter: &crate::filter::Filter,
    coordinates: &dyn RowCoordinates,
    context: bool,
) -> SelectedPackets {
    let grouping = crate::node::session_grouping(d);
    let verdicts = judged_by(d, filter, &grouping, Some(coordinates));
    let mut summary = SelectedPacketsSummary::default();
    let mut picked: BTreeSet<usize> = BTreeSet::new();
    // The picked positions per flow, by the flow's index in its table: what
    // context is gathered for.
    let mut stream_picks: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let mut datagram_picks: BTreeMap<usize, Vec<usize>> = BTreeMap::new();

    for_each_row(d, verdicts.as_ref(), coordinates, &mut |row| {
        match row.verdict {
            Some(RowVerdict::Yes) => summary.rows_yes += 1,
            Some(RowVerdict::No) => {
                summary.rows_no += 1;
                return;
            }
            Some(RowVerdict::Undecided) => {
                summary.rows_undecided += 1;
                return;
            }
            Some(RowVerdict::Unjudged) | None => {
                summary.rows_unjudged += 1;
                return;
            }
        }
        match row.source {
            RowSource::Stream {
                index,
                flow,
                position,
            } => {
                match flow.packets_carrying(&flow.frames.row(position)) {
                    Some(packets) => picked.extend(packets),
                    None => summary.rows_unplaced += 1,
                }
                stream_picks.entry(index).or_default().push(position);
            }
            RowSource::Datagram {
                index,
                flow,
                position,
            } => {
                picked.insert(flow.frames.row(position).stream_offset);
                datagram_picks.entry(index).or_default().push(position);
            }
            // Scouting rows are unjudged by construction and never reach here;
            // a packet is still the honest answer if one ever does.
            RowSource::Scouting { packet } => {
                picked.insert(packet);
            }
        }
    });

    let drops = d.drops();
    summary.rows_trimmed = (drops.frames + drops.scouting) as u64;
    summary.flows_evicted = drops.flows as u64;

    if context {
        let mut needed: BTreeSet<usize> = BTreeSet::new();
        for (index, positions) in &stream_picks {
            stream_context(
                &d.flows()[*index],
                positions,
                &mut needed,
                &mut summary.context_unplaced,
            );
        }
        for (index, positions) in &datagram_picks {
            let frames = &d.datagram_flows()[*index].frames;
            for position in context_rows(frames, positions) {
                needed.insert(frames.row(position).stream_offset);
            }
        }
        let added: Vec<usize> = needed.difference(&picked).copied().collect();
        summary.context_packets = added.len() as u64;
        picked.extend(added);
    }

    let packets: Vec<u64> = picked.into_iter().map(|p| p as u64).collect();
    summary.packets = packets.len() as u64;
    SelectedPackets { packets, summary }
}

/// The context of one TCP flow whose rows at `picked` were picked.
fn stream_context(
    flow: &crate::FlowDissection,
    picked: &[usize],
    into: &mut BTreeSet<usize>,
    unplaced: &mut u64,
) {
    for position in context_rows(&flow.frames, picked) {
        match flow.packets_carrying(&flow.frames.row(position)) {
            Some(packets) => into.extend(packets),
            None => *unplaced += 1,
        }
    }
    for direction in [Direction::A, Direction::B] {
        let first = flow
            .frames
            .iter()
            .find(|frame| frame.direction == direction)
            .map(|frame| frame.stream_offset);
        // A TLS record is opened at a sequence number counted from the first
        // record of its direction, so every record up to the last picked unit
        // is context there; elsewhere the opening alone is.
        let reach = if flow.framing().is_encrypted() {
            picked
                .iter()
                .map(|&position| flow.frames.row(position))
                .filter(|frame| frame.direction == direction)
                .filter_map(|frame| frame.wire_end)
                .max()
                .or(first)
        } else {
            first
        };
        let Some(reach) = reach.filter(|&reach| reach > 0) else {
            continue;
        };
        let assembler = flow.assembler(direction);
        if assembler.retained_from() > 0 {
            *unplaced += 1;
        } else if let Some(packets) = assembler.packets_in(0, reach) {
            into.extend(packets);
        }
    }
}

/// The positions in `list` that context needs when the rows at `picked` were
/// picked: the Init and Open rows, the rows carrying a Declare, and every row of
/// a fragment chain a picked row belongs to.
fn context_rows(list: &MessageList, picked: &[usize]) -> Vec<usize> {
    let chains = chain_members(list, picked);
    list.iter()
        .enumerate()
        .filter(|(position, frame)| {
            opens_the_session(frame) || carries_a_declaration(frame) || chains.contains(position)
        })
        .map(|(position, _)| position)
        .collect()
}

/// An Init or an Open, which carry the agreement every later message is read
/// under.
fn opens_the_session(frame: &PassiveFrame) -> bool {
    matches!(
        frame.frame,
        Ok(InboundFrame::Init { .. } | InboundFrame::Open { .. })
    )
}

/// Whether the batch this message carried holds a Declare.
fn carries_a_declaration(frame: &PassiveFrame) -> bool {
    let batch = match &frame.carried {
        Carried::Batch(batch) => batch,
        #[cfg(feature = "reassembly")]
        Carried::Reassembled { batch, .. } => batch,
        _ => return false,
    };
    batch
        .records()
        .any(|(message, _)| matches!(message, NetworkMessage::Declare(_)))
}

/// The positions of every row that belongs to a fragment chain a row at
/// `picked` belongs to, by the chain identity the list folds (the field
/// document's `chain_id`), from the state its discarded messages left.
#[cfg(feature = "reassembly")]
fn chain_members(list: &MessageList, picked: &[usize]) -> BTreeSet<usize> {
    let mut fold = list.chain_prefix().clone();
    let ids: Vec<Option<u64>> = list
        .iter()
        .map(|frame| fold.observe(&frame).and_then(|(_, id)| id))
        .collect();
    let wanted: BTreeSet<u64> = picked.iter().filter_map(|&p| ids[p]).collect();
    ids.iter()
        .enumerate()
        .filter(|(_, id)| id.is_some_and(|id| wanted.contains(&id)))
        .map(|(position, _)| position)
        .collect()
}

/// A build without reassembly forms no chain, so no row belongs to one.
#[cfg(not(feature = "reassembly"))]
fn chain_members(_list: &MessageList, _picked: &[usize]) -> BTreeSet<usize> {
    BTreeSet::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datagram_tests::{
        frame_carrying, init_datagram, open_datagram, push, sender_space, tcp_packet,
    };
    use crate::exchange::tests::declare_kexpr;
    use crate::link::LINKTYPE_ETHERNET;
    use crate::selection_json::tests::{labels, mixed_session_with_file};
    use crate::Dissection;

    /// A numbering that numbers every list, standing in for a handle's.
    struct EveryListNumbered;

    impl RowCoordinates for EveryListNumbered {
        fn list_id(&self, list: usize) -> Option<u64> {
            Some(list as u64)
        }

        fn scouting_list_id(&self, _flow: &crate::link::FlowKey) -> Option<u64> {
            None
        }
    }

    fn picked(d: &Dissection, selector: &str, context: bool) -> SelectedPackets {
        let filter = crate::filter::Filter::parse(selector).expect("the selector parses");
        selected_packets_coordinated(d, &filter, &EveryListNumbered, context)
    }

    /// The packet numbers of the contract capture's packets named `names`.
    fn numbered(names: &[&str]) -> Vec<u64> {
        let all = labels();
        let mut out: Vec<u64> = names
            .iter()
            .map(|name| {
                all.iter()
                    .position(|label| label == name)
                    .unwrap_or_else(|| panic!("no packet called {name}")) as u64
            })
            .collect();
        out.sort_unstable();
        out
    }

    /// On a datagram flow a picked row is its own packet, and context adds the
    /// handshake and the declaration and nothing else.
    ///
    /// The selector picks every row whose key is `demo/p`: four requests and
    /// their finals (an exchange is one verdict), a put and a del. The control is
    /// the rest of the capture: a `demo/q` query, its reply and the keepalive are
    /// not in either list.
    #[test]
    fn a_datagram_row_is_its_packet_and_context_is_the_handshake_and_declares() {
        let (d, _) = mixed_session_with_file();
        let rows = picked(&d, "key == demo/p", false);
        let expected = numbered(&[
            "push-put",
            "push-del",
            "request-put-8",
            "final-8",
            "request-put-10",
            "final-10",
            "request-put-13",
            "final-13",
        ]);
        assert_eq!(rows.packets, expected);
        assert_eq!(rows.summary.rows_yes, 8);
        assert_eq!(rows.summary.packets, 8);
        assert_eq!(rows.summary.context_packets, 0);
        let all_rows = rows.summary.rows_yes
            + rows.summary.rows_no
            + rows.summary.rows_undecided
            + rows.summary.rows_unjudged;
        assert_eq!(
            all_rows,
            labels().len() as u64,
            "the four words partition the rows"
        );

        let with_context = picked(&d, "key == demo/p", true);
        let mut expected_with_context = expected.clone();
        expected_with_context.extend(numbered(&[
            "init-syn", "init-ack", "open-syn", "open-ack", "declare",
        ]));
        expected_with_context.sort_unstable();
        assert_eq!(with_context.packets, expected_with_context);
        assert_eq!(with_context.summary.context_packets, 5);
        assert_eq!(with_context.summary.context_unplaced, 0);
    }

    /// An empty selector asks nothing, so it names nothing and counts every row
    /// unjudged; a selector that picks nothing names nothing either, and adds no
    /// context, because context is gathered for flows with a picked row.
    #[test]
    fn nothing_picked_names_no_packet_and_no_context() {
        let (d, _) = mixed_session_with_file();
        let empty = picked(&d, "", true);
        assert!(empty.packets.is_empty());
        assert_eq!(empty.summary.rows_unjudged, labels().len() as u64);
        let none = picked(&d, "key == demo/absent", true);
        assert!(none.packets.is_empty());
        assert_eq!(none.summary.rows_yes, 0);
        assert_eq!(none.summary.context_packets, 0);
    }

    /// One TCP direction: Init, Open, a Declare, a `demo/p` push SPLIT ACROSS
    /// TWO SEGMENTS, and a `demo/other` push. Packet `n` is the `n`th entry.
    fn split_message_capture() -> Dissection {
        let prefixed = |unit: Vec<u8>| {
            let mut out = (unit.len() as u16).to_le_bytes().to_vec();
            out.extend_from_slice(&unit);
            out
        };
        let big = prefixed(frame_carrying(&push(
            sender_space(0, Some("demo/p")),
            &[0x55; 200],
        )));
        let (front, back) = big.split_at(100);
        let payloads: Vec<Vec<u8>> = alloc::vec![
            prefixed(init_datagram(false, &[])),
            prefixed(open_datagram(false)),
            prefixed(frame_carrying(&declare_kexpr(1, "demo/declared"))),
            front.to_vec(),
            back.to_vec(),
            prefixed(frame_carrying(&push(
                sender_space(0, Some("demo/other")),
                b"x",
            ))),
        ];
        let mut seq = 1000u32;
        let wires: Vec<Vec<u8>> = payloads
            .iter()
            .map(|payload| {
                let wire = tcp_packet(seq, payload);
                seq += payload.len() as u32;
                wire
            })
            .collect();
        let rows: Vec<(u32, u32, &[u8])> = wires
            .iter()
            .enumerate()
            .map(|(i, wire)| (1, i as u32 * 10_000, wire.as_slice()))
            .collect();
        Dissection::from_capture(&crate::pcap::write(LINKTYPE_ETHERNET, &rows))
            .expect("the capture reads")
    }

    /// A stream row is carried by EVERY packet its unit's bytes came in, which is
    /// the case the first-byte packet of the field document cannot name. The
    /// control picks the one-segment message, which names its one packet.
    #[test]
    fn a_stream_row_split_across_segments_names_both_packets() {
        let d = split_message_capture();
        let split = picked(&d, "key == demo/p", false);
        assert_eq!(split.packets, alloc::vec![3, 4], "{:?}", split.summary);
        assert_eq!(split.summary.rows_yes, 1);
        assert_eq!(split.summary.rows_unplaced, 0);

        let whole = picked(&d, "key == demo/other", false);
        assert_eq!(whole.packets, alloc::vec![5]);

        let with_context = picked(&d, "key == demo/p", true);
        assert_eq!(with_context.packets, alloc::vec![0, 1, 2, 3, 4]);
        assert_eq!(with_context.summary.context_packets, 3);
    }

    /// A list the message ceilings made short says so: the rows they took are
    /// counted, never read as rows that were not picked.
    #[test]
    fn rows_a_ceiling_took_are_counted_beside_the_list() {
        let (_, file) = mixed_session_with_file();
        let limits = crate::DissectionLimits {
            frames_per_flow: Some(5),
            ..crate::DissectionLimits::default()
        };
        let d = Dissection::from_capture_bounded(&file, limits).expect("the capture reads");
        let rows = picked(&d, "key == demo/p", false);
        let held = rows.summary.rows_yes
            + rows.summary.rows_no
            + rows.summary.rows_undecided
            + rows.summary.rows_unjudged;
        assert_eq!(held, 5, "the ceiling holds five rows");
        assert_eq!(
            held + rows.summary.rows_trimmed,
            labels().len() as u64,
            "what was held and what was taken make the whole capture"
        );
    }

    /// One TCP direction: Init, Open, then two Frames. Packet 2 carries TWO
    /// messages in one Frame, `demo/a` with a 1-byte value and `demo/b` with a
    /// 50-byte one; packet 3 carries one message, `demo/a` with a 50-byte value.
    fn two_messages_in_one_frame_capture() -> Dissection {
        let prefixed = |unit: Vec<u8>| {
            let mut out = (unit.len() as u16).to_le_bytes().to_vec();
            out.extend_from_slice(&unit);
            out
        };
        let mut both = push(sender_space(0, Some("demo/a")), &[0x01]);
        both.extend_from_slice(&push(sender_space(0, Some("demo/b")), &[0x55; 50]));
        let payloads: Vec<Vec<u8>> = alloc::vec![
            prefixed(init_datagram(false, &[])),
            prefixed(open_datagram(false)),
            prefixed(frame_carrying(&both)),
            prefixed(frame_carrying(&push(
                sender_space(0, Some("demo/a")),
                &[0x55; 50],
            ))),
        ];
        let mut seq = 1000u32;
        let wires: Vec<Vec<u8>> = payloads
            .iter()
            .map(|payload| {
                let wire = tcp_packet(seq, payload);
                seq += payload.len() as u32;
                wire
            })
            .collect();
        let rows: Vec<(u32, u32, &[u8])> = wires
            .iter()
            .enumerate()
            .map(|(i, wire)| (1, i as u32 * 10_000, wire.as_slice()))
            .collect();
        Dissection::from_capture(&crate::pcap::write(LINKTYPE_ETHERNET, &rows))
            .expect("the capture reads")
    }

    /// Two selectors joined by `and` judge each MESSAGE against both, where two
    /// calls whose lists are intersected judge each against one and intersect
    /// FRAMES.
    ///
    /// Packet 2 carries a message that passes the first selector and another that
    /// passes the second, and none that passes both. Each selector alone names
    /// the packet, so the intersection of the two lists keeps it; the joined
    /// selector does not, because its verdict is made on each message and a row
    /// is picked when one of its messages is. Packet 3 carries a message that
    /// passes both, and every route names it. A pipeline that passes a message
    /// only when it passed the stage before is the joined selector, in any
    /// number of stages.
    #[test]
    fn selectors_joined_by_and_are_judged_message_by_message() {
        let d = two_messages_in_one_frame_capture();
        let first = "key == demo/a";
        let second = "bytes > 10";

        let by_first = picked(&d, first, false).packets;
        let by_second = picked(&d, second, false).packets;
        assert_eq!(by_first, alloc::vec![2, 3]);
        assert_eq!(by_second, alloc::vec![2, 3]);
        let intersection: Vec<u64> = by_first
            .iter()
            .copied()
            .filter(|packet| by_second.contains(packet))
            .collect();
        assert_eq!(
            intersection,
            alloc::vec![2, 3],
            "two calls intersected judge frames, and keep the frame no message of which passes both"
        );

        let joined = picked(&d, &alloc::format!("({first}) and ({second})"), false);
        assert_eq!(
            joined.packets,
            alloc::vec![3],
            "joined, a message must pass both: {:?}",
            joined.summary
        );
        assert_eq!(joined.summary.rows_yes, 1);

        let three = picked(
            &d,
            &alloc::format!("({first}) and ({second}) and (key == demo/b)"),
            false,
        );
        assert!(
            three.packets.is_empty(),
            "a third stage that nothing in packet 3 passes leaves nothing: {:?}",
            three.summary
        );
    }
}
