// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 924, step 1 — THE DIFFERENTIAL GATE of the two-pass
//! dissection (`docs/dissect-row-index.md`, D4).
//!
//! A holder of rows may let a decoded record go only if the record can be made
//! again, equal, from what the holder keeps: the unit's bytes, its place, and
//! the facts its first reading recorded ([`UnitFacts`]). This gate is that
//! claim, measured: every unit of every capture below is read a second time
//! through [`redecode_unit`] and each record must print exactly as the first
//! reading's did.
//!
//! # What it reads the bytes from, and why that is the point
//!
//! A stream unit's bytes come out of the flow's reassembled stream at the
//! unit's anchor and `wire_end`, and a datagram unit's out of the capture
//! packet its anchor names, through the same decapsulation the first reading
//! used. Neither is a copy the first reading left behind for this gate. The
//! context a unit starts in is the context its predecessor's last record
//! carries, so the gate also holds the claim that a session's context moves
//! only inside the walk.
//!
//! # What it does not reach
//!
//! A unit a stream flow handed over in packet space (a WebSocket message) has no
//! byte run this gate can re-gather, and a QUIC payload exists only as the
//! plaintext the caller recovered. Those units are COUNTED as skipped and still
//! carry the context forward; each capture asserts how many it read, so a
//! capture whose units all fell out of reach fails rather than passing with
//! nothing checked.

use crate::link::{self, Transport};
use crate::messages::{Messages, Row, RowHead};
use crate::{DatagramLink, Dissection};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
#[allow(unused_imports)] // `Carried` is read by the feature-gated tests only.
use wz_session_core::passive::Carried;
use wz_session_core::passive::{
    redecode_unit, Anchor, Direction, FlowContext, LinkHandshake, OffsetSpace, PassiveFrame,
    UnitFacts, UnitInput,
};

/// How much of one capture the gate read again.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Reach {
    /// Units read again and found equal.
    units: usize,
    /// Records those units held.
    records: usize,
    /// Units whose bytes the gate could not re-gather.
    skipped: usize,
    /// Records the flows held, read again or not.
    held: usize,
}

impl Reach {
    /// Every record held was read again, and there was at least one.
    fn assert_whole(&self, what: &str) {
        assert!(self.held > 0, "{what}: nothing was held to read again");
        assert_eq!(self.skipped, 0, "{what}: units out of reach: {self:?}");
        assert_eq!(self.records, self.held, "{what}: {self:?}");
    }
}

impl core::ops::AddAssign for Reach {
    fn add_assign(&mut self, other: Self) {
        self.units += other.units;
        self.records += other.records;
        self.skipped += other.skipped;
        self.held += other.held;
    }
}

/// The records of one session, grouped into the units they were read in, in
/// the order the units were read.
///
/// A unit's first record has `batch_index` 0, and a direction's units come out
/// whole and in order: a stream unit's later records wait in the session until
/// that direction is asked again, so the OTHER direction's records may fall
/// between them, but no record of this direction can. A unit is read when its
/// first record is produced, so the order of first records is the order the
/// units were read in.
fn units(frames: Messages<'_>) -> Vec<Vec<Row<'_>>> {
    let mut units: Vec<Vec<Row<'_>>> = Vec::new();
    let mut open: [Option<usize>; 2] = [None, None];
    for frame in frames {
        let seat = usize::from(frame.direction == Direction::B);
        if frame.batch_index == 0 {
            units.push(alloc::vec![frame]);
            open[seat] = Some(units.len() - 1);
        } else {
            let at = open[seat].expect("a unit's later record follows its first in its direction");
            units[at].push(frame);
        }
    }
    units
}

/// Read every unit of one session's `frames` again and compare. `bytes_of`
/// gives a unit's wire bytes and the handshake its link carries, from the
/// unit's first record, or `None` when they cannot be re-gathered.
fn reread(
    what: &str,
    frames: Messages<'_>,
    mut bytes_of: impl FnMut(&PassiveFrame) -> Option<(Vec<u8>, LinkHandshake)>,
) -> Reach {
    let mut reach = Reach {
        held: frames.len(),
        ..Reach::default()
    };
    let mut start = FlowContext::default();
    for (n, unit) in units(frames).into_iter().enumerate() {
        let first: &PassiveFrame = &unit[0];
        if let Some((bytes, handshake)) = bytes_of(first) {
            let facts = UnitFacts::of(start, unit.iter().map(|row| &**row));
            let again = redecode_unit(
                UnitInput {
                    direction: first.direction,
                    bytes: &bytes,
                    anchor: Anchor {
                        offset: first.stream_offset,
                        space: first.offset_space,
                    },
                    prefix_width: first.prefix_width,
                    handshake,
                },
                &facts,
            )
            .unwrap_or_else(|e| panic!("{what}: unit {n} refused its own facts: {e:?}"));
            for (i, (was, now)) in unit.iter().zip(&again).enumerate() {
                // The FRAME's own rendering, not the row's that holds it.
                let was: &PassiveFrame = was;
                let (was, now) = (format!("{was:?}"), format!("{now:?}"));
                assert!(
                    was == now,
                    "{what}: unit {n}, record {i} read again differs\n first: {was}\n again: {now}"
                );
            }
            reach.units += 1;
            reach.records += unit.len();
        } else {
            reach.skipped += 1;
        }
        start = unit[unit.len() - 1].context;
    }
    reach
}

/// `file` (a pcap) read the way [`Dissection::from_capture`] reads it, keeping
/// every message a stream flow reads off its own stream whole: the FIRST
/// reading, which is what every later reading is held equal to.
fn read_whole(what: &str, file: &[u8]) -> Dissection {
    let parsed = crate::pcap::parse(file).unwrap_or_else(|e| panic!("{what}: {e:?}"));
    let mut d = Dissection::new();
    d.keep_messages_whole();
    for packet in &parsed.packets {
        d.push_packet_at_nanos(
            parsed.link_type,
            packet.index,
            Some(packet.ts_nanos(parsed.timestamp_unit)),
            &packet.data,
        );
    }
    d.finish();
    d
}

/// Whether the row at `position` of `list` is decoded anew each time it is
/// read: two readings alive at once are two frames, where a row the list keeps
/// whole is the same one both times.
fn read_again(list: Messages<'_>, position: usize) -> bool {
    let (first, second) = (list.row(position), list.row(position));
    !core::ptr::eq::<PassiveFrame>(&*first, &*second)
}

/// Open-debt item 924, step 4b — THE CLAIM OF THE INDEX: a dissection whose
/// stream flows keep their messages as entries reads every list, row for row
/// and head for head, as the reading that kept them whole, by position and
/// walking, forward and back. Returns the rows that were read again from their
/// bytes, which a capture with stream units must make more than zero.
fn assert_reads_as_whole(what: &str, indexed: &Dissection, whole: &Dissection) -> usize {
    let mut read_from_bytes = 0usize;
    assert_reads_as(what, indexed, whole, |n, list, list_w, position| {
        assert!(
            !read_again(list_w, position),
            "{what}: the reference keeps list {n} row {position} whole"
        );
        if read_again(list, position) {
            read_from_bytes += 1;
        }
    });
    read_from_bytes
}

/// Every list of `subject` reads, row for row and head for head, as the same
/// list of `reference`, by position and walking, forward and back. `each` is
/// handed the number of every pair of lists, the pair, and the position of each
/// row in them.
fn assert_reads_as<'d>(
    what: &str,
    subject: &'d Dissection,
    reference: &'d Dissection,
    mut each: impl FnMut(usize, Messages<'d>, Messages<'d>, usize),
) {
    let lists: Vec<_> = subject.message_lists_with_origin().collect();
    let reference: Vec<_> = reference.message_lists_with_origin().collect();
    assert_eq!(lists.len(), reference.len(), "{what}: lists");
    for (n, ((flow, origin, list), (flow_w, origin_w, list_w))) in
        lists.into_iter().zip(reference).enumerate()
    {
        assert_eq!((flow, origin), (flow_w, origin_w), "{what}: list {n}");
        assert_eq!(list.len(), list_w.len(), "{what}: list {n} length");
        assert_eq!(
            list.produced(),
            list_w.produced(),
            "{what}: list {n} produced"
        );
        let walked: Vec<String> = list.iter().map(|row| format!("{:?}", *row)).collect();
        let expected: Vec<String> = list_w.iter().map(|row| format!("{:?}", *row)).collect();
        assert_eq!(walked, expected, "{what}: list {n}, walked forward");
        let mut backward: Vec<String> =
            list.iter().rev().map(|row| format!("{:?}", *row)).collect();
        backward.reverse();
        assert_eq!(backward, expected, "{what}: list {n}, walked backward");
        let heads: Vec<RowHead> = list.heads_from(0).collect();
        let heads_w: Vec<RowHead> = list_w.iter().map(|row| RowHead::of(&row)).collect();
        assert_eq!(heads, heads_w, "{what}: list {n}, heads");
        for (position, want) in expected.iter().enumerate() {
            assert_eq!(
                &format!("{:?}", *list.row(position)),
                want,
                "{what}: list {n}, row {position} by position"
            );
            each(n, list, list_w, position);
        }
    }
}

/// Open-debt item 924, step 3 — THE CLAIM OF THE LENT CONTAINER: a dissection
/// LENT `file` reads every list, row for row and head for head, every message's
/// bytes, the drop counts and the census of what was discarded as the one
/// HANDED the same bytes, and keeps no copy of a TCP payload.
///
/// `cuts` are the prefixes the container is followed through before the whole
/// of it, each lent as a container of its own at a new address: a container
/// that grows by moving, which every flow already held must follow. Returns
/// the rows compared.
fn assert_lent_reads_as_handed(
    what: &str,
    file: &[u8],
    limits: crate::DissectionLimits,
    cuts: &[usize],
) -> usize {
    let mut handed = Dissection::with_limits(limits);
    let mut lent = Dissection::with_limits(limits);
    let (mut handed_at, mut lent_at) = (crate::CaptureCursor::new(), crate::CaptureCursor::new());
    for &upto in cuts.iter().chain([&file.len()]) {
        let prefix = &file[..upto];
        let read = handed
            .follow_container(&mut handed_at, prefix)
            .unwrap_or_else(|e| panic!("{what}: handed {upto}: {e:?}"));
        let container: alloc::sync::Arc<dyn crate::LentCapture> =
            alloc::sync::Arc::new(prefix.to_vec());
        let read_lent = lent
            .follow_lent(&mut lent_at, container)
            .unwrap_or_else(|e| panic!("{what}: lent {upto}: {e:?}"));
        assert_eq!(read_lent, read, "{what}: packets read to {upto}");
    }
    handed.finish();
    lent.finish();
    let mut rows = 0usize;
    assert_reads_as(what, &lent, &handed, |_, _, _, _| rows += 1);
    for ((flow, origin, list), (_, _, list_h)) in lent
        .message_lists_with_origin()
        .zip(handed.message_lists_with_origin())
    {
        for index in 0..list.len() {
            let (bytes, bytes_h) = (
                format!("{:?}", lent.message_bytes_at(flow, origin, index)),
                format!("{:?}", handed.message_bytes_at(flow, origin, index)),
            );
            assert_eq!(bytes, bytes_h, "{what}: {flow:?} message {index} bytes");
        }
        assert_eq!(list.len(), list_h.len(), "{what}: {flow:?}");
    }
    assert_eq!(lent.drops(), handed.drops(), "{what}: drops");
    assert_eq!(
        lent.dropped_frame_census(),
        handed.dropped_frame_census(),
        "{what}: what was discarded"
    );
    // The control: the same bytes HANDED are copied, at least every retained
    // one, so the zero below is the lending's and not the capture's.
    let assemblers = |d: &'_ Dissection| -> Vec<(String, usize, usize)> {
        d.flows
            .iter()
            .flat_map(|flow| {
                [Direction::A, Direction::B].map(|dir| {
                    let assembler = flow.assembler(dir);
                    let at = format!("{:?} {dir:?}", flow.flow);
                    (at, assembler.bytes_kept(), assembler.retained_len())
                })
            })
            .collect()
    };
    for (at, kept, retained) in assemblers(&handed) {
        assert!(
            kept >= retained,
            "{what}: {at} handed keeps {kept} of {retained}"
        );
    }
    for (at, kept, _) in assemblers(&lent) {
        assert_eq!(kept, 0, "{what}: {at} kept a copy of a lent payload");
    }
    rows
}

/// THE LENT CONTAINER over every tracked capture and the stream shapes, read
/// whole and grown through cuts, and under the ceilings the list of entries is
/// gated under: a ceiling that trims a stream trims the place a run remembers,
/// and a message ceiling keeps messages whole out of bytes still in the
/// container.
#[test]
fn a_lent_container_reads_as_the_same_bytes_handed() {
    let shapes = stream_shapes_capture();
    let mut files: Vec<(&str, &[u8])> = alloc::vec![("stream shapes", &shapes)];
    files.extend(tracked_captures());
    // The tracked captures are mostly datagram links; the stream shapes are
    // what holds TCP payloads to lend, in both directions of three flows.
    let handed = Dissection::from_capture(&shapes).expect("the capture reads");
    let streams = handed
        .flows
        .iter()
        .flat_map(|flow| [Direction::A, Direction::B].map(|dir| flow.assembler(dir)))
        .filter(|assembler| !assembler.is_empty())
        .count();
    assert_eq!(streams, 4, "stream shapes: the directions holding a stream");
    for (name, file) in &files {
        let cuts: Vec<usize> = (1..4).map(|k| file.len() * k / 4).collect();
        let whole =
            assert_lent_reads_as_handed(name, file, crate::DissectionLimits::default(), &[]);
        let grown =
            assert_lent_reads_as_handed(name, file, crate::DissectionLimits::default(), &cuts);
        assert_eq!(whole, grown, "{name}: rows read whole and grown");
        // Scouting rides its own list, as in the tracked captures' test.
        if *name != "scout-and-hello-ipv4-ipv6" {
            assert!(whole > 0, "{name}: nothing was read");
        }
    }
    for limits in ceilings() {
        let what = format!("stream shapes, {limits:?}");
        let rows = assert_lent_reads_as_handed(&what, &shapes, limits, &[shapes.len() / 2]);
        assert!(rows > 0, "{what}: nothing was read");
    }
}

/// Open-debt item 924, step 4c — A LENT DATAGRAM IS READ WHERE IT SITS: a
/// dissection lent a capture of UDP datagrams logs no copy of their payloads,
/// so a flow whose container is taken away has nothing to read a row from. A
/// list that had logged a copy would read on.
#[test]
#[should_panic(expected = "bytes of a datagram a list holds are not at Container")]
fn a_lent_datagram_keeps_no_copy_of_its_payload() {
    let (name, file) = tracked_captures()[2];
    let mut lent = Dissection::new();
    let container: alloc::sync::Arc<dyn crate::LentCapture> = alloc::sync::Arc::new(file.to_vec());
    lent.follow_lent(&mut crate::CaptureCursor::new(), container)
        .unwrap_or_else(|e| panic!("{name}: {e:?}"));
    lent.finish();
    let flow = lent
        .datagram_flows
        .iter_mut()
        .find(|flow| !flow.frames().is_empty())
        .unwrap_or_else(|| unreachable!("{name}: a UDP flow carries messages"));
    flow.lent = None;
    let _ = flow.frames().row(0);
}

/// Read every unit of every stream and datagram flow of `file` again. A stream
/// flow's messages are compared twice: the first reading against each unit read
/// again from its bytes ([`redecode_unit`]), and a dissection that keeps entries
/// against the first reading ([`assert_reads_as_whole`]).
fn reread_capture(what: &str, file: &[u8]) -> Reach {
    let indexed = Dissection::from_capture(file).unwrap_or_else(|e| panic!("{what}: {e:?}"));
    let d = read_whole(what, file);
    // Every message a flow read off its own reassembled stream is an entry, and
    // so is every cleartext datagram's that is admissible on its link (step
    // 4c); nothing else is: a WebSocket message, a decrypted record, a
    // recovered QUIC message and a message inadmissible on its link are kept
    // whole.
    let read_from_bytes = assert_reads_as_whole(what, &indexed, &d);
    let stream_rows: usize = d
        .flows
        .iter()
        .filter(|flow| matches!(flow.framing(), crate::Framing::Stream))
        .map(|flow| flow.frames().len())
        .sum();
    let datagram_rows: usize = d
        .datagram_flows
        .iter()
        .map(|flow| {
            flow.frames()
                .heads_from(0)
                .filter(|head| !head.inadmissible_on_link)
                .count()
        })
        .sum();
    assert_eq!(
        read_from_bytes,
        stream_rows + datagram_rows,
        "{what}: the messages kept as entries"
    );
    let packets = crate::pcap::parse(file).ok();
    let mut reach = Reach::default();
    for flow in d.flows.iter() {
        reach += reread(what, flow.frames(), |frame| {
            if frame.offset_space != OffsetSpace::StreamBytes {
                return None;
            }
            use crate::messages::UnitBytes as _;
            let from = frame.stream_offset + frame.prefix_width;
            let bytes = flow
                .stream_bytes(frame.direction, from, frame.wire_end?)?
                .into_owned();
            Some((bytes, LinkHandshake::Present))
        });
    }
    for flow in d.datagram_flows.iter() {
        reach += reread(what, flow.frames(), |frame| {
            let file = packets.as_ref()?;
            let packet = file.packets.get(frame.stream_offset)?;
            let (datagram, link) =
                match link::decapsulate(file.link_type, packet.index, &packet.data).ok()? {
                    Transport::Udp(d) => (d, DatagramLink::Udp),
                    Transport::RawEth(d) => (d, DatagramLink::RawEth),
                    _ => return None,
                };
            let handshake = link.handshake(&datagram);
            Some((datagram.payload.to_vec(), handshake))
        });
    }
    reach
}

/// A capture file read whole, then read again unit by unit.
fn reread_file(what: &str, file: &[u8]) -> Reach {
    reread_capture(what, file)
}

/// THE TRACKED CAPTURES. Each is real traffic or the oracle-pinned output of
/// the production encoders, and together they reach a handshake on both a
/// stream and a datagram link, a compression-negotiated session, fragment
/// chains with and without the handshake that resolves them, and a raweth link
/// that has no handshake at all.
#[test]
fn every_unit_of_the_tracked_captures_reads_again_the_same() {
    let mut total = Reach::default();
    for (name, file) in tracked_captures() {
        // Scouting rides its own list, so the discovery capture holds no
        // transport record; every other tracked capture must be read whole.
        let reach = reread_file(name, file);
        if name != "scout-and-hello-ipv4-ipv6" {
            reach.assert_whole(name);
        }
        total += reach;
    }
    total.assert_whole("the tracked captures");
}

/// The tracked captures the test above reads, by name.
fn tracked_captures() -> [(&'static str, &'static [u8]); 5] {
    [
        (
            "compressed-session-refused-body",
            include_bytes!("../../../captures/compressed-session-refused-body.pcap"),
        ),
        (
            "fragmented-push-midsession-and-established",
            include_bytes!("../../../captures/fragmented-push-midsession-and-established.pcap"),
        ),
        (
            "publisher-priority-encoding-timestamp",
            include_bytes!("../../../captures/publisher-priority-encoding-timestamp.pcap"),
        ),
        (
            "raweth-transport-messages",
            include_bytes!("../../../captures/raweth-transport-messages.pcap"),
        ),
        (
            "scout-and-hello-ipv4-ipv6",
            include_bytes!("../../../captures/scout-and-hello-ipv4-ipv6.pcap"),
        ),
    ]
}

/// A STREAM's own shapes, which no tracked capture holds: batches of several
/// messages in one unit, a unit split across packets, a sequence-number gap
/// and a duplicate, three flows in one capture (so a unit's place is an offset
/// within ITS OWN stream), and bytes the framing has to resynchronise past.
#[test]
fn every_unit_of_a_stream_with_batches_gaps_and_garbage_reads_again_the_same() {
    let file = stream_shapes_capture();
    let d = Dissection::from_capture(&file).expect("the capture reads");
    // The shapes this capture is FOR must be in what was read, or the
    // comparison below says nothing about them.
    let held: Vec<Row<'_>> = d.flows.iter().flat_map(|f| f.frames()).collect();
    let verdicts: Vec<_> = held.iter().filter_map(|f| f.sn_verdict).collect();
    use wz_session_core::passive::SnVerdict;
    assert!(
        held.iter().any(|f| f.batch_index == 1),
        "a batch of two was read"
    );
    assert!(
        held.iter().any(|f| f.resync.is_some()),
        "a resynchronisation was read"
    );
    assert!(
        verdicts.iter().any(|v| matches!(v, SnVerdict::Gap { .. })),
        "a gap was judged: {verdicts:?}"
    );
    assert!(
        verdicts.contains(&SnVerdict::Duplicate),
        "a duplicate was judged: {verdicts:?}"
    );
    assert!(
        verdicts.contains(&SnVerdict::WithoutResolution),
        "a flow without a handshake was judged: {verdicts:?}"
    );
    assert_eq!(d.flows.len(), 3, "three stream flows");
    reread_capture("stream shapes", &file).assert_whole("stream shapes");
}

/// Open-debt item 924, step 4b — A LIST OF ENTRIES UNDER THE CEILINGS. A
/// message ceiling discards from the front, and on this capture it cuts a unit
/// of two between its records, whose second must still read back; a byte
/// ceiling releases stream bytes under messages still held, which the list keeps
/// whole before they go. Under every ceiling, every list, the census of what was
/// discarded and the drop counts read as the reading that kept every message
/// whole.
#[test]
fn a_list_of_entries_under_message_and_byte_ceilings_reads_as_the_reference() {
    let file = stream_shapes_capture();
    let parsed = crate::pcap::parse(&file).expect("the capture reads");
    let mut converted = 0usize;
    for limits in ceilings() {
        let what = format!("{limits:?}");
        let indexed = Dissection::from_pcap_declaring_bounded(&file, &[], &[], limits)
            .unwrap_or_else(|e| panic!("{what}: {e:?}"));
        let mut whole = Dissection::with_limits(limits);
        whole.keep_messages_whole();
        for packet in &parsed.packets {
            whole.push_packet_at_nanos(
                parsed.link_type,
                packet.index,
                Some(packet.ts_nanos(parsed.timestamp_unit)),
                &packet.data,
            );
        }
        whole.finish();
        let read_from_bytes = assert_reads_as_whole(&what, &indexed, &whole);
        let held: usize = indexed.flows.iter().map(|flow| flow.frames().len()).sum();
        if limits.stream_bytes_per_direction.is_none() {
            assert_eq!(read_from_bytes, held, "{what}: nothing kept whole");
        }
        converted += held - read_from_bytes;
        assert_eq!(indexed.drops(), whole.drops(), "{what}: drops");
        assert_eq!(
            indexed.dropped_frame_census(),
            whole.dropped_frame_census(),
            "{what}: what was discarded"
        );
    }
    assert!(
        converted > 0,
        "a byte ceiling released bytes under a message the list then kept whole"
    );
}

/// Open-debt item 924, step 4c — A LIST OF DATAGRAM ENTRIES UNDER THE
/// CEILINGS. A message ceiling, per flow or over all of them, discards from the
/// front of a list that logs its units, cutting a batched unit between its
/// records and releasing a unit's logged bytes with its last row. Under every
/// ceiling, every list, the drop counts and the census of what was discarded
/// read as the reading that kept every message whole, and a dissection LENT the
/// capture reads as one handed it.
#[test]
fn a_list_of_datagram_entries_under_message_ceilings_reads_as_the_reference() {
    let mut ceilings: Vec<crate::DissectionLimits> = Vec::new();
    for cap in [1, 2, 3, 5, 8] {
        ceilings.push(crate::DissectionLimits {
            frames_per_flow: Some(cap),
            ..crate::DissectionLimits::default()
        });
        ceilings.push(crate::DissectionLimits {
            frames_total: Some(cap),
            ..crate::DissectionLimits::default()
        });
    }
    let (mut read_from_bytes, mut discarded) = (0usize, 0usize);
    for (name, file) in tracked_captures() {
        let parsed = crate::pcap::parse(file).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        for limits in &ceilings {
            let what = format!("{name}, {limits:?}");
            let indexed = Dissection::from_pcap_declaring_bounded(file, &[], &[], *limits)
                .unwrap_or_else(|e| panic!("{what}: {e:?}"));
            let mut whole = Dissection::with_limits(*limits);
            whole.keep_messages_whole();
            for packet in &parsed.packets {
                whole.push_packet_at_nanos(
                    parsed.link_type,
                    packet.index,
                    Some(packet.ts_nanos(parsed.timestamp_unit)),
                    &packet.data,
                );
            }
            whole.finish();
            read_from_bytes += assert_reads_as_whole(&what, &indexed, &whole);
            discarded += indexed.drops().frames;
            assert_eq!(indexed.drops(), whole.drops(), "{what}: drops");
            assert_eq!(
                indexed.dropped_frame_census(),
                whole.dropped_frame_census(),
                "{what}: what was discarded"
            );
            assert_lent_reads_as_handed(&what, file, *limits, &[file.len() / 2]);
        }
    }
    assert!(
        read_from_bytes > 0,
        "a datagram row was read from its bytes"
    );
    assert!(discarded > 0, "a ceiling discarded a datagram row");
}

/// The ceilings the stream shapes are read under: a message ceiling of one to
/// eight per flow, and byte ceilings with and without a message ceiling beside.
fn ceilings() -> Vec<crate::DissectionLimits> {
    let mut ceilings: Vec<crate::DissectionLimits> = Vec::new();
    for cap in 1..=8 {
        ceilings.push(crate::DissectionLimits {
            frames_per_flow: Some(cap),
            ..crate::DissectionLimits::default()
        });
    }
    for keep in [6, 16, 40, 120] {
        ceilings.push(crate::DissectionLimits {
            stream_bytes_per_direction: Some(keep),
            ..crate::DissectionLimits::default()
        });
        ceilings.push(crate::DissectionLimits {
            stream_bytes_per_direction: Some(keep),
            frames_per_flow: Some(3),
            ..crate::DissectionLimits::default()
        });
    }
    ceilings
}

/// The capture `every_unit_of_a_stream_with_batches_gaps_and_garbage_reads_\
/// again_the_same` reads, built packet by packet.
fn stream_shapes_capture() -> Vec<u8> {
    use crate::datagram_tests::{
        framed_frame, framed_keepalive, init_datagram, open_datagram, tcp_packet_on,
        tcp_packet_reverse,
    };
    let framed = |message: &[u8]| {
        let mut out = (message.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(message);
        out
    };
    // Flow 1111 carries the whole handshake both ways, then data from the
    // dialer: a keepalive and a frame batched into ONE unit, a gap (sn 1 -> 4),
    // a duplicate, a unit cut across two packets, three garbage bytes the
    // reader has to find its framing again after, and two whole units in one
    // segment.
    let mut two_units_in_one_segment = framed_keepalive();
    two_units_in_one_segment.extend_from_slice(&framed_frame(11));
    // `framed_keepalive` and `framed_frame` are each a whole framed unit; two
    // unframed messages behind ONE prefix are what a batch is.
    let keepalive_and_frame = {
        let mut body = framed_keepalive()[2..].to_vec();
        body.extend_from_slice(&framed_frame(1)[2..]);
        framed(&body)
    };
    let split = framed_frame(9);
    let (head, tail) = split.split_at(3);
    let mut low: Vec<Vec<u8>> = alloc::vec![
        framed(&init_datagram(false, &[])),
        framed(&open_datagram(false)),
        keepalive_and_frame,
        framed_frame(4),
        framed_frame(4),
        head.to_vec(),
        tail.to_vec(),
        // A plausible two-byte length in front of a header no transport message
        // has: the framing loses its boundary here and has to find the next.
        alloc::vec![0x02, 0x00, 0xFF, 0xFF],
    ];
    // The reader resumes only on a chain of credible units as long as its
    // resynchronisation depth, so the garbage is followed by more than that.
    for sn in 0..=wz_session_core::passive::DEFAULT_RESYNC_DEPTH as u8 {
        low.push(framed_frame(20 + sn));
    }
    low.push(two_units_in_one_segment);
    let high: Vec<Vec<u8>> = alloc::vec![
        framed(&init_datagram(true, &[])),
        framed(&open_datagram(true)),
        framed_frame(1),
    ];
    let mut packets: Vec<Vec<u8>> = Vec::new();
    let (mut seq_low, mut seq_high) = (1_000u32, 9_000u32);
    for i in 0..low.len().max(high.len()) {
        if let Some(payload) = low.get(i) {
            packets.push(tcp_packet_on(1111, seq_low, payload));
            seq_low += payload.len() as u32;
        }
        if let Some(payload) = high.get(i) {
            packets.push(tcp_packet_reverse(seq_high, payload));
            seq_high += payload.len() as u32;
        }
    }
    // Flows 2222 and 3333 start mid-session: no handshake, so the reader
    // judges their sequence numbers without a resolution.
    for port in [2222u16, 3333] {
        let mut seq = 40_000u32;
        for sn in [3u8, 4, 6] {
            let payload = framed_frame(sn);
            packets.push(tcp_packet_on(port, seq, &payload));
            seq += payload.len() as u32;
        }
    }
    let rows: Vec<(u32, u32, &[u8])> = packets
        .iter()
        .enumerate()
        .map(|(i, p)| (i as u32, 0, p.as_slice()))
        .collect();
    crate::pcap::write(crate::link::LINKTYPE_ETHERNET, &rows)
}

/// THE COMPRESSION ARMS on a datagram link: a raw batch behind a clear batch
/// header, and a batch that is lz4 as a whole. Built the way the field
/// document's own tests build them.
#[cfg(all(feature = "dissect", feature = "network-codecs"))]
#[test]
fn every_unit_of_a_compressed_session_reads_again_the_same() {
    use crate::datagram_tests::{compressed_session_with_unit, frame_datagram, push, sender_space};
    let record = push(sender_space(0, Some("zip/again")), &[3u8; 8]);
    let mut clear = alloc::vec![0x00u8];
    clear.extend_from_slice(&frame_datagram(&record));
    // An lz4 block of one literal run, written from the block format.
    let body = frame_datagram(&record);
    let mut lz4 = alloc::vec![0x01u8];
    if body.len() < 15 {
        lz4.push((body.len() as u8) << 4);
    } else {
        lz4.push(0xF0);
        let mut rest = body.len() - 15;
        while rest >= 255 {
            lz4.push(255);
            rest -= 255;
        }
        lz4.push(rest as u8);
    }
    lz4.extend_from_slice(&body);
    for (name, unit) in [("clear batch header", clear), ("lz4 batch", lz4)] {
        let (d, file) = compressed_session_with_unit(unit);
        let last = d
            .datagram_flows
            .iter()
            .flat_map(|f| f.frames())
            .last()
            .map(|f| {
                (
                    f.decompressed.is_some(),
                    matches!(f.carried, Carried::Undecompressible),
                )
            });
        // The arm the unit is for must be the arm that was read: an lz4 body
        // is decompressed where this build has lz4 and refused where it does not.
        match name {
            "lz4 batch" if cfg!(feature = "compression") => {
                assert_eq!(last, Some((true, false)), "{name}")
            }
            "lz4 batch" => assert_eq!(last, Some((false, true)), "{name}"),
            _ => assert_eq!(last, Some((false, false)), "{name}"),
        }
        reread_capture(name, &file).assert_whole(name);
    }
}

/// FRAGMENT CHAINS, completed and broken, on both kinds of flow, including a
/// chain whose sequence numbers this reader cannot resolve: each fate a
/// fragment comes to is a fact the second reading is handed, and the batch a
/// completed chain carries is parsed again from the joined bytes.
#[cfg(all(
    feature = "reassembly",
    feature = "network-codecs",
    feature = "dissect"
))]
#[test]
fn every_unit_of_the_fragment_chain_captures_reads_again_the_same() {
    use crate::datagram_tests::{
        marked_fragment_dissection_with_file, midsession_fragment_dissection_with_file,
        reassembled_record_dissection_with_file, wide_sn_dissection_with_file,
    };
    let record = crate::datagram_tests::push(
        crate::datagram_tests::sender_space(0, Some("chain/again")),
        &[5u8; 24],
    );
    let mut total = Reach::default();
    let (_, file) = reassembled_record_dissection_with_file(&record);
    total += reread_capture("reassembled record", &file);
    let (_, file) = midsession_fragment_dissection_with_file();
    total += reread_capture("midsession fragments", &file);
    let (_, file) = marked_fragment_dissection_with_file(&[
        (0, true, true, false),
        (1, false, false, false),
        (2, true, false, true),
    ]);
    total += reread_capture("marked fragments", &file);
    let (_, file) = wide_sn_dissection_with_file(&[1, 2, 2, 7, 3, 1 << 40]);
    total += reread_capture("wide sequence numbers", &file);
    #[cfg(feature = "fixtures")]
    {
        let file = crate::fixtures::stream_chain_sequence_capture(3);
        total += reread_file("stream chain sequence", &file);
        let file = crate::fixtures::chain_sequence_capture(3);
        total += reread_file("datagram chain sequence", &file);
    }
    total.assert_whole("the fragment chain captures");
}

/// Each fate a fragment can come to was reached by the chain captures above,
/// so the facts the second reading is handed are not all of one kind.
#[cfg(all(
    feature = "reassembly",
    feature = "network-codecs",
    feature = "dissect"
))]
#[test]
fn the_fragment_chain_captures_reach_every_fate_a_fragment_comes_to() {
    use crate::datagram_tests::{
        marked_fragment_dissection_with_file, midsession_fragment_dissection_with_file,
        reassembled_record_dissection_with_file,
    };
    let record = crate::datagram_tests::push(
        crate::datagram_tests::sender_space(0, Some("chain/again")),
        &[5u8; 24],
    );
    let captures = [
        reassembled_record_dissection_with_file(&record).0,
        midsession_fragment_dissection_with_file().0,
        marked_fragment_dissection_with_file(&[
            (0, true, true, false),
            (1, false, false, false),
            (2, true, false, true),
        ])
        .0,
    ];
    let mut fates = [false; 3];
    for d in &captures {
        let rows = d
            .flows
            .iter()
            .flat_map(|f| f.frames())
            .chain(d.datagram_flows.iter().flat_map(|f| f.frames()));
        for frame in rows {
            match frame.carried {
                Carried::Reassembled { .. } => fates[0] = true,
                Carried::Fragment(_) => fates[1] = true,
                Carried::FragmentWithoutResolution => fates[2] = true,
                _ => {}
            }
        }
    }
    assert_eq!(
        fates, [true; 3],
        "joined, pending and without a resolution must each be reached"
    );
}
