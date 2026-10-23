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
use crate::{DatagramLink, Dissection};
use alloc::format;
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
fn units(frames: &[PassiveFrame]) -> Vec<Vec<&PassiveFrame>> {
    let mut units: Vec<Vec<&PassiveFrame>> = Vec::new();
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
    frames: &[PassiveFrame],
    mut bytes_of: impl FnMut(&PassiveFrame) -> Option<(Vec<u8>, LinkHandshake)>,
) -> Reach {
    let mut reach = Reach {
        held: frames.len(),
        ..Reach::default()
    };
    let mut start = FlowContext::default();
    for (n, unit) in units(frames).into_iter().enumerate() {
        let first = unit[0];
        if let Some((bytes, handshake)) = bytes_of(first) {
            let facts = UnitFacts::of(start, unit.iter().copied());
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

/// Read every unit of every stream and datagram flow of `d` again. `file` is
/// the capture `d` was read from, which a datagram unit's bytes come out of.
fn reread_capture(what: &str, d: &Dissection, file: &[u8]) -> Reach {
    let packets = crate::pcap::parse(file).ok();
    let mut reach = Reach::default();
    for flow in d.flows.iter() {
        reach += reread(what, flow.frames.as_slice(), |frame| {
            if frame.offset_space != OffsetSpace::StreamBytes {
                return None;
            }
            let assembler = flow.assembler(frame.direction);
            let origin = assembler.retained_from();
            let from = (frame.stream_offset + frame.prefix_width).checked_sub(origin)?;
            let to = frame.wire_end?.checked_sub(origin)?;
            let bytes = assembler.stream().get(from..to)?.to_vec();
            Some((bytes, LinkHandshake::Present))
        });
    }
    for flow in d.datagram_flows.iter() {
        reach += reread(what, flow.frames.as_slice(), |frame| {
            let file = packets.as_ref()?;
            let packet = file.packets.get(frame.stream_offset)?;
            let (datagram, link) =
                match link::decapsulate(file.link_type, packet.index, &packet.data).ok()? {
                    Transport::Udp(d) => (d, DatagramLink::Udp),
                    Transport::RawEth(d) => (d, DatagramLink::RawEth),
                    _ => return None,
                };
            let handshake = link.handshake(&datagram);
            Some((datagram.payload, handshake))
        });
    }
    reach
}

/// A capture file read whole, then read again unit by unit.
fn reread_file(what: &str, file: &[u8]) -> Reach {
    let d = Dissection::from_capture(file).unwrap_or_else(|e| panic!("{what}: {e:?}"));
    reread_capture(what, &d, file)
}

/// THE TRACKED CAPTURES. Each is real traffic or the oracle-pinned output of
/// the production encoders, and together they reach a handshake on both a
/// stream and a datagram link, a compression-negotiated session, fragment
/// chains with and without the handshake that resolves them, and a raweth link
/// that has no handshake at all.
#[test]
fn every_unit_of_the_tracked_captures_reads_again_the_same() {
    let tracked: [(&str, &[u8]); 5] = [
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
    ];
    let mut total = Reach::default();
    for (name, file) in tracked {
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

/// A STREAM's own shapes, which no tracked capture holds: batches of several
/// messages in one unit, a unit split across packets, a sequence-number gap
/// and a duplicate, three flows in one capture (so a unit's place is an offset
/// within ITS OWN stream), and bytes the framing has to resynchronise past.
#[test]
fn every_unit_of_a_stream_with_batches_gaps_and_garbage_reads_again_the_same() {
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
    let file = crate::pcap::write(crate::link::LINKTYPE_ETHERNET, &rows);
    let d = Dissection::from_capture(&file).expect("the capture reads");
    // The shapes this capture is FOR must be in what was read, or the
    // comparison below says nothing about them.
    let held: Vec<&PassiveFrame> = d.flows.iter().flat_map(|f| f.frames.as_slice()).collect();
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
    reread_capture("stream shapes", &d, &file).assert_whole("stream shapes");
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
            .flat_map(|f| f.frames.as_slice())
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
        reread_capture(name, &d, &file).assert_whole(name);
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
    let (d, file) = reassembled_record_dissection_with_file(&record);
    total += reread_capture("reassembled record", &d, &file);
    let (d, file) = midsession_fragment_dissection_with_file();
    total += reread_capture("midsession fragments", &d, &file);
    let (d, file) = marked_fragment_dissection_with_file(&[
        (0, true, true, false),
        (1, false, false, false),
        (2, true, false, true),
    ]);
    total += reread_capture("marked fragments", &d, &file);
    let (d, file) = wide_sn_dissection_with_file(&[1, 2, 2, 7, 3, 1 << 40]);
    total += reread_capture("wide sequence numbers", &d, &file);
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
            .flat_map(|f| f.frames.as_slice())
            .chain(d.datagram_flows.iter().flat_map(|f| f.frames.as_slice()));
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
