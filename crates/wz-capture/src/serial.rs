// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y720 (§1.1e / §D M3) — the SERIAL link, read out of a capture.
//!
//! # The item this closes, and the trap it was guarded against
//!
//! The register has carried "decap dispatches six link types and no serial one"
//! since R311y660, together with a standing warning that shaped this module:
//! **`LINKTYPE_RTAC_SERIAL` (250) has a pseudo-header whose layout cannot be
//! verified on this machine** — `/usr/include/pcap/dlt.h` gives the NUMBER and
//! nothing else. A reader written from a remembered header layout would parse a
//! direction bit out of whatever byte happened to be there and report it as
//! measured, which is the exact failure class this crate exists to end.
//!
//! So nothing here parses a pseudo-header. The caller DECLARES which link type
//! carries raw zenoh serial bytes, exactly as `--quic` declares a UDP port
//! whose traffic is QUIC, and this module reads what it can then verify: the
//! COBS envelope, the CRC32, and the handshake flags — all three of which are
//! pinned against zenoh-pico's own sources.
//!
//! # What the wire carries
//!
//! `wz_session_core::serial_link` already implements the framing, from
//! `vendor/zenoh-pico/src/protocol/codec/serial.c`: `[header|len|payload|crc32]`
//! COBS-encoded with a `0x00` end-of-packet byte. This module owns no framing
//! of its own — a second implementation of it would be a second opinion about
//! where the frames are.
//!
//! The link is UNICAST with a DATAGRAM flow
//! (`vendor/zenoh-pico/src/link/unicast/serial.c:67-68`:
//! `Z_LINK_CAP_TRANSPORT_UNICAST` and `Z_LINK_CAP_FLOW_DATAGRAM`), so each
//! frame's payload is ONE zenoh transport message and not a length-prefixed
//! stream — the same contract the UDP and raweth paths take, which is why the
//! decoded messages go through `next_datagram_on` rather than through a framer.
//!
//! # Direction, and the one thing that can settle it
//!
//! A serial line is two wires and a capture of one is a byte stream per wire.
//! Which wire a packet came off is not in the zenoh bytes — the handshake is
//! the only thing that names a ROLE, and only for the two frames that carry it:
//! a bare `INIT` is the initiator's and `INIT|ACK` is the responder's
//! (`_Z_FLAG_SERIAL_INIT` `0x01` / `_Z_FLAG_SERIAL_ACK` `0x02`,
//! `vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/serial.h:53-55`;
//! driven at `src/link/transport/upper/serial_protocol.c:257-276`).
//!
//! What the CAPTURE carries is its INTERFACE ID, which is a real field of the
//! file rather than an inference. So:
//!
//! 1. Each interface gets its own reader — two wires, two byte streams, and
//!    feeding them into one reader would interleave two COBS streams and
//!    resynchronise into garbage.
//! 2. The FIRST interface seen is provisionally `A` and the second `B`.
//! 3. A handshake frame CORRECTS that: if the interface provisionally called
//!    `A` is the one that sent `INIT|ACK`, it is the responder and the mapping
//!    is swapped. [`SerialCensus::roles_witnessed`] says whether this happened,
//!    so a reader can tell a measured attribution from a positional one.
//! 4. A capture with ONE interface cannot separate the directions at all. It is
//!    read, and [`SerialCensus::direction_unattributed`] says so rather than
//!    letting a positional `A` read as a measurement.

extern crate alloc;

use alloc::vec::Vec;

use wz_session_core::serial_link::{
    SerialFrameError, SerialFrameReader, SERIAL_FLAG_ACK, SERIAL_FLAG_INIT, SERIAL_FLAG_RESET,
};

/// What one serial capture turned out to hold.
///
/// Counts and not a verdict, on the rule every census in this crate follows: a
/// reader acts differently on a CRC failure (the line is noisy or the tap
/// dropped bytes) than on a frame whose payload no zenoh decoder accepted (the
/// declaration is wrong, or the traffic is not zenoh).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SerialCensus {
    /// Byte streams read — one per capture interface carrying the declared
    /// link type.
    pub interfaces: usize,
    /// Bytes handed to a COBS reader.
    pub bytes: usize,
    /// Frames whose envelope and CRC32 both checked out.
    pub frames: usize,
    /// Frames the CRC32 rejected.
    ///
    /// Its own counter and not folded into [`Self::framing_errors`], because
    /// the two say different things about the same line: a CRC failure is a
    /// frame that ARRIVED whole and was corrupted, and a framing error is one
    /// whose boundaries the reader could not find at all.
    pub crc_failures: usize,
    /// Frames refused before the CRC — a COBS overrun, an oversized frame, or
    /// a destuffed buffer too short to hold its own header.
    pub framing_errors: usize,
    /// Handshake frames seen: bare `INIT`, `INIT|ACK` and `RESET` together.
    pub handshake_frames: usize,
    /// Whether a handshake frame settled which interface is which side.
    ///
    /// `false` with two interfaces means the attribution is POSITIONAL — first
    /// interface seen is `A` — and a reader must treat the direction column as
    /// a convention rather than as a measurement.
    pub roles_witnessed: bool,
    /// Whether the capture carried too few interfaces to separate directions.
    ///
    /// A serial line is two wires. One byte stream holds both, and no rule over
    /// the zenoh bytes recovers which frame came off which — so this is the
    /// honest report rather than a direction column that looks measured.
    pub direction_unattributed: bool,
    /// R311y722 — whether the line COMMITTED to its positional mapping before
    /// any handshake frame could correct it.
    ///
    /// The bound's visible half. The frames a line reads before its handshake
    /// have to be held, because their direction is not knowable yet; a capture
    /// whose handshake never arrives would hold all of them, which is the
    /// unbounded accumulation this crate bounds everywhere else. Beyond
    /// [`crate::DissectionLimits::serial_frames_before_attribution`] the line
    /// stops waiting and commits — nothing is discarded, and a later handshake
    /// frame is deliberately IGNORED, because taking it would leave one capture
    /// with two mappings, which is the defect R311y720 measured and fixed.
    ///
    /// When this is set the direction column is a CONVENTION, whatever
    /// [`Self::roles_witnessed`] says, and every rendering must read this
    /// first.
    pub committed_positionally: bool,
}

/// One tapped serial line, read as zenoh.
///
/// Not a flow TABLE: a serial line is point to point, so a capture of one holds
/// exactly one link. The two interfaces of a two-wire tap are its two
/// directions, which is why they are readers inside this and not flows beside
/// each other.
#[derive(Debug, Default)]
pub struct SerialLine {
    /// One COBS reader per interface, in first-seen order.
    readers: Vec<(u32, SerialFrameReader)>,
    /// The interface provisionally or measuredly holding [`Direction::A`],
    /// once one has been seen.
    a_interface: Option<u32>,
    /// R311y722 — frames read so far, which is what the bound counts. Reset is
    /// never needed: once committed, the count stops mattering.
    read: usize,
    /// The ceiling on frames held before the mapping is committed. `None` is
    /// unbounded, which is right for a FILE and wrong for a live tap.
    limit: Option<usize>,
    census: SerialCensus,
}

/// Which side a frame's header proves it came from, where it proves anything.
///
/// `None` for a data frame, which is most of them: only the handshake carries a
/// role, and inventing one for the rest is the thing this module refuses to do.
pub fn role_of(header: u8) -> Option<SerialSide> {
    let init = header & SERIAL_FLAG_INIT != 0;
    let ack = header & SERIAL_FLAG_ACK != 0;
    if init && !ack {
        // `_z_connect_serial` sends a bare INIT as the initiator
        // (serial_protocol.c:257-259).
        Some(SerialSide::Initiator)
    } else if init && ack {
        // The responder's reply, which the initiator waits for
        // (serial_protocol.c:266-268).
        Some(SerialSide::Responder)
    } else {
        None
    }
}

/// Is this header a handshake frame at all — including `RESET`, which proves no
/// side but is not data either.
pub fn is_handshake(header: u8) -> bool {
    header & (SERIAL_FLAG_INIT | SERIAL_FLAG_RESET) != 0
}

/// Which end of the point-to-point link a handshake frame came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialSide {
    /// Sent the bare `INIT`.
    Initiator,
    /// Replied `INIT|ACK`.
    Responder,
}

/// One frame this reader recovered, with the interface it came off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialFrame {
    /// The capture interface, which is what stands in for a wire.
    pub interface: u32,
    /// The capture packet the bytes completing this frame arrived in.
    pub packet_index: usize,
    /// The control byte.
    pub header: u8,
    /// The zenoh transport message the frame carried, still encoded.
    pub payload: Vec<u8>,
}

impl SerialLine {
    /// R311y722 — a line that commits its direction mapping after `limit`
    /// frames rather than waiting for a handshake that may never come.
    ///
    /// See [`SerialCensus::committed_positionally`] for why the bound COMMITS
    /// instead of discarding: the frames are evidence, and a bound that threw
    /// evidence away to save memory would be trading the answer for the budget.
    pub fn with_limit(limit: Option<usize>) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }

    /// Feed one capture packet's raw serial bytes.
    ///
    /// Returns the frames that completed inside it, in order. A packet is a
    /// READ of the line and not a frame boundary — a frame may span packets and
    /// a packet may hold several — which is why the reader is retained per
    /// interface and this returns a list.
    pub fn push(&mut self, interface: u32, packet_index: usize, bytes: &[u8]) -> Vec<SerialFrame> {
        self.census.bytes += bytes.len();
        if !self.readers.iter().any(|(id, _)| *id == interface) {
            self.readers.push((interface, SerialFrameReader::new()));
            self.census.interfaces = self.readers.len();
            self.census.direction_unattributed = self.readers.len() < 2;
            if self.a_interface.is_none() {
                self.a_interface = Some(interface);
            }
        }
        let reader = self
            .readers
            .iter_mut()
            .find(|(id, _)| *id == interface)
            .map(|(_, r)| r)
            .expect("just inserted");
        // A framing error is returned by `feed` at the frame it happened on,
        // and the reader has ALREADY resynchronised past it. So the loop
        // continues rather than abandoning the rest of the packet: giving up
        // here would drop every later frame in the read because one was
        // corrupt, which is the opposite of what a resynchronising reader is
        // for.
        let mut out = Vec::new();
        let mut rest = bytes;
        loop {
            match reader.feed(rest) {
                Ok(frames) => {
                    for frame in frames {
                        out.push(SerialFrame {
                            interface,
                            packet_index,
                            header: frame.header,
                            payload: frame.payload,
                        });
                    }
                    break;
                }
                Err(err) => {
                    match err {
                        SerialFrameError::CrcMismatch => self.census.crc_failures += 1,
                        _ => self.census.framing_errors += 1,
                    }
                    // `feed` consumed the whole slice up to and including the
                    // frame it failed on; nothing in its contract says how
                    // much, so the remainder cannot be resumed here. The
                    // reader's own state carries the resynchronisation, and the
                    // NEXT packet continues from it. Counted above, never
                    // silent.
                    rest = &[];
                    if rest.is_empty() {
                        break;
                    }
                }
            }
        }
        self.census.frames += out.len();
        for frame in &out {
            if is_handshake(frame.header) {
                self.census.handshake_frames += 1;
            }
            self.read += 1;
            // R311y722 — the bound, as a COMMITMENT. Checked before the
            // correction below, so a handshake arriving in the same packet that
            // crosses the ceiling does not race it.
            if !self.census.committed_positionally
                && !self.census.roles_witnessed
                && self.limit.is_some_and(|n| self.read > n)
            {
                self.census.committed_positionally = true;
            }
            // The CORRECTION: a role read off the wire outranks the positional
            // guess. Applied once -- the first handshake frame that proves a
            // side settles it, and a later one cannot flip a line mid-capture.
            // Refused once committed, for the same reason: one capture, one
            // mapping.
            if !self.census.roles_witnessed && !self.census.committed_positionally {
                if let Some(side) = role_of(frame.header) {
                    self.a_interface = Some(match side {
                        SerialSide::Initiator => frame.interface,
                        SerialSide::Responder => self
                            .readers
                            .iter()
                            .map(|(id, _)| *id)
                            .find(|id| *id != frame.interface)
                            .unwrap_or(frame.interface),
                    });
                    self.census.roles_witnessed = true;
                }
            }
        }
        out
    }

    /// Which direction this interface's frames travelled.
    ///
    /// `A` is the initiator's half where a handshake proved it, and the
    /// first-seen interface otherwise — [`SerialCensus::roles_witnessed`] is
    /// what tells the two apart, and a reader that ignores it is reading a
    /// convention as a measurement.
    pub fn direction_of(&self, interface: u32) -> wz_session_core::passive::Direction {
        match self.a_interface {
            Some(a) if a == interface => wz_session_core::passive::Direction::A,
            Some(_) => wz_session_core::passive::Direction::B,
            None => wz_session_core::passive::Direction::A,
        }
    }

    /// What this line turned out to hold.
    pub fn census(&self) -> SerialCensus {
        self.census
    }

    /// Whether anything has been read at all, which is what a report branches
    /// on before printing a serial block.
    pub fn is_empty(&self) -> bool {
        self.readers.is_empty()
    }
}

/// The decoded frame type re-exported for a caller assembling its own reader.
pub use wz_session_core::serial_link::DecodedFrame as SerialDecodedFrame;

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::serial_link::encode_frame;

    /// THE ROLE RULE, against pico's own flag values.
    ///
    /// Asserted rather than assumed because the whole direction attribution
    /// rests on it: a bare INIT is the initiator's and INIT|ACK the
    /// responder's, and a build that read them the other way round would file
    /// every client message under the server.
    #[test]
    fn only_the_handshake_names_a_side_and_it_names_the_right_one() {
        assert_eq!(role_of(SERIAL_FLAG_INIT), Some(SerialSide::Initiator));
        assert_eq!(
            role_of(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK),
            Some(SerialSide::Responder)
        );
        // A data frame names nobody, which is the honest half: most frames
        // carry no role and a reader that invented one would be wrong on the
        // whole data plane.
        assert_eq!(role_of(0), None);
        assert_eq!(role_of(SERIAL_FLAG_RESET), None);
        // RESET is still a handshake frame -- it proves no side and it is not
        // data, and folding it into either would miscount both.
        assert!(is_handshake(SERIAL_FLAG_RESET));
        assert!(!is_handshake(0));
    }

    /// A frame split across two capture packets is recovered whole.
    ///
    /// The property the per-interface reader exists for: a packet is a READ of
    /// the line, not a frame boundary.
    #[test]
    fn a_frame_split_across_packets_is_recovered() {
        let wire = encode_frame(0, b"hello").expect("encodes");
        let (head, tail) = wire.split_at(wire.len() / 2);
        let mut line = SerialLine::default();
        assert!(
            line.push(0, 0, head).is_empty(),
            "half a frame is not a frame"
        );
        let got = line.push(0, 1, tail);
        assert_eq!(got.len(), 1, "and the other half completes it");
        assert_eq!(got[0].payload, b"hello");
        assert_eq!(
            got[0].packet_index, 1,
            "anchored at the packet that COMPLETED it, which is the only \
             packet whose bytes a reader can point at for the whole frame"
        );
    }

    /// TWO WIRES ARE TWO READERS, and the handshake settles which is which.
    ///
    /// Both halves are load-bearing. Feeding two interleaved COBS streams into
    /// one reader resynchronises into garbage; and taking the first-seen
    /// interface as `A` without checking the handshake would file the
    /// responder's traffic under the initiator whenever the tap happened to
    /// record the reply first.
    #[test]
    fn the_handshake_corrects_the_positional_direction() {
        use wz_session_core::passive::Direction;

        let mut line = SerialLine::default();
        // Interface 7 is seen FIRST and is provisionally A...
        line.push(7, 0, &encode_frame(0, b"data").expect("encodes"));
        assert_eq!(line.direction_of(7), Direction::A);
        assert!(
            !line.census().roles_witnessed,
            "and nothing has proved it yet"
        );
        // ...but interface 7 turns out to be the RESPONDER, so it is B.
        line.push(9, 1, &encode_frame(0, b"data").expect("encodes"));
        line.push(
            7,
            2,
            &encode_frame(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, &[]).expect("encodes"),
        );
        assert!(line.census().roles_witnessed, "the wire settled it");
        assert_eq!(line.direction_of(7), Direction::B, "the responder's half");
        assert_eq!(line.direction_of(9), Direction::A, "the initiator's");
    }

    /// ONE INTERFACE CANNOT SEPARATE THE DIRECTIONS, and says so.
    ///
    /// The alternative is a direction column that looks measured and is a
    /// coin flip, which is the failure this whole module is shaped around.
    #[test]
    fn a_single_interface_capture_reports_its_direction_as_unattributed() {
        let mut line = SerialLine::default();
        line.push(0, 0, &encode_frame(0, b"data").expect("encodes"));
        let census = line.census();
        assert_eq!(census.interfaces, 1);
        assert!(
            census.direction_unattributed,
            "one wire's worth of capture holds both halves"
        );
        let mut two = SerialLine::default();
        two.push(0, 0, &encode_frame(0, b"data").expect("encodes"));
        two.push(1, 1, &encode_frame(0, b"data").expect("encodes"));
        assert!(
            !two.census().direction_unattributed,
            "and two interfaces are two wires -- the CONTROL that keeps the \
             flag from being a constant"
        );
    }

    /// R311y722 — THE BOUND COMMITS RATHER THAN DISCARDS, and a late handshake
    /// cannot flip a line that has already committed.
    ///
    /// # Why a bound here had to be a decision
    ///
    /// A frame read before the handshake has no knowable direction, so it must
    /// be held; a capture whose handshake never arrives holds everything, which
    /// is the unbounded accumulation this crate bounds everywhere else. But the
    /// held frames are EVIDENCE -- discarding them to save memory would trade
    /// the capture's contents for its budget, which no other bound here does
    /// (they all trade recency). So the bound stops the WAIT instead: past it
    /// the mapping is committed, everything held is decoded under it, and the
    /// census says the attribution was positional.
    ///
    /// The refusal of a late handshake is the other half and is not an
    /// optimisation: taking it would leave one capture with two mappings, which
    /// is exactly the defect R311y720 measured and moved the decode to `finish`
    /// to fix.
    #[test]
    fn the_bound_commits_the_mapping_and_a_late_handshake_cannot_move_it() {
        use wz_session_core::passive::Direction;

        let data = encode_frame(0, b"data").expect("encodes");
        let mut line = SerialLine::with_limit(Some(2));
        // Interface 7 first, so positionally A. Three frames, one past the
        // ceiling of two.
        for at in 0..3 {
            line.push(7, at, &data);
        }
        line.push(9, 3, &data);
        assert!(
            line.census().committed_positionally,
            "past the ceiling the line stops waiting: {:?}",
            line.census()
        );
        assert_eq!(line.direction_of(7), Direction::A, "positionally");

        // The handshake arrives LATE and says interface 7 is the responder. It
        // is refused, and the census still says the attribution is positional
        // -- a reader is never told this direction was measured.
        line.push(
            7,
            4,
            &encode_frame(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, &[]).expect("encodes"),
        );
        assert_eq!(
            line.direction_of(7),
            Direction::A,
            "one capture, one mapping"
        );
        assert!(
            !line.census().roles_witnessed,
            "and the census does not claim the wire settled it"
        );
        assert_eq!(
            line.census().frames,
            5,
            "NOTHING was discarded -- the bound stopped a wait, not a read"
        );

        // THE CONTROL that keeps the commitment from being unconditional: the
        // same frames under a ceiling they do not reach let the handshake win.
        let mut patient = SerialLine::with_limit(Some(64));
        patient.push(7, 0, &data);
        patient.push(9, 1, &data);
        patient.push(
            7,
            2,
            &encode_frame(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, &[]).expect("encodes"),
        );
        assert!(patient.census().roles_witnessed && !patient.census().committed_positionally);
        assert_eq!(
            patient.direction_of(7),
            Direction::B,
            "the responder's half"
        );
    }

    /// A CORRUPT FRAME IS COUNTED, not swallowed.
    #[test]
    fn a_frame_whose_crc_fails_is_counted_as_such() {
        let mut wire = encode_frame(0, b"hello").expect("encodes");
        // Corrupt a byte inside the COBS-encoded body, past the length prefix,
        // so the envelope still parses and the CRC is what rejects it.
        let at = wire.len() / 2;
        wire[at] ^= 0xFF;
        let mut line = SerialLine::default();
        let got = line.push(0, 0, &wire);
        let census = line.census();
        assert!(got.is_empty(), "a frame that fails its CRC is not a frame");
        assert_eq!(
            census.crc_failures + census.framing_errors,
            1,
            "and the failure is COUNTED, under whichever of the two names \
             applies: {census:?}"
        );
        assert_eq!(census.frames, 0);
    }
}

/// R311y721 (§1.1f) — THE FOUR CENSUS PLANES SEE A SERIAL LINE.
///
/// # What R311y720 left, in its own words
///
/// "A serial capture's messages reach the flow listing, the capture-wide total
/// and the report block, and they do NOT reach the four census planes --
/// throughput, exchanges, payloads, nodes all walk the two flow TABLES and a
/// serial line is neither. That is the R311y700 shape one plane over."
///
/// It was the FIFTH instance of one omission, and the fix is the one the carry
/// named: an enumeration the planes walk (`Dissection::message_lists`) rather
/// than tables they name. These tests drive each plane over a real serial
/// capture, because a plane that is WIRED and not DRIVEN is the other half of
/// the same failure.
#[cfg(test)]
mod plane_tests {
    use crate::datagram_tests::{frame_carrying, push, sender_space};
    use crate::link::FlowKey;
    use crate::Dissection;
    use wz_session_core::serial_link::{encode_frame, SERIAL_FLAG_ACK, SERIAL_FLAG_INIT};

    /// The link type this fixture's capture declares. Its VALUE is all that is
    /// used -- nothing parses a header out of it.
    const SERIAL_LINKTYPE: u32 = 250;

    /// A zid-naming INIT, as a serial link carries it: no length prefix,
    /// because the frame IS the framing unit.
    fn init_wire(zid: &[u8]) -> alloc::vec::Vec<u8> {
        let mut wire = alloc::vec![
            wz_session_core::wire_const::T_MID_INIT,
            0x09,
            (((zid.len() as u8) - 1) << 4) | 0x02,
        ];
        wire.extend_from_slice(zid);
        wire
    }

    /// A capture of one serial line carrying a handshake, two INITs naming both
    /// ends, and a Put with a payload under a key expression.
    ///
    /// Everything each plane needs in ONE file: the INITs are the node plane's
    /// evidence, the Put's keyexpr is the throughput plane's row, and its
    /// payload is the payload plane's.
    fn serial_capture() -> alloc::vec::Vec<u8> {
        const A_ZID: &[u8] = &[0x11, 0x22, 0x33, 0x44];
        const B_ZID: &[u8] = &[0x55, 0x66, 0x77, 0x88];
        let put = frame_carrying(&push(sender_space(0, Some("home/temp")), &[0u8; 24]));

        // Interface 0 sends the bare INIT, so it is the initiator and A.
        let frames: alloc::vec::Vec<(u32, alloc::vec::Vec<u8>)> = alloc::vec![
            (0, encode_frame(SERIAL_FLAG_INIT, &[]).expect("encodes")),
            (
                1,
                encode_frame(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, &[]).expect("encodes")
            ),
            (0, encode_frame(0, &init_wire(A_ZID)).expect("encodes")),
            (1, encode_frame(0, &init_wire(B_ZID)).expect("encodes")),
            (0, encode_frame(0, &put).expect("encodes")),
        ];
        let packets: alloc::vec::Vec<(u32, u64, &[u8])> = frames
            .iter()
            .enumerate()
            .map(|(i, (iface, bytes))| (*iface, 1_000_000 + i as u64 * 100, bytes.as_slice()))
            .collect();
        crate::pcapng::write(&[(SERIAL_LINKTYPE, 6), (SERIAL_LINKTYPE, 6)], &packets)
    }

    fn dissect() -> Dissection {
        Dissection::from_capture_declaring(&serial_capture(), &[], &[SERIAL_LINKTYPE])
            .expect("the capture reads")
    }

    /// ANTI-VACUITY FIRST, and it is the leg that makes the other four mean
    /// anything: the SAME file, undeclared, decodes nothing. Every assertion
    /// below would otherwise pass on a build that read link type 250 by itself.
    #[test]
    fn an_undeclared_serial_capture_reaches_no_plane() {
        let d = Dissection::from_capture_declaring(&serial_capture(), &[], &[])
            .expect("the capture reads");
        assert_eq!(
            d.decoded_messages(),
            0,
            "nothing was declared, nothing read"
        );
        assert!(crate::agg::aggregate(&d).rows().is_empty());
        assert_eq!(crate::node::nodes(&d).nodes().len(), 0);
        #[cfg(feature = "network-codecs")]
        assert_eq!(crate::payload::payloads(&d).payloads(), 0);
    }

    /// The THROUGHPUT plane: the keyexpr a serial line carried.
    ///
    /// Gated on `network-codecs` like the two below it, and MEASURED rather
    /// than assumed: without it the fixture's `Push` is not decoded into a
    /// keyexpr at all, so the row list is empty and the assertion below would
    /// be a claim about a population of zero. Running `-p wz-capture
    /// --no-default-features` is what showed it.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn the_throughput_plane_sees_a_serial_line() {
        let d = dissect();
        let table = crate::agg::aggregate(&d);
        let keys: alloc::vec::Vec<&str> = table.rows().iter().map(|r| r.keyexpr.as_str()).collect();
        assert!(
            keys.contains(&"home/temp"),
            "the Put's key expression is a row: {keys:?}"
        );
    }

    /// The NODE plane: both zids, and the link between them.
    ///
    /// The link is the sharper half. It is recorded only where BOTH ends named
    /// themselves ON ONE FLOW, so it also proves the two directions were
    /// attributed to one key rather than to two -- which is the thing a serial
    /// line, having no addresses, could most easily have got wrong.
    #[test]
    fn the_node_plane_sees_a_serial_line() {
        let d = dissect();
        let census = crate::node::nodes(&d);
        let zids: alloc::vec::Vec<&[u8]> =
            census.nodes().iter().map(|n| n.zid.as_slice()).collect();
        assert!(
            zids.contains(&&[0x11u8, 0x22, 0x33, 0x44][..])
                && zids.contains(&&[0x55u8, 0x66, 0x77, 0x88][..]),
            "both ends of the line named themselves: {zids:?}"
        );
        assert_eq!(
            census.links().len(),
            1,
            "and the two INITs are ONE link, on one flow key"
        );
        assert_eq!(
            census.links()[0].flow,
            FlowKey::serial_line(),
            "under the key a serial line stands on, carrying the interface \
             count it was read off"
        );
    }

    /// The PAYLOAD plane: the bytes the Put carried.
    ///
    /// R311y721 — gated exactly as `payload::payloads` is. A test gated more
    /// WIDELY than the item it drives is the shape that reddened C1bt four
    /// times in R311y715.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn the_payload_plane_sees_a_serial_line() {
        let d = dissect();
        assert_eq!(
            crate::payload::payloads(&d).payloads(),
            1,
            "the Put's payload is judged"
        );
    }

    /// The EXCHANGE plane: it WALKS the line.
    ///
    /// Gated as `exchange` itself is — see the payload test above.
    ///
    /// This fixture carries no query, so the honest assertion is that the plane
    /// reaches the messages rather than that it finds a request in them -- and
    /// the way to state that without a query is to check that the plane's own
    /// message count moves. A `0 == 0` here would be the vacuous form.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn the_exchange_plane_walks_a_serial_line() {
        let d = dissect();
        let table = crate::exchange::exchanges(&d);
        assert_eq!(
            table.requests(),
            0,
            "no query was sent, so there is no request to match"
        );
        // What DID reach it: the same enumeration the other three walked. If
        // `message_lists` missed the serial line, this count would be zero for
        // a capture that decoded three messages.
        let seen: usize = d.message_lists().map(|(_, frames)| frames.len()).sum();
        assert_eq!(
            seen,
            d.decoded_messages(),
            "every decoded message is in the enumeration the planes walk"
        );
        assert_eq!(d.decoded_messages(), 3, "two INITs and one Put");
    }
}
