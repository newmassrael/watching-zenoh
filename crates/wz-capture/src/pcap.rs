// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Classic libpcap (`.pcap`) file reading.
//!
//! The format is a 24-byte file header followed by per-packet
//! `[16-byte record header][captured bytes]`. Four magic values are in
//! circulation and all four are accepted here, because a capture handed to a
//! dissector was written by whatever tool the reporter had:
//!
//! | magic        | byte order | timestamp unit |
//! |--------------|------------|----------------|
//! | `0xa1b2c3d4` | native     | microseconds   |
//! | `0xd4c3b2a1` | swapped    | microseconds   |
//! | `0xa1b23c4d` | native     | nanoseconds    |
//! | `0x4d3cb2a1` | swapped    | nanoseconds    |
//!
//! (`pcap-savefile(5)`; the nanosecond magics are the `0x3c4d` variant
//! libpcap 1.5 introduced.)
//!
//! **pcapng is not read here** — it is read by [`crate::pcapng`] (R311y605),
//! because it is a different, block-structured format whose byte order, link
//! type and timestamp resolution are all per-SECTION or per-INTERFACE rather
//! than per-file. Accepting its magic while parsing it as classic pcap would
//! produce confident nonsense, so [`PcapError::LooksLikePcapNg`] still names it
//! explicitly here and the failure stays legible rather than "bad magic".
//! [`crate::Dissection::from_capture`] is the entry point that dispatches
//! between the two on the magic.

use alloc::vec::Vec;

/// Classic pcap file-header length.
const FILE_HEADER_LEN: usize = 24;
/// Per-packet record-header length.
const RECORD_HEADER_LEN: usize = 16;

/// pcapng's Section Header Block type, the first four bytes of any pcapng
/// file. Recognised only to produce a better error.
const PCAPNG_SHB: u32 = 0x0A0D_0D0A;

/// What went wrong reading a capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapError {
    /// Fewer than `FILE_HEADER_LEN` bytes.
    TruncatedFileHeader,
    /// The magic matched none of the four classic variants.
    BadMagic(u32),
    /// The file is pcapng, which this reader does not parse.
    LooksLikePcapNg,
    /// A record header ran past the end of the file.
    TruncatedRecordHeader {
        /// Index of the record that could not be read.
        index: usize,
    },
    /// A record's captured length ran past the end of the file.
    TruncatedRecord {
        /// Index of the record that could not be read.
        index: usize,
        /// The captured length the header claimed.
        claimed: usize,
        /// How many bytes were actually left.
        available: usize,
    },
}

/// Timestamp resolution declared by the file magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampUnit {
    /// `0xa1b2c3d4` family.
    Microseconds,
    /// `0xa1b23c4d` family.
    Nanoseconds,
}

/// One captured packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Zero-based index in the file — the anchor a decoded message is
    /// ultimately reported against.
    pub index: usize,
    /// Seconds since the Unix epoch.
    pub ts_secs: u32,
    /// Sub-second part, in the unit the file header declared. Kept RAW
    /// rather than normalised so a consumer that only orders packets never
    /// pays for a conversion, and one that prints them knows the precision it
    /// actually has.
    pub ts_frac: u32,
    /// Bytes actually stored. Shorter than `orig_len` when the capture ran
    /// with a snaplen — the truncation a dissector must expect.
    pub data: Vec<u8>,
    /// Length the packet had on the wire.
    pub orig_len: u32,
}

impl Packet {
    /// `true` when the capture stored fewer bytes than the wire carried.
    /// A decode failure on such a packet is a snaplen artefact, not
    /// corruption, and the two must not be reported the same way.
    pub fn is_truncated(&self) -> bool {
        (self.data.len() as u32) < self.orig_len
    }

    /// R311y594 — this packet's capture time in MILLISECONDS, the unit
    /// `wz_session_core::passive::PassiveSession::observe_at` and
    /// `ReassemblyConfig::reassembly_timeout_ms` already speak.
    ///
    /// Converting HERE, where the file's declared unit is in hand, rather than
    /// exporting the raw pair and letting each consumer scale it: `ts_frac` is
    /// microseconds or nanoseconds depending on the file's MAGIC, so a consumer
    /// that assumed either would be right on half the corpus and quietly wrong
    /// on the other — a factor of 1000 in a deadline, which reads as "chains
    /// never expire" or "everything expires".
    ///
    /// Epoch-based rather than capture-relative, because it feeds a monotonic
    /// clock whose ORIGIN is irrelevant and whose DIFFERENCES are not. The
    /// `u64` holds the Unix epoch in milliseconds until well past year 500
    /// million.
    pub fn ts_millis(&self, unit: TimestampUnit) -> u64 {
        let sub_ms = match unit {
            TimestampUnit::Microseconds => u64::from(self.ts_frac) / 1_000,
            TimestampUnit::Nanoseconds => u64::from(self.ts_frac) / 1_000_000,
        };
        u64::from(self.ts_secs) * 1_000 + sub_ms
    }
}

/// A parsed classic pcap file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapFile {
    /// The `LINKTYPE_*` value from the file header — what the first bytes of
    /// each packet are ([`crate::link`]).
    pub link_type: u32,
    /// Timestamp resolution.
    pub timestamp_unit: TimestampUnit,
    /// The packets, in file order.
    pub packets: Vec<Packet>,
}

/// R2373 (open-debt item 661) — why a walk over a classic pcap stopped.
///
/// The counterpart of [`crate::pcapng::Halt`], and it carries the same
/// distinction for the same reason: a record header cut in half is TRUNCATION
/// in a file that will never grow and merely an UNFINISHED write in one that
/// is still being appended to. The bytes cannot tell the two apart; the caller
/// can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Halt {
    /// Every byte handed over was consumed; the walk ended on a record
    /// boundary.
    Complete,
    /// A partial record — or not yet a whole file header — remains. The error
    /// is the one a FINAL container would have raised, carried rather than
    /// raised so the caller decides.
    Partial(PcapError),
}

/// R2373 (open-debt item 661) — a RESUMABLE walk over a classic pcap
/// container.
///
/// See [`crate::pcapng::PcapngCursor`] for why this shape exists at all. This
/// one is the simpler half: a classic pcap declares its link type and
/// timestamp unit ONCE, in a 24-byte header, and then repeats a fixed record
/// header. So the only state a resumption needs is that header's three facts,
/// the byte offset, and the packet index — but it needs them for the same
/// reason, and [`parse`] runs this same walk so the two cannot part.
#[derive(Debug, Clone)]
pub struct PcapCursor {
    /// The file header's three facts, once it has arrived.
    header: Option<FileHeader>,
    /// How far into the container complete records have been consumed.
    consumed: usize,
    /// The index the next packet will carry.
    index: usize,
}

/// What a classic pcap's 24-byte file header declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileHeader {
    swapped: bool,
    timestamp_unit: TimestampUnit,
    link_type: u32,
}

impl Default for PcapCursor {
    fn default() -> Self {
        Self::new()
    }
}

impl PcapCursor {
    /// A walk positioned at the start of a container.
    pub fn new() -> Self {
        Self {
            header: None,
            consumed: 0,
            index: 0,
        }
    }

    /// How many bytes of the container have been consumed as COMPLETE records.
    pub fn consumed(&self) -> usize {
        self.consumed
    }

    /// How many packets have been produced.
    pub fn packets_produced(&self) -> usize {
        self.index
    }

    /// The link type the file header declared, or `None` before it arrived.
    pub fn link_type(&self) -> Option<u32> {
        self.header.map(|h| h.link_type)
    }

    /// The timestamp unit the magic declared, or `None` before it arrived.
    pub fn timestamp_unit(&self) -> Option<TimestampUnit> {
        self.header.map(|h| h.timestamp_unit)
    }

    /// Walk every record that is COMPLETE in `bytes` beyond
    /// [`Self::consumed`], handing each to `on`.
    ///
    /// `bytes` is the container from offset zero. A malformed magic is an
    /// error; a header or record that is merely not all there yet is
    /// [`Halt::Partial`].
    ///
    /// The sink is handed the file header's LINK TYPE and TIMESTAMP UNIT with
    /// every packet, rather than being told to read them off the cursor
    /// afterwards. A streaming consumer has no afterwards, and the two facts
    /// are per-FILE in this format and per-packet in the other one — so the
    /// sink that serves both takes them the same way.
    pub fn advance<F>(&mut self, bytes: &[u8], mut on: F) -> Result<Halt, PcapError>
    where
        F: FnMut(u32, TimestampUnit, Packet),
    {
        let header = match self.header {
            Some(h) => h,
            None => {
                // A pcapng SHB is not a bad classic pcap, it is the OTHER
                // format, and four bytes settle it. Below four, a container
                // still being written has said nothing yet.
                if bytes.len() < 4 {
                    return Ok(Halt::Partial(PcapError::TruncatedFileHeader));
                }
                let be_magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                if be_magic == PCAPNG_SHB {
                    return Err(PcapError::LooksLikePcapNg);
                }
                // The whole header before the magic is JUDGED, which is the
                // order `parse` has always answered in: a short file reports
                // truncation rather than a verdict on bytes it does not have
                // all of. A follower loses nothing by it — the same bad magic
                // is refused as soon as the twenty-fourth byte lands.
                if bytes.len() < FILE_HEADER_LEN {
                    return Ok(Halt::Partial(PcapError::TruncatedFileHeader));
                }
                let le_magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                let (swapped, timestamp_unit) = match le_magic {
                    0xa1b2_c3d4 => (false, TimestampUnit::Microseconds),
                    0xd4c3_b2a1 => (true, TimestampUnit::Microseconds),
                    0xa1b2_3c4d => (false, TimestampUnit::Nanoseconds),
                    0x4d3c_b2a1 => (true, TimestampUnit::Nanoseconds),
                    other => return Err(PcapError::BadMagic(other)),
                };
                let raw = [bytes[20], bytes[21], bytes[22], bytes[23]];
                let link_type = if swapped {
                    u32::from_be_bytes(raw)
                } else {
                    u32::from_le_bytes(raw)
                };
                let h = FileHeader {
                    swapped,
                    timestamp_unit,
                    link_type,
                };
                self.header = Some(h);
                self.consumed = FILE_HEADER_LEN;
                h
            }
        };
        if bytes.len() < self.consumed {
            return Ok(Halt::Partial(PcapError::TruncatedRecordHeader {
                index: self.index,
            }));
        }
        let u32_at = |b: &[u8], off: usize| -> u32 {
            let raw = [b[off], b[off + 1], b[off + 2], b[off + 3]];
            if header.swapped {
                u32::from_be_bytes(raw)
            } else {
                u32::from_le_bytes(raw)
            }
        };

        let mut off = self.consumed;
        while off < bytes.len() {
            if off + RECORD_HEADER_LEN > bytes.len() {
                self.consumed = off;
                return Ok(Halt::Partial(PcapError::TruncatedRecordHeader {
                    index: self.index,
                }));
            }
            let ts_secs = u32_at(bytes, off);
            let ts_frac = u32_at(bytes, off + 4);
            let incl_len = u32_at(bytes, off + 8) as usize;
            let orig_len = u32_at(bytes, off + 12);
            let body = off + RECORD_HEADER_LEN;
            let available = bytes.len() - body;
            if incl_len > available {
                // The record's own header says how long it is and the
                // container does not hold that much YET. `self.consumed` stays
                // at the record's START so the next, longer prefix reads it
                // whole rather than resuming inside it.
                self.consumed = off;
                return Ok(Halt::Partial(PcapError::TruncatedRecord {
                    index: self.index,
                    claimed: incl_len,
                    available,
                }));
            }
            on(
                header.link_type,
                header.timestamp_unit,
                Packet {
                    index: self.index,
                    ts_secs,
                    ts_frac,
                    data: bytes[body..body + incl_len].to_vec(),
                    orig_len,
                },
            );
            off = body + incl_len;
            self.consumed = off;
            self.index += 1;
        }
        Ok(Halt::Complete)
    }
}

/// Parse a whole classic pcap file from memory.
///
/// Reads the entire capture up front rather than streaming it. That is the
/// right trade for this layer: flow reassembly needs random-ish access across
/// the file anyway, and a dissection session is bounded by the capture the
/// user handed it. A streaming reader for live sources belongs beside the
/// live source, not here.
///
/// R2373 (open-debt item 661) — the record walk moved to [`PcapCursor`] and
/// this is one of its two callers, so the reader of a GROWING container is the
/// same reader rather than a second one.
pub fn parse(bytes: &[u8]) -> Result<PcapFile, PcapError> {
    let mut cursor = PcapCursor::new();
    let mut packets = Vec::new();
    let halt = cursor.advance(bytes, |_, _, p| packets.push(p))?;
    // A FILE does not grow, so the tail a follower would wait for is this
    // reader's truncation.
    if let Halt::Partial(e) = halt {
        return Err(e);
    }
    let (link_type, timestamp_unit) = (
        cursor.link_type().expect("a complete walk read the header"),
        cursor
            .timestamp_unit()
            .expect("a complete walk read the header"),
    );
    Ok(PcapFile {
        link_type,
        timestamp_unit,
        packets,
    })
}

/// Serialise packets back into a classic pcap file — native byte order,
/// microsecond timestamps.
///
/// Present because the reader's only honest test fixture is a file, and a
/// hand-typed byte string would pin whatever the author believed the layout
/// was. Building the file with this writer and reading it back with
/// [`parse`] is a round trip over ONE author's belief, so the tests pair it
/// with byte-level assertions on the header the writer emits.
pub fn write(link_type: u32, packets: &[(u32, u32, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes()); // version major
    out.extend_from_slice(&4u16.to_le_bytes()); // version minor
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&262_144u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&link_type.to_le_bytes());
    for (secs, frac, data) in packets {
        out.extend_from_slice(&secs.to_le_bytes());
        out.extend_from_slice(&frac.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The file header the writer emits, asserted BYTE BY BYTE against
    /// `pcap-savefile(5)` rather than against the reader. Without this the
    /// round trip below would only prove the two halves agree with each
    /// other — including on a layout that no other tool shares.
    #[test]
    fn the_written_file_header_matches_the_documented_layout() {
        let file = write(1, &[]);
        assert_eq!(
            file.len(),
            FILE_HEADER_LEN,
            "an empty capture is header-only"
        );
        assert_eq!(&file[0..4], &[0xd4, 0xc3, 0xb2, 0xa1], "LE 0xa1b2c3d4");
        assert_eq!(&file[4..6], &[0x02, 0x00], "version major 2");
        assert_eq!(&file[6..8], &[0x04, 0x00], "version minor 4");
        assert_eq!(&file[8..12], &[0, 0, 0, 0], "thiszone");
        assert_eq!(&file[12..16], &[0, 0, 0, 0], "sigfigs");
        assert_eq!(
            &file[20..24],
            &[0x01, 0x00, 0x00, 0x00],
            "linktype 1 = EN10MB"
        );
    }

    /// Round trip: two packets in, two packets out, with the fields intact.
    #[test]
    fn packets_round_trip() {
        let file = write(1, &[(7, 500, b"first"), (8, 600, b"second")]);
        let parsed = parse(&file).expect("parse");
        assert_eq!(parsed.link_type, 1);
        assert_eq!(parsed.timestamp_unit, TimestampUnit::Microseconds);
        assert_eq!(parsed.packets.len(), 2);
        assert_eq!(parsed.packets[0].index, 0);
        assert_eq!(parsed.packets[0].ts_secs, 7);
        assert_eq!(parsed.packets[0].ts_frac, 500);
        assert_eq!(parsed.packets[0].data, b"first");
        assert_eq!(parsed.packets[1].index, 1);
        assert_eq!(parsed.packets[1].data, b"second");
        assert!(!parsed.packets[0].is_truncated());
    }

    /// A BYTE-SWAPPED file reads identically. The fixture is the native file
    /// with its magic and every u32 flipped, so the assertion is that the
    /// reader's endianness handling is real and not a coincidence of the
    /// writer's.
    #[test]
    fn a_byte_swapped_file_reads_the_same() {
        let native = write(1, &[(7, 500, b"first")]);
        let mut swapped = native.clone();
        // File header: magic, then two u16s, then three u32s, then linktype.
        swapped[0..4].reverse();
        swapped[4..6].reverse();
        swapped[6..8].reverse();
        for range in [8..12, 12..16, 16..20, 20..24] {
            swapped[range].reverse();
        }
        // The one record header's four u32s.
        for i in 0..4 {
            let at = FILE_HEADER_LEN + i * 4;
            swapped[at..at + 4].reverse();
        }
        let parsed = parse(&swapped).expect("swapped parse");
        assert_eq!(parsed.link_type, 1);
        assert_eq!(parsed.packets.len(), 1);
        assert_eq!(parsed.packets[0].ts_secs, 7);
        assert_eq!(parsed.packets[0].ts_frac, 500);
        assert_eq!(parsed.packets[0].data, b"first");
    }

    /// The nanosecond magics are recognised as such rather than rejected —
    /// a capture written by libpcap >= 1.5 with `-tt` precision is an
    /// ordinary file, and reading it as microseconds would silently rescale
    /// every timestamp by 1000.
    #[test]
    fn nanosecond_magics_declare_their_unit() {
        let mut file = write(1, &[(1, 2, b"x")]);
        file[0..4].copy_from_slice(&0xa1b2_3c4du32.to_le_bytes());
        assert_eq!(
            parse(&file).expect("ns parse").timestamp_unit,
            TimestampUnit::Nanoseconds
        );
    }

    /// pcapng is named, not mistaken for a bad magic. A dissector that says
    /// "bad magic" for the commonest modern capture format sends its user
    /// looking in the wrong place.
    #[test]
    fn pcapng_is_diagnosed_by_name() {
        let shb = [0x0A, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0];
        assert_eq!(parse(&shb), Err(PcapError::LooksLikePcapNg));
    }

    /// Truncation is reported with enough detail to act on, at both levels:
    /// a record header cut in half, and a record whose payload was cut.
    #[test]
    fn truncation_is_reported_with_its_index() {
        let full = write(1, &[(1, 1, b"aaaa"), (2, 2, b"bbbb")]);
        // Cut inside the SECOND record's header.
        let cut = &full[..FILE_HEADER_LEN + RECORD_HEADER_LEN + 4 + 8];
        assert_eq!(
            parse(cut),
            Err(PcapError::TruncatedRecordHeader { index: 1 })
        );
        // Cut inside the second record's payload.
        let cut = &full[..full.len() - 1];
        assert_eq!(
            parse(cut),
            Err(PcapError::TruncatedRecord {
                index: 1,
                claimed: 4,
                available: 3
            })
        );
    }

    /// A snaplen-truncated packet is FLAGGED, because a downstream decode
    /// failure on one is the capture's fault and not the wire's.
    #[test]
    fn a_snaplen_truncated_packet_is_flagged() {
        let mut file = write(1, &[(1, 1, b"abc")]);
        // Raise orig_len past incl_len, as a snaplen capture would.
        let orig_len_at = FILE_HEADER_LEN + 12;
        file[orig_len_at..orig_len_at + 4].copy_from_slice(&99u32.to_le_bytes());
        let parsed = parse(&file).expect("parse");
        assert!(parsed.packets[0].is_truncated());
        assert_eq!(parsed.packets[0].orig_len, 99);
        assert_eq!(parsed.packets[0].data.len(), 3);
    }

    /// An unrecognised magic reports the value it saw.
    #[test]
    fn a_foreign_magic_reports_itself() {
        let mut file = write(1, &[]);
        file[0..4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        assert_eq!(parse(&file), Err(PcapError::BadMagic(0xdead_beef)));
    }

    /// R2373 (open-debt item 661) — a cursor fed the container in TWO PIECES
    /// reads exactly what [`parse`] reads in one, at every cut.
    ///
    /// The classic format's counterpart of the pcapng sweep, and it is here for
    /// the same reason: [`parse`] is now one of this walk's two callers, so a
    /// difference between resuming and reading whole is a difference between
    /// every door built on either.
    ///
    /// The population is the file's own length, including the offsets inside
    /// the 24-byte header — a prefix that is not yet a whole file header is the
    /// first window a writer ever presents, and it must be legal.
    #[test]
    fn a_cursor_fed_in_two_pieces_reads_what_parse_reads_in_one() {
        let file = write(
            1,
            &[
                (1, 500_000, &[1, 2, 3][..]),
                (2, 250_000, &[4, 5][..]),
                (3, 0, &[6, 7, 8, 9][..]),
            ],
        );
        let whole = parse(&file).expect("the fixture reads");
        assert_eq!(whole.packets.len(), 3);

        let cuts: Vec<usize> = (0..=file.len()).collect();
        assert!(cuts.len() > 1, "the population must not be empty");
        let mut mid_record = 0usize;
        let mut before_the_header = 0usize;

        for cut in cuts {
            let mut cursor = PcapCursor::new();
            let mut packets: Vec<Packet> = Vec::new();
            let mut sink = |_: u32, _: TimestampUnit, p: Packet| packets.push(p);
            cursor
                .advance(&file[..cut], &mut sink)
                .expect("a prefix of a good file is never malformed");
            assert!(cursor.consumed() <= cut);
            if cursor.consumed() == 0 && cut > 0 {
                before_the_header += 1;
            } else if cursor.consumed() < cut {
                mid_record += 1;
            }
            let halt = cursor.advance(&file, &mut sink).expect("the whole reads");
            assert_eq!(halt, Halt::Complete);
            assert_eq!(cursor.consumed(), file.len());
            assert_eq!(
                packets, whole.packets,
                "the file split at byte {cut} read differently from the same \
                 file read whole"
            );
        }
        assert!(
            before_the_header > 0,
            "no cut of this fixture landed inside the file header"
        );
        assert!(
            mid_record > 0,
            "no cut of this fixture landed inside a record, so resumption was \
             never exercised"
        );
    }
}
