// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! pcapng (`.pcapng`) file reading.
//!
//! R311y605 — the format wireshark, tshark and dumpcap write BY DEFAULT.
//! [`crate::pcap`] read only classic pcap and named this format in an error
//! (`PcapError::LooksLikePcapNg`), which was the right call while nothing could
//! parse it — a confident misparse is worse than a legible refusal. But it made
//! "open the capture your tool just produced" a hard failure, and the
//! workaround (`editcap -F pcap in.pcapng out.pcap`) is lossy in exactly the
//! places this reader is careful about: it collapses multiple interfaces to
//! one, so it cannot represent a `-i any` capture at all.
//!
//! ## Why this is not a variant of the classic reader
//!
//! Classic pcap has ONE link type and ONE timestamp resolution, both in a
//! 24-byte file header. pcapng has neither:
//!
//! | property | classic pcap | pcapng |
//! |---|---|---|
//! | byte order | whole file | per SECTION |
//! | link type | whole file | per INTERFACE |
//! | timestamp resolution | whole file (from the magic) | per INTERFACE |
//!
//! So a packet's link type and time unit are properties of the interface it
//! arrived on, and the file can carry several. Folding pcapng into
//! [`crate::pcap::PcapFile`] would mean picking one interface's link type and
//! applying it to every packet — which for the common `dumpcap -i any` or
//! two-`-i` capture decapsulates half the file as the wrong link layer. That
//! failure is silent: the wrong link header parses into a plausible IP packet
//! often enough to produce flows.
//!
//! Hence [`Packet`] carries its OWN `link_type` and its OWN resolved
//! timestamp, and [`PcapngFile`] is a list of interfaces plus a list of
//! packets that name one.
//!
//! ## The resolution trap
//!
//! `if_tsresol` (option code 9) is a single byte: the high bit selects base 2
//! or base 10 and the low 7 bits are the negative exponent. Its DEFAULT is 6
//! (microseconds), and an implementation that assumes the default is right on
//! most files and wrong by a factor of 1000 on every tshark capture written
//! with nanosecond resolution — the same class of error
//! [`crate::pcap::Packet::ts_millis`] exists to prevent for the classic magic.
//! So the timestamp is resolved to milliseconds HERE, where the interface's own
//! exponent is in hand.

use alloc::vec::Vec;

/// Section Header Block — starts every section.
const BT_SHB: u32 = 0x0A0D_0D0A;
/// Interface Description Block.
const BT_IDB: u32 = 0x0000_0001;
/// Simple Packet Block — no timestamp, no interface id.
const BT_SPB: u32 = 0x0000_0003;
/// Enhanced Packet Block — the one every modern writer emits.
const BT_EPB: u32 = 0x0000_0006;
/// The obsolete Packet Block, still present in old files.
const BT_PB: u32 = 0x0000_0002;
/// The byte-order magic inside an SHB body.
const BOM: u32 = 0x1A2B_3C4D;
/// `if_tsresol`.
const OPT_IF_TSRESOL: u16 = 9;
/// Smallest legal block: type + length + trailing length.
const MIN_BLOCK_LEN: usize = 12;

/// What went wrong reading a pcapng file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapngError {
    /// Fewer than [`MIN_BLOCK_LEN`] bytes, or a block header that ran past the
    /// end of the file.
    Truncated {
        /// Byte offset the read was attempted at.
        offset: usize,
    },
    /// The file does not begin with a Section Header Block.
    NotPcapng {
        /// The four bytes found instead, read big-endian.
        found: u32,
    },
    /// An SHB's byte-order magic matched neither orientation.
    BadByteOrderMagic {
        /// The raw value.
        found: u32,
    },
    /// A block's length is smaller than the 12 bytes a block cannot be smaller
    /// than, or not a multiple of 4.
    BadBlockLength {
        /// Byte offset of the block.
        offset: usize,
        /// The declared length.
        claimed: u32,
    },
    /// The trailing `block_total_length` did not match the leading one. This
    /// is the format's OWN integrity check — the field is duplicated precisely
    /// so a reader can detect it, and a mismatch means the file cannot be
    /// traversed in either direction with confidence.
    LengthMismatch {
        /// Byte offset of the block.
        offset: usize,
        /// The leading length.
        leading: u32,
        /// The trailing length.
        trailing: u32,
    },
    /// A packet block named an interface no preceding IDB described.
    ///
    /// A hard error rather than a guess: the interface is what carries the link
    /// type, so continuing would mean decapsulating with a link layer nobody
    /// declared.
    UnknownInterface {
        /// Index of the packet in the file.
        index: usize,
        /// The interface id it named.
        interface_id: u32,
    },
    /// A packet block declared more captured bytes than its own block holds.
    BadCapturedLength {
        /// Index of the packet in the file.
        index: usize,
        /// The declared captured length.
        claimed: u32,
        /// Bytes actually available in the block body.
        available: usize,
    },
    /// A Simple Packet Block appeared before any interface was described.
    ///
    /// An SPB carries no interface id and means "interface 0" by definition,
    /// so with no interfaces at all there is no link type for it.
    SimplePacketWithoutInterface {
        /// Index of the packet in the file.
        index: usize,
    },
}

/// One interface an IDB described.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interface {
    /// The `LINKTYPE_*` value — what the first bytes of this interface's
    /// packets are ([`crate::link`]).
    pub link_type: u32,
    /// The raw `if_tsresol` byte, default 6. High bit set selects base 2.
    pub ts_resol: u8,
    /// Snapshot length, 0 when unlimited or unstated.
    pub snaplen: u32,
}

impl Interface {
    /// Default resolution when no `if_tsresol` option is present: microseconds.
    const DEFAULT_TSRESOL: u8 = 6;

    /// Divisor that turns this interface's raw sub-second ticks into
    /// milliseconds, or `None` when the resolution is COARSER than a
    /// millisecond and ticks must be multiplied instead.
    ///
    /// Both directions are real: `if_tsresol` = 3 is milliseconds exactly and
    /// = 0 is whole seconds, which some hardware-timestamped and some
    /// synthetic captures use. A reader that only divided would report every
    /// such packet at time zero within its second.
    fn ticks_per_second(&self) -> u64 {
        let exp = u32::from(self.ts_resol & 0x7F);
        if self.ts_resol & 0x80 != 0 {
            // Base 2. Saturating, because a malformed exponent must not panic
            // and must not wrap into a small divisor.
            1u64.checked_shl(exp).unwrap_or(u64::MAX)
        } else {
            10u64.checked_pow(exp).unwrap_or(u64::MAX)
        }
    }
}

/// One captured packet, carrying the properties classic pcap kept per-FILE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Zero-based index in the file.
    pub index: usize,
    /// The interface this arrived on, as an index into
    /// [`PcapngFile::interfaces`].
    pub interface_id: u32,
    /// The interface's link type, copied here so a consumer never has to hold
    /// both lists to decapsulate one packet.
    pub link_type: u32,
    /// The 64-bit tick count the block carried, in the interface's own unit.
    /// Kept RAW for the same reason [`crate::pcap::Packet::ts_frac`] is: a
    /// consumer that only orders packets should not pay for a conversion.
    pub ts_ticks: u64,
    /// Bytes actually stored.
    pub data: Vec<u8>,
    /// Length the packet had on the wire.
    pub orig_len: u32,
}

impl Packet {
    /// `true` when the capture stored fewer bytes than the wire carried.
    pub fn is_truncated(&self) -> bool {
        (self.data.len() as u32) < self.orig_len
    }

    /// This packet's capture time in MILLISECONDS, resolved against the
    /// interface that recorded it.
    ///
    /// `iface` must be the interface named by [`Self::interface_id`];
    /// [`PcapngFile::ts_millis`] is the safe form that looks it up.
    ///
    /// pcapng timestamps are a single 64-bit tick count since the Unix epoch,
    /// not the seconds/fraction pair classic pcap uses, so there is no
    /// `ts_secs` to expose — the split is a property of the old format rather
    /// than of the data.
    pub fn ts_millis(&self, iface: &Interface) -> u64 {
        let per_sec = iface.ticks_per_second();
        if per_sec >= 1_000 {
            // Finer than a millisecond (the usual case: micro or nano).
            self.ts_ticks / (per_sec / 1_000)
        } else {
            // Coarser: milliseconds per tick, so multiply.
            self.ts_ticks * (1_000 / per_sec.max(1))
        }
    }
}

/// A parsed pcapng file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapngFile {
    /// Every interface described, in the order the IDBs appeared. A packet's
    /// `interface_id` indexes this.
    pub interfaces: Vec<Interface>,
    /// The packets, in file order.
    pub packets: Vec<Packet>,
    /// How many sections the file carried. More than one is legal and means
    /// the byte order and the interface list may both have changed partway
    /// through; surfaced because it is a fact about the capture a consumer may
    /// want to report, not because this reader needs it.
    pub sections: usize,
}

impl PcapngFile {
    /// `packet`'s capture time in milliseconds, resolved against its own
    /// interface. `None` when the id is out of range, which [`parse`] does not
    /// produce — it rejects such a packet — but which a hand-built value can.
    pub fn ts_millis(&self, packet: &Packet) -> Option<u64> {
        self.interfaces
            .get(packet.interface_id as usize)
            .map(|i| packet.ts_millis(i))
    }
}

/// Does this look like a pcapng file? Reads only the first four bytes.
///
/// Separate from [`parse`] so a caller can DISPATCH between the two formats
/// without parsing either, which is what [`crate::Dissection::from_capture`]
/// does.
pub fn looks_like_pcapng(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) == BT_SHB
}

/// Read a `u32` at `off` in the section's byte order.
fn u32_at(b: &[u8], off: usize, swapped: bool) -> u32 {
    let raw = [b[off], b[off + 1], b[off + 2], b[off + 3]];
    if swapped {
        u32::from_be_bytes(raw)
    } else {
        u32::from_le_bytes(raw)
    }
}

/// Read a `u16` at `off` in the section's byte order.
fn u16_at(b: &[u8], off: usize, swapped: bool) -> u16 {
    let raw = [b[off], b[off + 1]];
    if swapped {
        u16::from_be_bytes(raw)
    } else {
        u16::from_le_bytes(raw)
    }
}

/// Scan a block's option list for `if_tsresol`.
///
/// Options are `[code u16][length u16][value padded to 4]`, terminated by code
/// 0 (`opt_endofopt`) or by the end of the block. An absent or malformed list
/// leaves the default — an option list is metadata, and refusing a whole
/// capture over one is the wrong trade.
fn scan_tsresol(body: &[u8], swapped: bool) -> Option<u8> {
    let mut off = 0usize;
    while off + 4 <= body.len() {
        let code = u16_at(body, off, swapped);
        let len = u16_at(body, off + 2, swapped) as usize;
        off += 4;
        if code == 0 {
            return None;
        }
        if off + len > body.len() {
            return None;
        }
        if code == OPT_IF_TSRESOL && len >= 1 {
            return Some(body[off]);
        }
        // Every option's value is padded to a 4-byte boundary.
        off += (len + 3) & !3;
    }
    None
}

/// Parse a whole pcapng file from memory.
///
/// Reads it up front for the same reason [`crate::pcap::parse`] does: flow
/// reassembly wants the whole capture anyway, and a dissection is bounded by
/// the file the user handed over.
///
/// Unknown block types are SKIPPED by their declared length, which is what the
/// format is designed for — name resolution, statistics, decryption-secret and
/// custom blocks all appear in real captures and none of them carries packets.
/// A reader that failed on them would reject most files wireshark writes.
pub fn parse(bytes: &[u8]) -> Result<PcapngFile, PcapngError> {
    if bytes.len() < MIN_BLOCK_LEN {
        return Err(PcapngError::Truncated { offset: 0 });
    }
    let first = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if first != BT_SHB {
        return Err(PcapngError::NotPcapng { found: first });
    }

    let mut interfaces: Vec<Interface> = Vec::new();
    let mut packets: Vec<Packet> = Vec::new();
    let mut sections = 0usize;
    // The byte order of the section currently being read. Set by each SHB;
    // the SHB's own type field is byte-order agnostic (it is a palindrome
    // under swapping by construction), which is why the magic is inside it.
    let mut swapped = false;
    let mut off = 0usize;
    let mut index = 0usize;

    while off < bytes.len() {
        if off + MIN_BLOCK_LEN > bytes.len() {
            return Err(PcapngError::Truncated { offset: off });
        }
        // A block type is read in the section's order, EXCEPT an SHB, whose
        // order is not yet known. `BT_SHB` is `0x0A0D0D0A` — deliberately
        // unchanged by byte swapping — so comparing either reading works.
        let raw_type = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
        let is_shb = u32::from_be_bytes(raw_type) == BT_SHB;
        if is_shb {
            // Read the byte-order magic BEFORE trusting any length in this
            // block: `block_total_length` itself is in the section's order.
            if off + 12 > bytes.len() {
                return Err(PcapngError::Truncated { offset: off });
            }
            let bom_raw = u32::from_le_bytes([
                bytes[off + 8],
                bytes[off + 9],
                bytes[off + 10],
                bytes[off + 11],
            ]);
            swapped = match bom_raw {
                BOM => false,
                x if x == BOM.swap_bytes() => true,
                other => return Err(PcapngError::BadByteOrderMagic { found: other }),
            };
            sections += 1;
            // A new section restarts the interface numbering: ids in the next
            // section index ITS interface list, not the previous one's. Not
            // clearing this would attribute a packet to an interface from a
            // different section, with a link type that may differ.
            interfaces.clear();
        }
        let block_type = u32_at(bytes, off, swapped);
        let total_len = u32_at(bytes, off + 4, swapped);
        if total_len < MIN_BLOCK_LEN as u32 || !total_len.is_multiple_of(4) {
            return Err(PcapngError::BadBlockLength {
                offset: off,
                claimed: total_len,
            });
        }
        let total = total_len as usize;
        if off + total > bytes.len() {
            return Err(PcapngError::Truncated { offset: off });
        }
        let trailing = u32_at(bytes, off + total - 4, swapped);
        if trailing != total_len {
            return Err(PcapngError::LengthMismatch {
                offset: off,
                leading: total_len,
                trailing,
            });
        }
        // The body sits between the leading length and the trailing one.
        let body = &bytes[off + 8..off + total - 4];

        match block_type {
            BT_SHB => {}
            BT_IDB => {
                // linktype u16, reserved u16, snaplen u32, then options.
                if body.len() < 8 {
                    return Err(PcapngError::Truncated { offset: off });
                }
                let link_type = u32::from(u16_at(body, 0, swapped));
                let snaplen = u32_at(body, 4, swapped);
                let ts_resol =
                    scan_tsresol(&body[8..], swapped).unwrap_or(Interface::DEFAULT_TSRESOL);
                interfaces.push(Interface {
                    link_type,
                    ts_resol,
                    snaplen,
                });
            }
            BT_EPB => {
                // interface_id u32, ts_high u32, ts_low u32, captured u32,
                // original u32, then the data padded to 4, then options.
                if body.len() < 20 {
                    return Err(PcapngError::Truncated { offset: off });
                }
                let interface_id = u32_at(body, 0, swapped);
                let ts_high = u64::from(u32_at(body, 4, swapped));
                let ts_low = u64::from(u32_at(body, 8, swapped));
                let captured = u32_at(body, 12, swapped);
                let orig_len = u32_at(body, 16, swapped);
                let available = body.len() - 20;
                if captured as usize > available {
                    return Err(PcapngError::BadCapturedLength {
                        index,
                        claimed: captured,
                        available,
                    });
                }
                let link_type = interfaces
                    .get(interface_id as usize)
                    .ok_or(PcapngError::UnknownInterface {
                        index,
                        interface_id,
                    })?
                    .link_type;
                packets.push(Packet {
                    index,
                    interface_id,
                    link_type,
                    // The two halves are a single 64-bit count, high word
                    // first. Reading them as a seconds/fraction pair — which
                    // the classic layout invites — is wrong by construction.
                    ts_ticks: (ts_high << 32) | ts_low,
                    data: body[20..20 + captured as usize].to_vec(),
                    orig_len,
                });
                index += 1;
            }
            BT_SPB => {
                // original_len u32, then the packet, padded to 4. An SPB has
                // NO captured length of its own: the stored bytes are whatever
                // the block holds, which is the original length unless the
                // capture ran with a snaplen — in which case the block is
                // shorter and the reader must take the block's word for it.
                if body.len() < 4 {
                    return Err(PcapngError::Truncated { offset: off });
                }
                if interfaces.is_empty() {
                    return Err(PcapngError::SimplePacketWithoutInterface { index });
                }
                let orig_len = u32_at(body, 0, swapped);
                let stored = core::cmp::min(orig_len as usize, body.len() - 4);
                packets.push(Packet {
                    index,
                    interface_id: 0,
                    link_type: interfaces[0].link_type,
                    // An SPB carries no timestamp at all. Zero is the only
                    // honest answer, and it is why a capture of SPBs cannot
                    // drive a reassembly deadline.
                    ts_ticks: 0,
                    data: body[4..4 + stored].to_vec(),
                    orig_len,
                });
                index += 1;
            }
            BT_PB => {
                // The obsolete Packet Block: interface_id u16, drops u16, then
                // the same timestamp / lengths / data as an EPB. Read because
                // old captures still carry it and the alternative is skipping
                // every packet in such a file while reporting success.
                if body.len() < 20 {
                    return Err(PcapngError::Truncated { offset: off });
                }
                let interface_id = u32::from(u16_at(body, 0, swapped));
                let ts_high = u64::from(u32_at(body, 4, swapped));
                let ts_low = u64::from(u32_at(body, 8, swapped));
                let captured = u32_at(body, 12, swapped);
                let orig_len = u32_at(body, 16, swapped);
                let available = body.len() - 20;
                if captured as usize > available {
                    return Err(PcapngError::BadCapturedLength {
                        index,
                        claimed: captured,
                        available,
                    });
                }
                let link_type = interfaces
                    .get(interface_id as usize)
                    .ok_or(PcapngError::UnknownInterface {
                        index,
                        interface_id,
                    })?
                    .link_type;
                packets.push(Packet {
                    index,
                    interface_id,
                    link_type,
                    ts_ticks: (ts_high << 32) | ts_low,
                    data: body[20..20 + captured as usize].to_vec(),
                    orig_len,
                });
                index += 1;
            }
            // Name resolution, interface statistics, decryption secrets,
            // custom blocks: skipped by length, which is what the format's
            // self-describing block structure is FOR.
            _ => {}
        }
        off += total;
    }

    Ok(PcapngFile {
        interfaces,
        packets,
        sections,
    })
}

/// Serialise blocks back into a pcapng file — native byte order.
///
/// Present for the same reason [`crate::pcap::write`] is: the reader's only
/// honest fixture is a file, and a hand-typed byte string pins whatever the
/// author believed the layout was. `interfaces` is `(link_type, tsresol)`;
/// each packet is `(interface_id, ts_ticks, data)`.
///
/// The tests pair this with byte-level assertions on what it emits, because a
/// round trip through one author's belief proves only self-consistency.
pub fn write(interfaces: &[(u32, u8)], packets: &[(u32, u64, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    // SHB: type, length, BOM, major, minor, section length (-1 = unknown).
    out.extend_from_slice(&BT_SHB.to_le_bytes());
    out.extend_from_slice(&28u32.to_le_bytes());
    out.extend_from_slice(&BOM.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(-1i64).to_le_bytes());
    out.extend_from_slice(&28u32.to_le_bytes());

    for (link_type, ts_resol) in interfaces {
        // IDB: linktype u16, reserved u16, snaplen u32, one if_tsresol option
        // (code 9, len 1, padded to 4), opt_endofopt, trailing length.
        out.extend_from_slice(&BT_IDB.to_le_bytes());
        out.extend_from_slice(&32u32.to_le_bytes());
        out.extend_from_slice(&(*link_type as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&OPT_IF_TSRESOL.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&[*ts_resol, 0, 0, 0]);
        out.extend_from_slice(&0u16.to_le_bytes()); // opt_endofopt code
        out.extend_from_slice(&0u16.to_le_bytes()); // opt_endofopt length
        out.extend_from_slice(&32u32.to_le_bytes());
    }

    for (iface, ticks, data) in packets {
        let pad = (4 - (data.len() % 4)) % 4;
        let total = 32 + data.len() + pad;
        out.extend_from_slice(&BT_EPB.to_le_bytes());
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(&iface.to_le_bytes());
        out.extend_from_slice(&((ticks >> 32) as u32).to_le_bytes());
        out.extend_from_slice(&(*ticks as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
        out.extend_from_slice(&alloc::vec![0u8; pad]);
        out.extend_from_slice(&(total as u32).to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_written_file_reads_back_with_its_interface_and_timestamp() {
        // if_tsresol = 6, microseconds: 1_500_000 ticks = 1500 ms.
        let file = write(&[(1, 6)], &[(0, 1_500_000, &[0xDE, 0xAD, 0xBE, 0xEF])]);
        let parsed = parse(&file).expect("the writer's own file must read back");
        assert_eq!(parsed.sections, 1);
        assert_eq!(parsed.interfaces.len(), 1);
        assert_eq!(parsed.interfaces[0].link_type, 1);
        assert_eq!(parsed.interfaces[0].ts_resol, 6);
        assert_eq!(parsed.packets.len(), 1);
        assert_eq!(parsed.packets[0].data, alloc::vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(parsed.packets[0].link_type, 1);
        assert_eq!(parsed.ts_millis(&parsed.packets[0]), Some(1_500));
    }

    /// The byte-level half of the pair above: a round trip proves the two
    /// halves agree with each other, not that either agrees with the format.
    #[test]
    fn the_writers_header_is_the_formats_header() {
        let file = write(&[(1, 6)], &[]);
        assert_eq!(&file[0..4], &0x0A0D_0D0Au32.to_le_bytes());
        assert_eq!(&file[4..8], &28u32.to_le_bytes());
        // The byte-order magic, which is what makes the rest readable.
        assert_eq!(&file[8..12], &0x1A2B_3C4Du32.to_le_bytes());
        assert_eq!(&file[12..14], &1u16.to_le_bytes(), "version major");
        // The SHB's trailing length repeats the leading one.
        assert_eq!(&file[24..28], &28u32.to_le_bytes());
        // Then the IDB.
        assert_eq!(&file[28..32], &1u32.to_le_bytes());
    }

    /// THE ONE THAT MATTERS for the per-interface design: two interfaces with
    /// DIFFERENT link types, and each packet must carry its own.
    ///
    /// This is the shape `dumpcap -i any` and any two-`-i` capture produce, and
    /// the shape a single-link-type reader gets silently wrong — the wrong link
    /// header parses into a plausible IP packet often enough to produce flows.
    #[test]
    fn each_packet_carries_its_own_interfaces_link_type() {
        // 1 = LINKTYPE_ETHERNET, 113 = LINKTYPE_LINUX_SLL.
        let file = write(&[(1, 6), (113, 6)], &[(0, 0, &[0xAA]), (1, 0, &[0xBB])]);
        let parsed = parse(&file).expect("parse");
        assert_eq!(parsed.interfaces.len(), 2);
        assert_eq!(parsed.packets[0].link_type, 1);
        assert_eq!(parsed.packets[1].link_type, 113);
        assert_eq!(parsed.packets[0].interface_id, 0);
        assert_eq!(parsed.packets[1].interface_id, 1);
    }

    /// The resolution trap, in both directions from a millisecond.
    ///
    /// The SAME tick count must resolve to three different times under three
    /// declared resolutions. A reader that assumed the default (6) is right on
    /// most files and wrong by 1000x on a nanosecond capture, which is what
    /// `tshark -w` writes when asked for one.
    #[test]
    fn the_interfaces_declared_resolution_decides_the_time() {
        // 2_000_000 ticks: 2 s at microseconds, 2 ms at nanoseconds.
        for (resol, expect_ms) in [(6u8, 2_000u64), (9, 2), (3, 2_000_000)] {
            let file = write(&[(1, resol)], &[(0, 2_000_000, &[0xAA])]);
            let parsed = parse(&file).expect("parse");
            assert_eq!(
                parsed.ts_millis(&parsed.packets[0]),
                Some(expect_ms),
                "if_tsresol {resol} must not be read as the default"
            );
        }
        // Coarser than a millisecond: if_tsresol 0 is whole SECONDS, so ticks
        // are multiplied. A reader that only ever divided would report 0.
        let file = write(&[(1, 0)], &[(0, 7, &[0xAA])]);
        let parsed = parse(&file).expect("parse");
        assert_eq!(parsed.ts_millis(&parsed.packets[0]), Some(7_000));
        // Base 2: the high bit selects it, so 0x80 | 20 is 2^-20 seconds.
        let file = write(&[(1, 0x80 | 20)], &[(0, 1 << 20, &[0xAA])]);
        let parsed = parse(&file).expect("parse");
        assert_eq!(parsed.ts_millis(&parsed.packets[0]), Some(1_000));
    }

    /// The 64-bit timestamp is ONE count, high word first — not the
    /// seconds/fraction pair the classic format uses.
    #[test]
    fn the_timestamp_halves_are_one_64_bit_count() {
        let ticks = (3u64 << 32) | 7;
        let file = write(&[(1, 6)], &[(0, ticks, &[0xAA])]);
        let parsed = parse(&file).expect("parse");
        assert_eq!(parsed.packets[0].ts_ticks, ticks);
        assert_ne!(
            parsed.packets[0].ts_ticks, 3,
            "reading the high word alone as seconds is the classic-format habit"
        );
    }

    /// An unknown block type is SKIPPED by its length, not fatal. Without this
    /// the reader would reject most files wireshark writes, which carry name
    /// resolution and interface statistics blocks.
    #[test]
    fn an_unknown_block_is_skipped_by_its_length() {
        let mut file = write(&[(1, 6)], &[(0, 0, &[0xAA])]);
        // A 16-byte block of an invented type, appended after the packet.
        let mut unknown = Vec::new();
        unknown.extend_from_slice(&0x0000_0BADu32.to_le_bytes());
        unknown.extend_from_slice(&16u32.to_le_bytes());
        // 16 total = type(4) + length(4) + body(4) + trailing length(4).
        unknown.extend_from_slice(&[0xFF; 4]);
        unknown.extend_from_slice(&16u32.to_le_bytes());
        file.extend_from_slice(&unknown);
        // And a second real packet after it, which only a reader that skipped
        // by the declared length can reach.
        let tail = write(&[], &[(0, 0, &[0xBB])]);
        file.extend_from_slice(&tail[28..]);

        let parsed = parse(&file).expect("an unknown block must not be fatal");
        assert_eq!(parsed.packets.len(), 2, "the block after the unknown one");
        assert_eq!(parsed.packets[1].data, alloc::vec![0xBB]);
    }

    /// The trailing length is the format's OWN integrity check. A mismatch is
    /// reported rather than trusted: the field is duplicated precisely so a
    /// reader can detect this, and traversal in either direction is unsafe
    /// once they disagree.
    #[test]
    fn a_trailing_length_that_disagrees_is_reported() {
        let mut file = write(&[(1, 6)], &[(0, 0, &[0xAA])]);
        // The IDB is at 28 and is 32 bytes; its trailing length is its last 4.
        let tail = 28 + 32 - 4;
        file[tail..tail + 4].copy_from_slice(&36u32.to_le_bytes());
        match parse(&file) {
            Err(PcapngError::LengthMismatch {
                leading, trailing, ..
            }) => {
                assert_eq!(leading, 32);
                assert_eq!(trailing, 36);
            }
            other => panic!("expected a length mismatch, got {other:?}"),
        }
    }

    /// A packet naming an interface nobody described is an ERROR, not a guess.
    /// The interface carries the link type, so continuing would decapsulate
    /// with a link layer that was never declared.
    #[test]
    fn a_packet_on_an_undescribed_interface_is_refused() {
        let file = write(&[(1, 6)], &[(3, 0, &[0xAA])]);
        match parse(&file) {
            Err(PcapngError::UnknownInterface {
                index,
                interface_id,
            }) => {
                assert_eq!(index, 0);
                assert_eq!(interface_id, 3);
            }
            other => panic!("expected UnknownInterface, got {other:?}"),
        }
    }

    /// A classic pcap file is not silently read as pcapng.
    #[test]
    fn a_classic_pcap_is_not_pcapng() {
        let classic = crate::pcap::write(1, &[(1, 0, &[0xAA])]);
        assert!(!looks_like_pcapng(&classic));
        assert!(matches!(
            parse(&classic),
            Err(PcapngError::NotPcapng { .. })
        ));
    }

    /// A second SECTION restarts the interface numbering, and may change the
    /// byte order. Not clearing the list would attribute the new section's
    /// packets to the old section's interfaces, whose link type may differ.
    #[test]
    fn a_second_section_restarts_the_interface_list() {
        let mut file = write(&[(1, 6)], &[(0, 0, &[0xAA])]);
        // A whole second section, this one describing a DIFFERENT link type.
        let second = write(&[(113, 6)], &[(0, 0, &[0xBB])]);
        file.extend_from_slice(&second);
        let parsed = parse(&file).expect("parse");
        assert_eq!(parsed.sections, 2);
        assert_eq!(
            parsed.interfaces.len(),
            1,
            "the second section's list replaces the first's"
        );
        assert_eq!(parsed.packets.len(), 2);
        assert_eq!(parsed.packets[0].link_type, 1);
        assert_eq!(
            parsed.packets[1].link_type, 113,
            "the second section's packet must take ITS interface's link type"
        );
    }

    /// A big-endian section is read as such. The BOM is inside the SHB body
    /// precisely because the block type cannot carry the orientation.
    #[test]
    fn a_big_endian_section_is_read_in_its_own_order() {
        let mut file = Vec::new();
        file.extend_from_slice(&BT_SHB.to_be_bytes());
        file.extend_from_slice(&28u32.to_be_bytes());
        file.extend_from_slice(&BOM.to_be_bytes());
        file.extend_from_slice(&1u16.to_be_bytes());
        file.extend_from_slice(&0u16.to_be_bytes());
        file.extend_from_slice(&(-1i64).to_be_bytes());
        file.extend_from_slice(&28u32.to_be_bytes());
        // IDB, big-endian, linktype 113 with if_tsresol 9.
        file.extend_from_slice(&BT_IDB.to_be_bytes());
        file.extend_from_slice(&32u32.to_be_bytes());
        file.extend_from_slice(&113u16.to_be_bytes());
        file.extend_from_slice(&0u16.to_be_bytes());
        file.extend_from_slice(&0u32.to_be_bytes());
        file.extend_from_slice(&OPT_IF_TSRESOL.to_be_bytes());
        file.extend_from_slice(&1u16.to_be_bytes());
        file.extend_from_slice(&[9, 0, 0, 0]);
        file.extend_from_slice(&0u16.to_be_bytes());
        file.extend_from_slice(&0u16.to_be_bytes());
        file.extend_from_slice(&32u32.to_be_bytes());
        // EPB, big-endian, 3_000_000 ns = 3 ms.
        file.extend_from_slice(&BT_EPB.to_be_bytes());
        file.extend_from_slice(&36u32.to_be_bytes());
        file.extend_from_slice(&0u32.to_be_bytes());
        file.extend_from_slice(&0u32.to_be_bytes());
        file.extend_from_slice(&3_000_000u32.to_be_bytes());
        file.extend_from_slice(&2u32.to_be_bytes());
        file.extend_from_slice(&2u32.to_be_bytes());
        file.extend_from_slice(&[0xAA, 0xBB, 0, 0]);
        file.extend_from_slice(&36u32.to_be_bytes());

        let parsed = parse(&file).expect("a big-endian section must read");
        assert_eq!(parsed.interfaces[0].link_type, 113);
        assert_eq!(parsed.interfaces[0].ts_resol, 9);
        assert_eq!(parsed.packets[0].data, alloc::vec![0xAA, 0xBB]);
        assert_eq!(parsed.ts_millis(&parsed.packets[0]), Some(3));
    }

    /// A snaplen-truncated packet is named as such rather than read as
    /// corruption — the same distinction the classic reader makes.
    #[test]
    fn a_truncated_packet_says_so() {
        // Build an EPB by hand so captured < original, which the writer
        // deliberately cannot express.
        let mut file = write(&[(1, 6)], &[]);
        file.extend_from_slice(&BT_EPB.to_le_bytes());
        file.extend_from_slice(&36u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&2u32.to_le_bytes()); // captured
        file.extend_from_slice(&1500u32.to_le_bytes()); // original
        file.extend_from_slice(&[0xAA, 0xBB, 0, 0]);
        file.extend_from_slice(&36u32.to_le_bytes());
        let parsed = parse(&file).expect("parse");
        assert!(parsed.packets[0].is_truncated());
        assert_eq!(parsed.packets[0].data.len(), 2);
        assert_eq!(parsed.packets[0].orig_len, 1500);
    }

    /// A captured length larger than the block that holds it is refused,
    /// rather than read past the block.
    #[test]
    fn a_captured_length_past_the_block_is_refused() {
        let mut file = write(&[(1, 6)], &[]);
        file.extend_from_slice(&BT_EPB.to_le_bytes());
        file.extend_from_slice(&36u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&9999u32.to_le_bytes()); // captured, a lie
        file.extend_from_slice(&9999u32.to_le_bytes());
        file.extend_from_slice(&[0xAA, 0xBB, 0, 0]);
        file.extend_from_slice(&36u32.to_le_bytes());
        assert!(matches!(
            parse(&file),
            Err(PcapngError::BadCapturedLength { claimed: 9999, .. })
        ));
    }

    /// A Simple Packet Block carries no interface id and no timestamp.
    #[test]
    fn a_simple_packet_block_takes_interface_zero_and_no_time() {
        let mut file = write(&[(1, 6)], &[]);
        file.extend_from_slice(&BT_SPB.to_le_bytes());
        file.extend_from_slice(&20u32.to_le_bytes());
        file.extend_from_slice(&4u32.to_le_bytes()); // original length
        file.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        file.extend_from_slice(&20u32.to_le_bytes());
        let parsed = parse(&file).expect("parse");
        assert_eq!(parsed.packets.len(), 1);
        assert_eq!(parsed.packets[0].interface_id, 0);
        assert_eq!(parsed.packets[0].link_type, 1);
        assert_eq!(parsed.packets[0].ts_ticks, 0);
        assert_eq!(parsed.packets[0].data, alloc::vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    /// The obsolete Packet Block still reads. Old captures carry it, and the
    /// alternative is skipping every packet in such a file while reporting
    /// success — a green parse of nothing.
    #[test]
    fn the_obsolete_packet_block_still_reads() {
        let mut file = write(&[(1, 6)], &[]);
        file.extend_from_slice(&BT_PB.to_le_bytes());
        file.extend_from_slice(&36u32.to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes()); // interface_id u16
        file.extend_from_slice(&0u16.to_le_bytes()); // drops
        file.extend_from_slice(&0u32.to_le_bytes()); // ts high
        file.extend_from_slice(&5_000u32.to_le_bytes()); // ts low, 5 ms at us
        file.extend_from_slice(&2u32.to_le_bytes());
        file.extend_from_slice(&2u32.to_le_bytes());
        file.extend_from_slice(&[0xAA, 0xBB, 0, 0]);
        file.extend_from_slice(&36u32.to_le_bytes());
        let parsed = parse(&file).expect("parse");
        assert_eq!(parsed.packets.len(), 1);
        assert_eq!(parsed.packets[0].data, alloc::vec![0xAA, 0xBB]);
        assert_eq!(parsed.ts_millis(&parsed.packets[0]), Some(5));
    }

    /// A block length that is not a multiple of 4, or smaller than a block can
    /// be, is refused instead of advancing the cursor by a nonsense amount.
    #[test]
    fn a_nonsense_block_length_is_refused() {
        let mut file = write(&[(1, 6)], &[]);
        file[4..8].copy_from_slice(&13u32.to_le_bytes());
        assert!(matches!(
            parse(&file),
            Err(PcapngError::BadBlockLength { claimed: 13, .. })
        ));
        let mut file = write(&[(1, 6)], &[]);
        file[4..8].copy_from_slice(&8u32.to_le_bytes());
        assert!(matches!(
            parse(&file),
            Err(PcapngError::BadBlockLength { claimed: 8, .. })
        ));
    }
}
