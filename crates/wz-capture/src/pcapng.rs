// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
/// Interface Statistics Block — what the CAPTURE TOOL counted, including the
/// packets it never handed anyone.
const BT_ISB: u32 = 0x0000_0005;
/// Decryption Secrets Block — the KEYS, carried in the capture file itself.
///
/// R311y625 (§1.4d) — named because its silence was the costliest of the three
/// this reader skips. §8.1 records that wz cannot read its own encrypted
/// traffic; a file with a DSB in it is one where the material to do so is
/// PRESENT and this build walked past it. Reporting "encrypted, unreadable"
/// about such a file is a true statement about the reader and a false one about
/// the capture.
const BT_DSB: u32 = 0x0000_000A;

/// R311y659 (§1.2a) — the most Decryption Secrets Block payload this reader
/// retains, across every DSB in a file.
///
/// A key log is text and a long-running process writes a large one, so this is
/// the one accumulation in this parser that grows with the file's CONTENT
/// rather than with its packet count. 1 MiB is roughly 8 000 TLS 1.3
/// connections' worth of lines -- far past any capture a person opens -- and it
/// is a bound rather than a policy: what is dropped is reported through
/// [`DecryptionSecrets::truncated`] rather than being silently short.
pub const MAX_DECRYPTION_SECRETS_BYTES: usize = 1024 * 1024;
/// Name Resolution Block — address-to-name records this reader does not use.
const BT_NRB: u32 = 0x0000_0004;
/// The byte-order magic inside an SHB body.
const BOM: u32 = 0x1A2B_3C4D;
/// `if_tsresol`.
const OPT_IF_TSRESOL: u16 = 9;
/// `isb_ifrecv` — packets the interface RECEIVED over the capture.
const OPT_ISB_IFRECV: u16 = 4;
/// `isb_ifdrop` — packets the capture tool DROPPED and nobody ever saw.
const OPT_ISB_IFDROP: u16 = 5;
/// Smallest legal block: type + length + trailing length.
const MIN_BLOCK_LEN: usize = 12;

/// What went wrong reading a pcapng file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapngError {
    /// Fewer than `MIN_BLOCK_LEN` bytes, or a block header that ran past the
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
    /// The 64-bit tick count the block carried, in the interface's own unit,
    /// or `None` for a block that carried NO timestamp at all.
    ///
    /// Kept RAW for the same reason [`crate::pcap::Packet::ts_frac`] is: a
    /// consumer that only orders packets should not pay for a conversion.
    ///
    /// R311y625 (§1.4d) — an `Option`, and it used to be a `u64` that a Simple
    /// Packet Block filled with `0` under a comment calling zero "the only
    /// honest answer". It is the opposite: an SPB carries no time, and `0` is a
    /// PLAUSIBLE one. It travelled — `from_pcapng` handed `Some(0)` to
    /// `push_packet_at`, which SET the observer's clock, and R311y624 pinned
    /// that clock as STICKY, so every later frame in an SPB capture reported an
    /// instant nobody recorded. A reader asking `time > 0` got a confident No
    /// and a latency came out as 0 ms.
    pub ts_ticks: Option<u64>,
    /// R2373 (open-debt item 661) — [`Self::ts_ticks`] already put through the
    /// `if_tsresol` of the interface that recorded it, at the moment the block
    /// was read.
    ///
    /// Stored rather than resolved on demand because a SECTION BOUNDARY clears
    /// the interface list: a reader that resolved afterwards, from the
    /// interfaces a file ENDED with, would put an early packet's ticks through
    /// a later section's resolution and be wrong by a factor of a thousand.
    /// [`PcapngFile::ts_millis`] did exactly that until this field existed, and
    /// it is the one fact a follower of a growing container could not have
    /// agreed with [`parse`] about — the follower has no "afterwards".
    pub ts_millis: Option<u64>,
    /// Bytes actually stored.
    pub data: Vec<u8>,
    /// Length the packet had on the wire.
    pub orig_len: u32,
}

impl Packet {
    /// One packet, with its capture time resolved against `iface` HERE, where
    /// the interface that recorded it is still in hand.
    ///
    /// The one constructor the walk uses, so the three block types that carry a
    /// packet cannot resolve it three ways.
    fn resolved(
        index: usize,
        interface_id: u32,
        iface: &Interface,
        ts_ticks: Option<u64>,
        data: Vec<u8>,
        orig_len: u32,
    ) -> Self {
        let mut packet = Self {
            index,
            interface_id,
            link_type: iface.link_type,
            ts_ticks,
            ts_millis: None,
            data,
            orig_len,
        };
        packet.ts_millis = packet.resolve_ts_millis(iface);
        packet
    }

    /// `true` when the capture stored fewer bytes than the wire carried.
    pub fn is_truncated(&self) -> bool {
        (self.data.len() as u32) < self.orig_len
    }

    /// This packet's capture time in MILLISECONDS, resolved against the
    /// interface that recorded it.
    ///
    /// `iface` must be the interface named by [`Self::interface_id`]. Callers
    /// reading a parsed file want [`Self::ts_millis`], which is this answer
    /// already computed against the right section's interface;
    /// [`PcapngFile::ts_millis`] is the same value through the file.
    ///
    /// pcapng timestamps are a single 64-bit tick count since the Unix epoch,
    /// not the seconds/fraction pair classic pcap uses, so there is no
    /// `ts_secs` to expose — the split is a property of the old format rather
    /// than of the data.
    pub fn resolve_ts_millis(&self, iface: &Interface) -> Option<u64> {
        let ticks = self.ts_ticks?;
        let per_sec = iface.ticks_per_second();
        Some(if per_sec >= 1_000 {
            // Finer than a millisecond (the usual case: micro or nano).
            ticks / (per_sec / 1_000)
        } else {
            // Coarser: milliseconds per tick, so multiply.
            ticks * (1_000 / per_sec.max(1))
        })
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
    /// R311y607 — every Interface Statistics Block, in file order. Empty when
    /// the writer emitted none, which is ordinary: an ISB is optional and its
    /// absence says nothing either way about whether packets were lost.
    pub interface_stats: Vec<InterfaceStats>,
    /// R311y625 (§1.4d) — block types this reader walked past, with a count
    /// each, in first-seen order.
    ///
    /// The format is self-describing precisely so an unknown block can be
    /// stepped over, and stepping over one silently is a different thing from
    /// stepping over one and saying so. [`Self::carries_decryption_secrets`] is
    /// the case that motivated this.
    pub skipped_blocks: Vec<SkippedBlock>,
    /// R311y658 (§1.2a) — the Decryption Secrets Blocks' payloads, in
    /// first-seen order. Empty for a file that carried none.
    pub decryption_secrets: Vec<DecryptionSecrets>,
}

/// R311y658 (§1.2a) — one Decryption Secrets Block's payload, KEPT.
///
/// R311y625 counted these blocks and dropped their bytes, which made the file's
/// own answer to "can this capture be read" unreachable: the keys were in the
/// capture, the reader knew a DSB was there, and it walked past the material.
///
/// The bytes are handed on UNPARSED. `secrets_type` says what they are (RFC
/// draft-tuexen-opsawg-pcapng §4.7 registers `0x544c534b`, `"TLSK"`, for an NSS
/// key log), and reading them is TLS vocabulary that does not belong in a file
/// parser -- `wz-tls-record::keylog` is where that lives, on the far side of the
/// same seam the cipher went over.
#[derive(Clone, PartialEq, Eq)]
pub struct DecryptionSecrets {
    /// The registered secrets type word, in host order.
    pub secrets_type: u32,
    /// The block's secrets data, exactly as the file carried it.
    pub secrets: Vec<u8>,
    /// R311y659 — `true` when this reader kept less than the block held,
    /// because [`MAX_DECRYPTION_SECRETS_BYTES`] was reached.
    ///
    /// Its own flag rather than a comparison a caller could make, because a
    /// caller cannot: the bytes it did not get are the evidence it would need.
    /// A key log cut in the middle parses to FEWER connections with no error,
    /// which is the silent shortfall this crate refuses everywhere else.
    pub truncated: bool,
}

impl core::fmt::Debug for DecryptionSecrets {
    /// Prints the TYPE and the LENGTH and never the bytes. A capture tool that
    /// spilled key material into a log would be worse than one that could not
    /// read it at all.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DecryptionSecrets")
            .field("secrets_type", &format_args!("{:#010x}", self.secrets_type))
            .field("secrets", &format_args!("<{} byte(s)>", self.secrets.len()))
            .field("truncated", &self.truncated)
            .finish()
    }
}

/// R311y625 (§1.4d) — one block type this reader stepped over, and how often.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkippedBlock {
    /// The pcapng block type word.
    pub block_type: u32,
    /// How many blocks of that type the file carried.
    pub count: usize,
}

impl PcapngFile {
    /// R311y625 (§1.4d) — how many Decryption Secrets Blocks the file carried
    /// and this reader did not use.
    ///
    /// Its own accessor rather than a lookup a caller writes, because it is the
    /// one skipped type whose presence CHANGES WHAT A REPORT MEANS: §8.1
    /// records that wz cannot decrypt its own TLS traffic, and a file carrying
    /// a DSB is one where the keys were in the capture. "Encrypted and
    /// unreadable" is then true of this build and false of the file.
    pub fn carries_decryption_secrets(&self) -> usize {
        self.skipped_blocks
            .iter()
            .find(|s| s.block_type == BT_DSB)
            .map_or(0, |s| s.count)
    }

    /// R311y625 — Name Resolution Blocks stepped over.
    pub fn carries_name_resolution(&self) -> usize {
        self.skipped_blocks
            .iter()
            .find(|s| s.block_type == BT_NRB)
            .map_or(0, |s| s.count)
    }

    /// `packet`'s capture time in milliseconds, resolved against its own
    /// interface. `None` for a block that carried no timestamp at all.
    ///
    /// R2373 (open-debt item 661) — reads [`Packet::ts_millis`], which the walk
    /// resolved when the block was read. It used to look the interface up in
    /// [`Self::interfaces`] HERE, which holds the LAST section's list: on a
    /// multi-section capture that put a first-section packet's ticks through a
    /// last-section `if_tsresol`. The bug was found while building the
    /// follower, which cannot resolve afterwards and so had to be given the
    /// answer the file's own reader would give.
    pub fn ts_millis(&self, packet: &Packet) -> Option<u64> {
        packet.ts_millis
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

/// R311y607 — read one u64 option out of an option list.
///
/// Separate from [`scan_tsresol`] rather than generalised over it, because the
/// two disagree on width for a reason: `if_tsresol` is ONE byte and the ISB
/// counters are eight, and a shared helper would have to guess. Length is
/// checked exactly: a writer that emitted a 4-byte counter is not silently
/// zero-extended into a number a reader would then quote.
fn scan_u64_option(body: &[u8], swapped: bool, want: u16) -> Option<u64> {
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
        if code == want && len == 8 {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&body[off..off + 8]);
            return Some(if swapped {
                u64::from_be_bytes(raw)
            } else {
                u64::from_le_bytes(raw)
            });
        }
        off += (len + 3) & !3;
    }
    None
}

/// R311y607 — what the CAPTURE TOOL said about one interface, as opposed to
/// what this reader observed.
///
/// The distinction is the whole point. `wz-capture` counts what IT drops (its
/// own caps, its own expiries) and reports that in [`crate::DissectionDrops`].
/// It has no way to count what never reached the file: a `dumpcap` whose
/// kernel ring overflowed writes an `isb_ifdrop` and hands over a capture with
/// a HOLE in it. Read from a stream, that hole desynchronises the assembler
/// and every message after it is lost — and until this block was read, the
/// only available explanation was "the dissector is broken".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceStats {
    /// Which interface these counters describe, indexing
    /// [`PcapngFile::interfaces`].
    pub interface_id: u32,
    /// `isb_ifrecv`: packets the interface saw. `None` when unstated — which
    /// is different from zero, and a reader that conflated them would report a
    /// dead interface for a writer that simply omits the option.
    pub received: Option<u64>,
    /// `isb_ifdrop`: packets the capture tool dropped. `None` when unstated.
    pub dropped: Option<u64>,
}

/// R2373 (open-debt item 661) — one thing a walk over a pcapng container
/// produced.
///
/// Handed to the walk's sink by value rather than accumulated inside
/// [`PcapngCursor`], because the two callers want opposite things with it:
/// [`parse`] collects every packet into a [`PcapngFile`], and a FOLLOWER of a
/// growing container pushes each one into a dissection and drops it. A cursor
/// that accumulated would make the second one grow without bound for no reason
/// but the first one's convenience.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcapngYield {
    /// A packet block, with its capture time ALREADY resolved against the
    /// interface list as of that block. See [`Packet::ts_millis`].
    Packet(Packet),
    /// A Decryption Secrets Block's payload.
    Secrets(DecryptionSecrets),
    /// An Interface Statistics Block's counters.
    Stats(InterfaceStats),
    /// The obsolete Packet Block's per-block drop count, which is an INCREMENT
    /// rather than a total. Yielded only when non-zero, because a zero must not
    /// manufacture an [`InterfaceStats`] row the file never carried.
    PacketBlockDrops {
        /// Which interface lost them.
        interface_id: u32,
        /// How many, since the previous packet on that interface.
        dropped: u64,
    },
}

/// R2373 (open-debt item 661) — why a walk stopped.
///
/// The distinction this type carries is the whole reason a growing container
/// can be read at all: a prefix that ends in the middle of a block is
/// TRUNCATED for a file that will never grow and merely UNFINISHED for one
/// still being written. The bytes are identical; only the caller knows which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Halt {
    /// Every byte handed over was consumed; the walk ended on a block boundary.
    Complete,
    /// A partial block remains at the end. The error is the one a FINAL
    /// container would have raised, CARRIED rather than raised so the caller
    /// decides — [`parse`] raises it, a follower waits for more bytes.
    Partial(PcapngError),
}

/// R2373 (open-debt item 661) — a RESUMABLE walk over a pcapng container.
///
/// # Why this exists rather than a second parser
///
/// [`parse`] reads a whole file, and a capture still being WRITTEN has no
/// whole. Until this type existed, a consumer holding a growing pcapng had two
/// options and both are worse than they look: re-parse the whole prefix every
/// window, which restarts every counter and coordinate the reader hands out; or
/// open the container itself, which is the second reader of the format that
/// `wz_dissect_pcap_replay`'s own header paragraph forbids by name.
///
/// So the walk became the SSOT and [`parse`] became one of its two callers. The
/// two cannot disagree about where a block ends, what an unknown block type
/// costs, or which section's `if_tsresol` a packet's ticks go through, because
/// there is one walk and both run it.
///
/// # What it holds across calls
///
/// Everything a block's meaning depends on that an EARLIER block established:
/// the section's byte order, its interface list (cleared at each new section,
/// exactly as [`parse`] always did), the packet index, and the accumulation
/// budget for Decryption Secrets Blocks — which is a cap on the FILE and would
/// be re-spent from zero by any per-window re-parse.
#[derive(Debug, Clone)]
pub struct PcapngCursor {
    /// The interfaces of the section being read. Cleared by each SHB.
    interfaces: Vec<Interface>,
    /// Block types walked past, with a count each, in first-seen order.
    skipped: Vec<SkippedBlock>,
    /// Decryption-secret bytes retained so far, against
    /// [`MAX_DECRYPTION_SECRETS_BYTES`].
    dsb_bytes: usize,
    /// How many sections have begun.
    sections: usize,
    /// Byte order of the section being read.
    swapped: bool,
    /// How far into the container complete blocks have been consumed.
    consumed: usize,
    /// The index the next packet will carry.
    index: usize,
}

impl Default for PcapngCursor {
    fn default() -> Self {
        Self::new()
    }
}

impl PcapngCursor {
    /// A walk positioned at the start of a container.
    pub fn new() -> Self {
        Self {
            interfaces: Vec::new(),
            skipped: Vec::new(),
            dsb_bytes: 0,
            sections: 0,
            // The byte order of the section currently being read. Set by each
            // SHB; the SHB's own type field is byte-order agnostic (it is a
            // palindrome under swapping by construction), which is why the
            // magic is inside it.
            swapped: false,
            consumed: 0,
            index: 0,
        }
    }

    /// How many bytes of the container have been consumed as COMPLETE blocks.
    ///
    /// A follower hands over the whole prefix it has on every call; this is
    /// what tells the walk where to resume, and it is the reason a message
    /// split across two windows is decoded exactly once.
    pub fn consumed(&self) -> usize {
        self.consumed
    }

    /// How many packets have been produced, which is the index the next one
    /// will carry.
    pub fn packets_produced(&self) -> usize {
        self.index
    }

    /// How many sections have begun.
    pub fn sections(&self) -> usize {
        self.sections
    }

    /// The interfaces of the section currently being read.
    pub fn interfaces(&self) -> &[Interface] {
        &self.interfaces
    }

    /// Block types this walk stepped over, with a count each.
    pub fn skipped_blocks(&self) -> &[SkippedBlock] {
        &self.skipped
    }

    /// Walk every block that is COMPLETE in `bytes` beyond [`Self::consumed`],
    /// handing each result to `on`.
    ///
    /// `bytes` is the container from offset zero — the whole prefix, not the
    /// new tail. A pcapng suffix is not a container (it has no SHB and no IDB),
    /// so a caller handing over only new bytes would have to splice a header
    /// on, and a consumer that writes pcapng headers is a second WRITER as
    /// surely as one that parses them is a second reader.
    ///
    /// A malformed block is an error and leaves the cursor at that block's
    /// start. A block that is merely INCOMPLETE is [`Halt::Partial`], and the
    /// same cursor takes the longer prefix on the next call.
    ///
    /// A `bytes` shorter than [`Self::consumed`] — a container that SHRANK,
    /// which is a caller error — consumes nothing and reports
    /// [`Halt::Partial`]. Only the caller can tell a shrink from a slow writer,
    /// so only the caller can name it; [`crate::FollowError::Shrank`] is where
    /// that is done.
    pub fn advance<F>(&mut self, bytes: &[u8], mut on: F) -> Result<Halt, PcapngError>
    where
        F: FnMut(PcapngYield),
    {
        if self.consumed == 0 {
            // The magic, before any length in the file is trusted. Fewer than
            // four bytes is not yet WRONG on a container still being written,
            // so it waits rather than failing.
            if bytes.len() < 4 {
                return Ok(Halt::Partial(PcapngError::Truncated { offset: 0 }));
            }
            let first = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            if first != BT_SHB {
                return Err(PcapngError::NotPcapng { found: first });
            }
        }
        if bytes.len() < self.consumed {
            return Ok(Halt::Partial(PcapngError::Truncated {
                offset: bytes.len(),
            }));
        }

        let mut off = self.consumed;
        while off < bytes.len() {
            if off + MIN_BLOCK_LEN > bytes.len() {
                self.consumed = off;
                return Ok(Halt::Partial(PcapngError::Truncated { offset: off }));
            }
            // A block type is read in the section's order, EXCEPT an SHB, whose
            // order is not yet known. `BT_SHB` is `0x0A0D0D0A` — deliberately
            // unchanged by byte swapping — so comparing either reading works.
            let raw_type = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
            let is_shb = u32::from_be_bytes(raw_type) == BT_SHB;
            if is_shb {
                // Read the byte-order magic BEFORE trusting any length in this
                // block: `block_total_length` itself is in the section's order.
                // The `MIN_BLOCK_LEN` guard above already secured these twelve
                // bytes, which is why there is no second length check here.
                let bom_raw = u32::from_le_bytes([
                    bytes[off + 8],
                    bytes[off + 9],
                    bytes[off + 10],
                    bytes[off + 11],
                ]);
                self.swapped = match bom_raw {
                    BOM => false,
                    x if x == BOM.swap_bytes() => true,
                    other => {
                        self.consumed = off;
                        return Err(PcapngError::BadByteOrderMagic { found: other });
                    }
                };
            }
            let swapped = self.swapped;
            let block_type = u32_at(bytes, off, swapped);
            let total_len = u32_at(bytes, off + 4, swapped);
            if total_len < MIN_BLOCK_LEN as u32 || !total_len.is_multiple_of(4) {
                self.consumed = off;
                return Err(PcapngError::BadBlockLength {
                    offset: off,
                    claimed: total_len,
                });
            }
            let total = total_len as usize;
            if off + total > bytes.len() {
                // The block's own header says how long it is and the container
                // does not hold that much YET. This is the case this type
                // exists for, and the one place a growing capture differs from
                // a damaged one.
                self.consumed = off;
                return Ok(Halt::Partial(PcapngError::Truncated { offset: off }));
            }
            let trailing = u32_at(bytes, off + total - 4, swapped);
            if trailing != total_len {
                self.consumed = off;
                return Err(PcapngError::LengthMismatch {
                    offset: off,
                    leading: total_len,
                    trailing,
                });
            }
            // The body sits between the leading length and the trailing one.
            let body = &bytes[off + 8..off + total - 4];

            // From here the block is COMPLETE, so every remaining failure is a
            // malformed block rather than a short container. `self.consumed` is
            // left at `off` on each, so a caller that swallows the error and
            // hands over more bytes cannot resume half way into a block.
            match block_type {
                BT_SHB => {
                    self.sections += 1;
                    // A new section restarts the interface numbering: ids in
                    // the next section index ITS interface list, not the
                    // previous one's. Not clearing this would attribute a
                    // packet to an interface from a different section, with a
                    // link type that may differ.
                    self.interfaces.clear();
                }
                BT_IDB => {
                    // linktype u16, reserved u16, snaplen u32, then options.
                    if body.len() < 8 {
                        self.consumed = off;
                        return Err(PcapngError::Truncated { offset: off });
                    }
                    let link_type = u32::from(u16_at(body, 0, swapped));
                    let snaplen = u32_at(body, 4, swapped);
                    let ts_resol =
                        scan_tsresol(&body[8..], swapped).unwrap_or(Interface::DEFAULT_TSRESOL);
                    self.interfaces.push(Interface {
                        link_type,
                        ts_resol,
                        snaplen,
                    });
                }
                BT_EPB => {
                    // interface_id u32, ts_high u32, ts_low u32, captured u32,
                    // original u32, then the data padded to 4, then options.
                    if body.len() < 20 {
                        self.consumed = off;
                        return Err(PcapngError::Truncated { offset: off });
                    }
                    let interface_id = u32_at(body, 0, swapped);
                    let ts_high = u64::from(u32_at(body, 4, swapped));
                    let ts_low = u64::from(u32_at(body, 8, swapped));
                    let captured = u32_at(body, 12, swapped);
                    let orig_len = u32_at(body, 16, swapped);
                    let available = body.len() - 20;
                    if captured as usize > available {
                        self.consumed = off;
                        return Err(PcapngError::BadCapturedLength {
                            index: self.index,
                            claimed: captured,
                            available,
                        });
                    }
                    let Some(iface) = self.interfaces.get(interface_id as usize).copied() else {
                        self.consumed = off;
                        return Err(PcapngError::UnknownInterface {
                            index: self.index,
                            interface_id,
                        });
                    };
                    on(PcapngYield::Packet(Packet::resolved(
                        self.index,
                        interface_id,
                        &iface,
                        // The two halves are a single 64-bit count, high word
                        // first. Reading them as a seconds/fraction pair — which
                        // the classic layout invites — is wrong by construction.
                        Some((ts_high << 32) | ts_low),
                        body[20..20 + captured as usize].to_vec(),
                        orig_len,
                    )));
                    self.index += 1;
                }
                BT_SPB => {
                    // original_len u32, then the packet, padded to 4. An SPB has
                    // NO captured length of its own: the stored bytes are whatever
                    // the block holds, which is the original length unless the
                    // capture ran with a snaplen — in which case the block is
                    // shorter and the reader must take the block's word for it.
                    if body.len() < 4 {
                        self.consumed = off;
                        return Err(PcapngError::Truncated { offset: off });
                    }
                    let Some(iface) = self.interfaces.first().copied() else {
                        self.consumed = off;
                        return Err(PcapngError::SimplePacketWithoutInterface {
                            index: self.index,
                        });
                    };
                    let orig_len = u32_at(body, 0, swapped);
                    let stored = core::cmp::min(orig_len as usize, body.len() - 4);
                    on(PcapngYield::Packet(Packet::resolved(
                        self.index,
                        0,
                        &iface,
                        // An SPB carries no timestamp at all, and the ABSENCE is
                        // what travels rather than a plausible zero (R311y625).
                        None,
                        body[4..4 + stored].to_vec(),
                        orig_len,
                    )));
                    self.index += 1;
                }
                BT_PB => {
                    // The obsolete Packet Block: interface_id u16, drops u16, then
                    // the same timestamp / lengths / data as an EPB. Read because
                    // old captures still carry it and the alternative is skipping
                    // every packet in such a file while reporting success.
                    if body.len() < 20 {
                        self.consumed = off;
                        return Err(PcapngError::Truncated { offset: off });
                    }
                    let interface_id = u32::from(u16_at(body, 0, swapped));
                    // R311y607 — the PB's own drop counter, which this reader used
                    // to step over. It counts packets lost BETWEEN this packet and
                    // the previous one on the same interface, so it is a per-block
                    // increment rather than a total: accumulated into the same
                    // place an ISB's `isb_ifdrop` lands, because a consumer asking
                    // "did the capture tool lose anything" must not have to know
                    // which block type the writer chose.
                    let block_drops = u64::from(u16_at(body, 2, swapped));
                    let ts_high = u64::from(u32_at(body, 4, swapped));
                    let ts_low = u64::from(u32_at(body, 8, swapped));
                    let captured = u32_at(body, 12, swapped);
                    let orig_len = u32_at(body, 16, swapped);
                    let available = body.len() - 20;
                    if captured as usize > available {
                        self.consumed = off;
                        return Err(PcapngError::BadCapturedLength {
                            index: self.index,
                            claimed: captured,
                            available,
                        });
                    }
                    let Some(iface) = self.interfaces.get(interface_id as usize).copied() else {
                        self.consumed = off;
                        return Err(PcapngError::UnknownInterface {
                            index: self.index,
                            interface_id,
                        });
                    };
                    // Yielded BEFORE the packet, and only when non-zero: the
                    // count is what was lost leading UP to this block, so a
                    // consumer that stops on the packet has already been told.
                    if block_drops > 0 {
                        on(PcapngYield::PacketBlockDrops {
                            interface_id,
                            dropped: block_drops,
                        });
                    }
                    on(PcapngYield::Packet(Packet::resolved(
                        self.index,
                        interface_id,
                        &iface,
                        Some((ts_high << 32) | ts_low),
                        body[20..20 + captured as usize].to_vec(),
                        orig_len,
                    )));
                    self.index += 1;
                }
                BT_ISB => {
                    // interface_id u32, ts_high u32, ts_low u32, then options.
                    // The counters live ONLY in the options; the fixed part
                    // carries no drop figure at all.
                    if body.len() < 12 {
                        self.consumed = off;
                        return Err(PcapngError::Truncated { offset: off });
                    }
                    let interface_id = u32_at(body, 0, swapped);
                    let opts = &body[12..];
                    on(PcapngYield::Stats(InterfaceStats {
                        interface_id,
                        received: scan_u64_option(opts, swapped, OPT_ISB_IFRECV),
                        dropped: scan_u64_option(opts, swapped, OPT_ISB_IFDROP),
                    }));
                }
                // R311y625 (§1.4d) — skipped by length, which is what the format's
                // self-describing block structure is FOR, and now COUNTED, which is
                // what this crate's own rule requires of anything it drops. A
                // reader that walks past a block silently reports the file it can
                // read as if it were the file it was given.
                // R311y658 (§1.2a) — the one skipped type whose BYTES are worth
                // more than its count. Still recorded as skipped, because this
                // reader does not act on it: the count says "there were keys here"
                // and the payload is what a decryptor needs, and dropping the
                // skipped entry would make the file look fully understood.
                BT_DSB => {
                    if body.len() >= 8 && self.dsb_bytes < MAX_DECRYPTION_SECRETS_BYTES {
                        let secrets_type = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                        let len = u32::from_le_bytes([body[4], body[5], body[6], body[7]]) as usize;
                        // The declared length is the file's claim; the block is the
                        // evidence. A DSB whose secrets run past its own block is
                        // truncated, and taking `min` keeps what is really there
                        // rather than reading whatever follows in the buffer.
                        let end = (8 + len).min(body.len());
                        // R311y659 — bounded, like every other accumulation in this
                        // crate. A capture may embed a key log of any size and this
                        // is the only thing here that grows with the FILE's content
                        // rather than with its packet count. The cap is on the
                        // total across blocks, so a file that splits one huge log
                        // across many DSBs is bounded the same as one that does not.
                        //
                        // R2373 — the budget lives on the CURSOR, so a follower
                        // spends it once over the container's life. A door that
                        // re-parsed each window would re-spend it from zero and
                        // retain a multiple of the cap.
                        let keep = (MAX_DECRYPTION_SECRETS_BYTES - self.dsb_bytes).min(end - 8);
                        self.dsb_bytes += keep;
                        on(PcapngYield::Secrets(DecryptionSecrets {
                            secrets_type,
                            secrets: body[8..8 + keep].to_vec(),
                            truncated: 8 + keep < end,
                        }));
                    }
                    self.count_skipped(BT_DSB);
                }
                other => self.count_skipped(other),
            }
            off += total;
            self.consumed = off;
        }
        Ok(Halt::Complete)
    }

    /// Record one more block of `block_type` stepped over.
    fn count_skipped(&mut self, block_type: u32) {
        match self
            .skipped
            .iter_mut()
            .find(|s: &&mut SkippedBlock| s.block_type == block_type)
        {
            Some(e) => e.count += 1,
            None => self.skipped.push(SkippedBlock {
                block_type,
                count: 1,
            }),
        }
    }
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
///
/// R2373 (open-debt item 661) — the block walk itself moved to
/// [`PcapngCursor`] and this is one of its two callers. What this function
/// reads did not change; what changed is that the follower of a GROWING
/// container is now the same walk rather than a second one, so the two cannot
/// disagree about where a block ends.
pub fn parse(bytes: &[u8]) -> Result<PcapngFile, PcapngError> {
    // Kept ahead of the cursor so a file too short to hold one block reports
    // TRUNCATION rather than a verdict on its magic: a `bytes.len()` in 4..12
    // has enough to judge the magic and not enough to be a file, and this
    // function has answered `Truncated { offset: 0 }` for it since it was
    // written. The cursor cannot make that call — on a container still being
    // written those same bytes are neither.
    if bytes.len() < MIN_BLOCK_LEN {
        return Err(PcapngError::Truncated { offset: 0 });
    }

    let mut cursor = PcapngCursor::new();
    let mut packets: Vec<Packet> = Vec::new();
    let mut interface_stats: Vec<InterfaceStats> = Vec::new();
    let mut dsb: Vec<DecryptionSecrets> = Vec::new();
    // R311y607 — obsolete-Packet-Block drop counters, summed per interface.
    // A map rather than a Vec because the interface list is rebuilt at each
    // section boundary while these are accumulated across the whole file, and
    // an index into a list that is cleared underneath would attribute one
    // section's losses to another's interface.
    let mut pb_drops: alloc::collections::BTreeMap<u32, u64> = alloc::collections::BTreeMap::new();

    let halt = cursor.advance(bytes, |y| match y {
        PcapngYield::Packet(p) => packets.push(p),
        PcapngYield::Secrets(s) => dsb.push(s),
        PcapngYield::Stats(s) => interface_stats.push(s),
        PcapngYield::PacketBlockDrops {
            interface_id,
            dropped,
        } => {
            pb_drops
                .entry(interface_id)
                .and_modify(|d| *d += dropped)
                .or_insert(dropped);
        }
    })?;
    // A FILE does not grow, so the tail a follower would wait for is this
    // reader's truncation.
    if let Halt::Partial(e) = halt {
        return Err(e);
    }

    // A Packet Block's per-block drop count is folded in as if it had been an
    // ISB, so `interface_stats` is the ONE place a consumer asks the question
    // regardless of which block type the writer chose. `received` stays `None`
    // because a PB carries no such figure — reporting 0 would be a claim the
    // file never made.
    for (interface_id, dropped) in pb_drops {
        match interface_stats
            .iter_mut()
            .find(|s| s.interface_id == interface_id)
        {
            Some(existing) => {
                existing.dropped = Some(existing.dropped.unwrap_or(0) + dropped);
            }
            None => interface_stats.push(InterfaceStats {
                interface_id,
                received: None,
                dropped: Some(dropped),
            }),
        }
    }

    Ok(PcapngFile {
        interfaces: cursor.interfaces,
        packets,
        sections: cursor.sections,
        interface_stats,
        skipped_blocks: cursor.skipped,
        decryption_secrets: dsb,
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

    /// One Interface Statistics Block, laid out per the pcapng spec §4.6:
    /// block type, total length, interface id, ts_high, ts_low, then options,
    /// then the trailing length. Each option is code u16 / length u16 / value
    /// padded to 4.
    ///
    /// Hand-laid because [`write`] emits no ISB, and it is asserted at the
    /// BYTE level below rather than only round-tripped — a fixture the reader
    /// and the writer agree on proves only that they share a belief.
    fn isb(interface_id: u32, recv: Option<u64>, drop: Option<u64>) -> Vec<u8> {
        let mut opts = Vec::new();
        for (code, value) in [(OPT_ISB_IFRECV, recv), (OPT_ISB_IFDROP, drop)] {
            if let Some(v) = value {
                opts.extend_from_slice(&code.to_le_bytes());
                opts.extend_from_slice(&8u16.to_le_bytes());
                opts.extend_from_slice(&v.to_le_bytes());
            }
        }
        // opt_endofopt terminates the list.
        opts.extend_from_slice(&0u16.to_le_bytes());
        opts.extend_from_slice(&0u16.to_le_bytes());

        // type(4) + length(4) + interface_id(4) + ts_high(4) + ts_low(4)
        // + options + trailing length(4).
        let total = (24 + opts.len()) as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&BT_ISB.to_le_bytes());
        out.extend_from_slice(&total.to_le_bytes());
        out.extend_from_slice(&interface_id.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // ts_high
        out.extend_from_slice(&0u32.to_le_bytes()); // ts_low
        out.extend_from_slice(&opts);
        out.extend_from_slice(&total.to_le_bytes());
        out
    }

    /// R311y607 — THE ONE THAT MATTERS: what the CAPTURE TOOL lost is read,
    /// not skipped.
    ///
    /// `wz-capture` counts what it discards itself and reported that as though
    /// it were the whole story. It is not: a capture tool whose kernel ring
    /// overflows writes an `isb_ifdrop` and hands over a file with a hole. Read
    /// from a TCP stream that hole desynchronises the assembler, which has no
    /// resynchronise path — so the visible symptom is "the dissector stopped
    /// decoding", and the cause was in the file all along, in a block this
    /// reader stepped over by length.
    #[test]
    fn the_capture_tools_own_drop_count_is_read_rather_than_skipped() {
        let mut file = write(&[(1, 6)], &[(0, 1_000_000, &[0u8; 4])]);
        file.extend_from_slice(&isb(0, Some(1_000), Some(17)));
        let parsed = parse(&file).expect("an ISB must not disturb the parse");

        assert_eq!(parsed.packets.len(), 1, "the packet still reads");
        assert_eq!(parsed.interface_stats.len(), 1);
        assert_eq!(parsed.interface_stats[0].interface_id, 0);
        assert_eq!(parsed.interface_stats[0].received, Some(1_000));
        assert_eq!(
            parsed.interface_stats[0].dropped,
            Some(17),
            "17 packets never reached this file and the file says so"
        );
    }

    /// An absent option is NOT zero. A writer that emits an ISB with only
    /// `isb_ifrecv` has said nothing about drops, and answering 0 would be
    /// inventing a claim the file never made — the difference between "nothing
    /// was lost" and "nobody counted".
    #[test]
    fn an_unstated_counter_is_none_rather_than_zero() {
        let mut file = write(&[(1, 6)], &[]);
        file.extend_from_slice(&isb(0, Some(42), None));
        let parsed = parse(&file).expect("parse");
        assert_eq!(parsed.interface_stats[0].received, Some(42));
        assert_eq!(parsed.interface_stats[0].dropped, None);
    }

    /// A counter of the wrong WIDTH is refused rather than zero-extended: an
    /// 8-byte option read as 4 (or the reverse) would produce a number the
    /// reader would then quote as the capture's own.
    #[test]
    fn a_wrong_width_counter_is_refused_rather_than_guessed() {
        let mut file = write(&[(1, 6)], &[]);
        let mut block = Vec::new();
        let mut opts = Vec::new();
        opts.extend_from_slice(&OPT_ISB_IFDROP.to_le_bytes());
        opts.extend_from_slice(&4u16.to_le_bytes()); // four bytes, not eight
        opts.extend_from_slice(&9u32.to_le_bytes());
        opts.extend_from_slice(&0u32.to_le_bytes()); // opt_endofopt
                                                     // type(4) + length(4) + interface_id(4) + ts_high(4) + ts_low(4)
                                                     // + options + trailing length(4).
        let total = (24 + opts.len()) as u32;
        block.extend_from_slice(&BT_ISB.to_le_bytes());
        block.extend_from_slice(&total.to_le_bytes());
        block.extend_from_slice(&0u32.to_le_bytes());
        block.extend_from_slice(&0u32.to_le_bytes());
        block.extend_from_slice(&0u32.to_le_bytes());
        block.extend_from_slice(&opts);
        block.extend_from_slice(&total.to_le_bytes());
        file.extend_from_slice(&block);

        let parsed = parse(&file).expect("a malformed option is not a fatal file");
        assert_eq!(
            parsed.interface_stats[0].dropped, None,
            "a 4-byte isb_ifdrop is not a 64-bit count"
        );
    }

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

    /// R311y715 (§C G6) — and the resolution a file does NOT declare.
    ///
    /// `if_tsresol` is OPTIONAL; its absence means microseconds. Beside the
    /// test above rather than in a module of its own, because the two are one
    /// rule read from two directions and the declared half had a witness while
    /// the default half had none: changing `DEFAULT_TSRESOL` from 6 to 3 left
    /// all 391 tests green. That is not a small silence — every time this
    /// reader states about such a file (elapsed, exchange latency, the flow
    /// clock eviction orders by) would be out by 1000x, and a capture carries
    /// no second clock to disagree with it.
    ///
    /// The IDB is hand-laid because [`write`] always emits the option, and a
    /// fixture that cannot omit it cannot test the omission.
    #[test]
    fn an_interface_that_declares_no_resolution_is_microseconds() {
        let mut file = Vec::new();
        file.extend_from_slice(&BT_SHB.to_le_bytes());
        file.extend_from_slice(&28u32.to_le_bytes());
        file.extend_from_slice(&BOM.to_le_bytes());
        file.extend_from_slice(&1u16.to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes());
        file.extend_from_slice(&(-1i64).to_le_bytes());
        file.extend_from_slice(&28u32.to_le_bytes());
        // IDB with NO options: linktype, reserved, snaplen, and nothing else.
        file.extend_from_slice(&BT_IDB.to_le_bytes());
        file.extend_from_slice(&20u32.to_le_bytes());
        file.extend_from_slice(&1u16.to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&20u32.to_le_bytes());
        // EPB: the same 2_000_000 ticks the declared-resolution test uses.
        file.extend_from_slice(&BT_EPB.to_le_bytes());
        file.extend_from_slice(&36u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&2_000_000u32.to_le_bytes());
        file.extend_from_slice(&4u32.to_le_bytes());
        file.extend_from_slice(&4u32.to_le_bytes());
        file.extend_from_slice(&[0xAA; 4]);
        file.extend_from_slice(&36u32.to_le_bytes());

        let parsed = parse(&file).expect("an IDB may carry no options at all");
        assert_eq!(
            parsed.interfaces[0].ts_resol, 6,
            "the pcapng default, and the assertion that keeps it one"
        );
        assert_eq!(
            parsed.ts_millis(&parsed.packets[0]),
            Some(2_000),
            "2_000_000 microseconds is two seconds, not two thousand"
        );
    }

    /// The 64-bit timestamp is ONE count, high word first — not the
    /// seconds/fraction pair the classic format uses.
    #[test]
    fn the_timestamp_halves_are_one_64_bit_count() {
        let ticks = (3u64 << 32) | 7;
        let file = write(&[(1, 6)], &[(0, ticks, &[0xAA])]);
        let parsed = parse(&file).expect("parse");
        assert_eq!(parsed.packets[0].ts_ticks, Some(ticks));
        assert_ne!(
            parsed.packets[0].ts_ticks,
            Some(3),
            "reading the high word alone as seconds is the classic-format habit"
        );
    }

    /// R311y625 (§1.4d) — a file carrying DECRYPTION SECRETS says so, and this
    /// is the skipped block whose silence cost the most.
    ///
    /// §8.1 records that wz cannot read its own encrypted traffic. A capture
    /// with a DSB in it is one where the material to do so was IN THE FILE, and
    /// the reader walked past it without a word — so a report saying "encrypted
    /// and unreadable" was true about this build and false about the capture.
    /// The block is still skipped: implementing TLS decryption is not this
    /// round's business. Being able to SAY it was there is.
    #[test]
    fn a_file_carrying_decryption_secrets_says_so_rather_than_walking_past() {
        let mut file = write(&[(1, 6)], &[(0, 1_000_000, &[0xAA; 4])]);
        // A DSB: type, total length, secrets type, secrets length, body, length.
        let mut dsb = Vec::new();
        dsb.extend_from_slice(&BT_DSB.to_le_bytes());
        dsb.extend_from_slice(&24u32.to_le_bytes());
        dsb.extend_from_slice(&0x544c_534bu32.to_le_bytes()); // "TLSK"
        dsb.extend_from_slice(&4u32.to_le_bytes());
        dsb.extend_from_slice(b"key!");
        dsb.extend_from_slice(&24u32.to_le_bytes());
        file.extend_from_slice(&dsb);

        let parsed = parse(&file).expect("a DSB must not be fatal");
        assert_eq!(parsed.packets.len(), 1, "the packet before it still reads");
        assert_eq!(
            parsed.carries_decryption_secrets(),
            1,
            "and the file's own keys are REPORTED, not walked past: {:?}",
            parsed.skipped_blocks
        );
        assert_eq!(parsed.carries_name_resolution(), 0);
    }

    /// R311y658 (§1.2a) — and the BYTES are kept, not just the count.
    ///
    /// R311y625 counted the block and dropped its payload, which made the
    /// file's own answer to "can this capture be read" unreachable: the keys
    /// were in the capture, this reader knew a DSB was there, and it walked
    /// past the material. The payload is handed on UNPARSED -- what an NSS key
    /// log means is TLS vocabulary, and a pcapng parser that grew it would be
    /// carrying a protocol it cannot use.
    #[test]
    fn a_decryption_secrets_blocks_payload_is_kept_for_a_decryptor() {
        const TLSK: u32 = 0x544c_534b;
        let body = b"CLIENT_TRAFFIC_SECRET_0 00 11\n";
        let mut dsb = Vec::new();
        dsb.extend_from_slice(&BT_DSB.to_le_bytes());
        let total = 12 + 8 + body.len() + 2; // header/trailer + type + len + body + pad
        dsb.extend_from_slice(&(total as u32).to_le_bytes());
        dsb.extend_from_slice(&TLSK.to_le_bytes());
        dsb.extend_from_slice(&(body.len() as u32).to_le_bytes());
        dsb.extend_from_slice(body);
        dsb.extend_from_slice(&[0, 0]); // to a 4-byte boundary
        dsb.extend_from_slice(&(total as u32).to_le_bytes());

        let mut file = write(&[(1, 6)], &[(0, 1_000_000, &[0xAA; 4])]);
        file.extend_from_slice(&dsb);
        let parsed = parse(&file).expect("a DSB must not be fatal");

        assert_eq!(
            parsed.carries_decryption_secrets(),
            1,
            "the count R311y625 added must not have been traded away"
        );
        assert_eq!(parsed.decryption_secrets.len(), 1);
        assert_eq!(parsed.decryption_secrets[0].secrets_type, TLSK);
        assert_eq!(
            parsed.decryption_secrets[0].secrets,
            body.to_vec(),
            "the payload must arrive byte for byte, without the padding"
        );
        assert!(
            !parsed.decryption_secrets[0].truncated,
            "a payload that fits is not truncated"
        );

        // AND NO KEY MATERIAL IN THE DEBUG RENDERING: a capture tool that
        // spilled secrets into a log would be worse than one that could not
        // read them at all.
        let shown = alloc::format!("{:?}", parsed.decryption_secrets[0]);
        assert!(shown.contains("byte(s)"), "{shown}");
        assert!(!shown.contains("CLIENT_TRAFFIC"), "{shown}");

        // R311y659 — THE BOUND, and its report. Every other accumulation in
        // this crate is capped and counted; the retained payload was the one
        // that grew with the FILE's content and had no limit at all. What is
        // dropped is not silent: `truncated` says the log a caller parses is
        // shorter than the one the file carried, which a caller cannot work out
        // for itself -- the bytes it did not get are the evidence it would need.
        let over = MAX_DECRYPTION_SECRETS_BYTES + 100;
        let mut big = Vec::new();
        big.extend_from_slice(&BT_DSB.to_le_bytes());
        let total = 12 + 8 + over;
        big.extend_from_slice(&(total as u32).to_le_bytes());
        big.extend_from_slice(&TLSK.to_le_bytes());
        big.extend_from_slice(&(over as u32).to_le_bytes());
        big.resize(big.len() + over, b'x');
        big.extend_from_slice(&(total as u32).to_le_bytes());
        let mut file = write(&[(1, 6)], &[(0, 1_000_000, &[0xAA; 4])]);
        file.extend_from_slice(&big);
        let parsed = parse(&file).expect("an oversized DSB must not be fatal");
        assert_eq!(
            parsed.decryption_secrets[0].secrets.len(),
            MAX_DECRYPTION_SECRETS_BYTES,
            "the bound must hold"
        );
        assert!(
            parsed.decryption_secrets[0].truncated,
            "and it must say that it bit"
        );

        // A TRUNCATED DSB: the block declares more secrets than it carries,
        // which is the ordinary shape of a capture cut short while the writer
        // was flushing. The DECLARED length is the file's claim and the block is
        // the evidence, so what is really there is what arrives -- and not a
        // panic, and not whatever bytes follow in the buffer. Without the clamp
        // the leg above passes unchanged, because a well-formed DSB's two
        // lengths agree; this is the only shape that separates them.
        let mut cut = Vec::new();
        cut.extend_from_slice(&BT_DSB.to_le_bytes());
        let total = 12 + 8 + 4;
        cut.extend_from_slice(&(total as u32).to_le_bytes());
        cut.extend_from_slice(&TLSK.to_le_bytes());
        cut.extend_from_slice(&999u32.to_le_bytes()); // the claim
        cut.extend_from_slice(b"abcd"); // the evidence
        cut.extend_from_slice(&(total as u32).to_le_bytes());
        let mut file = write(&[(1, 6)], &[(0, 1_000_000, &[0xAA; 4])]);
        file.extend_from_slice(&cut);
        let parsed = parse(&file).expect("a truncated DSB must not be fatal");
        assert_eq!(
            parsed.decryption_secrets[0].secrets,
            b"abcd".to_vec(),
            "a DSB may not read past its own block on the strength of its own \
             length field"
        );
    }

    /// THE CONTROL: an ordinary capture reports nothing skipped. Without it a
    /// census that counted every block would satisfy the page above.
    #[test]
    fn a_file_with_nothing_unusual_reports_no_skipped_block() {
        let file = write(&[(1, 6)], &[(0, 1_000_000, &[0xAA; 4])]);
        let parsed = parse(&file).expect("parse");
        assert!(
            parsed.skipped_blocks.is_empty(),
            "{:?}",
            parsed.skipped_blocks
        );
        assert_eq!(parsed.carries_decryption_secrets(), 0);
    }

    /// R311y625 (§1.4d) — an SPB capture leaves the observer's clock UNSET
    /// rather than pinning it to zero, end to end through the dissection.
    ///
    /// The page that makes the `Option` worth the churn. Before it, `ts_ticks`
    /// was `0`, `from_pcapng` handed `Some(0)` to `push_packet_at`, that SET
    /// the clock, and R311y624 pinned the clock as STICKY — so every frame in
    /// such a capture reported an instant nobody had recorded, a `time > 0`
    /// term got a confident No, and any latency came out as 0 ms.
    #[test]
    fn a_simple_packet_capture_leaves_the_observers_clock_unset() {
        let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let payload =
            crate::datagram_tests::udp_packet([10, 0, 0, 1], 7447, [10, 0, 0, 2], 7447, &keepalive);
        let mut file = write(&[(1, 6)], &[]);
        let padded = (payload.len() + 3) & !3;
        file.extend_from_slice(&BT_SPB.to_le_bytes());
        file.extend_from_slice(&((16 + padded) as u32).to_le_bytes());
        file.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        file.extend_from_slice(&payload);
        file.extend_from_slice(&alloc::vec![0u8; padded - payload.len()]);
        file.extend_from_slice(&((16 + padded) as u32).to_le_bytes());

        let d = crate::Dissection::from_pcapng(&file).expect("the SPB capture must read");
        let flow = &d.datagram_flows()[0];
        assert_eq!(flow.frames.len(), 1, "the packet reached a flow");
        assert_eq!(
            flow.frames[0].observed_at_ms, None,
            "a block with no timestamp must not produce one"
        );
        assert_eq!(
            flow.session.observed_at(),
            None,
            "and the observer must still be able to say it was never told"
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
        // R311y625 (§1.4d) — the ABSENCE, not a plausible zero. The old
        // assertion read `0` and the field could not tell "no timestamp" from
        // "timestamp zero"; `from_pcapng` then handed `Some(0)` to the
        // observer's clock and every frame in an SPB capture reported an
        // instant nobody recorded.
        assert_eq!(parsed.packets[0].ts_ticks, None);
        assert_eq!(
            parsed.ts_millis(&parsed.packets[0]),
            None,
            "and the absence survives the resolution against an interface"
        );
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

    /// R311y607 — the Packet Block's own drop counter is ACCUMULATED, not
    /// stepped over.
    ///
    /// A PB states losses per block (packets missed since the previous one on
    /// that interface), where an ISB states a total, so the two need different
    /// arithmetic to reach the same answer. They land in one place regardless,
    /// because a consumer asking "did the capture tool lose anything" must not
    /// have to know which block type a 2010-era writer chose.
    #[test]
    fn the_obsolete_blocks_drop_counter_is_summed_rather_than_stepped_over() {
        let mut file = write(&[(1, 6)], &[]);
        for drops in [3u16, 4u16] {
            file.extend_from_slice(&BT_PB.to_le_bytes());
            file.extend_from_slice(&36u32.to_le_bytes());
            file.extend_from_slice(&0u16.to_le_bytes()); // interface_id
            file.extend_from_slice(&drops.to_le_bytes());
            file.extend_from_slice(&0u32.to_le_bytes()); // ts high
            file.extend_from_slice(&1_000u32.to_le_bytes()); // ts low
            file.extend_from_slice(&2u32.to_le_bytes());
            file.extend_from_slice(&2u32.to_le_bytes());
            file.extend_from_slice(&[0xAA, 0xBB, 0, 0]);
            file.extend_from_slice(&36u32.to_le_bytes());
        }
        let parsed = parse(&file).expect("parse");
        assert_eq!(parsed.packets.len(), 2, "both packets still read");
        assert_eq!(parsed.interface_stats.len(), 1);
        assert_eq!(
            parsed.interface_stats[0].dropped,
            Some(7),
            "3 + 4, summed across the blocks rather than last-write-wins"
        );
        assert_eq!(
            parsed.interface_stats[0].received, None,
            "a PB states no received count, and inventing 0 would be a claim"
        );
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

    /// R2373 (open-debt item 661) — a packet's time is resolved against the
    /// interface of ITS OWN section, not the one the file happened to end with.
    ///
    /// # The bug this pins, and how it was found
    ///
    /// [`PcapngFile::ts_millis`] used to look the interface up in
    /// [`PcapngFile::interfaces`], which a section boundary CLEARS and refills:
    /// on a multi-section capture it therefore put every earlier packet's ticks
    /// through the LAST section's `if_tsresol`. Here that is microseconds
    /// against milliseconds, so the first packet came back a thousand times too
    /// late — 1 500 000 ms rather than 1 500.
    ///
    /// It was not found by reading this function. It was found by building a
    /// reader for a container still being WRITTEN, which has no "afterwards" to
    /// resolve in and so had to be handed the answer at the moment the block
    /// was read. Once one door had to resolve early, the two doors disagreed,
    /// and the disagreement is what named the older one as wrong.
    #[test]
    fn a_packets_time_is_resolved_against_its_own_sections_interface() {
        // Two whole sections, one after the other, which is what a writer that
        // restarted mid-file produces. The second declares MILLISECOND ticks
        // where the first declared microseconds.
        let mut file = write(&[(1, 6)], &[(0, 1_500_000, &[1, 2, 3])]);
        file.extend_from_slice(&write(&[(1, 3)], &[(0, 7_000, &[4, 5, 6])]));

        let parsed = parse(&file).expect("two sections are legal");
        assert_eq!(parsed.sections, 2, "the fixture must carry two sections");
        assert_eq!(parsed.packets.len(), 2);
        assert_eq!(
            parsed.ts_millis(&parsed.packets[0]),
            Some(1_500),
            "the first packet's ticks are MICROSECONDS, as its own section said"
        );
        assert_eq!(
            parsed.ts_millis(&parsed.packets[1]),
            Some(7_000),
            "the second packet's ticks are MILLISECONDS, as its own section said"
        );
    }

    /// R2373 (open-debt item 661) — a cursor fed the container in TWO PIECES
    /// reads exactly what [`parse`] reads in one, at every cut.
    ///
    /// # The population is the container's length
    ///
    /// Every byte boundary of the fixture, so a block header cut between its
    /// two length words, a packet cut inside its data and a prefix one byte
    /// short of a trailing length are all in it because they exist rather than
    /// because they were thought of. The empty population is refused below.
    ///
    /// This is the walk's own gate, one layer under the C door's: if these two
    /// ever part, every door built on either of them parts with them.
    #[test]
    fn a_cursor_fed_in_two_pieces_reads_what_parse_reads_in_one() {
        let file = write(
            &[(1, 6), (101, 9)],
            &[
                (0, 1_000, &[1, 2, 3]),
                (1, 2_000, &[4, 5, 6, 7, 8]),
                (0, 3_000, &[9]),
            ],
        );
        let whole = parse(&file).expect("the fixture reads");
        assert_eq!(whole.packets.len(), 3);

        let cuts: Vec<usize> = (0..=file.len()).collect();
        assert!(cuts.len() > 1, "the population must not be empty");
        let mut mid_block = 0usize;

        for cut in cuts {
            let mut cursor = PcapngCursor::new();
            let mut packets: Vec<Packet> = Vec::new();
            let mut sink = |y: PcapngYield| {
                if let PcapngYield::Packet(p) = y {
                    packets.push(p);
                }
            };
            let halt = cursor
                .advance(&file[..cut], &mut sink)
                .expect("a prefix of a good container is never malformed");
            assert!(
                cursor.consumed() <= cut,
                "the walk consumed {} of the {cut} byte(s) it was given",
                cursor.consumed()
            );
            if cursor.consumed() < cut {
                mid_block += 1;
                assert!(
                    matches!(halt, Halt::Partial(_)),
                    "a walk that stopped short of {cut} reported Complete"
                );
            }
            let resumed = cursor
                .advance(&file, &mut sink)
                .expect("the whole container reads");
            assert_eq!(resumed, Halt::Complete);
            assert_eq!(cursor.consumed(), file.len());
            assert_eq!(
                packets, whole.packets,
                "the container split at byte {cut} read differently from the \
                 same container read whole"
            );
        }
        assert!(
            mid_block > 0,
            "no cut of this fixture landed inside a block, so resumption was \
             never exercised"
        );
    }
}
