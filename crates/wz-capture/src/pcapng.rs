// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
use core::ops::ControlFlow;

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
/// `epb_flags` on an Enhanced Packet Block, and `pack_flags` on the obsolete
/// Packet Block: the same 32-bit word under the same code.
const OPT_EPB_FLAGS: u16 = 2;
/// A Custom Option holding a UTF-8 string that can be copied to a new file when
/// an application rewrites the capture (`opt_custom`, pcapng, Custom Options).
pub const OPT_CUSTOM_UTF8_COPYABLE: u16 = 2988;
/// A Custom Option holding binary octets that can be copied to a new file when
/// an application rewrites the capture.
pub const OPT_CUSTOM_BINARY_COPYABLE: u16 = 2989;
/// A Custom Option holding a UTF-8 string that should NOT be copied to a new
/// file when an application rewrites the capture.
pub const OPT_CUSTOM_UTF8_NONCOPYABLE: u16 = 19372;
/// A Custom Option holding binary octets that should NOT be copied to a new
/// file when an application rewrites the capture.
pub const OPT_CUSTOM_BINARY_NONCOPYABLE: u16 = 19373;
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
    /// [`Self::ts_ticks`] through the same `if_tsresol`, in NANOSECONDS: the
    /// digits [`Self::ts_millis`] drops. That field is this one divided by a
    /// million, rounded down, and `None` exactly when this one is.
    pub ts_nanos: Option<u64>,
    /// The block's `epb_flags` word (`pack_flags` on an obsolete Packet Block),
    /// or `None` when it carried none; a Simple Packet Block never does.
    ///
    /// Bits 0-1 are the DIRECTION the capture tool recorded (`0` not known, `1`
    /// inbound, `2` outbound), bits 2-4 the reception type, bits 5-8 the FCS
    /// length, and the high half link-layer errors. Carried whole: which of them
    /// a reader needs is the reader's, and the direction of a record a writer
    /// defined for its own link type is that writer's statement.
    pub flags: Option<u32>,
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
        ticks_to_millis(self.ts_ticks, iface)
    }

    /// [`Self::resolve_ts_millis`], in nanoseconds.
    pub fn resolve_ts_nanos(&self, iface: &Interface) -> Option<u64> {
        ticks_to_nanos(self.ts_ticks, iface)
    }
}

/// The one conversion from a block's raw tick count to epoch NANOSECONDS,
/// shared by the owned [`Packet`] and the borrowed [`PacketRef`] so the two
/// cannot resolve `if_tsresol` two ways.
///
/// Exact for every resolution: the tick count times a billion over the ticks
/// per second, in 128 bits, so a resolution finer than a nanosecond is divided
/// down and a coarser one is multiplied up without the intermediate
/// overflowing and without the divisor being rounded first. (Rounding the
/// divisor first is what the millisecond conversion did, and it is wrong for a
/// base-2 resolution, whose ticks per second are not a multiple of a thousand:
/// `if_tsresol` 0x80 | 20 is 1 048 576 ticks a second, divided by 1 000 to
/// 1 048, which reads one second of ticks as 1 000.5 ms and drifts by half a
/// millisecond for every second since the epoch.)
/// A result past `u64` -- a corrupt file -- saturates at the top, the failure
/// that cannot be mistaken for a plausible instant.
fn ticks_to_nanos(ts_ticks: Option<u64>, iface: &Interface) -> Option<u64> {
    const NANOS_PER_SEC: u128 = 1_000_000_000;
    let ticks = u128::from(ts_ticks?);
    let per_sec = u128::from(iface.ticks_per_second()).max(1);
    Some(u64::try_from(ticks * NANOS_PER_SEC / per_sec).unwrap_or(u64::MAX))
}

/// The millisecond reading of [`ticks_to_nanos`]: that value divided by a
/// million, rounded down, so the two readings of one packet cannot name
/// different instants. For every DECIMAL resolution this is the value the
/// conversion has always given; a base-2 resolution is now exact where it was
/// off by half a millisecond for every second since the epoch.
fn ticks_to_millis(ts_ticks: Option<u64>, iface: &Interface) -> Option<u64> {
    ticks_to_nanos(ts_ticks, iface).map(|ns| ns / 1_000_000)
}

/// One captured packet whose bytes are BORROWED from the container.
///
/// What [`PcapngCursor::advance_with`] hands its sink, where [`Packet`] is what
/// [`PcapngCursor::advance`] hands its own. The walk is the same walk; only the
/// ownership of the block's bytes differs. See [`crate::pcap::PacketRef`] for
/// why a borrow is the right shape for a sink that reads a packet and drops it.
///
/// The lifetime is the CONTAINER's: `data` is a window of the `bytes` the walk
/// was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketRef<'a> {
    /// Zero-based index in the file.
    pub index: usize,
    /// The interface this arrived on, as an index into the section's interface
    /// list.
    pub interface_id: u32,
    /// The interface's link type, copied here so a consumer never has to hold
    /// both lists to decapsulate one packet.
    pub link_type: u32,
    /// The raw 64-bit tick count, or `None` for a block that carried no time.
    pub ts_ticks: Option<u64>,
    /// [`Self::ts_ticks`] already put through the recording interface's
    /// `if_tsresol`, at the moment the block was read.
    pub ts_millis: Option<u64>,
    /// The same instant in nanoseconds; [`Self::ts_millis`] is this divided by
    /// a million, rounded down.
    pub ts_nanos: Option<u64>,
    /// The block's `epb_flags` word; see [`Packet::flags`]. It is read out of
    /// [`Self::options`], the one list this and every other option of the block
    /// is read from.
    pub flags: Option<u32>,
    /// The block's option list, borrowed from the container: empty for a block
    /// that has none (a Simple Packet Block never does).
    ///
    /// Held rather than read out piece by piece so that an option nobody asked
    /// about when the block was walked, a Custom Option for one, is still there
    /// for a reader that asks afterwards, and is read by the same code that
    /// read `epb_flags`.
    pub options: OptionList<'a>,
    /// Bytes actually stored, link header included.
    pub data: &'a [u8],
    /// Length the packet had on the wire.
    pub orig_len: u32,
}

impl<'a> PacketRef<'a> {
    /// One packet, with its capture time resolved against `iface` HERE, where
    /// the interface that recorded it is still in hand.
    ///
    /// The one constructor the walk uses, so the three block types that carry a
    /// packet cannot resolve it three ways. Its `epb_flags` word is read from
    /// `options` here, for the same reason.
    fn resolved(
        index: usize,
        interface_id: u32,
        iface: &Interface,
        ts_ticks: Option<u64>,
        options: OptionList<'a>,
        data: &'a [u8],
        orig_len: u32,
    ) -> Self {
        Self {
            index,
            interface_id,
            link_type: iface.link_type,
            ts_ticks,
            ts_millis: ticks_to_millis(ts_ticks, iface),
            ts_nanos: ticks_to_nanos(ts_ticks, iface),
            flags: options.u32_option(OPT_EPB_FLAGS),
            options,
            data,
            orig_len,
        }
    }

    /// The same packet with its bytes copied out of the container.
    ///
    /// Not named `to_owned`: the type is `Copy`, so that name would resolve to
    /// the blanket trait method and hand back another borrow.
    pub fn into_packet(self) -> Packet {
        Packet {
            index: self.index,
            interface_id: self.interface_id,
            link_type: self.link_type,
            ts_ticks: self.ts_ticks,
            ts_millis: self.ts_millis,
            ts_nanos: self.ts_nanos,
            flags: self.flags,
            data: self.data.to_vec(),
            orig_len: self.orig_len,
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
    /// R311y607 — every Interface Statistics Block, in file order. Empty when
    /// the writer emitted none, which is ordinary: an ISB is optional and its
    /// absence says nothing either way about whether packets were lost.
    pub interface_stats: Vec<InterfaceStats>,
    /// What the capture tool admitted losing, over every Interface Statistics
    /// Block AND every obsolete Packet Block's drop count. This, and not a sum
    /// over [`Self::interface_stats`], is the file's figure: the blocks state
    /// running totals, and see [`DropLedger`] for why adding them is wrong.
    pub reported_drops: DropLedger,
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

    /// [`Self::ts_millis`], in nanoseconds.
    pub fn ts_nanos(&self, packet: &Packet) -> Option<u64> {
        packet.ts_nanos
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

/// A block's option list, borrowed from the container, in the byte order of the
/// section the block is in.
///
/// # The one reader of options
///
/// Every block that carries options carries them in one shape: `[code u16]
/// [length u16][value, padded to 4]`, repeated, ended by code 0
/// (`opt_endofopt`). This reader used to walk that shape three times over, once
/// for `if_tsresol`, once for the 64-bit counters of an Interface Statistics
/// Block and once for `epb_flags`, each a copy of the same loop that could drift
/// from the others. They are all [`OptionList::iter`] now, and so is the Custom
/// Option reader: there is no second opinion about where an option ends.
///
/// Copying nothing: an option's value is a window of the container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OptionList<'a> {
    bytes: &'a [u8],
    swapped: bool,
}

/// One option of a block's list, as the block stored it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawOption<'a> {
    /// Where the option sits in its block's list: `0` for the first. The list's
    /// terminator is not an option and takes no place.
    pub index: u32,
    /// The option code.
    pub code: u16,
    /// The value, exactly as long as the option's length field says: the
    /// padding to four bytes is not part of it.
    pub value: &'a [u8],
}

/// How an option walk ended, which is more than "it ended".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OptionsEnd {
    /// Still walking.
    Running,
    /// `opt_endofopt`: the list said it was over.
    Terminated,
    /// Fewer than four bytes were left, too few for an option header. A block's
    /// length is a multiple of four, so this is the list ending without a
    /// terminator, which writers do.
    Exhausted,
    /// An option's length ran past the end of the list. What follows cannot be
    /// found, because the next option starts where this one ends.
    Overran,
}

/// The walk over an [`OptionList`]. Yields each option in order and stops at
/// `opt_endofopt`, at the end of the list, or at an option that runs past it.
#[derive(Debug, Clone, Copy)]
pub struct OptionIter<'a> {
    list: OptionList<'a>,
    off: usize,
    next_index: u32,
    end: OptionsEnd,
}

impl<'a> OptionList<'a> {
    /// A block with no options.
    pub const fn empty() -> Self {
        Self {
            bytes: &[],
            swapped: false,
        }
    }

    /// The options in `bytes`, written in `swapped` byte order (a section whose
    /// byte order is not this machine's reading of its magic).
    const fn new(bytes: &'a [u8], swapped: bool) -> Self {
        Self { bytes, swapped }
    }

    /// The byte order of the section these options were written in: the order
    /// every number in the list, and every number an organization put in its
    /// data, is in unless the organization says otherwise.
    pub const fn byte_order(&self) -> ByteOrder {
        if self.swapped {
            ByteOrder::Big
        } else {
            ByteOrder::Little
        }
    }

    /// Every option, in order. See [`OptionIter`] for where the walk stops.
    pub fn iter(&self) -> OptionIter<'a> {
        OptionIter {
            list: *self,
            off: 0,
            next_index: 0,
            end: OptionsEnd::Running,
        }
    }

    /// The first option with this `code` whose value is exactly `N` bytes.
    ///
    /// The width is checked exactly, as it always was: a writer that emitted a
    /// 4-byte counter where eight were owed is not zero-extended into a number
    /// a reader would then quote. An option of the right code and the wrong
    /// width is passed over, and a later one of the right width is found.
    fn fixed_option<const N: usize>(&self, code: u16) -> Option<[u8; N]> {
        self.iter()
            .find(|o| o.code == code && o.value.len() == N)
            .and_then(|o| <[u8; N]>::try_from(o.value).ok())
    }

    /// The first `want` option holding a `u32`, in the section's byte order.
    fn u32_option(&self, want: u16) -> Option<u32> {
        self.fixed_option::<4>(want).map(|raw| {
            if self.swapped {
                u32::from_be_bytes(raw)
            } else {
                u32::from_le_bytes(raw)
            }
        })
    }

    /// The first `want` option holding a `u64`, in the section's byte order.
    fn u64_option(&self, want: u16) -> Option<u64> {
        self.fixed_option::<8>(want).map(|raw| {
            if self.swapped {
                u64::from_be_bytes(raw)
            } else {
                u64::from_le_bytes(raw)
            }
        })
    }

    /// The Custom Options of this list: the four codes the format reserves for
    /// them, in list order, repeats included. See [`CustomOptions`].
    pub fn custom(&self) -> CustomOptions<'a> {
        CustomOptions {
            inner: self.iter(),
            malformed: 0,
        }
    }
}

impl<'a> Iterator for OptionIter<'a> {
    type Item = RawOption<'a>;

    fn next(&mut self) -> Option<RawOption<'a>> {
        if self.end != OptionsEnd::Running {
            return None;
        }
        let OptionList { bytes, swapped } = self.list;
        if self.off + 4 > bytes.len() {
            self.end = OptionsEnd::Exhausted;
            return None;
        }
        let code = u16_at(bytes, self.off, swapped);
        let len = u16_at(bytes, self.off + 2, swapped) as usize;
        if code == 0 {
            self.end = OptionsEnd::Terminated;
            return None;
        }
        let start = self.off + 4;
        let Some(value) = bytes.get(start..start + len) else {
            self.end = OptionsEnd::Overran;
            return None;
        };
        // Every option's value is padded to a 4-byte boundary.
        self.off = start + ((len + 3) & !3);
        let index = self.next_index;
        self.next_index = self.next_index.saturating_add(1);
        Some(RawOption { index, code, value })
    }
}

impl OptionIter<'_> {
    /// Whether the walk stopped because an option's length ran past the end of
    /// the list, as opposed to the list ending. Meaningful once the iterator has
    /// returned `None`.
    pub fn ended_inside_an_option(&self) -> bool {
        self.end == OptionsEnd::Overran
    }
}

/// What the format says about one of the four Custom Option codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustomKind {
    /// The Custom Data is a UTF-8 string (`2988`, `19372`) and not binary
    /// octets (`2989`, `19373`).
    pub text: bool,
    /// The option can be safely copied to a new file when an application
    /// rewrites the capture (`2988`, `2989`). The other two should not be.
    pub copyable: bool,
}

/// The kind of a Custom Option code, or `None` for a code that is not one.
///
/// The ONE place the four codes are classified: a record that carries a code
/// and also its flags carries them from here, so the two cannot disagree. The
/// table is the pcapng format's Custom Options section and the test that pins
/// it quotes that text.
pub const fn custom_kind(code: u16) -> Option<CustomKind> {
    match code {
        OPT_CUSTOM_UTF8_COPYABLE => Some(CustomKind {
            text: true,
            copyable: true,
        }),
        OPT_CUSTOM_BINARY_COPYABLE => Some(CustomKind {
            text: false,
            copyable: true,
        }),
        OPT_CUSTOM_UTF8_NONCOPYABLE => Some(CustomKind {
            text: true,
            copyable: false,
        }),
        OPT_CUSTOM_BINARY_NONCOPYABLE => Some(CustomKind {
            text: false,
            copyable: false,
        }),
        _ => None,
    }
}

/// One Custom Option of a block.
///
/// The format lays it out as the option code, the option length (which
/// INCLUDES the four bytes of the next field), a Private Enterprise Number in
/// the byte order of the section, and the Custom Data padded to four. What the
/// data means is the organization's; this carries it and does not look.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustomOption<'a> {
    /// Where the option sits in its block's list; see [`RawOption::index`].
    pub index: u32,
    /// `2988`, `2989`, `19372` or `19373`.
    pub code: u16,
    /// What the format says of [`Self::code`], classified once, where the option
    /// was found, so that nobody has to look the code up again.
    pub kind: CustomKind,
    /// The Private Enterprise Number of the organization that defined the
    /// option, as the section's byte order reads it.
    pub organization: u32,
    /// The byte order of the section the option's block is in. The format gives
    /// the Custom Data no order of its own, so a number the organization wrote
    /// in it is in this order unless the organization's own definition says
    /// otherwise; a reader that does not know the order has to guess.
    pub byte_order: ByteOrder,
    /// The Custom Data: the option's value after the number, without the
    /// padding.
    pub data: &'a [u8],
}

/// The Custom Options of one block's list, in list order.
///
/// An option with a Custom Option's code but no room for the organization
/// number (a length under four) cannot be read, and is COUNTED rather than
/// skipped without a word: [`Self::malformed`]. The same goes for a list that
/// ends inside an option, where the code of what was lost is not known. A
/// reader that dropped these silently would report a short list as if it were
/// whole.
#[derive(Debug, Clone, Copy)]
pub struct CustomOptions<'a> {
    inner: OptionIter<'a>,
    malformed: u32,
}

impl CustomOptions<'_> {
    /// How many options this walk could not read: a Custom Option too short for
    /// its organization number, and one for a list cut off inside an option.
    /// Complete only once the iterator has returned `None`.
    pub fn malformed(&self) -> u32 {
        self.malformed + u32::from(self.inner.ended_inside_an_option())
    }
}

impl<'a> Iterator for CustomOptions<'a> {
    type Item = CustomOption<'a>;

    fn next(&mut self) -> Option<CustomOption<'a>> {
        let byte_order = self.inner.list.byte_order();
        loop {
            let option = self.inner.next()?;
            let Some(kind) = custom_kind(option.code) else {
                continue;
            };
            let Some((number, data)) = option.value.split_first_chunk::<4>() else {
                self.malformed = self.malformed.saturating_add(1);
                continue;
            };
            return Some(CustomOption {
                index: option.index,
                code: option.code,
                kind,
                organization: match byte_order {
                    ByteOrder::Big => u32::from_be_bytes(*number),
                    ByteOrder::Little => u32::from_le_bytes(*number),
                },
                byte_order,
                data,
            });
        }
    }
}

/// Scan a block's option list for `if_tsresol`.
///
/// An absent or malformed list leaves the default — an option list is
/// metadata, and refusing a whole capture over one is the wrong trade.
fn scan_tsresol(body: &[u8], swapped: bool) -> Option<u8> {
    OptionList::new(body, swapped)
        .iter()
        .find(|o| o.code == OPT_IF_TSRESOL && !o.value.is_empty())
        .map(|o| o.value[0])
}

/// R311y607 — read one u64 option out of an option list.
///
/// Separate from [`scan_tsresol`] because the two disagree on width for a
/// reason: `if_tsresol` is ONE byte and the ISB counters are eight, so the
/// width is the caller's to state and a shared helper must not guess it. Length
/// is checked exactly: a writer that emitted a 4-byte counter is not silently
/// zero-extended into a number a reader would then quote.
fn scan_u64_option(body: &[u8], swapped: bool, want: u16) -> Option<u64> {
    OptionList::new(body, swapped).u64_option(want)
}

/// The option list of a packet block whose fixed part is `fixed` bytes and whose
/// data is `captured` bytes: the options start past the data, padded to four.
/// A block with nothing past the data has an empty list.
fn packet_options(body: &[u8], fixed: usize, captured: usize, swapped: bool) -> OptionList<'_> {
    body.get(fixed + ((captured + 3) & !3)..)
        .map_or(OptionList::empty(), |options| {
            OptionList::new(options, swapped)
        })
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
    /// Which section's interface list `interface_id` indexes, counted from 0.
    /// An interface is named by the pair: ids restart at each Section Header
    /// Block, so the id alone would give two sections' interfaces one name.
    pub section: usize,
    /// Which interface these counters describe, indexing the interface list
    /// of [`Self::section`].
    pub interface_id: u32,
    /// `isb_ifrecv`: packets the interface saw. `None` when unstated — which
    /// is different from zero, and a reader that conflated them would report a
    /// dead interface for a writer that simply omits the option.
    pub received: Option<u64>,
    /// `isb_ifdrop`: packets the capture tool dropped, counted from the START
    /// OF THE CAPTURE to the time of this block. `None` when unstated.
    ///
    /// A running total and not an increment, so two blocks of one interface
    /// state one count twice and do not add. [`DropLedger`] is the place that
    /// knows that.
    pub dropped: Option<u64>,
}

/// What the capture tool admitted losing, as a function of what the file SAYS
/// and not of how often it said it.
///
/// An Interface Statistics Block states `isb_ifdrop` as a total since the start
/// of the capture, and a tool that writes statistics when a count changes
/// (`dumpcap` does) writes the same interface's running total again and again.
/// Summing the blocks counts every packet lost before the last block once for
/// each block written after it: totals 10 and then 17 are 17 lost packets, not
/// 27. So the figure kept per interface is the HIGHEST total stated for it in
/// its section. A loss cannot be undone, so the highest is the floor every
/// block agrees on, and for a file whose totals only grow it is the last.
///
/// Interfaces are told apart by section and id. A new section is a new capture
/// as far as the counters go, so its interfaces start from nothing and add.
///
/// The obsolete Packet Block states an INCREMENT (packets missed since the
/// previous packet on that interface), and increments add. The two kinds land
/// in one total because a consumer asking whether the tool lost anything must
/// not have to know which block type the writer chose. A file that stated one
/// loss both ways would count it twice; no writer is known to, and the obsolete
/// block is not written by anything current.
///
/// Like every figure of its kind this one is a floor: it holds the losses the
/// tool noticed and wrote down.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DropLedger {
    /// The highest `isb_ifdrop` stated for each (section, interface).
    interface_totals: alloc::collections::BTreeMap<(usize, u32), u64>,
    /// The obsolete Packet Block counts, added.
    block_increments: u64,
    /// A sum overflowed, so no number is a floor any more.
    overflowed: bool,
    /// Some block stated a drop count, zero included. Without it the ledger
    /// holds nothing, and a total of nothing is not a total of zero.
    stated: bool,
}

/// What a capture says about the packets its tool dropped. Three answers, because
/// a figure that is a number or `None` made two of them one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropStatement {
    /// No block stated a count: a classic pcap, which has nowhere to put one, or
    /// a pcapng none of whose blocks carries one (no Interface Statistics Block,
    /// or none with `isb_ifdrop`, and no obsolete Packet Block with a count). The
    /// capture does not say whether anything was dropped.
    Unstated,
    /// A block stated a count: the sum, which is zero when every block that spoke
    /// said zero. A capture that was written to its end and lost nothing is this.
    Stated(u64),
    /// Blocks stated counts and the sum does not fit in a `u64`, so no number is
    /// a floor any more.
    Overflowed,
}

impl DropLedger {
    /// An empty ledger: nothing stated, which totals nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Take one Interface Statistics Block. A block that states no `isb_ifdrop`
    /// says nothing about drops, and reading it as zero would turn silence into
    /// a measurement, so it adds nothing and does not make the ledger "stated".
    pub fn note_interface_total(&mut self, stats: &InterfaceStats) {
        let Some(total) = stats.dropped else { return };
        self.stated = true;
        let slot = self
            .interface_totals
            .entry((stats.section, stats.interface_id))
            .or_insert(0);
        *slot = (*slot).max(total);
    }

    /// Take one obsolete Packet Block's drop count, an increment. A count of zero
    /// is a statement (nothing was lost since the previous packet) and makes the
    /// ledger "stated"; a block whose count is unavailable is not noted at all.
    pub fn note_block_increment(&mut self, dropped: u64) {
        self.stated = true;
        match self.block_increments.checked_add(dropped) {
            Some(sum) => self.block_increments = sum,
            None => self.overflowed = true,
        }
    }

    /// What the capture says, in three answers: see [`DropStatement`].
    pub fn statement(&self) -> DropStatement {
        if !self.stated {
            return DropStatement::Unstated;
        }
        let sum = if self.overflowed {
            None
        } else {
            self.interface_totals
                .values()
                .try_fold(self.block_increments, |acc, &d| acc.checked_add(d))
        };
        match sum {
            Some(n) => DropStatement::Stated(n),
            None => DropStatement::Overflowed,
        }
    }

    /// The packets the capture tool reported losing, or `None` when it did not
    /// say (nothing was stated) or the sum does not fit: a wrapped count is a
    /// smaller number than the truth, and this figure exists to stop a floor
    /// being read as a total. [`Self::statement`] tells the two `None`s apart.
    pub fn total(&self) -> Option<u64> {
        match self.statement() {
            DropStatement::Stated(n) => Some(n),
            DropStatement::Unstated | DropStatement::Overflowed => None,
        }
    }
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
    /// rather than a total. Yielded whenever the block STATES a count, a zero
    /// included (it says nothing was lost since the previous packet), and not for
    /// the reserved 0xFFFF that means "unavailable". It manufactures no
    /// [`InterfaceStats`] row the file never carried: it is its own yield.
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

/// How a walk that a sink may cut short ended.
///
/// A separate type from [`Halt`], which is the walk's own account of the
/// container and stays two-valued for every caller that never stops early. A
/// sink that answers [`ControlFlow::Break`] has asked for something the
/// container did not say, and folding that into [`Halt`] would make every
/// existing `match` on it name a case only one caller can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Walk {
    /// The walk ran to where the container ends, and this is why it stopped.
    Halted(Halt),
    /// The sink asked to stop, and the walk stopped after the WHOLE block that
    /// held the yield it answered. Every other yield of that block was still
    /// delivered and the cursor stands on the NEXT block's start, exactly as it
    /// would had the walk continued, so a later call resumes without a gap or a
    /// repeat.
    Stopped,
}

/// [`PcapngYield`] with the packet's bytes BORROWED from the
/// container, for [`PcapngCursor::advance_with`].
///
/// The three non-packet yields are the owned values [`PcapngYield`] carries:
/// they are small, they are the walk's own accounting, and a sink that wants
/// only packets ignores them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcapngYieldRef<'a> {
    /// A packet block, with its capture time already resolved. See
    /// [`PacketRef::ts_millis`].
    Packet(PacketRef<'a>),
    /// A Decryption Secrets Block's payload.
    Secrets(DecryptionSecrets),
    /// An Interface Statistics Block's counters.
    Stats(InterfaceStats),
    /// The obsolete Packet Block's per-block drop count, an INCREMENT, yielded
    /// whenever the block states one (zero included, 0xFFFF excluded).
    PacketBlockDrops {
        /// Which interface lost them.
        interface_id: u32,
        /// How many, since the previous packet on that interface.
        dropped: u64,
    },
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
    ///
    /// A thin owner of [`Self::advance_with`]: each packet's bytes are
    /// copied out of the container before the sink sees them, which is what
    /// [`parse`] wants (it keeps every packet) and what a sink that only reads
    /// and drops does not. There is ONE walk; this and `advance_with` differ in
    /// who owns the bytes.
    pub fn advance<F>(&mut self, bytes: &[u8], mut on: F) -> Result<Halt, PcapngError>
    where
        F: FnMut(PcapngYield),
    {
        match self.advance_with(bytes, |y| {
            on(match y {
                PcapngYieldRef::Packet(p) => PcapngYield::Packet(p.into_packet()),
                PcapngYieldRef::Secrets(s) => PcapngYield::Secrets(s),
                PcapngYieldRef::Stats(s) => PcapngYield::Stats(s),
                PcapngYieldRef::PacketBlockDrops {
                    interface_id,
                    dropped,
                } => PcapngYield::PacketBlockDrops {
                    interface_id,
                    dropped,
                },
            });
            ControlFlow::Continue(())
        })? {
            Walk::Halted(halt) => Ok(halt),
            // The sink above answers `Continue` to every yield, so the walk
            // cannot have been cut short.
            Walk::Stopped => unreachable!("advance never asks its walk to stop"),
        }
    }

    /// [`Self::advance`], handing the sink each packet's bytes as a
    /// BORROW of `bytes` and letting it stop the walk.
    ///
    /// The sink answers [`ControlFlow::Break`] to end the walk. The walk then
    /// finishes the block it is in — every yield of that block is delivered, so
    /// a Packet Block's drop count is never separated from its packet — and
    /// reports [`Walk::Stopped`] with the cursor on the next block, so it is
    /// resumable. A packet the sink never asks to keep costs nothing but reading
    /// its block header.
    ///
    /// Everything else — what a partial tail is, what a malformed block is,
    /// where the cursor stands after either — is [`Self::advance`]'s, because
    /// this is the function that body lives in.
    pub fn advance_with<'b, F>(&mut self, bytes: &'b [u8], mut on: F) -> Result<Walk, PcapngError>
    where
        F: FnMut(PcapngYieldRef<'b>) -> ControlFlow<()>,
    {
        if self.consumed == 0 {
            // The magic, before any length in the file is trusted. Fewer than
            // four bytes is not yet WRONG on a container still being written,
            // so it waits rather than failing.
            if bytes.len() < 4 {
                return Ok(Walk::Halted(Halt::Partial(PcapngError::Truncated {
                    offset: 0,
                })));
            }
            let first = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            if first != BT_SHB {
                return Err(PcapngError::NotPcapng { found: first });
            }
        }
        if bytes.len() < self.consumed {
            return Ok(Walk::Halted(Halt::Partial(PcapngError::Truncated {
                offset: bytes.len(),
            })));
        }

        let mut off = self.consumed;
        while off < bytes.len() {
            if off + MIN_BLOCK_LEN > bytes.len() {
                self.consumed = off;
                return Ok(Walk::Halted(Halt::Partial(PcapngError::Truncated {
                    offset: off,
                })));
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
                return Ok(Walk::Halted(Halt::Partial(PcapngError::Truncated {
                    offset: off,
                })));
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
            // A sink's `Break` is remembered and acted on once the block is
            // done, not at the yield: a block that yields twice (a Packet
            // Block's drop count, then its packet) must not be cut between the
            // two, and the cursor must not stop mid-block.
            let mut stop = false;

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
                    stop |= on(PcapngYieldRef::Packet(PacketRef::resolved(
                        self.index,
                        interface_id,
                        &iface,
                        // The two halves are a single 64-bit count, high word
                        // first. Reading them as a seconds/fraction pair — which
                        // the classic layout invites — is wrong by construction.
                        Some((ts_high << 32) | ts_low),
                        packet_options(body, 20, captured as usize, swapped),
                        &body[20..20 + captured as usize],
                        orig_len,
                    )))
                    .is_break();
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
                    stop |= on(PcapngYieldRef::Packet(PacketRef::resolved(
                        self.index,
                        0,
                        &iface,
                        // An SPB carries no timestamp at all, and the ABSENCE is
                        // what travels rather than a plausible zero (R311y625).
                        None,
                        // Nor any option: an SPB has no option list.
                        OptionList::empty(),
                        &body[4..4 + stored],
                        orig_len,
                    )))
                    .is_break();
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
                    //
                    // The format reserves 0xFFFF for "this information is not
                    // available" (pcapng, Obsolete Packet Block, Drops Count), so
                    // that value is silence and not 65535 lost packets: it is not
                    // yielded. A count of ZERO is a statement and is.
                    let raw_drops = u16_at(body, 2, swapped);
                    let block_drops = u64::from(raw_drops);
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
                    // Yielded BEFORE the packet, and whenever the block states a
                    // count (zero included, 0xFFFF excluded): the count is what
                    // was lost leading UP to this block, so a consumer that stops
                    // on the packet has already been told.
                    if raw_drops != 0xFFFF {
                        stop |= on(PcapngYieldRef::PacketBlockDrops {
                            interface_id,
                            dropped: block_drops,
                        })
                        .is_break();
                    }
                    stop |= on(PcapngYieldRef::Packet(PacketRef::resolved(
                        self.index,
                        interface_id,
                        &iface,
                        Some((ts_high << 32) | ts_low),
                        packet_options(body, 20, captured as usize, swapped),
                        &body[20..20 + captured as usize],
                        orig_len,
                    )))
                    .is_break();
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
                    stop |= on(PcapngYieldRef::Stats(InterfaceStats {
                        // The section being read: `sections` counts those begun,
                        // and an ISB is only read after the SHB that began its.
                        section: self.sections.saturating_sub(1),
                        interface_id,
                        received: scan_u64_option(opts, swapped, OPT_ISB_IFRECV),
                        dropped: scan_u64_option(opts, swapped, OPT_ISB_IFDROP),
                    }))
                    .is_break();
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
                        stop |= on(PcapngYieldRef::Secrets(DecryptionSecrets {
                            secrets_type,
                            secrets: body[8..8 + keep].to_vec(),
                            truncated: 8 + keep < end,
                        }))
                        .is_break();
                    }
                    self.count_skipped(BT_DSB);
                }
                other => self.count_skipped(other),
            }
            off += total;
            self.consumed = off;
            if stop {
                return Ok(Walk::Stopped);
            }
        }
        Ok(Walk::Halted(Halt::Complete))
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
    // R311y607 — what the tool admitted losing, from both block types that can
    // say it. One ledger, because the two state it differently (a running total
    // and an increment) and only the ledger knows how each adds up.
    let mut reported_drops = DropLedger::new();

    let halt = cursor.advance(bytes, |y| match y {
        PcapngYield::Packet(p) => packets.push(p),
        PcapngYield::Secrets(s) => dsb.push(s),
        PcapngYield::Stats(s) => {
            reported_drops.note_interface_total(&s);
            interface_stats.push(s);
        }
        PcapngYield::PacketBlockDrops { dropped, .. } => {
            reported_drops.note_block_increment(dropped);
        }
    })?;
    // A FILE does not grow, so the tail a follower would wait for is this
    // reader's truncation.
    if let Halt::Partial(e) = halt {
        return Err(e);
    }

    Ok(PcapngFile {
        interfaces: cursor.interfaces,
        packets,
        sections: cursor.sections,
        interface_stats,
        reported_drops,
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
    let flagged: Vec<(u32, u64, &[u8], Option<u32>)> = packets
        .iter()
        .map(|&(iface, ticks, data)| (iface, ticks, data, None))
        .collect();
    write_flagged(interfaces, &flagged)
}

/// [`write()`], with an `epb_flags` option (code 2, four bytes) on each packet
/// whose fourth element is `Some`, then `opt_endofopt`. A packet with `None`
/// has no option list, byte for byte what [`write()`] emits.
pub fn write_flagged(
    interfaces: &[(u32, u8)],
    packets: &[(u32, u64, &[u8], Option<u32>)],
) -> Vec<u8> {
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

    for (iface, ticks, data, flags) in packets {
        let pad = (4 - (data.len() % 4)) % 4;
        // epb_flags (4 + 4) and opt_endofopt (4), when there is a flags word.
        let options = if flags.is_some() { 12 } else { 0 };
        let total = 32 + data.len() + pad + options;
        out.extend_from_slice(&BT_EPB.to_le_bytes());
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(&iface.to_le_bytes());
        out.extend_from_slice(&((ticks >> 32) as u32).to_le_bytes());
        out.extend_from_slice(&(*ticks as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
        out.extend_from_slice(&alloc::vec![0u8; pad]);
        if let Some(word) = flags {
            out.extend_from_slice(&OPT_EPB_FLAGS.to_le_bytes());
            out.extend_from_slice(&4u16.to_le_bytes());
            out.extend_from_slice(&word.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // opt_endofopt code
            out.extend_from_slice(&0u16.to_le_bytes()); // opt_endofopt length
        }
        out.extend_from_slice(&(total as u32).to_le_bytes());
    }
    out
}

/// The byte order a section is written in. A pcapng file says which in its
/// Section Header Block, and a reader that handled only its own would pass every
/// fixture made on its own machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder {
    /// Least significant byte first.
    Little,
    /// Most significant byte first.
    Big,
}

impl ByteOrder {
    fn u16(self, v: u16) -> [u8; 2] {
        match self {
            Self::Little => v.to_le_bytes(),
            Self::Big => v.to_be_bytes(),
        }
    }

    fn u32(self, v: u32) -> [u8; 4] {
        match self {
            Self::Little => v.to_le_bytes(),
            Self::Big => v.to_be_bytes(),
        }
    }

    fn u64(self, v: u64) -> [u8; 8] {
        match self {
            Self::Little => v.to_le_bytes(),
            Self::Big => v.to_be_bytes(),
        }
    }
}

/// One packet for [`write_with_options`]: an Enhanced Packet Block whose option
/// list is exactly `options`.
#[derive(Debug, Clone, Copy)]
pub struct PacketSpec<'a> {
    /// The interface it arrived on.
    pub interface: u32,
    /// Its 64-bit tick count.
    pub ticks: u64,
    /// The bytes it stored.
    pub data: &'a [u8],
    /// The option list, in order, as `(code, value)`. The writer pads each value
    /// to four bytes and ends a non-empty list with `opt_endofopt`; an empty
    /// slice writes no list at all.
    pub options: &'a [(u16, &'a [u8])],
}

/// The value of a Custom Option: the Private Enterprise Number in `order`, then
/// the Custom Data. The option LENGTH a writer states for it is this value's
/// length, which includes the four bytes of the number.
pub fn custom_option_value(order: ByteOrder, organization: u32, data: &[u8]) -> Vec<u8> {
    let mut value = order.u32(organization).to_vec();
    value.extend_from_slice(data);
    value
}

/// A pcapng file in `order` whose packets carry the option lists they are given.
///
/// What [`write_flagged`] is for one option in native order, this is for any
/// list in either: the fixture for Custom Options, repeated options, odd value
/// lengths that need padding, and a big-endian section. Laid out from the format
/// and not through the reader under test, and the tests pair it with byte-level
/// assertions for the same reason [`write`] is.
pub fn write_with_options(
    order: ByteOrder,
    interfaces: &[(u32, u8)],
    packets: &[PacketSpec<'_>],
) -> Vec<u8> {
    let mut out = Vec::new();
    // SHB: type, length, BOM, major, minor, section length (-1 = unknown).
    out.extend_from_slice(&order.u32(BT_SHB));
    out.extend_from_slice(&order.u32(28));
    out.extend_from_slice(&order.u32(BOM));
    out.extend_from_slice(&order.u16(1));
    out.extend_from_slice(&order.u16(0));
    out.extend_from_slice(&order.u64(u64::MAX));
    out.extend_from_slice(&order.u32(28));

    for (link_type, ts_resol) in interfaces {
        out.extend_from_slice(&order.u32(BT_IDB));
        out.extend_from_slice(&order.u32(32));
        out.extend_from_slice(&order.u16(*link_type as u16));
        out.extend_from_slice(&order.u16(0));
        out.extend_from_slice(&order.u32(0));
        out.extend_from_slice(&order.u16(OPT_IF_TSRESOL));
        out.extend_from_slice(&order.u16(1));
        out.extend_from_slice(&[*ts_resol, 0, 0, 0]);
        out.extend_from_slice(&order.u16(0));
        out.extend_from_slice(&order.u16(0));
        out.extend_from_slice(&order.u32(32));
    }

    for packet in packets {
        let pad = (4 - (packet.data.len() % 4)) % 4;
        let mut list = Vec::new();
        for (code, value) in packet.options {
            list.extend_from_slice(&order.u16(*code));
            list.extend_from_slice(&order.u16(value.len() as u16));
            list.extend_from_slice(value);
            list.extend_from_slice(&alloc::vec![0u8; (4 - (value.len() % 4)) % 4]);
        }
        if !list.is_empty() {
            list.extend_from_slice(&order.u16(0)); // opt_endofopt code
            list.extend_from_slice(&order.u16(0)); // opt_endofopt length
        }
        let total = 32 + packet.data.len() + pad + list.len();
        out.extend_from_slice(&order.u32(BT_EPB));
        out.extend_from_slice(&order.u32(total as u32));
        out.extend_from_slice(&order.u32(packet.interface));
        out.extend_from_slice(&order.u32((packet.ticks >> 32) as u32));
        out.extend_from_slice(&order.u32(packet.ticks as u32));
        out.extend_from_slice(&order.u32(packet.data.len() as u32));
        out.extend_from_slice(&order.u32(packet.data.len() as u32));
        out.extend_from_slice(packet.data);
        out.extend_from_slice(&alloc::vec![0u8; pad]);
        out.extend_from_slice(&list);
        out.extend_from_slice(&order.u32(total as u32));
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

    /// A base-2 resolution is exact at a real epoch instant, in both readings.
    ///
    /// The test above reads ONE second of ticks, where the old conversion (ticks
    /// over `per_sec / 1000`, which is 1 048 for 2^20) is off by half a
    /// millisecond and floors back to the right answer. At 1.7e9 seconds the same
    /// error is 9.4e8 seconds, and only an instant that large can see it. The
    /// expected values are arithmetic on the number the file was written from.
    #[test]
    fn a_base_2_resolution_is_exact_at_a_real_epoch_instant() {
        const SECS: u64 = 1_700_000_000;
        // 123_456 ticks of 2^-20 s is 117.7 ms; 117_737_548.8 ns, floored.
        let frac_ticks = 123_456u64;
        let ticks = (SECS << 20) + frac_ticks;
        let file = write(&[(1, 0x80 | 20)], &[(0, ticks, &[0xAA])]);
        let parsed = parse(&file).expect("parse");
        let want_ns = SECS * 1_000_000_000 + frac_ticks * 1_000_000_000 / (1 << 20);
        assert_eq!(parsed.packets[0].ts_nanos, Some(want_ns));
        assert_eq!(parsed.ts_nanos(&parsed.packets[0]), Some(want_ns));
        assert_eq!(
            parsed.ts_millis(&parsed.packets[0]),
            Some(want_ns / 1_000_000)
        );
        assert_eq!(
            parsed.ts_millis(&parsed.packets[0]),
            Some(SECS * 1_000 + 117),
            "the instant is 117 ms past the whole second"
        );
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
        assert!(
            parsed.interface_stats.is_empty(),
            "a PB states no interface statistics, and inventing a row would claim a received count"
        );
        assert_eq!(
            parsed.reported_drops.total(),
            Some(7),
            "3 + 4, summed across the blocks rather than last-write-wins"
        );
    }

    /// A statistics block with `isb_ifdrop` for one interface of a section.
    fn isb_stats(interface_id: u32, dropped: Option<u64>) -> Vec<u8> {
        isb(interface_id, None, dropped)
    }

    /// A running total written again is the same loss, not a new one. This is
    /// the shape `dumpcap` writes: a block each time the count changes, each
    /// stating the total so far, so 10 and then 17 are 17 packets.
    #[test]
    fn a_running_total_written_twice_is_counted_once() {
        let mut file = write(&[(1, 6)], &[]);
        file.extend_from_slice(&isb_stats(0, Some(10)));
        file.extend_from_slice(&isb_stats(0, Some(17)));
        let parsed = parse(&file).expect("parse");
        assert_eq!(parsed.interface_stats.len(), 2, "both blocks are kept");
        assert_eq!(parsed.reported_drops.total(), Some(17));
    }

    /// Interfaces are separate losses and add; the same interface does not.
    #[test]
    fn interfaces_add_and_one_interface_does_not() {
        let mut file = write(&[(1, 6), (1, 6)], &[]);
        file.extend_from_slice(&isb_stats(0, Some(9)));
        file.extend_from_slice(&isb_stats(1, Some(3)));
        file.extend_from_slice(&isb_stats(0, Some(12)));
        file.extend_from_slice(&isb_stats(1, Some(3)));
        let parsed = parse(&file).expect("parse");
        assert_eq!(parsed.reported_drops.total(), Some(12 + 3));
    }

    /// The highest stated total wins and not the last block: a loss cannot be
    /// undone, so a later, smaller figure is a writer's mistake and must not
    /// lower what an earlier block already admitted.
    #[test]
    fn the_highest_total_stands_when_a_later_block_states_less() {
        let mut file = write(&[(1, 6)], &[]);
        file.extend_from_slice(&isb_stats(0, Some(17)));
        file.extend_from_slice(&isb_stats(0, Some(5)));
        let parsed = parse(&file).expect("parse");
        assert_eq!(parsed.reported_drops.total(), Some(17));
    }

    /// A block that states no `isb_ifdrop` neither adds nor resets: between two
    /// blocks that do state it, it says nothing.
    #[test]
    fn a_block_without_the_option_changes_nothing() {
        let mut file = write(&[(1, 6)], &[]);
        file.extend_from_slice(&isb_stats(0, Some(10)));
        file.extend_from_slice(&isb_stats(0, None));
        file.extend_from_slice(&isb_stats(0, Some(11)));
        let parsed = parse(&file).expect("parse");
        assert_eq!(parsed.reported_drops.total(), Some(11));
    }

    /// A new section is a new capture as far as the counters go: its interface
    /// 0 is not the first section's interface 0, and the two add.
    #[test]
    fn a_new_section_starts_its_interfaces_counters_again() {
        let mut file = write(&[(1, 6)], &[]);
        file.extend_from_slice(&isb_stats(0, Some(10)));
        file.extend_from_slice(&write(&[(1, 6)], &[]));
        file.extend_from_slice(&isb_stats(0, Some(4)));
        let parsed = parse(&file).expect("parse");
        assert_eq!(parsed.sections, 2);
        assert_eq!(
            parsed
                .interface_stats
                .iter()
                .map(|s| s.section)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        assert_eq!(parsed.reported_drops.total(), Some(10 + 4));
    }

    /// Increments from an obsolete block add to the totals of the current ones.
    #[test]
    fn block_increments_and_interface_totals_share_one_figure() {
        let mut ledger = DropLedger::new();
        ledger.note_block_increment(3);
        ledger.note_interface_total(&InterfaceStats {
            section: 0,
            interface_id: 0,
            received: None,
            dropped: Some(10),
        });
        ledger.note_interface_total(&InterfaceStats {
            section: 0,
            interface_id: 0,
            received: None,
            dropped: Some(17),
        });
        assert_eq!(ledger.total(), Some(20));
    }

    /// A sum that does not fit is not a number, rather than a wrapped smaller
    /// one: the figure exists to stop a floor being read as a total.
    #[test]
    fn a_sum_that_overflows_is_none() {
        let mut ledger = DropLedger::new();
        for interface_id in 0..2 {
            ledger.note_interface_total(&InterfaceStats {
                section: 0,
                interface_id,
                received: None,
                dropped: Some(u64::MAX),
            });
        }
        assert_eq!(ledger.total(), None);

        let mut ledger = DropLedger::new();
        ledger.note_block_increment(u64::MAX);
        ledger.note_block_increment(1);
        assert_eq!(ledger.total(), None);
        assert_eq!(
            ledger.statement(),
            DropStatement::Overflowed,
            "an overflow is told apart from silence"
        );
    }

    /// A ledger nothing was ever noted in says nothing, and that is not zero: a
    /// capture none of whose blocks states a count does not say it lost nothing.
    /// Every way of stating a count, zero included, is a statement; every way of
    /// being silent is not.
    #[test]
    fn a_ledger_told_nothing_says_nothing_and_a_stated_zero_says_zero() {
        let silent = DropLedger::new();
        assert_eq!(silent.statement(), DropStatement::Unstated);
        assert_eq!(
            silent.total(),
            None,
            "no block spoke, so there is no figure"
        );

        // An ISB without `isb_ifdrop` is silence, whatever else it states.
        let mut ledger = DropLedger::new();
        ledger.note_interface_total(&InterfaceStats {
            section: 0,
            interface_id: 0,
            received: Some(40),
            dropped: None,
        });
        assert_eq!(ledger.statement(), DropStatement::Unstated);

        // An `isb_ifdrop` of zero is a claim that nothing was dropped.
        ledger.note_interface_total(&InterfaceStats {
            section: 0,
            interface_id: 0,
            received: Some(40),
            dropped: Some(0),
        });
        assert_eq!(ledger.statement(), DropStatement::Stated(0));
        assert_eq!(ledger.total(), Some(0));

        // So is an obsolete Packet Block's count of zero.
        let mut ledger = DropLedger::new();
        ledger.note_block_increment(0);
        assert_eq!(ledger.statement(), DropStatement::Stated(0));
    }

    /// The same distinction read out of bytes: a pcapng whose blocks state no
    /// count, whose statistics block omits the option, whose Packet Block marks
    /// the count unavailable (0xFFFF, which is not 65535 lost packets), and one
    /// that states zero.
    #[test]
    fn a_file_that_states_no_count_has_no_total_and_one_that_states_zero_has_zero() {
        // No statistics block and no obsolete block at all.
        let parsed = parse(&write(&[(1, 6)], &[(0, 1_000, &[0u8; 4])])).expect("parse");
        assert_eq!(parsed.reported_drops.total(), None);

        // A statistics block that does not state `isb_ifdrop`.
        let mut file = write(&[(1, 6)], &[]);
        file.extend_from_slice(&isb_stats(0, None));
        assert_eq!(parse(&file).expect("parse").reported_drops.total(), None);

        // The same block stating zero.
        let mut file = write(&[(1, 6)], &[]);
        file.extend_from_slice(&isb_stats(0, Some(0)));
        assert_eq!(parse(&file).expect("parse").reported_drops.total(), Some(0));

        // An obsolete Packet Block whose count is the reserved "unavailable".
        let mut file = write(&[(1, 6)], &[]);
        file.extend_from_slice(&pb(0, 0xFFFF, &[0xAA, 0xBB]));
        let parsed = parse(&file).expect("parse");
        assert_eq!(parsed.packets.len(), 1, "the packet still reads");
        assert_eq!(
            parsed.reported_drops.total(),
            None,
            "0xFFFF is silence, not 65535 packets"
        );

        // An obsolete Packet Block that states zero.
        let mut file = write(&[(1, 6)], &[]);
        file.extend_from_slice(&pb(0, 0, &[0xAA, 0xBB]));
        assert_eq!(parse(&file).expect("parse").reported_drops.total(), Some(0));
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

    /// One obsolete Packet Block, laid out per the pcapng spec (§ Obsolete
    /// Packet Block): block type, total length, interface id u16, drops u16,
    /// timestamp halves, captured and original length, the data padded to 4,
    /// the trailing length. Hand-laid because [`write`] emits only Enhanced
    /// Packet Blocks.
    fn pb(interface_id: u16, drops: u16, data: &[u8]) -> Vec<u8> {
        let pad = (4 - (data.len() % 4)) % 4;
        let total = 32 + data.len() + pad;
        let mut out = Vec::new();
        out.extend_from_slice(&BT_PB.to_le_bytes());
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(&interface_id.to_le_bytes());
        out.extend_from_slice(&drops.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1_000u32.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
        out.extend_from_slice(&alloc::vec![0u8; pad]);
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out
    }

    /// The borrowing walk and the owning one are ONE walk.
    ///
    /// `advance` became a thin owner of `advance_with`, and the claim that they
    /// differ only in who owns a packet's bytes is worth nothing as a comment.
    /// The fixture carries every kind of yield the walk produces — packets on
    /// two interfaces, a second section on another link type, an Interface
    /// Statistics Block, and an obsolete Packet Block with a drop count — and
    /// the two sequences must be equal, in order.
    #[test]
    fn the_borrowing_walk_yields_what_the_owning_walk_yields() {
        let mut file = write(
            &[(1, 6), (101, 9)],
            &[(0, 1_000, &[1, 2, 3]), (1, 2_000, &[4, 5, 6, 7, 8])],
        );
        file.extend_from_slice(&isb(0, Some(10), Some(2)));
        file.extend_from_slice(&pb(0, 2, &[0xAA, 0xBB]));
        file.extend_from_slice(&write(&[(113, 6)], &[(0, 3_000, &[9])]));

        let mut owned: Vec<PcapngYield> = Vec::new();
        let halt = PcapngCursor::new()
            .advance(&file, |y| owned.push(y))
            .expect("the fixture reads");
        assert_eq!(halt, Halt::Complete);

        let mut borrowed: Vec<PcapngYield> = Vec::new();
        let walk = PcapngCursor::new()
            .advance_with(&file, |y| {
                borrowed.push(match y {
                    PcapngYieldRef::Packet(p) => PcapngYield::Packet(p.into_packet()),
                    PcapngYieldRef::Secrets(s) => PcapngYield::Secrets(s),
                    PcapngYieldRef::Stats(s) => PcapngYield::Stats(s),
                    PcapngYieldRef::PacketBlockDrops {
                        interface_id,
                        dropped,
                    } => PcapngYield::PacketBlockDrops {
                        interface_id,
                        dropped,
                    },
                });
                ControlFlow::Continue(())
            })
            .expect("the fixture reads");
        assert_eq!(walk, Walk::Halted(Halt::Complete));

        assert_eq!(owned, borrowed, "the two walks yielded different things");
        let kinds = |pred: fn(&PcapngYield) -> bool| owned.iter().filter(|y| pred(y)).count();
        assert!(
            kinds(|y| matches!(y, PcapngYield::Packet(_))) >= 4
                && kinds(|y| matches!(y, PcapngYield::Stats(_))) == 1
                && kinds(|y| matches!(y, PcapngYield::PacketBlockDrops { .. })) == 1,
            "the fixture must exercise every yield the walk produces: {owned:?}"
        );
    }

    /// A walk the sink stops resumes where it stopped.
    ///
    /// For every packet in turn: stop after it, and the cursor must have
    /// counted it and nothing after it; a second call over the same container
    /// must then yield exactly the packets `parse` holds beyond it. A stop that
    /// left the cursor on the packet it just delivered would repeat it, and one
    /// that stopped short would lose it.
    #[test]
    fn a_walk_stopped_by_its_sink_resumes_where_it_stopped() {
        let file = write(
            &[(1, 6), (101, 9)],
            &[
                (0, 1_000, &[1, 2, 3]),
                (1, 2_000, &[4, 5, 6, 7, 8]),
                (0, 3_000, &[9]),
            ],
        );
        let whole = parse(&file).expect("the fixture reads");
        assert!(whole.packets.len() >= 3, "the population must not be empty");

        for stop_at in 0..whole.packets.len() {
            let mut cursor = PcapngCursor::new();
            let mut seen: Vec<usize> = Vec::new();
            let walk = cursor
                .advance_with(&file, |y| {
                    if let PcapngYieldRef::Packet(p) = y {
                        seen.push(p.index);
                        if p.index == stop_at {
                            return ControlFlow::Break(());
                        }
                    }
                    ControlFlow::Continue(())
                })
                .expect("the fixture reads");
            assert_eq!(walk, Walk::Stopped, "stopping at packet {stop_at}");
            assert_eq!(
                seen,
                (0..=stop_at).collect::<Vec<_>>(),
                "the walk delivered a packet after the one it was told to stop at"
            );
            assert_eq!(cursor.packets_produced(), stop_at + 1);

            let mut rest: Vec<Packet> = Vec::new();
            let resumed = cursor
                .advance(&file, |y| {
                    if let PcapngYield::Packet(p) = y {
                        rest.push(p);
                    }
                })
                .expect("the container reads on");
            assert_eq!(resumed, Halt::Complete);
            assert_eq!(
                rest,
                whole.packets[stop_at + 1..].to_vec(),
                "resuming after a stop at packet {stop_at} repeated or lost a packet"
            );
        }
    }

    /// A stop is honoured at the end of the BLOCK, never inside it.
    ///
    /// An obsolete Packet Block yields its drop count and then its packet. A
    /// sink that breaks on the first must still be handed the second, because
    /// the walk has already counted that packet and a cursor that stood on the
    /// next block with the packet undelivered would have lost it.
    #[test]
    fn a_stop_does_not_split_a_packet_block_from_its_drop_count() {
        let mut file = write(&[(1, 6)], &[]);
        file.extend_from_slice(&pb(0, 3, &[0xAA, 0xBB]));

        let mut cursor = PcapngCursor::new();
        let mut order: Vec<&'static str> = Vec::new();
        let walk = cursor
            .advance_with(&file, |y| {
                order.push(match y {
                    PcapngYieldRef::PacketBlockDrops { .. } => "drops",
                    PcapngYieldRef::Packet(_) => "packet",
                    _ => "other",
                });
                ControlFlow::Break(())
            })
            .expect("the fixture reads");
        assert_eq!(walk, Walk::Stopped);
        assert_eq!(
            order,
            ["drops", "packet"],
            "the block's second yield was withheld after the first said stop"
        );
        assert_eq!(cursor.packets_produced(), 1);
        assert_eq!(
            cursor.consumed(),
            file.len(),
            "the cursor must stand past the whole block"
        );
    }
}

/// The option reader: the three loops it replaced, the Custom Options it reads
/// and the lists it must survive.
#[cfg(test)]
mod custom_option_tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::ops::ControlFlow;

    /// The three scanners as they were before they shared one reader, kept here
    /// as the REFERENCE the shared reader is graded against: the claim of the
    /// change is "no list reads differently", and a claim like that is only as
    /// good as the oracle it is compared with. Copied, not reimplemented.
    mod before {
        use super::super::{u16_at, u32_at, OPT_IF_TSRESOL};

        pub fn scan_tsresol(body: &[u8], swapped: bool) -> Option<u8> {
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
                off += (len + 3) & !3;
            }
            None
        }

        pub fn scan_u64_option(body: &[u8], swapped: bool, want: u16) -> Option<u64> {
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

        pub fn scan_u32_option(body: &[u8], swapped: bool, want: u16) -> Option<u32> {
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
                if code == want && len == 4 {
                    return Some(u32_at(body, off, swapped));
                }
                off += (len + 3) & !3;
            }
            None
        }
    }

    /// A deterministic generator: xorshift64*, so a failure reproduces.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn order_of(round: usize) -> (ByteOrder, bool) {
        if round & 1 == 0 {
            (ByteOrder::Little, false)
        } else {
            (ByteOrder::Big, true)
        }
    }

    /// One option, laid out as the format does: code, length, the value, padded.
    fn put(list: &mut Vec<u8>, order: ByteOrder, code: u16, length: u16, value: &[u8]) {
        list.extend_from_slice(&order.u16(code));
        list.extend_from_slice(&order.u16(length));
        list.extend_from_slice(value);
        if value.len() == usize::from(length) {
            list.extend_from_slice(&vec![0u8; (4 - value.len() % 4) % 4]);
        }
    }

    /// A list that lies: lengths longer than the bytes, terminators in the
    /// middle, stray bytes after the end and cuts at any byte. The population the
    /// old loops had to survive and the new reader must agree with them on.
    fn wild_list(rng: &mut Rng, order: ByteOrder) -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..rng.below(7) {
            let code = match rng.below(12) {
                0 => 0,
                1 => 2,
                2 => 4,
                3 => 5,
                4 => 9,
                5 => OPT_CUSTOM_UTF8_COPYABLE,
                6 => OPT_CUSTOM_BINARY_COPYABLE,
                7 => OPT_CUSTOM_UTF8_NONCOPYABLE,
                8 => OPT_CUSTOM_BINARY_NONCOPYABLE,
                9 => 1,
                _ => rng.below(65_536) as u16,
            };
            let length = if rng.below(8) == 0 {
                rng.below(70) as u16
            } else {
                [0u16, 1, 2, 3, 4, 5, 8, 12, 16][rng.below(9) as usize]
            };
            let have = if rng.below(10) == 0 {
                rng.below(u64::from(length) + 1) as usize
            } else {
                usize::from(length)
            };
            let value: Vec<u8> = (0..have).map(|_| rng.next() as u8).collect();
            put(&mut out, order, code, length, &value);
        }
        match rng.below(4) {
            0 => out.extend_from_slice(&[0; 4]),
            1 => out.extend_from_slice(&[7, 7]),
            _ => {}
        }
        if rng.below(6) == 0 && !out.is_empty() {
            let cut = rng.below(out.len() as u64) as usize;
            out.truncate(cut);
        }
        out
    }

    /// The change moved three loops into one reader, and the claim is that no
    /// list reads differently. 60 000 lists in both byte orders, among them the
    /// ones that lie, are read by the reference loops and by the shared reader,
    /// and every answer is the same. The counts at the end say the population
    /// held lists the readers actually found something in, so equal silence is
    /// not what passed.
    #[test]
    fn the_shared_reader_reads_every_list_as_the_three_loops_did() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut found = [0usize; 3];
        for round in 0..60_000 {
            let (order, swapped) = order_of(round);
            let list = wild_list(&mut rng, order);
            let shared = OptionList::new(&list, swapped);
            assert_eq!(
                scan_tsresol(&list, swapped),
                before::scan_tsresol(&list, swapped),
                "if_tsresol over {list:?} ({order:?})"
            );
            found[0] += usize::from(scan_tsresol(&list, swapped).is_some());
            for want in [2u16, 4, 5] {
                let (u64_new, u64_old) = (
                    shared.u64_option(want),
                    before::scan_u64_option(&list, swapped, want),
                );
                assert_eq!(u64_new, u64_old, "u64 {want} over {list:?} ({order:?})");
                let (u32_new, u32_old) = (
                    shared.u32_option(want),
                    before::scan_u32_option(&list, swapped, want),
                );
                assert_eq!(u32_new, u32_old, "u32 {want} over {list:?} ({order:?})");
                found[1] += usize::from(u64_new.is_some());
                found[2] += usize::from(u32_new.is_some());
            }
        }
        assert!(
            found.iter().all(|&n| n > 500),
            "the lists must hold options the readers find: {found:?}"
        );
    }

    /// The list a writer lays out is the list the reader reads back, option by
    /// option: for any mix of Custom Options of the four codes among others, in
    /// either byte order, repeats and empty data and every padding included. The
    /// truth is the structure that generated the bytes, not the reader.
    #[test]
    fn a_written_list_reads_back_as_it_was_generated() {
        let mut rng = Rng(0xC0FF_EE00_1234_5678);
        let codes = [
            OPT_CUSTOM_UTF8_COPYABLE,
            OPT_CUSTOM_BINARY_COPYABLE,
            OPT_CUSTOM_UTF8_NONCOPYABLE,
            OPT_CUSTOM_BINARY_NONCOPYABLE,
        ];
        let mut seen = 0usize;
        for round in 0..20_000 {
            let (order, swapped) = order_of(round);
            let mut list = Vec::new();
            let mut expected: Vec<(u32, u16, u32, Vec<u8>)> = Vec::new();
            for index in 0..rng.below(7) as u32 {
                if rng.below(3) == 0 {
                    // An option that is not a Custom Option, which must be
                    // stepped over without disturbing the index of the rest.
                    let value: Vec<u8> = (0..rng.below(9)).map(|_| rng.next() as u8).collect();
                    put(
                        &mut list,
                        order,
                        [1u16, 2, 9][rng.below(3) as usize],
                        value.len() as u16,
                        &value,
                    );
                } else {
                    let code = codes[rng.below(4) as usize];
                    let organization = rng.next() as u32;
                    let data: Vec<u8> = (0..rng.below(21)).map(|_| rng.next() as u8).collect();
                    let value = custom_option_value(order, organization, &data);
                    put(&mut list, order, code, value.len() as u16, &value);
                    expected.push((index, code, organization, data));
                }
            }
            if rng.below(2) == 0 {
                list.extend_from_slice(&[0; 4]);
            }
            let mut custom = OptionList::new(&list, swapped).custom();
            let read: Vec<(u32, u16, u32, Vec<u8>)> = custom
                .by_ref()
                .map(|o| (o.index, o.code, o.organization, o.data.to_vec()))
                .collect();
            assert_eq!(read, expected, "list {list:?} ({order:?})");
            assert_eq!(
                custom.malformed(),
                0,
                "a well-formed list has nothing malformed"
            );
            seen += read.len();
        }
        assert!(
            seen > 20_000,
            "the population must hold Custom Options: {seen}"
        );
    }

    /// Bytes that are not a list at all. Nothing may panic, and what the reader
    /// does hand out is inside the list: each Custom Option's data lies within
    /// the bytes it was read from, directly after the four bytes of the number
    /// that was decoded, its code is one of the four, and the positions rise.
    #[test]
    fn any_bytes_read_without_a_panic_and_every_range_stays_inside() {
        let mut rng = Rng(0xDEAD_BEEF_0BAD_F00D);
        for round in 0..60_000 {
            let (_, swapped) = order_of(round);
            let len = rng.below(90) as usize;
            let mut list: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            // Steer a share of them toward real options so that the walk goes
            // past the first header.
            if len >= 8 && rng.below(2) == 0 {
                let code = [2988u16, 2989, 19372, 19373][rng.below(4) as usize];
                let (hi, lo) = (code >> 8, code & 0xFF);
                let length = rng.below(40) as u16;
                if swapped {
                    list[..4].copy_from_slice(&[
                        hi as u8,
                        lo as u8,
                        (length >> 8) as u8,
                        length as u8,
                    ]);
                } else {
                    list[..4].copy_from_slice(&[
                        lo as u8,
                        hi as u8,
                        length as u8,
                        (length >> 8) as u8,
                    ]);
                }
            }
            let base = list.as_ptr() as usize;
            let mut previous: Option<u32> = None;
            let mut custom = OptionList::new(&list, swapped).custom();
            for option in custom.by_ref() {
                assert!(custom_kind(option.code).is_some());
                if let Some(before) = previous {
                    assert!(option.index > before, "positions rise");
                }
                previous = Some(option.index);
                let at = option.data.as_ptr() as usize;
                assert!(at >= base + 4, "the number comes first");
                assert!(
                    at + option.data.len() <= base + list.len(),
                    "inside the list"
                );
                let number = &list[at - base - 4..at - base];
                let expected = if swapped {
                    u32::from_be_bytes(number.try_into().unwrap())
                } else {
                    u32::from_le_bytes(number.try_into().unwrap())
                };
                assert_eq!(option.organization, expected);
                assert_eq!(
                    option.byte_order,
                    if swapped {
                        ByteOrder::Big
                    } else {
                        ByteOrder::Little
                    },
                    "the option says the order of the list it was read from"
                );
            }
            let _ = custom.malformed();
            for (expected_index, option) in OptionList::new(&list, swapped).iter().enumerate() {
                assert_eq!(
                    option.index as usize, expected_index,
                    "positions are consecutive"
                );
                let at = option.value.as_ptr() as usize;
                assert!(at >= base && at + option.value.len() <= base + list.len());
            }
        }
    }

    /// The four codes and what the format says of each.
    ///
    /// The pcapng format's Custom Options section, read for this table:
    ///
    /// - 2988: "a Custom Option containing a UTF-8 string in the Custom Data
    ///   portion", of which "This Custom Option can be safely copied to a new
    ///   file if the pcapng file is manipulated by an application; otherwise
    ///   19372 should be used instead."
    /// - 2989: the same for "binary octets", copyable.
    /// - 19372, 19373: the string and the binary kind of which "This Custom
    ///   Option should not be copied to a new file if the pcapng file is
    ///   manipulated by an application."
    ///
    /// A table that changed would change what a writer's option is called
    /// copyable, so it is pinned here, and the structure under it is checked too:
    /// the non-copyable code of each kind is the copyable one plus 16384.
    #[test]
    fn the_four_custom_codes_are_classified_as_the_formats_text_says() {
        let kind = |text, copyable| Some(CustomKind { text, copyable });
        assert_eq!(custom_kind(2988), kind(true, true));
        assert_eq!(custom_kind(2989), kind(false, true));
        assert_eq!(custom_kind(19372), kind(true, false));
        assert_eq!(custom_kind(19373), kind(false, false));
        assert_eq!(
            OPT_CUSTOM_UTF8_NONCOPYABLE - OPT_CUSTOM_UTF8_COPYABLE,
            16_384
        );
        assert_eq!(
            OPT_CUSTOM_BINARY_NONCOPYABLE - OPT_CUSTOM_BINARY_COPYABLE,
            16_384
        );
        for code in [0u16, 1, 2, 9, 2987, 2990, 19371, 19374, 0x8000, 0xFFFF] {
            assert_eq!(
                custom_kind(code),
                None,
                "code {code} is not a Custom Option"
            );
        }
    }

    /// The writer lays a Custom Option out as the format does, asserted at the
    /// BYTE level against the format and not against the reader, in both byte
    /// orders, and the reader finds it in each. The option length is 16 for a
    /// 12-byte datum because it counts the four bytes of the number.
    #[test]
    fn the_writer_lays_a_custom_option_out_as_the_format_does_and_both_orders_read_it() {
        let data = [0xAAu8; 12];
        for order in [ByteOrder::Little, ByteOrder::Big] {
            let value = custom_option_value(order, 0x0102_0304, &data);
            assert_eq!(value.len(), 16);
            let file = write_with_options(
                order,
                &[(147, 6)],
                &[PacketSpec {
                    interface: 0,
                    ticks: 5,
                    data: &[1, 2, 3, 4],
                    options: &[(OPT_CUSTOM_BINARY_NONCOPYABLE, &value)],
                }],
            );
            // The byte-order magic is the section's own statement of its order.
            let bom: &[u8] = match order {
                ByteOrder::Little => &[0x4D, 0x3C, 0x2B, 0x1A],
                ByteOrder::Big => &[0x1A, 0x2B, 0x3C, 0x4D],
            };
            assert_eq!(&file[8..12], bom);
            // SHB 28, one IDB 32, the packet block's fixed part 28 and 4 data.
            let at = 28 + 32 + 28 + 4;
            let header: &[u8] = match order {
                ByteOrder::Little => &[0xAD, 0x4B, 16, 0, 4, 3, 2, 1],
                ByteOrder::Big => &[0x4B, 0xAD, 0, 16, 1, 2, 3, 4],
            };
            assert_eq!(&file[at..at + 8], header, "{order:?}");
            assert_eq!(&file[at + 8..at + 20], &data);
            assert_eq!(&file[at + 20..at + 24], &[0, 0, 0, 0], "opt_endofopt");

            let mut read = Vec::new();
            PcapngCursor::new()
                .advance_with(&file, |y| {
                    if let PcapngYieldRef::Packet(p) = y {
                        read.extend(p.options.custom().map(|o| {
                            (
                                o.index,
                                o.code,
                                o.organization,
                                o.byte_order,
                                o.data.to_vec(),
                            )
                        }));
                    }
                    ControlFlow::Continue(())
                })
                .expect("the fixture reads");
            // The order the option reports is the one the file's magic states,
            // asserted above, and not the order of the machine that read it.
            assert_eq!(
                read,
                vec![(0, 19373, 0x0102_0304, order, data.to_vec())],
                "{order:?}"
            );
        }
    }

    /// Repeats come out in list order, every one of them, with their place in
    /// the block's list counting the options between them that are not Custom
    /// Options; an option of exactly four bytes is an organization with no data.
    #[test]
    fn repeated_options_come_out_in_order_with_their_place_in_the_list() {
        let order = ByteOrder::Little;
        let mut list = Vec::new();
        put(&mut list, order, 1, 3, b"hi!"); // opt_comment, padded
        let first = custom_option_value(order, 7, b"one");
        put(
            &mut list,
            order,
            OPT_CUSTOM_UTF8_COPYABLE,
            first.len() as u16,
            &first,
        );
        let second = custom_option_value(order, 7, b"");
        put(&mut list, order, OPT_CUSTOM_UTF8_COPYABLE, 4, &second);
        let third = custom_option_value(order, 9, &[0xEE; 5]);
        put(
            &mut list,
            order,
            OPT_CUSTOM_BINARY_COPYABLE,
            third.len() as u16,
            &third,
        );
        list.extend_from_slice(&[0; 4]);
        let mut custom = OptionList::new(&list, false).custom();
        let read: Vec<(u32, u16, u32, usize)> = custom
            .by_ref()
            .map(|o| (o.index, o.code, o.organization, o.data.len()))
            .collect();
        assert_eq!(
            read,
            vec![(1, 2988, 7, 3), (2, 2988, 7, 0), (3, 2989, 9, 5)]
        );
        assert_eq!(custom.malformed(), 0);
    }

    /// What cannot be read is COUNTED, and what can be is still read. A Custom
    /// Option with no room for its number is passed over and counted, and the
    /// option after it is found. A list cut off inside an option stops there and
    /// counts that, whatever the option's code was. The list ending without a
    /// terminator, with stray bytes too few to be a header, and with bytes after a
    /// terminator, are none of them malformed.
    #[test]
    fn what_cannot_be_read_is_counted_and_the_rest_still_is() {
        let order = ByteOrder::Little;
        let good = custom_option_value(order, 3, b"ok");

        // Too short for the number: 2 bytes where 4 are owed.
        let mut list = Vec::new();
        put(&mut list, order, OPT_CUSTOM_BINARY_COPYABLE, 2, &[1, 2]);
        put(
            &mut list,
            order,
            OPT_CUSTOM_BINARY_COPYABLE,
            good.len() as u16,
            &good,
        );
        let mut custom = OptionList::new(&list, false).custom();
        let read: Vec<u32> = custom.by_ref().map(|o| o.index).collect();
        assert_eq!((read, custom.malformed()), (vec![1], 1));

        // Cut inside the option: it says 16 and 6 bytes follow.
        let mut cut = Vec::new();
        put(&mut cut, order, OPT_CUSTOM_BINARY_NONCOPYABLE, 16, &[0; 6]);
        let mut custom = OptionList::new(&cut, false).custom();
        assert_eq!(custom.by_ref().count(), 0);
        assert_eq!(custom.malformed(), 1);

        // Cut inside an option that is not a Custom Option: the lost option may
        // have been one, so it is counted all the same.
        let mut other = Vec::new();
        put(
            &mut other,
            order,
            OPT_CUSTOM_BINARY_COPYABLE,
            good.len() as u16,
            &good,
        );
        put(&mut other, order, OPT_ISB_IFDROP, 8, &[0; 3]);
        let mut custom = OptionList::new(&other, false).custom();
        assert_eq!(custom.by_ref().count(), 1);
        assert_eq!(custom.malformed(), 1);

        // Not malformed: no terminator, stray bytes too few for a header, and
        // bytes after the terminator, which are not read.
        let mut tidy = Vec::new();
        put(
            &mut tidy,
            order,
            OPT_CUSTOM_BINARY_COPYABLE,
            good.len() as u16,
            &good,
        );
        let mut no_terminator = tidy.clone();
        no_terminator.extend_from_slice(&[7, 7]);
        let mut after_terminator = tidy.clone();
        after_terminator.extend_from_slice(&[0; 4]);
        put(
            &mut after_terminator,
            order,
            OPT_CUSTOM_BINARY_COPYABLE,
            good.len() as u16,
            &good,
        );
        for (name, bytes) in [
            ("none", &tidy),
            ("stray", &no_terminator),
            ("after", &after_terminator),
        ] {
            let mut custom = OptionList::new(bytes, false).custom();
            assert_eq!(custom.by_ref().count(), 1, "{name}");
            assert_eq!(custom.malformed(), 0, "{name}");
        }
    }

    /// A file written by ANOTHER implementation of the format, read here.
    ///
    /// Every other fixture in this module comes from this crate's writer or from
    /// bytes laid out by the same author, and a reader and a writer that agree
    /// prove only that they share a belief. These bytes are what Wireshark's
    /// `editcap` 4.2.2 wrote (`editcap -F pcapng`, the same bytes from a
    /// little-endian and a big-endian input) when given a pcapng built by a
    /// separate script: one packet whose block listed a comment and the four
    /// Custom Option codes, the organization number 0x01020304 and, for the
    /// binary ones, twelve bytes of 0xAA.
    ///
    /// It is also the format's own copy rule, applied by a different program:
    /// `editcap` carried 2988 and 2989 into the new file and DROPPED 19372 and
    /// 19373, which the format says should not be copied. So the codes this crate
    /// classes as copyable are the ones that program copies. The bytes show its
    /// layout too: a section header carrying its own options (the name of the
    /// program), a byte order it normalised to little-endian, and an option list
    /// that begins with a comment, so the index of the first Custom Option is 1.
    #[test]
    fn a_file_another_program_wrote_reads_as_the_format_says() {
        const WRITTEN_BY_EDITCAP: &[u8] = &[
            0x0A, 0x0D, 0x0D, 0x0A, 0x68, 0x00, 0x00, 0x00, 0x4D, 0x3C, 0x2B, 0x1A, 0x01, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x04, 0x00, 0x42, 0x00,
            0x45, 0x64, 0x69, 0x74, 0x63, 0x61, 0x70, 0x20, 0x28, 0x57, 0x69, 0x72, 0x65, 0x73,
            0x68, 0x61, 0x72, 0x6B, 0x29, 0x20, 0x34, 0x2E, 0x32, 0x2E, 0x32, 0x20, 0x28, 0x47,
            0x69, 0x74, 0x20, 0x76, 0x34, 0x2E, 0x32, 0x2E, 0x32, 0x20, 0x70, 0x61, 0x63, 0x6B,
            0x61, 0x67, 0x65, 0x64, 0x20, 0x61, 0x73, 0x20, 0x34, 0x2E, 0x32, 0x2E, 0x32, 0x2D,
            0x31, 0x2E, 0x31, 0x62, 0x75, 0x69, 0x6C, 0x64, 0x33, 0x29, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0x00, 0x06, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
            0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x03,
            0x00, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
            0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
            0x01, 0x00, 0x02, 0x00, 0x68, 0x69, 0x00, 0x00, 0xAC, 0x0B, 0x07, 0x00, 0x04, 0x03,
            0x02, 0x01, 0x61, 0x62, 0x63, 0x00, 0xAD, 0x0B, 0x10, 0x00, 0x04, 0x03, 0x02, 0x01,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00,
            0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
        ];
        // The transcription is whole: each block states its own total length (little-endian,
        // the byte order the program wrote), and the blocks fill the bytes exactly, so a byte
        // lost or added in copying shows here and not as an odd parse below.
        let mut at = 0;
        while at + 8 <= WRITTEN_BY_EDITCAP.len() {
            let stated = &WRITTEN_BY_EDITCAP[at + 4..at + 8];
            at += u32::from_le_bytes(stated.try_into().expect("four bytes")) as usize;
        }
        assert_eq!(
            at,
            WRITTEN_BY_EDITCAP.len(),
            "the blocks' lengths fill the file"
        );

        let mut seen = Vec::new();
        let mut flags = None;
        PcapngCursor::new()
            .advance_with(WRITTEN_BY_EDITCAP, |y| {
                if let PcapngYieldRef::Packet(p) = y {
                    flags = Some((p.link_type, p.data.len(), p.flags));
                    let mut custom = p.options.custom();
                    for o in custom.by_ref() {
                        assert_eq!(o.byte_order, ByteOrder::Little, "editcap writes little");
                        seen.push((o.index, o.code, o.organization, o.data.to_vec()));
                    }
                    assert_eq!(custom.malformed(), 0);
                }
                ControlFlow::Continue(())
            })
            .expect("the file another program wrote reads");
        assert_eq!(flags, Some((1, 60, None)));
        assert_eq!(
            seen,
            vec![
                (1, 2988, 0x0102_0304, b"abc".to_vec()),
                (2, 2989, 0x0102_0304, vec![0xAA; 12]),
            ]
        );
        // What the other program dropped is what the format says not to copy.
        for dropped in [19372u16, 19373] {
            assert_eq!(custom_kind(dropped).map(|k| k.copyable), Some(false));
        }
        for kept in [2988u16, 2989] {
            assert_eq!(custom_kind(kept).map(|k| k.copyable), Some(true));
        }
    }
}
