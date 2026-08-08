// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Link-layer and network-layer decapsulation: from a captured frame down to
//! a TCP segment plus the 4-tuple that identifies its flow.
//!
//! Only the link types a zenoh capture actually arrives on are handled, and
//! an unhandled one says so rather than guessing — a dissector that assumed
//! Ethernet on a `LINKTYPE_LINUX_SLL` capture would read the IP header 2
//! bytes off and report plausible garbage.

use alloc::vec::Vec;

/// `LINKTYPE_ETHERNET` — the ordinary case.
pub const LINKTYPE_ETHERNET: u32 = 1;
/// `LINKTYPE_RAW` — bare IP, no link header. What a tun interface yields.
pub const LINKTYPE_RAW: u32 = 101;
/// `LINKTYPE_LINUX_SLL` — the cooked header `tcpdump -i any` produces.
pub const LINKTYPE_LINUX_SLL: u32 = 113;
/// `LINKTYPE_IPV4` — bare IPv4.
pub const LINKTYPE_IPV4: u32 = 228;
/// `LINKTYPE_IPV6` — bare IPv6.
pub const LINKTYPE_IPV6: u32 = 229;
/// `LINKTYPE_LINUX_SLL2` — the 20-byte cooked v2 header.
pub const LINKTYPE_LINUX_SLL2: u32 = 276;
/// `LINKTYPE_VSOCK` — AF_VSOCK, captured through the kernel's `vsockmon`
/// device (`DLT_VSOCK`, `/usr/include/pcap/dlt.h:1448`).
///
/// R311y603. Absent from this table, a `vsock/...` zenoh link — the VM-to-VM
/// shape an AP deployment actually takes — came back as
/// [`SkipReason::UnsupportedLinkType`]`(271)`. That was a NAMED skip and so
/// never silent, but it was an under-promise: both the DLT and `vsockmon.ko`
/// exist, so nothing was blocking it.
pub const LINKTYPE_VSOCK: u32 = 271;

/// Bytes of `struct af_vsockmon_hdr` (`/usr/include/linux/vsockmon.h`), read
/// off that header rather than remembered: `__le64 src_cid` + `__le64 dst_cid`
/// + `__le32 src_port` + `__le32 dst_port` + `__le16 op` + `__le16 transport`
/// + `__le16 len` + 2 reserved.
const VSOCKMON_HDR_LEN: usize = 32;

/// `AF_VSOCK_OP_PAYLOAD` — the only op that carries data. The header's own
/// comment is explicit: "If af_vsockmon_hdr->op is AF_VSOCK_OP_PAYLOAD then
/// the payload follows the transport header. Other ops do not have a payload."
const AF_VSOCK_OP_PAYLOAD: u16 = 4;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;

const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;

/// One end of a flow: address bytes plus a port.
///
/// The address is a fixed 16-byte buffer with a length, not an enum: the
/// flow key only ever compares and orders it, and a `[u8; 16]` keeps the key
/// `Copy` and hashable without an address-family split rippling into every
/// consumer. The LENGTH is also what distinguishes the families — 4 for IPv4,
/// 16 for IPv6, and (R311y603) 8 for an AF_VSOCK context id, so a vsock flow
/// can never collide with an IP one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {
    addr: [u8; 16],
    addr_len: u8,
    /// TCP / UDP port, host order — or an AF_VSOCK port, which is 32 bits
    /// wide (`struct af_vsockmon_hdr.src_port`, `linux/vsockmon.h`). The field
    /// is `u32` for that reason: truncating a vsock port to 16 bits would
    /// silently alias two distinct flows onto one key.
    pub port: u32,
}

impl Endpoint {
    /// The address bytes, network order, 4 or 16 long.
    pub fn addr(&self) -> &[u8] {
        &self.addr[..self.addr_len as usize]
    }

    /// `true` for an IPv4 endpoint.
    pub fn is_ipv4(&self) -> bool {
        self.addr_len == 4
    }

    /// The context id of an AF_VSOCK endpoint, or `None` for an IP one.
    ///
    /// Distinguished by the address LENGTH rather than by a flag: a vsock
    /// endpoint is the only 8-byte one, so a consumer that asks this question
    /// gets an answer the key itself already encodes.
    pub fn vsock_cid(&self) -> Option<u64> {
        if self.addr_len != 8 {
            return None;
        }
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&self.addr[..8]);
        Some(u64::from_le_bytes(raw))
    }

    /// `pub(crate)` and not `pub`: R311y606 needs it in [`crate::frag`]'s
    /// tests to build a fragment key, and a crate-private constructor is the
    /// smallest thing that allows. Still not public — an endpoint outside this
    /// crate should come from a decapsulated packet, not be asserted into
    /// existence.
    pub(crate) fn new(addr_bytes: &[u8], port: u32) -> Self {
        let mut addr = [0u8; 16];
        addr[..addr_bytes.len()].copy_from_slice(addr_bytes);
        Self {
            addr,
            addr_len: addr_bytes.len() as u8,
            port,
        }
    }
}

/// A TCP connection, identified without regard to direction.
///
/// The two endpoints are stored SORTED, so both directions of one connection
/// produce the same key and a consumer never has to canonicalise. Which
/// direction a given segment travelled is [`Segment::from_low`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    /// The lesser of the two endpoints, by `(addr, port)` order.
    pub low: Endpoint,
    /// The greater.
    pub high: Endpoint,
}

impl FlowKey {
    fn new(a: Endpoint, b: Endpoint) -> (Self, bool) {
        if a <= b {
            (Self { low: a, high: b }, true)
        } else {
            (Self { low: b, high: a }, false)
        }
    }
}

/// What a packet's checksums said, REPORTED rather than acted on.
///
/// R311y597 — this build verified nothing at all before, so a corrupted packet
/// was read as good and its garbage entered the byte stream as though the peer
/// had sent it.
///
/// ## Why it reports instead of dropping, which is not timidity
///
/// A NIC computes TX checksums in hardware, so a capture taken on the SENDING
/// host routinely sees zeroed or stale fields — the packet is fine and the
/// checksum has not been filled in yet. Dropping on a bad checksum would make
/// a loopback or same-host capture disappear almost entirely, which is exactly
/// the case a developer captures most. Wireshark defaults its own validation
/// off for this reason. The verdict is therefore evidence a reader can weigh,
/// not a gate this crate applies on their behalf.
///
/// This crate's own fixtures write zero checksums, and they keep working
/// precisely because nothing acts on the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checksums {
    /// The IPv4 header checksum. `None` for IPv6, which has none at all —
    /// the field was removed on the grounds that the layers below and above
    /// already cover it.
    pub ip: Option<bool>,
    /// The TCP or UDP checksum. `None` when a UDP datagram over IPv4 carried
    /// zero, which is the sender explicitly DECLINING to compute one
    /// (RFC 768) rather than getting it wrong. Over IPv6 zero is illegal and
    /// reports `Some(false)`.
    pub transport: Option<bool>,
}

impl Checksums {
    /// `true` when a checksum was present and did not verify — the only state
    /// that is evidence of corruption rather than of absence.
    pub fn any_invalid(&self) -> bool {
        self.ip == Some(false) || self.transport == Some(false)
    }
}

/// One TCP segment lifted out of a captured packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Which connection it belongs to.
    pub flow: FlowKey,
    /// `true` when it travelled from [`FlowKey::low`] toward `high`.
    pub from_low: bool,
    /// Sequence number of its first payload byte.
    pub seq: u32,
    /// SYN flag — carries the initial sequence number, which is what lets a
    /// reassembler know where a stream BEGAN rather than merely where the
    /// capture did.
    pub syn: bool,
    /// FIN flag.
    pub fin: bool,
    /// RST flag.
    pub rst: bool,
    /// Payload bytes, empty for a pure ACK.
    pub payload: Vec<u8>,
    /// Index of the packet this came out of, carried through so a decoded
    /// message can be reported against the packet that carried it.
    pub packet_index: usize,
    /// What this packet's checksums said. Reported, never acted on.
    pub checksums: Checksums,
}

/// Why a captured packet yielded no TCP segment.
///
/// Every variant is a REASON, not a bare `None`. A dissector that silently
/// drops packets cannot tell its user whether a missing message was never
/// captured, was IP-fragmented, or was simply not TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The capture's link type is not decapsulated by this build.
    UnsupportedLinkType(u32),
    /// The packet was shorter than the headers it declared.
    Truncated,
    /// Not IP (ARP, LLDP, ...), or not a protocol carried onward.
    NotIp,
    /// IP, but neither TCP nor UDP — the two transports zenoh links use.
    ///
    /// R311y584 (A3) — was `NotTcp`, and UDP fell into it. That named skip
    /// was honest about the byte stream having a hole and silent about WHICH
    /// hole: scouting, multicast Join, and the whole UDP unicast link are all
    /// carried there, so a capture of a multicast deployment produced a
    /// dissection with no messages and no error.
    NotTransport(u8),
    /// An IPv4 fragment other than the first.
    ///
    /// R311y606 — RETAINED but no longer produced by [`decapsulate`], which now
    /// reports every piece as [`Transport::IpFragment`] and leaves the
    /// reassembly decision to the consumer. A consumer that does not reassemble
    /// records this, so the vocabulary a reader chases a hole with is unchanged.
    Ipv4Fragment,
    /// R311y606 — a piece of a fragmented datagram that is now IN the
    /// reassembly table, waiting for the rest of it.
    ///
    /// Distinct from [`Self::Ipv4Fragment`] on purpose: those bytes were LOST,
    /// these are held. A packet recorded here yielded no frames of its own and
    /// belongs in the skipped list for that reason, but the datagram it belongs
    /// to may still arrive — and when it does, the packet that COMPLETES it is
    /// the one that produces the frames.
    IpFragmentPending,
    /// An IPv6 packet whose extension-header chain could not be walked to a
    /// transport, carrying the header that stopped it.
    ///
    /// R311y597 — the payload is the extension header's own number, and it is
    /// now only ever one of [`is_ipv6_extension_header`]'s set. It previously
    /// carried any next-header that was not TCP, so a reader saw UDP (17) and
    /// ICMPv6 (58) reported as unwalked chains.
    ///
    /// R311y603 — the chain IS walked now, so this narrowed from "any chain" to
    /// the three cases that genuinely cannot be walked: ESP (50), whose
    /// remainder is encrypted, the two experimental numbers (253 / 254) that
    /// carry no length this reader may assume, and a chain longer than
    /// [`IPV6_MAX_EXT_HEADERS`].
    Ipv6ExtensionChain(u8),
    /// An IPv6 fragment other than the first, which has no transport header to
    /// find. The v6 twin of [`Self::Ipv4Fragment`], and named separately
    /// because a reader chasing a hole should not have to guess which address
    /// family produced it.
    Ipv6Fragment,
    /// R311y603 — a `vsockmon` record whose op is not `AF_VSOCK_OP_PAYLOAD`,
    /// carrying the op itself.
    ///
    /// CONNECT / DISCONNECT / CONTROL records are the credit-and-lifecycle
    /// traffic of the transport, and by the kernel header's own statement they
    /// have no payload at all. Skipping them is correct; skipping them ANONYMOUS
    /// would leave a reader unable to tell a quiet link from a link whose
    /// records this build could not read.
    VsockNonPayload(u16),
}

/// One UDP datagram lifted out of a captured packet.
///
/// R311y584 (A3) — deliberately NOT a [`Segment`] with the TCP fields left
/// blank. A datagram has no sequence number and needs no reassembly: zenoh
/// puts exactly ONE wire message in each one and relies on the datagram
/// boundary instead of a length prefix
/// (`wz-runtime-tokio/src/udp_pipeline.rs:34-36`). Giving it a `seq` field to
/// ignore would invite a reader to treat the two the same, and they are not
/// the same — the framing differs, which is the whole reason UDP could not
/// simply be routed into the existing TCP path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    /// The two endpoints, sorted, exactly as for TCP so a consumer keys both
    /// transports the same way.
    pub flow: FlowKey,
    /// `true` when it travelled from [`FlowKey::low`] toward `high`.
    pub from_low: bool,
    /// The datagram body: one complete zenoh wire message.
    pub payload: Vec<u8>,
    /// Index of the packet this came out of.
    pub packet_index: usize,
    /// What this packet's checksums said. Reported, never acted on.
    pub checksums: Checksums,
}

/// R311y603 — one AF_VSOCK record's payload, lifted out of a `vsockmon`
/// capture.
///
/// The byte-stream twin of [`Datagram`]: same flow keying, same direction bit,
/// but the payload is a piece OF a stream rather than a whole message, because
/// zenoh's vsock link is `SOCK_STREAM` and carries the same length-prefixed
/// StreamEnvelope framing tcp does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VsockRecord {
    /// The two endpoints, sorted, keyed by `(cid, port)`.
    pub flow: FlowKey,
    /// `true` when it travelled from [`FlowKey::low`] toward `high`.
    pub from_low: bool,
    /// The record's payload bytes.
    pub payload: Vec<u8>,
    /// Index of the packet this came out of.
    pub packet_index: usize,
}

/// What a captured packet turned out to carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// A TCP segment, to be fed to a stream reassembler.
    Tcp(Segment),
    /// A UDP datagram, already a whole message.
    Udp(Datagram),
    /// R311y603 — the payload of one AF_VSOCK record.
    ///
    /// A distinct variant from [`Self::Tcp`] even though both feed a byte
    /// stream, because a vsockmon record has NO sequence number: the transport
    /// is reliable and in-order and the monitor device records what the kernel
    /// delivered, so the stream position is the running byte count and nothing
    /// else. Handing this back as a `Segment` with a fabricated `seq` would put
    /// that fabrication in the parser, where the running count cannot be known;
    /// [`crate::Dissection`] holds the counter and synthesises the sequence
    /// there, one layer up, where it is per-flow state rather than a guess.
    Vsock(VsockRecord),
    /// A raweth (L2) frame's payload — one whole message, like a datagram.
    ///
    /// R311y597. A separate variant from [`Self::Udp`] even though both carry
    /// a [`Datagram`], because the two are only alike in SHAPE: a raweth flow
    /// is keyed by MAC with no ports, so a consumer that reports "UDP flow"
    /// over it would be naming a transport that is not there.
    RawEth(Datagram),
    /// R311y606 — one piece of a fragmented IP datagram, v4 or v6.
    ///
    /// Reported rather than skipped. Reassembling needs a table and a deadline,
    /// which is per-capture state this function does not hold — the same
    /// division [`Self::Vsock`] is under, where the parser reports the record
    /// and [`crate::Dissection`] holds the running count. A consumer that does
    /// not want to reassemble treats this exactly as the old skip.
    IpFragment(IpFragment),
}

/// The fragment fields of one piece of a fragmented IP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentInfo {
    /// The datagram's identification: 16 bits on IPv4, 32 on IPv6. Widened to
    /// `u32` so one type carries both — the value is only ever compared, and
    /// the two families never share a key because their addresses differ in
    /// length.
    pub ident: u32,
    /// This piece's first byte, as an offset into the reassembled payload.
    /// Both families encode it in 8-byte units; this is already multiplied out.
    pub offset: usize,
    /// Whether more pieces follow. The LAST piece is the one that declares the
    /// total length, and it is the only piece that can.
    pub more: bool,
}

/// One piece of a fragmented IP datagram, with what it takes to place it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpFragment {
    /// Source address, port zero — a fragment other than the first carries no
    /// transport header, so no port is knowable here for any of them.
    pub src: Endpoint,
    /// Destination address, port zero.
    pub dst: Endpoint,
    /// The upper-layer protocol the reassembled datagram will carry.
    pub proto: u8,
    /// Where this piece goes and whether it is the last.
    pub info: FragmentInfo,
    /// This piece's bytes.
    pub payload: Vec<u8>,
    /// Index of the captured packet this came from.
    pub packet_index: usize,
    /// IP-header verdict only. The transport checksum is deliberately absent:
    /// it covers the whole datagram, so no single fragment can verify it, and
    /// reporting `Some(false)` for a piece would call every fragmented capture
    /// corrupt.
    pub checksums: Checksums,
}

/// What an IP header resolved to, before the transport layer is read.
struct IpDatagram<'a> {
    src: Endpoint,
    dst: Endpoint,
    proto: u8,
    payload: &'a [u8],
    /// `Some` when this packet is one piece of a larger datagram.
    fragment: Option<FragmentInfo>,
}

/// Decapsulate one captured packet down to the transport payload zenoh uses.
///
/// R311y584 (A3) — returns both transports rather than TCP alone. The
/// previous shape made "not TCP" a skip reason, which is where every
/// multicast and scouting packet went.
pub fn decapsulate(
    link_type: u32,
    packet_index: usize,
    bytes: &[u8],
) -> Result<Transport, SkipReason> {
    if link_type == LINKTYPE_VSOCK {
        return strip_vsockmon(bytes, packet_index).map(Transport::Vsock);
    }
    if link_type == LINKTYPE_ETHERNET {
        if let Some(d) = strip_raweth(bytes, packet_index) {
            return Ok(Transport::RawEth(d));
        }
    }
    let (ip_bytes, is_v6) = strip_link(link_type, bytes)?;
    let ip = if is_v6 {
        strip_ipv6(ip_bytes)?
    } else {
        strip_ipv4(ip_bytes)?
    };
    let ip_checksum = if is_v6 {
        None
    } else {
        Some(ipv4_header_ok(&ip_bytes[..ipv4_header_len(ip_bytes)]))
    };
    // R311y606 — a fragment leaves here before the transport strip, because
    // there is no transport to strip. Even the FIRST fragment must: its header
    // is present but the body behind it is a prefix, and reading it as whole is
    // how a fragmented TCP segment used to advance the stream by less than the
    // sender sent — which desynchronises the flow, and desynchronisation is
    // terminal (`passive.rs:394`).
    if let Some(info) = ip.fragment {
        return Ok(Transport::IpFragment(IpFragment {
            src: ip.src,
            dst: ip.dst,
            proto: ip.proto,
            info,
            payload: ip.payload.to_vec(),
            packet_index,
            checksums: Checksums {
                ip: ip_checksum,
                transport: None,
            },
        }));
    }
    // R311y597 — computed here, where both the addresses (for the pseudo
    // header) and the transport body are in hand, and REPORTED rather than
    // acted on. See [`Checksums`] for why a bad one is not a skip.
    let checksums = Checksums {
        ip: ip_checksum,
        transport: transport_checksum(&ip.src, &ip.dst, ip.proto, ip.payload),
    };
    transport_from_ip(
        ip.src,
        ip.dst,
        ip.proto,
        ip.payload,
        packet_index,
        checksums,
    )
}

/// Read the transport layer of a whole IP datagram.
///
/// Split out of [`decapsulate`] so a REASSEMBLED datagram takes the same path
/// as one that arrived whole. The alternative was re-synthesising an IP header
/// around the reassembled bytes just to feed it back through the front door,
/// and a synthesised header is a second place for the fields to be wrong.
pub fn transport_from_ip(
    src: Endpoint,
    dst: Endpoint,
    proto: u8,
    payload: &[u8],
    packet_index: usize,
    checksums: Checksums,
) -> Result<Transport, SkipReason> {
    match proto {
        IP_PROTO_TCP => strip_tcp(src, dst, payload, packet_index, checksums).map(Transport::Tcp),
        IP_PROTO_UDP => strip_udp(src, dst, payload, packet_index, checksums).map(Transport::Udp),
        other => Err(SkipReason::NotTransport(other)),
    }
}

/// The transport checksum of a reassembled datagram.
///
/// Public for the same reason [`transport_from_ip`] is: the verdict can only be
/// reached once every piece is in hand, so the reassembler is the only caller
/// that can produce it, and it must produce the same value the whole-datagram
/// path does.
pub fn reassembled_transport_checksum(
    src: &Endpoint,
    dst: &Endpoint,
    proto: u8,
    payload: &[u8],
) -> Option<bool> {
    transport_checksum(src, dst, proto, payload)
}

/// The IPv4 header's own declared length, clamped to what was captured.
fn ipv4_header_len(bytes: &[u8]) -> usize {
    let ihl = bytes.first().map_or(0, |b| ((b & 0x0F) as usize) * 4);
    ihl.clamp(0, bytes.len())
}

/// The UDP header is eight fixed bytes: src port, dst port, length, checksum.
///
/// The header's own `length` field is READ and used, not ignored in favour of
/// the slice length: a captured frame can carry trailing padding (Ethernet's
/// 60-byte minimum pads a short datagram), and handing those pad bytes to the
/// decoder as part of the message turns a valid Scout into a trailing-garbage
/// parse error.
fn strip_udp(
    src: Endpoint,
    dst: Endpoint,
    bytes: &[u8],
    packet_index: usize,
    checksums: Checksums,
) -> Result<Datagram, SkipReason> {
    if bytes.len() < 8 {
        return Err(SkipReason::Truncated);
    }
    let src_port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let dst_port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let declared = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    // `length` counts the header itself. A value below 8 is malformed; one
    // past the captured bytes means the capture was snapped short.
    if declared < 8 {
        return Err(SkipReason::Truncated);
    }
    let body_len = declared - 8;
    if bytes.len() < 8 + body_len {
        return Err(SkipReason::Truncated);
    }
    let src = Endpoint::new(src.addr(), src_port as u32);
    let dst = Endpoint::new(dst.addr(), dst_port as u32);
    let (flow, from_low) = FlowKey::new(src, dst);
    Ok(Datagram {
        flow,
        from_low,
        payload: bytes[8..8 + body_len].to_vec(),
        packet_index,
        checksums,
    })
}

/// The 16-bit one's-complement sum RFC 1071 defines, folded to a checksum.
///
/// Returns the value the field must hold. Verification runs the same sum over
/// the bytes WITH the field in place and expects `0`, which is the standard
/// property and avoids having to zero and restore the field.
fn ones_complement(bytes: &[u8], seed: u32) -> u16 {
    let mut sum = seed;
    let mut chunks = bytes.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    // An odd trailing byte is padded on the RIGHT with zero.
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// The IPv4 header checksum, verified over the header as captured.
fn ipv4_header_ok(header: &[u8]) -> bool {
    ones_complement(header, 0) == 0
}

/// The TCP / UDP checksum, verified over the pseudo-header plus the segment.
///
/// `None` means the sender declined: a UDP datagram over IPv4 whose field is
/// zero carried no checksum at all (RFC 768), which is legal and is NOT a
/// failure. Over IPv6 the checksum is mandatory, so zero there is a real
/// `Some(false)`.
fn transport_checksum(src: &Endpoint, dst: &Endpoint, proto: u8, body: &[u8]) -> Option<bool> {
    // The field sits at offset 16 in TCP and 6 in UDP.
    let field_at = if proto == IP_PROTO_TCP { 16 } else { 6 };
    if body.len() < field_at + 2 {
        return None;
    }
    let field = u16::from_be_bytes([body[field_at], body[field_at + 1]]);
    let is_v4 = src.is_ipv4();
    if field == 0 && proto == IP_PROTO_UDP && is_v4 {
        return None;
    }
    // Pseudo-header: the addresses, the protocol, and the transport length.
    let mut seed: u32 = 0;
    for addr in [src.addr(), dst.addr()] {
        for c in addr.chunks_exact(2) {
            seed += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
    }
    let len = body.len() as u32;
    seed += u32::from(proto as u16);
    seed += (len >> 16) & 0xFFFF;
    seed += len & 0xFFFF;
    Some(ones_complement(body, seed) == 0)
}

/// A raweth (L2) frame, or `None` if this is not one.
///
/// R311y597 — before this, every non-IP ethertype died on
/// [`SkipReason::NotIp`] at the Ethernet arm, so zenoh-pico's raweth link was
/// invisible to a capture even though the framing had been sitting in
/// `wz_session_core::raweth_link` since R311y579.
///
/// ## Why this runs BEFORE `strip_link` rather than as a case inside it
///
/// The generic VLAN walk would half-succeed on the VLAN form and be wrong in a
/// way that looks right. pico spells its VLAN type `0x0081` so a little-endian
/// `memcpy` lands the real `81 00`, which the generic walk consumes; it then
/// reads pico's ethertype from the correct offset and treats the NEXT two
/// bytes as payload. Those two bytes are raweth's `data_length`. Delegating to
/// [`RawEthHeader::decode`] instead keeps one implementation of pico's layout,
/// including its VLAN detection, rather than a second one that agrees until it
/// does not.
///
/// ## Both byte orders are accepted, and that is not laxity
///
/// pico `memcpy`s the header struct, so `ethtype` lands in the SENDER's byte
/// order (`raweth_link`'s module doc). A little-endian pico puts `0x72e0` on
/// the wire as `e0 72` and a big-endian one as `72 e0`. The sender's
/// endianness is not observable from the capture, so a reader that accepted
/// only one spelling would be blind to half the deployments — for a property
/// that is pico's, not this parser's, to normalise.
fn strip_raweth(bytes: &[u8], packet_index: usize) -> Option<Datagram> {
    use wz_session_core::raweth_link::{self, RawEthHeader, DEFAULT_ETHTYPE};

    let (header, _) = RawEthHeader::decode(bytes).ok()?;
    if header.ethtype != DEFAULT_ETHTYPE && header.ethtype != DEFAULT_ETHTYPE.swap_bytes() {
        return None;
    }
    let (_, payload) = raweth_link::deframe(bytes).ok()?;
    // MACs, not addresses, and no ports — `Endpoint` carries the six bytes and
    // `is_ipv4()` answers false, so nothing downstream can mistake one for an
    // address it could route.
    let src = Endpoint::new(&header.smac, 0);
    let dst = Endpoint::new(&header.dmac, 0);
    let (flow, from_low) = FlowKey::new(src, dst);
    Some(Datagram {
        flow,
        from_low,
        payload: payload.to_vec(),
        packet_index,
        // A raweth frame has NEITHER: no IP header to checksum and no
        // transport pseudo-header to build one over. `None`/`None` is the
        // honest report, not an unchecked default -- the Ethernet FCS the NIC
        // verifies is stripped before a capture ever sees the frame.
        checksums: Checksums {
            ip: None,
            transport: None,
        },
    })
}

/// Returns the IP-layer bytes and whether they are IPv6.
fn strip_link(link_type: u32, bytes: &[u8]) -> Result<(&[u8], bool), SkipReason> {
    match link_type {
        LINKTYPE_ETHERNET => {
            if bytes.len() < 14 {
                return Err(SkipReason::Truncated);
            }
            let mut off = 12;
            let mut ethertype = u16::from_be_bytes([bytes[off], bytes[off + 1]]);
            // Walk any number of VLAN / QinQ tags: each is 4 bytes, the last
            // two of which are the next ethertype.
            while ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ {
                off += 4;
                if bytes.len() < off + 2 {
                    return Err(SkipReason::Truncated);
                }
                ethertype = u16::from_be_bytes([bytes[off], bytes[off + 1]]);
            }
            off += 2;
            match ethertype {
                ETHERTYPE_IPV4 => Ok((&bytes[off..], false)),
                ETHERTYPE_IPV6 => Ok((&bytes[off..], true)),
                _ => Err(SkipReason::NotIp),
            }
        }
        LINKTYPE_LINUX_SLL => {
            if bytes.len() < 16 {
                return Err(SkipReason::Truncated);
            }
            match u16::from_be_bytes([bytes[14], bytes[15]]) {
                ETHERTYPE_IPV4 => Ok((&bytes[16..], false)),
                ETHERTYPE_IPV6 => Ok((&bytes[16..], true)),
                _ => Err(SkipReason::NotIp),
            }
        }
        LINKTYPE_LINUX_SLL2 => {
            if bytes.len() < 20 {
                return Err(SkipReason::Truncated);
            }
            // SLL2 puts the protocol FIRST, unlike SLL.
            match u16::from_be_bytes([bytes[0], bytes[1]]) {
                ETHERTYPE_IPV4 => Ok((&bytes[20..], false)),
                ETHERTYPE_IPV6 => Ok((&bytes[20..], true)),
                _ => Err(SkipReason::NotIp),
            }
        }
        LINKTYPE_RAW => {
            // Bare IP: the version nibble is the only discriminator.
            match bytes.first().map(|b| b >> 4) {
                Some(4) => Ok((bytes, false)),
                Some(6) => Ok((bytes, true)),
                Some(_) => Err(SkipReason::NotIp),
                None => Err(SkipReason::Truncated),
            }
        }
        LINKTYPE_IPV4 => Ok((bytes, false)),
        LINKTYPE_IPV6 => Ok((bytes, true)),
        other => Err(SkipReason::UnsupportedLinkType(other)),
    }
}

fn strip_ipv4(bytes: &[u8]) -> Result<IpDatagram<'_>, SkipReason> {
    if bytes.len() < 20 {
        return Err(SkipReason::Truncated);
    }
    let ihl = ((bytes[0] & 0x0F) as usize) * 4;
    if ihl < 20 || bytes.len() < ihl {
        return Err(SkipReason::Truncated);
    }
    // The flags/offset word: bit 13 is More Fragments, the low 13 bits are the
    // offset in 8-byte units.
    //
    // R311y606 — BOTH halves decide. Reading the offset alone called a first
    // fragment (offset 0, MF set) a whole datagram and handed its prefix to the
    // transport, which is a silent truncation rather than a named skip.
    let flags_off = u16::from_be_bytes([bytes[6], bytes[7]]);
    let frag_off = (flags_off & 0x1FFF) as usize * 8;
    let more = flags_off & 0x2000 != 0;
    let fragment = (more || frag_off != 0).then(|| FragmentInfo {
        ident: u16::from_be_bytes([bytes[4], bytes[5]]) as u32,
        offset: frag_off,
        more,
    });
    let total_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    // Trust the header's total length when it fits, so trailing link padding
    // (an Ethernet frame padded to 60 bytes) is not read as payload. Fall
    // back to the captured length when the capture was snaplen-truncated.
    let end = if total_len >= ihl && total_len <= bytes.len() {
        total_len
    } else {
        bytes.len()
    };
    Ok(IpDatagram {
        src: Endpoint::new(&bytes[12..16], 0),
        dst: Endpoint::new(&bytes[16..20], 0),
        proto: bytes[9],
        payload: &bytes[ihl..end],
        fragment,
    })
}

/// Whether an IPv6 next-header value names an EXTENSION HEADER rather than an
/// upper-layer protocol (RFC 8200 §4.1 plus the IANA additions). Walking a
/// chain of these needs per-header length rules this build does not implement,
/// so they are refused by name.
///
/// R311y597 — this predicate is the fix, and the shape it replaced is worth
/// recording. The test was `next_header != IP_PROTO_TCP`, which refused UDP
/// and every other protocol as though it were an unwalked chain. Two failures
/// came out of that one line, and the second is the reason a bare "allow UDP
/// too" patch would not have been enough:
///
/// 1. An IPv6 UDP datagram never reached the UDP arm [`decapsulate`] already
///    had, so IPv6 multicast scouting and IPv6 UDP unicast links produced a
///    dissection with no messages.
/// 2. The skip NAMED THE WRONG CAUSE. `Ipv6ExtensionChain(17)` says "this
///    build cannot walk the chain" about a packet with no chain at all, which
///    points a reader at writing a chain walker rather than at the missing
///    branch. A skip reason that misattributes is worse than a generic one.
///
/// The IPv4 path never had either failure because [`strip_ipv4`] returns its
/// protocol byte through and lets [`decapsulate`] classify it. This restores
/// the same division of labour: refuse only what genuinely cannot be parsed
/// here, and let the caller name everything else.
const fn is_ipv6_extension_header(next_header: u8) -> bool {
    matches!(
        next_header,
        0        // Hop-by-Hop Options
        | 43     // Routing
        | 44     // Fragment
        | 50     // Encapsulating Security Payload
        | 51     // Authentication Header
        | 60     // Destination Options
        | 135    // Mobility
        | 139    // Host Identity Protocol
        | 140    // Shim6
        | 253    // reserved for experimentation
        | 254 // reserved for experimentation
    )
}

/// R311y603 — one `vsockmon` record: a 32-byte transport-independent header, a
/// transport header whose length the first one declares, then the payload.
///
/// The layout is read straight off `/usr/include/linux/vsockmon.h` on this
/// machine, and the `len` field is what makes the transport header skippable
/// without knowing which transport it is — the header's own stated purpose:
/// "so that no transport-specific knowledge is necessary to process packets".
/// That is why this reader needs nothing about virtio.
fn strip_vsockmon(bytes: &[u8], packet_index: usize) -> Result<VsockRecord, SkipReason> {
    if bytes.len() < VSOCKMON_HDR_LEN {
        return Err(SkipReason::Truncated);
    }
    let le64 = |at: usize| {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&bytes[at..at + 8]);
        u64::from_le_bytes(raw)
    };
    let le32 =
        |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    let le16 = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);

    let src_cid = le64(0);
    let dst_cid = le64(8);
    let src_port = le32(16);
    let dst_port = le32(20);
    let op = le16(24);
    let transport_hdr_len = le16(28) as usize;

    if op != AF_VSOCK_OP_PAYLOAD {
        return Err(SkipReason::VsockNonPayload(op));
    }
    let payload_at = VSOCKMON_HDR_LEN
        .checked_add(transport_hdr_len)
        .ok_or(SkipReason::Truncated)?;
    if bytes.len() < payload_at {
        return Err(SkipReason::Truncated);
    }
    // The CID goes in as its little-endian bytes, giving an 8-byte address —
    // a length no IP endpoint can have, so a vsock flow cannot collide with an
    // IP one in the shared key space.
    let src = Endpoint::new(&src_cid.to_le_bytes(), src_port);
    let dst = Endpoint::new(&dst_cid.to_le_bytes(), dst_port);
    let (flow, from_low) = FlowKey::new(src, dst);
    Ok(VsockRecord {
        flow,
        from_low,
        payload: bytes[payload_at..].to_vec(),
        packet_index,
    })
}

/// How many extension headers this build will walk before giving up.
///
/// RFC 8200 sets no limit, so a corrupt or hostile capture can present a chain
/// that never terminates; a bound turns that into a named skip instead of a
/// loop. Eight is far past anything real — a packet with more than two or three
/// is already unusual.
const IPV6_MAX_EXT_HEADERS: usize = 8;

fn strip_ipv6(bytes: &[u8]) -> Result<IpDatagram<'_>, SkipReason> {
    if bytes.len() < 40 {
        return Err(SkipReason::Truncated);
    }
    let payload_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let end = if 40 + payload_len <= bytes.len() {
        40 + payload_len
    } else {
        bytes.len()
    };
    let src = Endpoint::new(&bytes[8..24], 0);
    let dst = Endpoint::new(&bytes[24..40], 0);

    // R311y603 — WALK the chain rather than refusing at its first link.
    //
    // A zenoh session over IPv6 with any extension header present produced a
    // dissection with no messages: the transport header is a few bytes past the
    // one this used to stop at, and every one of those bytes is a fixed-layout
    // field this crate already reads five other kinds of. The named skip was
    // the right SHAPE — it said which header stopped it — but it named work
    // rather than a limit, and the work is this loop.
    let mut next_header = bytes[6];
    let mut at = 40usize;
    // R311y606 — set by the Fragment header if the chain carries one. The walk
    // CONTINUES past it either way now: a first fragment's remaining chain is
    // what names the upper-layer protocol, and a later fragment's `next_header`
    // field carries the same value, so both arrive with `proto` correct.
    let mut fragment: Option<FragmentInfo> = None;
    for _ in 0..IPV6_MAX_EXT_HEADERS {
        // Not an extension header: hand the protocol byte back and let
        // `decapsulate` classify it, exactly as `strip_ipv4` does. TCP and UDP
        // reach their arms; anything else lands on `NotTransport`, which names
        // the real cause.
        if !is_ipv6_extension_header(next_header) {
            return Ok(IpDatagram {
                src,
                dst,
                proto: next_header,
                payload: &bytes[at.min(end)..end],
                fragment,
            });
        }
        let step = match next_header {
            // ESP encrypts everything after it, so there is nothing to walk to
            // — the same honest refusal as TLS without keys, one layer down.
            // 253 / 254 are reserved for experimentation and carry no length
            // this reader may assume.
            50 | 253 | 254 => return Err(SkipReason::Ipv6ExtensionChain(next_header)),
            // Fragment: fixed 8 bytes, and the only extension header that
            // makes this packet a PIECE rather than a datagram.
            //
            // R311y606 — the walk now continues for every offset, not only
            // zero. A later fragment has no transport header behind this one,
            // but it does not need one: `next_header` names the protocol the
            // reassembled datagram will carry, and the bytes after this header
            // are the piece's payload. Stopping at offset != 0 is what made
            // every fragmented IPv6 datagram unreadable.
            44 => {
                if end < at + 8 {
                    return Err(SkipReason::Truncated);
                }
                let off_word = u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]);
                fragment = Some(FragmentInfo {
                    ident: u32::from_be_bytes([
                        bytes[at + 4],
                        bytes[at + 5],
                        bytes[at + 6],
                        bytes[at + 7],
                    ]),
                    offset: (off_word >> 3) as usize * 8,
                    more: off_word & 0x1 != 0,
                });
                next_header = bytes[at];
                8
            }
            // Authentication Header measures in 4-byte units and counts from 2,
            // which is NOT the (len+1)*8 rule every other header here uses —
            // reading it with the common formula would land the walk in the
            // middle of the payload and decode noise.
            51 => {
                if end < at + 2 {
                    return Err(SkipReason::Truncated);
                }
                let len = (bytes[at + 1] as usize + 2) * 4;
                if end < at + len {
                    return Err(SkipReason::Truncated);
                }
                next_header = bytes[at];
                len
            }
            // Hop-by-Hop, Routing, Destination Options, Mobility, HIP, Shim6:
            // the common form, 8-byte units counted from 1.
            _ => {
                if end < at + 2 {
                    return Err(SkipReason::Truncated);
                }
                let len = (bytes[at + 1] as usize + 1) * 8;
                if end < at + len {
                    return Err(SkipReason::Truncated);
                }
                next_header = bytes[at];
                len
            }
        };
        at += step;
    }
    // Past the bound: still a chain this build did not walk to the end, and the
    // header it stopped on is the actionable part.
    Err(SkipReason::Ipv6ExtensionChain(next_header))
}

fn strip_tcp(
    src: Endpoint,
    dst: Endpoint,
    bytes: &[u8],
    packet_index: usize,
    checksums: Checksums,
) -> Result<Segment, SkipReason> {
    if bytes.len() < 20 {
        return Err(SkipReason::Truncated);
    }
    let src_port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let dst_port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let seq = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let data_off = ((bytes[12] >> 4) as usize) * 4;
    if data_off < 20 || bytes.len() < data_off {
        return Err(SkipReason::Truncated);
    }
    let flags = bytes[13];
    let src = Endpoint::new(src.addr(), src_port as u32);
    let dst = Endpoint::new(dst.addr(), dst_port as u32);
    let (flow, from_low) = FlowKey::new(src, dst);
    Ok(Segment {
        flow,
        from_low,
        seq,
        syn: flags & 0x02 != 0,
        fin: flags & 0x01 != 0,
        rst: flags & 0x04 != 0,
        payload: bytes[data_off..].to_vec(),
        packet_index,
        checksums,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Decapsulate and require a TCP segment. R311y584 made `decapsulate`
    /// return both transports; these legs are all about the TCP path, so the
    /// unwrap is here rather than repeated at every call site.
    #[track_caller]
    fn tcp(link_type: u32, idx: usize, bytes: &[u8]) -> Result<Segment, SkipReason> {
        match decapsulate(link_type, idx, bytes) {
            Ok(Transport::Tcp(s)) => Ok(s),
            Ok(Transport::Udp(d) | Transport::RawEth(d)) => {
                panic!("expected TCP, got a datagram: {d:?}")
            }
            Ok(Transport::Vsock(r)) => panic!("expected TCP, got a vsock record: {r:?}"),
            Ok(Transport::IpFragment(f)) => panic!("expected TCP, got an IP fragment: {f:?}"),
            Err(e) => Err(e),
        }
    }

    /// Decapsulate and require an IP fragment. The sibling of [`tcp`] for the
    /// R311y606 legs, and it PANICS on a whole datagram rather than returning
    /// an option: a test that meant to build a fragment and built a whole
    /// packet would otherwise assert about the wrong thing.
    #[track_caller]
    fn fragment(link_type: u32, idx: usize, bytes: &[u8]) -> IpFragment {
        match decapsulate(link_type, idx, bytes) {
            Ok(Transport::IpFragment(f)) => f,
            other => panic!("expected an IP fragment, got {other:?}"),
        }
    }

    /// Build an Ethernet + IPv4 + TCP packet. The fixture builder is here in
    /// the tests rather than in the library because nothing in production
    /// EMITS packets — a builder in `src` would be a second, unverified
    /// opinion about the layouts the parser reads.
    /// R311y584 (A3) — Ethernet + IPv4 + UDP. Pads the Ethernet frame out to
    /// the 60-byte minimum on purpose: a real NIC does, and the pad bytes are
    /// exactly what makes the UDP header's own `length` field load-bearing
    /// rather than decorative.
    fn eth_ipv4_udp(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend_from_slice(&sport.to_be_bytes());
        udp.extend_from_slice(&dport.to_be_bytes());
        udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes()); // checksum (unverified)
        udp.extend_from_slice(payload);

        let mut ip = Vec::new();
        ip.push(0x45);
        ip.push(0);
        ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.push(64);
        ip.push(IP_PROTO_UDP);
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&udp);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    fn eth_ipv4_tcp(
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        seq: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&sport.to_be_bytes());
        tcp.extend_from_slice(&dport.to_be_bytes());
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
        tcp.push(5 << 4); // data offset 5 words, no options
        tcp.push(flags);
        tcp.extend_from_slice(&0xFFFFu16.to_be_bytes()); // window
        tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum (unverified)
        tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent
        tcp.extend_from_slice(payload);

        let mut ip = Vec::new();
        ip.push(0x45); // v4, IHL 5
        ip.push(0);
        ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes()); // id
        ip.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
        ip.push(64); // ttl
        ip.push(IP_PROTO_TCP);
        ip.extend_from_slice(&0u16.to_be_bytes()); // checksum (unverified)
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&tcp);

        let mut eth = vec![0x02; 12];
        eth.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        eth.extend_from_slice(&ip);
        eth
    }

    /// The ordinary path, end to end, with the flow key and the direction.
    #[test]
    fn an_ethernet_ipv4_tcp_packet_yields_its_segment() {
        let pkt = eth_ipv4_tcp(
            [10, 0, 0, 1],
            7447,
            [10, 0, 0, 2],
            40000,
            42,
            0x18,
            b"hello",
        );
        let seg = tcp(LINKTYPE_ETHERNET, 3, &pkt).expect("decapsulate");
        assert_eq!(seg.payload, b"hello");
        assert_eq!(seg.seq, 42);
        assert_eq!(seg.packet_index, 3);
        assert!(!seg.syn && !seg.fin && !seg.rst);
        assert_eq!(seg.flow.low.addr(), &[10, 0, 0, 1]);
        assert_eq!(seg.flow.low.port, 7447);
        assert!(seg.from_low, "10.0.0.1:7447 sorts below 10.0.0.2:40000");
    }

    /// BOTH directions of one connection produce the SAME flow key, with
    /// `from_low` as the only difference. Without this a reassembler would
    /// see two unrelated half-flows and never pair them.
    #[test]
    fn both_directions_share_one_flow_key() {
        let a = eth_ipv4_tcp([10, 0, 0, 1], 7447, [10, 0, 0, 2], 40000, 1, 0x18, b"a");
        let b = eth_ipv4_tcp([10, 0, 0, 2], 40000, [10, 0, 0, 1], 7447, 1, 0x18, b"b");
        let sa = tcp(LINKTYPE_ETHERNET, 0, &a).expect("a");
        let sb = tcp(LINKTYPE_ETHERNET, 1, &b).expect("b");
        assert_eq!(sa.flow, sb.flow, "one connection, one key");
        assert_ne!(sa.from_low, sb.from_low, "opposite directions");
    }

    /// VLAN tags are walked, however many there are. A capture off a trunk
    /// port carries them and an unwalked tag shifts the IP header by 4.
    #[test]
    fn vlan_and_qinq_tags_are_walked() {
        let plain = eth_ipv4_tcp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 5, 0x18, b"tagged");
        for tags in [vec![ETHERTYPE_VLAN], vec![ETHERTYPE_QINQ, ETHERTYPE_VLAN]] {
            let mut tagged: Vec<u8> = plain[..12].to_vec();
            for t in &tags {
                tagged.extend_from_slice(&t.to_be_bytes());
                tagged.extend_from_slice(&[0x00, 0x64]); // VID 100
            }
            tagged.extend_from_slice(&plain[12..]);
            let seg = tcp(LINKTYPE_ETHERNET, 0, &tagged)
                .unwrap_or_else(|e| panic!("{tags:?} tags: {e:?}"));
            assert_eq!(seg.payload, b"tagged");
        }
    }

    /// Ethernet PADDING is not payload. A short frame is padded to 60 bytes
    /// on the wire, and a reassembler that appended the padding would inject
    /// zero bytes into the middle of a byte stream — a corruption that looks
    /// exactly like a protocol bug.
    #[test]
    fn ethernet_padding_is_not_read_as_payload() {
        let mut pkt = eth_ipv4_tcp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 9, 0x18, b"hi");
        assert!(pkt.len() < 60);
        pkt.resize(60, 0x00);
        let seg = tcp(LINKTYPE_ETHERNET, 0, &pkt).expect("padded frame");
        assert_eq!(
            seg.payload, b"hi",
            "the IP header's total length bounds the payload, not the frame length"
        );
    }

    /// Every non-TCP outcome is a NAMED reason. Silent drops are what make a
    /// dissector's byte stream unaccountable.
    #[test]
    fn every_skip_names_itself() {
        // Not IP: an ARP ethertype.
        let mut arp = vec![0x02; 12];
        arp.extend_from_slice(&0x0806u16.to_be_bytes());
        arp.extend_from_slice(&[0; 28]);
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &arp),
            Err(SkipReason::NotIp)
        );

        // IP but UDP.
        // IP, but a transport zenoh does not use (SCTP).
        let mut sctp = eth_ipv4_tcp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 0, 0x18, b"x");
        sctp[14 + 9] = 132;
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &sctp),
            Err(SkipReason::NotTransport(132))
        );

        // A non-first IPv4 fragment. R311y606 — this is no longer a skip: the
        // piece is REPORTED, with the offset it claims, and the reassembly
        // decision belongs to the consumer. The leg is kept here because the
        // packet it builds is the same one that used to be lost.
        let mut frag = eth_ipv4_tcp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 0, 0x18, b"x");
        frag[14 + 6..14 + 8].copy_from_slice(&0x0001u16.to_be_bytes());
        let piece = fragment(LINKTYPE_ETHERNET, 0, &frag);
        assert_eq!(piece.info.offset, 8);
        assert!(!piece.info.more);
        assert_eq!(piece.proto, IP_PROTO_TCP);

        // An IPv6 extension-header chain. R311y597 — this leg was MISSING,
        // which is why the test's name was a claim it did not keep: the one
        // variant it never built was the one whose branch was wrong.
        //
        // R311y603 — the chain is WALKED now, so the leg moved to a header that
        // genuinely cannot be walked. ESP encrypts its remainder, which is a
        // limit rather than unfinished work.
        let ipv6_esp = {
            let mut ip = Vec::new();
            ip.extend_from_slice(&0x6000_0000u32.to_be_bytes());
            ip.extend_from_slice(&8u16.to_be_bytes());
            ip.push(50); // ESP
            ip.push(64);
            ip.extend_from_slice(&[0u8; 32]);
            ip.extend_from_slice(&[0u8; 8]);
            let mut eth = vec![0x02; 12];
            eth.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
            eth.extend_from_slice(&ip);
            eth
        };
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &ipv6_esp),
            Err(SkipReason::Ipv6ExtensionChain(50))
        );

        // R311y603 — a NON-FIRST IPv6 fragment, the v6 twin of the IPv4 leg
        // above. Named separately so a reader chasing a hole is not left to
        // guess the address family.
        let ipv6_frag = {
            let mut frag = alloc::vec![0u8; 8];
            frag[0] = IP_PROTO_TCP;
            // Offset 185 (bytes 1480), M clear. Non-zero offset is the point.
            frag[2..4].copy_from_slice(&(185u16 << 3).to_be_bytes());
            eth_ipv6([0x20; 16], [0x21; 16], 44, &frag)
        };
        // R311y606 — reported, not skipped, and the v6 identification is the
        // full 32 bits.
        let piece = fragment(LINKTYPE_ETHERNET, 0, &ipv6_frag);
        assert_eq!(piece.info.offset, 1480);
        assert!(!piece.info.more);
        assert_eq!(piece.proto, IP_PROTO_TCP);

        // A link type this build does not decapsulate.
        assert_eq!(
            decapsulate(999, 0, &[0u8; 64]),
            Err(SkipReason::UnsupportedLinkType(999))
        );

        // Truncated.
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &[0u8; 8]),
            Err(SkipReason::Truncated)
        );
    }

    /// The bare-IP and cooked link types reach the same segment as Ethernet
    /// does — the assertion is that the header WIDTHS are right, since an
    /// off-by-N would not fail, it would decode a different flow.
    #[test]
    fn raw_and_cooked_link_types_reach_the_same_segment() {
        let eth = eth_ipv4_tcp([10, 0, 0, 1], 7447, [10, 0, 0, 2], 40000, 3, 0x18, b"body");
        let ip = &eth[14..];
        let reference = tcp(LINKTYPE_ETHERNET, 0, &eth).expect("ethernet");

        for (lt, framed) in [
            (LINKTYPE_RAW, ip.to_vec()),
            (LINKTYPE_IPV4, ip.to_vec()),
            (LINKTYPE_LINUX_SLL, {
                let mut v = vec![0u8; 14];
                v.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
                v.extend_from_slice(ip);
                v
            }),
            (LINKTYPE_LINUX_SLL2, {
                let mut v = ETHERTYPE_IPV4.to_be_bytes().to_vec();
                v.extend_from_slice(&[0u8; 18]);
                v.extend_from_slice(ip);
                v
            }),
        ] {
            let seg = tcp(lt, 0, &framed).unwrap_or_else(|e| panic!("link {lt}: {e:?}"));
            assert_eq!(seg, reference, "link type {lt} decapsulates identically");
        }
    }

    /// TCP options are skipped by the data offset, not assumed away. A SYN
    /// carries them (MSS, window scale, SACK-permitted), and reading past a
    /// fixed 20 bytes would treat the options as stream payload.
    #[test]
    fn tcp_options_are_skipped_by_the_data_offset() {
        let mut pkt = eth_ipv4_tcp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 0, 0x02, b"");
        // Splice 8 bytes of options in and widen the data offset to 7 words.
        let tcp_at = 14 + 20;
        pkt[tcp_at + 12] = 7 << 4;
        let opts = [0x02, 0x04, 0x05, 0xB4, 0x01, 0x01, 0x01, 0x00];
        let insert_at = tcp_at + 20;
        for (i, b) in opts.iter().enumerate() {
            pkt.insert(insert_at + i, *b);
        }
        let total = (pkt.len() - 14) as u16;
        pkt[14 + 2..14 + 4].copy_from_slice(&total.to_be_bytes());
        let seg = tcp(LINKTYPE_ETHERNET, 0, &pkt).expect("syn with options");
        assert!(seg.syn);
        assert!(
            seg.payload.is_empty(),
            "the options are header, not payload: {:?}",
            seg.payload
        );
    }

    /// R311y584 (A3) — the leg the old `NotTcp(17)` skip stood in for.
    ///
    /// Before this, every UDP packet in a capture became a named skip, which
    /// meant scouting, multicast Join and the whole UDP unicast link produced
    /// a dissection with no messages and no error.
    #[test]
    fn a_udp_datagram_is_decapsulated_rather_than_skipped() {
        let pkt = eth_ipv4_udp([10, 0, 0, 1], 7447, [224, 0, 0, 224], 7446, b"hello");
        match decapsulate(LINKTYPE_ETHERNET, 5, &pkt) {
            Ok(Transport::Udp(d)) => {
                assert_eq!(d.payload, b"hello");
                assert_eq!(d.packet_index, 5);
                assert_eq!(d.flow.low.port.min(d.flow.high.port), 7446);
            }
            other => panic!("expected a datagram, got {other:?}"),
        }
    }

    /// The UDP header's `length` field is READ, not inferred from the slice.
    ///
    /// The fixture's Ethernet frame is padded to the 60-byte minimum, so the
    /// captured bytes run PAST the datagram. A reader that took "everything
    /// after the header" would hand five bytes of payload plus a tail of
    /// zeroes to the decoder, and a zenoh message followed by zero bytes
    /// parses as trailing garbage rather than as the message it is.
    #[test]
    fn ethernet_padding_is_not_read_as_datagram_payload() {
        let pkt = eth_ipv4_udp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, b"abc");
        assert_eq!(pkt.len(), 60, "the fixture must actually be padded");
        match decapsulate(LINKTYPE_ETHERNET, 0, &pkt) {
            Ok(Transport::Udp(d)) => assert_eq!(d.payload, b"abc"),
            other => panic!("expected a datagram, got {other:?}"),
        }
    }

    /// Both directions of one UDP conversation key to the SAME flow, exactly
    /// as they do for TCP — otherwise an observer would treat a request and
    /// its reply as two unrelated sessions.
    #[test]
    fn both_directions_of_a_udp_flow_share_one_key() {
        let a = eth_ipv4_udp([10, 0, 0, 1], 1000, [10, 0, 0, 2], 2000, b"x");
        let b = eth_ipv4_udp([10, 0, 0, 2], 2000, [10, 0, 0, 1], 1000, b"y");
        let (da, db) = match (
            decapsulate(LINKTYPE_ETHERNET, 0, &a),
            decapsulate(LINKTYPE_ETHERNET, 1, &b),
        ) {
            (Ok(Transport::Udp(x)), Ok(Transport::Udp(y))) => (x, y),
            other => panic!("expected two datagrams, got {other:?}"),
        };
        assert_eq!(da.flow, db.flow);
        assert_ne!(da.from_low, db.from_low);
    }

    // ---- R311y597: checksums ------------------------------------------------

    /// A REAL IPv4 + UDP packet whose two checksums were computed by an
    /// INDEPENDENT implementation (a short Python one's-complement), not by
    /// the code under test.
    ///
    /// That distinction is the whole value of the fixture. Generating the
    /// expected value with `ones_complement` itself would assert only that the
    /// function agrees with itself, which is true of a wrong one.
    /// `ip ck = 0x66ca`, `udp ck = 0xe1a4`, payload `"zenoh"`.
    #[rustfmt::skip]
    const GOOD_CHECKSUM_PKT: [u8; 47] = [
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x08, 0x00, 0x45, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11,
        0x66, 0xca, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x1d, 0x17,
        0x9c, 0x40, 0x00, 0x0d, 0xe1, 0xa4, 0x7a, 0x65, 0x6e, 0x6f, 0x68,
    ];

    fn checksums_of(pkt: &[u8]) -> Checksums {
        match decapsulate(LINKTYPE_ETHERNET, 0, pkt) {
            Ok(Transport::Udp(d)) => d.checksums,
            other => panic!("expected a datagram, got {other:?}"),
        }
    }

    /// Correct checksums verify — against a vector this crate did not compute.
    #[test]
    fn a_correctly_checksummed_packet_verifies() {
        let c = checksums_of(&GOOD_CHECKSUM_PKT);
        assert_eq!(c.ip, Some(true), "the IPv4 header checksum must verify");
        assert_eq!(c.transport, Some(true), "the UDP checksum must verify");
        assert!(!c.any_invalid());
    }

    /// Corruption is CAUGHT — and separately for each layer, so a verifier
    /// that only ever answered "true" or that conflated the two fails here.
    #[test]
    fn corruption_is_caught_in_the_layer_it_happened_in() {
        // A payload byte is covered by the UDP checksum and not by the IP one.
        let mut body = GOOD_CHECKSUM_PKT;
        body[44] ^= 0xFF;
        let c = checksums_of(&body);
        assert_eq!(c.ip, Some(true), "the IP header was not touched");
        assert_eq!(c.transport, Some(false), "a flipped payload byte must show");
        assert!(c.any_invalid());

        // The IP TTL is covered by the IP checksum and is NOT in the UDP
        // pseudo-header, so exactly the opposite verdict must come back.
        let mut ttl = GOOD_CHECKSUM_PKT;
        ttl[22] ^= 0xFF;
        let c = checksums_of(&ttl);
        assert_eq!(c.ip, Some(false), "a flipped TTL must show");
        assert_eq!(c.transport, Some(true), "the UDP body was not touched");
    }

    /// A UDP datagram over IPv4 with a ZERO checksum declined to compute one
    /// (RFC 768). That is absence, not corruption, and the two must not be
    /// reported the same way — every fixture in this file is that shape.
    #[test]
    fn a_zero_udp_checksum_over_ipv4_is_absence_not_failure() {
        let pkt = eth_ipv4_udp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, b"abc");
        let c = checksums_of(&pkt);
        assert_eq!(c.transport, None, "zero over IPv4 means none was computed");
        // ...and the SAME fixture's IP header checksum really is wrong, because
        // the builder writes zero there too and zero is not special for IPv4.
        // The two layers reporting differently on one packet is the point: an
        // implementation that folded them into a single verdict could not say
        // this, and this is the shape every fixture in this file has.
        assert_eq!(
            c.ip,
            Some(false),
            "a zero IPv4 header checksum is wrong, not absent",
        );
    }

    /// IPv6 has no header checksum at all, so claiming one either way would be
    /// an invention.
    #[test]
    fn ipv6_reports_no_header_checksum() {
        let pkt = eth_ipv6(V6_A, V6_B, IP_PROTO_UDP, &udp_body(1, 2, b"x"));
        let c = checksums_of(&pkt);
        assert_eq!(c.ip, None);
    }

    /// A raweth frame has neither checksum available: no IP header, and no
    /// pseudo-header to build a transport one over.
    #[test]
    fn a_raweth_frame_reports_neither_checksum() {
        use wz_session_core::raweth_link::DEFAULT_ETHTYPE;
        let pkt = raweth_frame([1; 6], [2; 6], DEFAULT_ETHTYPE, b"x");
        match decapsulate(LINKTYPE_ETHERNET, 0, &pkt) {
            Ok(Transport::RawEth(d)) => {
                assert_eq!(d.checksums.ip, None);
                assert_eq!(d.checksums.transport, None);
                assert!(!d.checksums.any_invalid());
            }
            other => panic!("expected a raweth datagram, got {other:?}"),
        }
    }

    // ---- R311y597: raweth (L2) ---------------------------------------------

    /// The fixture is built with `raweth_link`'s OWN framer, so a walker that
    /// disagrees with wz's framing fails here instead of agreeing with my
    /// reading of pico's header.
    fn raweth_frame(smac: [u8; 6], dmac: [u8; 6], ethtype: u16, payload: &[u8]) -> Vec<u8> {
        use wz_session_core::raweth_link::{frame, RawEthHeader};
        let h = RawEthHeader::new(dmac, smac, ethtype, payload.len() as u16);
        frame(&h, payload).expect("raweth frame")
    }

    /// THE GAP. A raweth frame used to die on `NotIp` at the Ethernet arm.
    #[test]
    fn a_raweth_frame_yields_its_payload_as_a_datagram() {
        use wz_session_core::raweth_link::DEFAULT_ETHTYPE;
        let smac = [0x30, 0x03, 0xc8, 0x37, 0x25, 0xa1];
        let dmac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let pkt = raweth_frame(smac, dmac, DEFAULT_ETHTYPE, b"zenoh-batch");

        match decapsulate(LINKTYPE_ETHERNET, 11, &pkt) {
            Ok(Transport::RawEth(d)) => {
                assert_eq!(d.payload, b"zenoh-batch");
                assert_eq!(d.packet_index, 11);
                // Keyed by MAC, and neither endpoint claims to be an address.
                assert!(!d.flow.low.is_ipv4() && !d.flow.high.is_ipv4());
                assert_eq!(d.flow.low.port, 0);
                let mut macs = alloc::vec![d.flow.low.addr(), d.flow.high.addr()];
                macs.sort();
                assert_eq!(macs, alloc::vec![&smac[..], &dmac[..]]);
            }
            other => panic!("expected a raweth datagram, got {other:?}"),
        }
    }

    /// BOTH byte orders of pico's ethertype are admitted, because the sender's
    /// endianness is not observable and pico `memcpy`s the field.
    #[test]
    fn a_raweth_frame_is_recognised_in_either_byte_order() {
        use wz_session_core::raweth_link::DEFAULT_ETHTYPE;
        for (ethtype, label) in [
            (DEFAULT_ETHTYPE, "as a little-endian pico writes it"),
            (
                DEFAULT_ETHTYPE.swap_bytes(),
                "as a big-endian pico writes it",
            ),
        ] {
            let pkt = raweth_frame([1; 6], [2; 6], ethtype, b"x");
            assert!(
                matches!(
                    decapsulate(LINKTYPE_ETHERNET, 0, &pkt),
                    Ok(Transport::RawEth(_))
                ),
                "{label}",
            );
        }
    }

    /// The CONTROL, and it is the leg that keeps the change honest: another
    /// non-IP ethertype must STILL be `NotIp`. Admitting every non-IP frame as
    /// raweth would pass the two legs above.
    #[test]
    fn a_non_raweth_ethertype_is_still_not_ip() {
        let pkt = raweth_frame([1; 6], [2; 6], 0x1234, b"x");
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &pkt),
            Err(SkipReason::NotIp),
        );
        // ...and an ordinary IPv4 frame must not be diverted into raweth.
        let ip = eth_ipv4_udp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, b"abc");
        assert!(matches!(
            decapsulate(LINKTYPE_ETHERNET, 0, &ip),
            Ok(Transport::Udp(_))
        ));
    }

    /// A frame whose `data_length` overruns what was captured is declined, not
    /// read past — the payload is cut to the header's claim, so a NIC-padded
    /// short frame does not hand pad bytes to the decoder.
    #[test]
    fn a_raweth_payload_is_cut_to_its_declared_length() {
        use wz_session_core::raweth_link::DEFAULT_ETHTYPE;
        let mut pkt = raweth_frame([1; 6], [2; 6], DEFAULT_ETHTYPE, b"abc");
        while pkt.len() < 60 {
            pkt.push(0); // the NIC's minimum-frame padding
        }
        match decapsulate(LINKTYPE_ETHERNET, 0, &pkt) {
            Ok(Transport::RawEth(d)) => assert_eq!(d.payload, b"abc"),
            other => panic!("expected a raweth datagram, got {other:?}"),
        }
    }

    // ---- R311y597: the IPv6 leg, which had NO tests at all ----------------
    //
    // That absence is the finding, not a footnote. `strip_ipv6` is reachable
    // from all four link types `strip_link` handles, and every one of its legs
    // was unwitnessed — which is how a branch that refused UDP survived the
    // round that added UDP support to the IPv4 side.

    /// Ethernet + IPv6 + an ARBITRARY next-header, so a leg can aim at the
    /// classification directly. `body` is placed after the 40-byte fixed
    /// header with `payload_len` set to its length, which is what a packet
    /// with no extension chain looks like.
    fn eth_ipv6(src: [u8; 16], dst: [u8; 16], next_header: u8, body: &[u8]) -> Vec<u8> {
        let mut ip = Vec::new();
        ip.extend_from_slice(&0x6000_0000u32.to_be_bytes()); // version 6
        ip.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ip.push(next_header);
        ip.push(64); // hop limit
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(body);

        let mut eth = vec![0x02; 12];
        eth.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        eth.extend_from_slice(&ip);
        eth
    }

    fn udp_body(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend_from_slice(&sport.to_be_bytes());
        udp.extend_from_slice(&dport.to_be_bytes());
        udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes()); // checksum (unverified)
        udp.extend_from_slice(payload);
        udp
    }

    const V6_A: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    const V6_B: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];

    /// THE DEFECT. An IPv6 UDP datagram must reach the UDP arm. Before
    /// R311y597 this returned `Ipv6ExtensionChain(17)`, so IPv6 multicast
    /// scouting and IPv6 UDP unicast links were invisible to a capture.
    #[test]
    fn an_ipv6_udp_datagram_reaches_the_udp_arm() {
        let pkt = eth_ipv6(V6_A, V6_B, IP_PROTO_UDP, &udp_body(7447, 7447, b"scout"));
        match decapsulate(LINKTYPE_ETHERNET, 5, &pkt) {
            Ok(Transport::Udp(d)) => {
                assert_eq!(d.payload, b"scout");
                assert_eq!(d.packet_index, 5);
                assert_eq!(d.flow.low.addr(), &V6_A);
                assert_eq!(d.flow.low.port, 7447);
            }
            other => panic!("expected an IPv6 datagram, got {other:?}"),
        }
    }

    /// The TCP leg the old branch did allow — kept so the fix is shown not to
    /// have traded one protocol for the other.
    #[test]
    fn an_ipv6_tcp_segment_still_reaches_the_tcp_arm() {
        let pkt = eth_ipv6(
            V6_A,
            V6_B,
            IP_PROTO_TCP,
            &tcp_body(7447, 40000, 99, 0x18, b"hi"),
        );
        let seg = tcp(LINKTYPE_ETHERNET, 0, &pkt).expect("decapsulate");
        assert_eq!(seg.payload, b"hi");
        assert_eq!(seg.seq, 99);
    }

    /// A bare TCP header + body, for the tests that build what sits BEHIND an
    /// IPv6 extension chain. Extracted from the test above rather than written
    /// twice: a chain-walk test whose TCP fixture differs from the no-chain
    /// one's proves less than it looks like, because a difference in the
    /// fixture and a difference in the walk are then indistinguishable.
    fn tcp_body(sport: u16, dport: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&sport.to_be_bytes());
        out.extend_from_slice(&dport.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // ack
        out.push(5 << 4); // data offset, no options
        out.push(flags);
        out.extend_from_slice(&0xFFFFu16.to_be_bytes()); // window
        out.extend_from_slice(&0u16.to_be_bytes()); // checksum, unverified
        out.extend_from_slice(&0u16.to_be_bytes()); // urgent
        out.extend_from_slice(payload);
        out
    }

    /// R311y603 — the extension headers that genuinely CANNOT be walked still
    /// refuse, and the reason still carries the header's own number.
    ///
    /// This list shrank from eleven to three in the round that added the walk,
    /// and the shrink is the deliverable rather than a test being relaxed: ESP
    /// (50) encrypts everything after it, and 253 / 254 are reserved for
    /// experimentation with no length a reader may assume. Those three are
    /// LIMITS. The other eight were WORK, and the tests below do it.
    #[test]
    fn an_unwalkable_ipv6_extension_header_is_still_refused_by_name() {
        for ext in [50u8, 253, 254] {
            let pkt = eth_ipv6(V6_A, V6_B, ext, b"whatever");
            assert_eq!(
                decapsulate(LINKTYPE_ETHERNET, 0, &pkt),
                Err(SkipReason::Ipv6ExtensionChain(ext)),
                "next-header {ext} cannot be walked and must be named as such",
            );
        }
    }

    /// THE ONE THAT MATTERS. Every walkable extension header must land the
    /// walk on the TCP segment behind it — a zenoh session over IPv6 with a
    /// Hop-by-Hop option present produced a dissection with no messages, and
    /// nothing said why beyond naming the header.
    ///
    /// Each header is built with a REAL length field rather than padding,
    /// because the failure mode of a chain walker is landing a few bytes off:
    /// an off-by-N would not error, it would decode a different flow out of
    /// the middle of the payload. Asserting the recovered ports and body is
    /// what catches that; asserting only "not an error" would not.
    #[test]
    fn every_walkable_ipv6_extension_header_is_stepped_over_to_the_transport() {
        // The (len+1)*8 family: Hop-by-Hop, Routing, Destination Options,
        // Mobility, HIP, Shim6.
        for ext in [0u8, 43, 60, 135, 139, 140] {
            let mut chain = alloc::vec![0u8; 8];
            chain[0] = IP_PROTO_TCP;
            chain[1] = 0; // (0 + 1) * 8 = this 8-byte header
            chain.extend_from_slice(&tcp_body(7447, 40000, 99, 0x18, b"hi"));
            let pkt = eth_ipv6(V6_A, V6_B, ext, &chain);
            let seg = tcp(LINKTYPE_ETHERNET, 0, &pkt)
                .unwrap_or_else(|e| panic!("next-header {ext} must be walked, got {e:?}"));
            assert_eq!(seg.payload, b"hi", "walked to the wrong offset for {ext}");
            assert_eq!(seg.seq, 99);
        }
    }

    /// The Authentication Header measures in 4-byte units counted from 2, not
    /// in 8-byte units counted from 1. Reading it with the common formula lands
    /// the walk inside the payload, so it gets its own leg with a length the
    /// two rules disagree about: `len = 1` means 12 bytes by AH's rule and 16
    /// by the common one.
    #[test]
    fn the_authentication_header_uses_its_own_length_rule() {
        let mut chain = alloc::vec![0u8; 12];
        chain[0] = IP_PROTO_TCP;
        chain[1] = 1; // (1 + 2) * 4 = 12
        chain.extend_from_slice(&tcp_body(7447, 40000, 7, 0x18, b"ah"));
        let pkt = eth_ipv6(V6_A, V6_B, 51, &chain);
        let seg = tcp(LINKTYPE_ETHERNET, 0, &pkt).expect("AH must be walked");
        assert_eq!(seg.payload, b"ah");
        assert_eq!(seg.seq, 7);
    }

    /// Every piece of a fragmented IPv6 datagram is reported as a piece —
    /// INCLUDING the first, which is the leg this test used to get wrong.
    ///
    /// R311y606. The old shape walked the first fragment through to TCP and
    /// asserted its payload, which is the silent-truncation defect stated as an
    /// expectation: `f1` was a PREFIX of that segment, and delivering it
    /// advanced the stream by less than the sender sent. The fix is that offset
    /// zero with M set is a fragment like any other.
    #[test]
    fn every_ipv6_fragment_is_reported_as_a_piece() {
        let mut first = alloc::vec![0u8; 8];
        first[0] = IP_PROTO_TCP;
        first[2..4].copy_from_slice(&0x0001u16.to_be_bytes()); // offset 0, M set
        first[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        first.extend_from_slice(&tcp_body(7447, 40000, 5, 0x18, b"f1"));
        let piece = fragment(LINKTYPE_ETHERNET, 0, &eth_ipv6(V6_A, V6_B, 44, &first));
        assert_eq!(piece.info.offset, 0);
        assert!(piece.info.more, "M is set, so this is not the last piece");
        assert_eq!(piece.info.ident, 0xDEAD_BEEF);
        assert_eq!(piece.proto, IP_PROTO_TCP);
        // The piece's bytes are the TCP header and its prefix — carried, not
        // parsed. Parsing them here is exactly what used to happen.
        assert_eq!(&piece.payload[20..], b"f1");

        let mut later = alloc::vec![0u8; 8];
        later[0] = IP_PROTO_TCP;
        later[2..4].copy_from_slice(&(64u16 << 3).to_be_bytes());
        later[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        let piece = fragment(LINKTYPE_ETHERNET, 0, &eth_ipv6(V6_A, V6_B, 44, &later));
        assert_eq!(piece.info.offset, 512);
        assert!(!piece.info.more);
        assert_eq!(
            piece.info.ident, 0xDEAD_BEEF,
            "both pieces must key to one datagram"
        );
    }

    /// Two headers in a row, because a walker that handles one can still be a
    /// walker that does not loop.
    #[test]
    fn a_chain_of_two_headers_reaches_the_transport() {
        let mut second = alloc::vec![0u8; 8];
        second[0] = IP_PROTO_TCP;
        second.extend_from_slice(&tcp_body(7447, 40000, 11, 0x18, b"two"));
        let mut first = alloc::vec![0u8; 8];
        first[0] = 60; // -> Destination Options
        first.extend_from_slice(&second);
        let seg = tcp(LINKTYPE_ETHERNET, 0, &eth_ipv6(V6_A, V6_B, 0, &first))
            .expect("hop-by-hop then destination-options then TCP");
        assert_eq!(seg.payload, b"two");
        assert_eq!(seg.seq, 11);
    }

    /// A chain that never terminates must stop at the bound and NAME the
    /// header it stopped on, not loop. Each header points at another of its own
    /// kind, so the only thing that ends this walk is the cap.
    #[test]
    fn an_endless_chain_stops_at_the_bound_instead_of_looping() {
        let mut chain = Vec::new();
        for _ in 0..IPV6_MAX_EXT_HEADERS + 2 {
            chain.extend_from_slice(&[60u8, 0, 0, 0, 0, 0, 0, 0]);
        }
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &eth_ipv6(V6_A, V6_B, 60, &chain)),
            Err(SkipReason::Ipv6ExtensionChain(60)),
        );
    }

    /// THE SECOND FAILURE OF THE SAME LINE, and the reason "also allow UDP"
    /// would have been the wrong fix. A non-transport upper-layer protocol
    /// (ICMPv6 here) is not an extension header, and reporting it as an
    /// unwalked chain points a reader at building a chain walker that would
    /// not have helped. It must classify exactly as the IPv4 path does.
    #[test]
    fn a_non_transport_ipv6_protocol_is_not_reported_as_an_extension_chain() {
        const IP_PROTO_ICMPV6: u8 = 58;
        let pkt = eth_ipv6(V6_A, V6_B, IP_PROTO_ICMPV6, b"\x80\x00\x00\x00");
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &pkt),
            Err(SkipReason::NotTransport(IP_PROTO_ICMPV6)),
        );
    }

    /// IPv6 has no header checksum and no `total_length` — only `payload_len`,
    /// counted from the END of the fixed header rather than from its start.
    /// Getting that origin wrong reads link padding as payload, so it is
    /// pinned the same way the IPv4 leg pins its own.
    #[test]
    fn ipv6_payload_len_is_measured_from_the_end_of_the_fixed_header() {
        let mut pkt = eth_ipv6(V6_A, V6_B, IP_PROTO_UDP, &udp_body(1, 2, b"abc"));
        while pkt.len() < 60 {
            pkt.push(0); // the pad a real NIC adds
        }
        match decapsulate(LINKTYPE_ETHERNET, 0, &pkt) {
            Ok(Transport::Udp(d)) => assert_eq!(d.payload, b"abc"),
            other => panic!("expected a datagram, got {other:?}"),
        }
    }
}
