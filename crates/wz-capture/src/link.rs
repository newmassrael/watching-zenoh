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

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;

const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;

/// An IP endpoint: address bytes (4 for v4, 16 for v6) plus a port.
///
/// The address is a fixed 16-byte buffer with a length, not an enum: the
/// flow key only ever compares and orders it, and a `[u8; 16]` keeps the key
/// `Copy` and hashable without a v4/v6 split rippling into every consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {
    addr: [u8; 16],
    addr_len: u8,
    /// TCP port, host order.
    pub port: u16,
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

    fn new(addr_bytes: &[u8], port: u16) -> Self {
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
    /// An IPv4 fragment other than the first. Reassembling IP fragments is a
    /// separate problem from reassembling a TCP stream and is NOT done here;
    /// naming it keeps a hole in the byte stream attributable.
    Ipv4Fragment,
    /// An IPv6 packet whose first next-header is a genuine EXTENSION HEADER,
    /// which this build does not walk.
    ///
    /// R311y597 — the payload is the extension header's own number, and it is
    /// now only ever one of [`is_ipv6_extension_header`]'s set. It previously
    /// carried any next-header that was not TCP, so a reader saw UDP (17) and
    /// ICMPv6 (58) reported as unwalked chains.
    Ipv6ExtensionChain(u8),
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
}

/// What a captured packet turned out to carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// A TCP segment, to be fed to a stream reassembler.
    Tcp(Segment),
    /// A UDP datagram, already a whole message.
    Udp(Datagram),
    /// A raweth (L2) frame's payload — one whole message, like a datagram.
    ///
    /// R311y597. A separate variant from [`Self::Udp`] even though both carry
    /// a [`Datagram`], because the two are only alike in SHAPE: a raweth flow
    /// is keyed by MAC with no ports, so a consumer that reports "UDP flow"
    /// over it would be naming a transport that is not there.
    RawEth(Datagram),
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
    if link_type == LINKTYPE_ETHERNET {
        if let Some(d) = strip_raweth(bytes, packet_index) {
            return Ok(Transport::RawEth(d));
        }
    }
    let (ip_bytes, is_v6) = strip_link(link_type, bytes)?;
    let (src, dst, proto, payload) = if is_v6 {
        strip_ipv6(ip_bytes)?
    } else {
        strip_ipv4(ip_bytes)?
    };
    match proto {
        IP_PROTO_TCP => strip_tcp(src, dst, payload, packet_index).map(Transport::Tcp),
        IP_PROTO_UDP => strip_udp(src, dst, payload, packet_index).map(Transport::Udp),
        other => Err(SkipReason::NotTransport(other)),
    }
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
    let src = Endpoint::new(src.addr(), src_port);
    let dst = Endpoint::new(dst.addr(), dst_port);
    let (flow, from_low) = FlowKey::new(src, dst);
    Ok(Datagram {
        flow,
        from_low,
        payload: bytes[8..8 + body_len].to_vec(),
        packet_index,
    })
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

fn strip_ipv4(bytes: &[u8]) -> Result<(Endpoint, Endpoint, u8, &[u8]), SkipReason> {
    if bytes.len() < 20 {
        return Err(SkipReason::Truncated);
    }
    let ihl = ((bytes[0] & 0x0F) as usize) * 4;
    if ihl < 20 || bytes.len() < ihl {
        return Err(SkipReason::Truncated);
    }
    // Fragment offset is the low 13 bits of the flags/offset word. A non-zero
    // offset means this is NOT the first fragment and carries no TCP header.
    let frag_off = u16::from_be_bytes([bytes[6], bytes[7]]) & 0x1FFF;
    if frag_off != 0 {
        return Err(SkipReason::Ipv4Fragment);
    }
    let total_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    // Trust the header's total length when it fits, so trailing link padding
    // (an Ethernet frame padded to 60 bytes) is not read as payload. Fall
    // back to the captured length when the capture was snaplen-truncated.
    let end = if total_len >= ihl && total_len <= bytes.len() {
        total_len
    } else {
        bytes.len()
    };
    let proto = bytes[9];
    let src = &bytes[12..16];
    let dst = &bytes[16..20];
    Ok((
        Endpoint::new(src, 0),
        Endpoint::new(dst, 0),
        proto,
        &bytes[ihl..end],
    ))
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

fn strip_ipv6(bytes: &[u8]) -> Result<(Endpoint, Endpoint, u8, &[u8]), SkipReason> {
    if bytes.len() < 40 {
        return Err(SkipReason::Truncated);
    }
    let next_header = bytes[6];
    // Refuse ONLY a genuine extension header. Everything else is returned
    // through for `decapsulate` to classify, exactly as `strip_ipv4` does with
    // its protocol byte: TCP and UDP reach their arms, and anything else lands
    // on `NotTransport`, which names the real cause.
    if is_ipv6_extension_header(next_header) {
        return Err(SkipReason::Ipv6ExtensionChain(next_header));
    }
    let payload_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let end = if 40 + payload_len <= bytes.len() {
        40 + payload_len
    } else {
        bytes.len()
    };
    Ok((
        Endpoint::new(&bytes[8..24], 0),
        Endpoint::new(&bytes[24..40], 0),
        next_header,
        &bytes[40..end],
    ))
}

fn strip_tcp(
    src: Endpoint,
    dst: Endpoint,
    bytes: &[u8],
    packet_index: usize,
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
    let src = Endpoint::new(src.addr(), src_port);
    let dst = Endpoint::new(dst.addr(), dst_port);
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
            Err(e) => Err(e),
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

        // A non-first IPv4 fragment.
        let mut frag = eth_ipv4_tcp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 0, 0x18, b"x");
        frag[14 + 6..14 + 8].copy_from_slice(&0x0001u16.to_be_bytes());
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &frag),
            Err(SkipReason::Ipv4Fragment)
        );

        // An IPv6 extension-header chain. R311y597 — this leg was MISSING,
        // which is why the test's name was a claim it did not keep: the one
        // variant it never built was the one whose branch was wrong.
        let ipv6_frag = {
            let mut ip = Vec::new();
            ip.extend_from_slice(&0x6000_0000u32.to_be_bytes());
            ip.extend_from_slice(&8u16.to_be_bytes());
            ip.push(44); // Fragment header
            ip.push(64);
            ip.extend_from_slice(&[0u8; 32]);
            ip.extend_from_slice(&[0u8; 8]);
            let mut eth = vec![0x02; 12];
            eth.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
            eth.extend_from_slice(&ip);
            eth
        };
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &ipv6_frag),
            Err(SkipReason::Ipv6ExtensionChain(44))
        );

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
        let mut tcp_body = Vec::new();
        tcp_body.extend_from_slice(&7447u16.to_be_bytes());
        tcp_body.extend_from_slice(&40000u16.to_be_bytes());
        tcp_body.extend_from_slice(&99u32.to_be_bytes()); // seq
        tcp_body.extend_from_slice(&0u32.to_be_bytes()); // ack
        tcp_body.push(5 << 4);
        tcp_body.push(0x18);
        tcp_body.extend_from_slice(&0xFFFFu16.to_be_bytes());
        tcp_body.extend_from_slice(&0u16.to_be_bytes());
        tcp_body.extend_from_slice(&0u16.to_be_bytes());
        tcp_body.extend_from_slice(b"hi");

        let pkt = eth_ipv6(V6_A, V6_B, IP_PROTO_TCP, &tcp_body);
        let seg = tcp(LINKTYPE_ETHERNET, 0, &pkt).expect("decapsulate");
        assert_eq!(seg.payload, b"hi");
        assert_eq!(seg.seq, 99);
    }

    /// A GENUINE extension header still refuses, and the reason still carries
    /// the header's own number. This is the half of the old behaviour that was
    /// correct, and the leg exists so the fix cannot silently drop it.
    #[test]
    fn a_genuine_ipv6_extension_header_is_still_refused_by_name() {
        for ext in [0u8, 43, 44, 50, 51, 60, 135, 139, 140, 253, 254] {
            let pkt = eth_ipv6(V6_A, V6_B, ext, b"whatever");
            assert_eq!(
                decapsulate(LINKTYPE_ETHERNET, 0, &pkt),
                Err(SkipReason::Ipv6ExtensionChain(ext)),
                "next-header {ext} is an extension header and must be named as one",
            );
        }
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
