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
    /// IP, but not TCP.
    NotTcp(u8),
    /// An IPv4 fragment other than the first. Reassembling IP fragments is a
    /// separate problem from reassembling a TCP stream and is NOT done here;
    /// naming it keeps a hole in the byte stream attributable.
    Ipv4Fragment,
    /// An IPv6 packet whose extension-header chain this build does not walk.
    Ipv6ExtensionChain(u8),
}

/// Decapsulate one captured packet down to a TCP segment.
pub fn decapsulate(
    link_type: u32,
    packet_index: usize,
    bytes: &[u8],
) -> Result<Segment, SkipReason> {
    let (ip_bytes, is_v6) = strip_link(link_type, bytes)?;
    let (src, dst, proto, payload) = if is_v6 {
        strip_ipv6(ip_bytes)?
    } else {
        strip_ipv4(ip_bytes)?
    };
    if proto != IP_PROTO_TCP {
        return Err(SkipReason::NotTcp(proto));
    }
    strip_tcp(src, dst, payload, packet_index)
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

fn strip_ipv6(bytes: &[u8]) -> Result<(Endpoint, Endpoint, u8, &[u8]), SkipReason> {
    if bytes.len() < 40 {
        return Err(SkipReason::Truncated);
    }
    let next_header = bytes[6];
    // No extension-header walk: a chain would need per-header length rules
    // and none of them appear on a zenoh TCP flow. Named rather than guessed.
    if next_header != IP_PROTO_TCP {
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

    /// Build an Ethernet + IPv4 + TCP packet. The fixture builder is here in
    /// the tests rather than in the library because nothing in production
    /// EMITS packets — a builder in `src` would be a second, unverified
    /// opinion about the layouts the parser reads.
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
        let seg = decapsulate(LINKTYPE_ETHERNET, 3, &pkt).expect("decapsulate");
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
        let sa = decapsulate(LINKTYPE_ETHERNET, 0, &a).expect("a");
        let sb = decapsulate(LINKTYPE_ETHERNET, 1, &b).expect("b");
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
            let seg = decapsulate(LINKTYPE_ETHERNET, 0, &tagged)
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
        let seg = decapsulate(LINKTYPE_ETHERNET, 0, &pkt).expect("padded frame");
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
        let mut udp = eth_ipv4_tcp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 0, 0x18, b"x");
        udp[14 + 9] = 17;
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &udp),
            Err(SkipReason::NotTcp(17))
        );

        // A non-first IPv4 fragment.
        let mut frag = eth_ipv4_tcp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 0, 0x18, b"x");
        frag[14 + 6..14 + 8].copy_from_slice(&0x0001u16.to_be_bytes());
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &frag),
            Err(SkipReason::Ipv4Fragment)
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
        let reference = decapsulate(LINKTYPE_ETHERNET, 0, &eth).expect("ethernet");

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
            let seg = decapsulate(lt, 0, &framed).unwrap_or_else(|e| panic!("link {lt}: {e:?}"));
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
        let seg = decapsulate(LINKTYPE_ETHERNET, 0, &pkt).expect("syn with options");
        assert!(seg.syn);
        assert!(
            seg.payload.is_empty(),
            "the options are header, not payload: {:?}",
            seg.payload
        );
    }
}
