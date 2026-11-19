// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE NETWORK'S OWN WORD ABOUT A FLOW: ICMP and ICMPv6 errors, and IGMP and
//! MLD membership.
//!
//! None of these is zenoh, and the transport path skips them
//! (`SkipReason::NotTransport`, which still counts them). Two of zenoh's
//! failures are answered in them and nowhere else:
//!
//! * a datagram sent to a port nobody listens on, a host the network cannot
//!   reach, or a packet too big for a link on the way, comes back as an ICMP
//!   error QUOTING the start of the packet it refuses (RFC 792, RFC 4443
//!   section 3), and the quote names the flow it was about;
//! * a multicast group a switch has stopped forwarding, which is how scouting
//!   on `224.0.0.224:7446` fails without a word from zenoh, shows as the IGMP
//!   queries a querier sends and the reports members answer them with (RFC
//!   2236, RFC 3376; MLD for IPv6, RFC 2710 and RFC 3810).
//!
//! This module reads one such message out of an IP payload into
//! [`ControlMessage`]. What it keeps is what those two questions need: for an
//! error, why and about which flow; for membership, which group and who.

use alloc::vec::Vec;

use crate::link::{Endpoint, FlowKey, LinkKind};

/// IP protocol number of ICMP.
pub const IP_PROTO_ICMP: u8 = 1;
/// IP protocol number of IGMP.
pub const IP_PROTO_IGMP: u8 = 2;
/// IP protocol number of ICMPv6.
pub const IP_PROTO_ICMPV6: u8 = 58;

/// Whether `proto` is a protocol this module reads.
pub fn reads(proto: u8) -> bool {
    matches!(proto, IP_PROTO_ICMP | IP_PROTO_IGMP | IP_PROTO_ICMPV6)
}

/// Why an ICMP or ICMPv6 error refused a packet. The closed set the documents
/// write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreachable {
    /// No process listened on the port (ICMP type 3 code 3, ICMPv6 type 1
    /// code 4).
    Port,
    /// The host could not be reached (ICMP type 3 code 1, ICMPv6 type 1 code
    /// 3).
    Host,
    /// The network could not be reached, or there was no route (ICMP type 3
    /// code 0, ICMPv6 type 1 code 0).
    Network,
    /// The protocol is not served (ICMP type 3 code 2).
    Protocol,
    /// The packet is bigger than a link on the way and may not be fragmented
    /// (ICMP type 3 code 4, ICMPv6 type 2): the MTU comes with it.
    FragmentationNeeded,
    /// A filter refused it (ICMP type 3 codes 9, 10 and 13, ICMPv6 type 1 code
    /// 1).
    Prohibited,
    /// Another code of the destination-unreachable message.
    Other,
}

impl Unreachable {
    /// The word this reason is written as.
    pub const fn name(self) -> &'static str {
        match self {
            Unreachable::Port => "port",
            Unreachable::Host => "host",
            Unreachable::Network => "network",
            Unreachable::Protocol => "protocol",
            Unreachable::FragmentationNeeded => "fragmentation_needed",
            Unreachable::Prohibited => "prohibited",
            Unreachable::Other => "other",
        }
    }

    /// Every reason, from an exhaustive match.
    pub fn all() -> [Unreachable; 7] {
        let one = |u: Unreachable| match u {
            Unreachable::Port => Unreachable::Port,
            Unreachable::Host => Unreachable::Host,
            Unreachable::Network => Unreachable::Network,
            Unreachable::Protocol => Unreachable::Protocol,
            Unreachable::FragmentationNeeded => Unreachable::FragmentationNeeded,
            Unreachable::Prohibited => Unreachable::Prohibited,
            Unreachable::Other => Unreachable::Other,
        };
        [
            one(Unreachable::Port),
            one(Unreachable::Host),
            one(Unreachable::Network),
            one(Unreachable::Protocol),
            one(Unreachable::FragmentationNeeded),
            one(Unreachable::Prohibited),
            one(Unreachable::Other),
        ]
    }

    /// Every word, sorted.
    pub fn names() -> Vec<&'static str> {
        let mut words: Vec<&'static str> = Self::all().iter().map(|u| u.name()).collect();
        words.sort_unstable();
        words
    }
}

/// What a membership message did. The closed set the documents write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Membership {
    /// A querier asked which groups have members (IGMP type 0x11, MLD 130).
    Query,
    /// A host said it is a member (IGMP types 0x12, 0x16 and 0x22, MLD 131 and
    /// 143).
    Report,
    /// A host said it left (IGMP type 0x17, MLD 132).
    Leave,
}

impl Membership {
    /// The word this message is written as.
    pub const fn name(self) -> &'static str {
        match self {
            Membership::Query => "query",
            Membership::Report => "report",
            Membership::Leave => "leave",
        }
    }

    /// Every word, sorted, from an exhaustive match.
    pub fn names() -> Vec<&'static str> {
        let one = |m: Membership| match m {
            Membership::Query => Membership::Query,
            Membership::Report => Membership::Report,
            Membership::Leave => Membership::Leave,
        };
        let mut words: Vec<&'static str> = [
            one(Membership::Query),
            one(Membership::Report),
            one(Membership::Leave),
        ]
        .iter()
        .map(|m| m.name())
        .collect();
        words.sort_unstable();
        words
    }
}

/// One control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlKind {
    /// An error refusing a packet.
    Unreachable {
        /// Why.
        why: Unreachable,
        /// The flow of the packet it quotes, `None` when the quote is too short
        /// to name both ports or quotes a protocol with none.
        about: Option<FlowKey>,
        /// The MTU of the link on the way, for [`Unreachable::FragmentationNeeded`]
        /// when the message states one.
        mtu: Option<u32>,
    },
    /// A membership message.
    Membership {
        /// What it did.
        what: Membership,
        /// The groups it names: none for a general query, the group for a
        /// group query, a leave or a version 1 or 2 report, every group record's
        /// for a version 3 report. Each 4 or 16 address bytes.
        groups: Vec<Vec<u8>>,
    },
}

/// One ICMP, ICMPv6 or IGMP message, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlMessage {
    /// The sender's address (no port).
    pub from: Endpoint,
    /// The destination address (no port).
    pub to: Endpoint,
    /// The capture-global packet it was read from.
    pub packet: usize,
    /// What it said.
    pub kind: ControlKind,
}

/// How many errors one flow holds: see [`FlowErrors`].
pub const FLOW_ERRORS_HELD: usize = 64;

/// One error that quoted a packet of a flow, as the flow keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowError {
    /// Why the packet was refused.
    pub why: Unreachable,
    /// The capture-global packet that carried the error.
    pub packet: usize,
    /// Who sent the error: the host itself for a closed port, a router on the
    /// way for the others.
    pub from: Endpoint,
    /// The MTU a [`Unreachable::FragmentationNeeded`] stated.
    pub mtu: Option<u32>,
}

/// The errors that quoted a packet of one flow, in capture order, up to
/// [`FLOW_ERRORS_HELD`], and how many more there were.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FlowErrors {
    held: Vec<FlowError>,
    more: u64,
}

impl FlowErrors {
    /// One more error about the flow.
    pub fn observe(&mut self, error: FlowError) {
        if self.held.len() < FLOW_ERRORS_HELD {
            self.held.push(error);
        } else {
            self.more += 1;
        }
    }

    /// The errors held.
    pub fn errors(&self) -> &[FlowError] {
        &self.held
    }

    /// The errors past the bound, not held.
    pub fn more(&self) -> u64 {
        self.more
    }
}

/// How many control messages a capture holds. A capture of a network that
/// fails can carry an error for every datagram it sent; the bound keeps that
/// from growing without end, and [`ControlPlane::more`] counts what it left.
pub const CONTROL_MESSAGES_HELD: usize = 1024;

/// The control messages a capture carried, in capture order, up to
/// [`CONTROL_MESSAGES_HELD`].
#[derive(Debug, Default, Clone)]
pub struct ControlPlane {
    held: Vec<ControlMessage>,
    more: u64,
}

impl ControlPlane {
    /// One message, read at its packet.
    pub fn observe(&mut self, message: ControlMessage) {
        if self.held.len() < CONTROL_MESSAGES_HELD {
            self.held.push(message);
        } else {
            self.more += 1;
        }
    }

    /// The messages held, in capture order.
    pub fn messages(&self) -> &[ControlMessage] {
        &self.held
    }

    /// The messages read past the bound and not held. Zero means
    /// [`Self::messages`] is every one the capture carried.
    pub fn more(&self) -> u64 {
        self.more
    }
}

impl ControlMessage {
    /// The flow an error quotes and what the flow keeps of it; `None` for a
    /// membership message and for an error whose quote names no flow.
    pub fn about(&self) -> Option<(&FlowKey, FlowError)> {
        match &self.kind {
            ControlKind::Unreachable {
                why,
                about: Some(about),
                mtu,
            } => Some((
                about,
                FlowError {
                    why: *why,
                    packet: self.packet,
                    from: self.from,
                    mtu: *mtu,
                },
            )),
            _ => None,
        }
    }
}

/// Read one control message out of the payload of an IP datagram of protocol
/// `proto` from `src` to `dst`. `None` for a protocol or a type this module
/// does not read, or a message too short for its fixed part.
pub fn read(
    src: Endpoint,
    dst: Endpoint,
    proto: u8,
    payload: &[u8],
    packet: usize,
) -> Option<ControlMessage> {
    let kind = match proto {
        IP_PROTO_ICMP => icmp(payload)?,
        IP_PROTO_ICMPV6 => icmpv6(payload)?,
        IP_PROTO_IGMP => igmp(payload)?,
        _ => return None,
    };
    Some(ControlMessage {
        from: src,
        to: dst,
        packet,
        kind,
    })
}

/// ICMP (RFC 792): type 3, destination unreachable, is the one read. Its eight
/// bytes are type, code, checksum, an unused half-word and, for code 4, the
/// next-hop MTU (RFC 1191); the quoted IP header and eight bytes follow.
fn icmp(m: &[u8]) -> Option<ControlKind> {
    if m.len() < 8 || m[0] != 3 {
        return None;
    }
    let why = match m[1] {
        0 => Unreachable::Network,
        1 => Unreachable::Host,
        2 => Unreachable::Protocol,
        3 => Unreachable::Port,
        4 => Unreachable::FragmentationNeeded,
        9 | 10 | 13 => Unreachable::Prohibited,
        _ => Unreachable::Other,
    };
    let mtu = (why == Unreachable::FragmentationNeeded)
        .then(|| u32::from(u16::from_be_bytes([m[6], m[7]])))
        .filter(|mtu| *mtu != 0);
    Some(ControlKind::Unreachable {
        why,
        about: quoted_v4(&m[8..]),
        mtu,
    })
}

/// ICMPv6 (RFC 4443): type 1, destination unreachable, and type 2, packet too
/// big, are the errors read; 130 to 132 and 143 are MLD (RFC 2710, RFC 3810).
fn icmpv6(m: &[u8]) -> Option<ControlKind> {
    if m.len() < 8 {
        return None;
    }
    match m[0] {
        1 => Some(ControlKind::Unreachable {
            why: match m[1] {
                0 => Unreachable::Network,
                1 => Unreachable::Prohibited,
                3 => Unreachable::Host,
                4 => Unreachable::Port,
                _ => Unreachable::Other,
            },
            about: quoted_v6(&m[8..]),
            mtu: None,
        }),
        2 => Some(ControlKind::Unreachable {
            why: Unreachable::FragmentationNeeded,
            about: quoted_v6(&m[8..]),
            mtu: Some(u32::from_be_bytes([m[4], m[5], m[6], m[7]])),
        }),
        130..=132 => {
            // Type, code, checksum, maximum delay, reserved, then the group.
            let group = m.get(8..24)?;
            let what = match m[0] {
                130 => Membership::Query,
                131 => Membership::Report,
                _ => Membership::Leave,
            };
            Some(ControlKind::Membership {
                what,
                groups: named_group(group),
            })
        }
        143 => {
            // MLDv2 report: type, code, checksum, reserved, the record count,
            // then records of type, aux length (32-bit words), source count and
            // the group, followed by the sources and the aux data.
            let count = usize::from(u16::from_be_bytes([m[6], m[7]]));
            let mut groups = Vec::new();
            let mut at = 8;
            for _ in 0..count {
                let head = m.get(at..at + 20)?;
                let aux = usize::from(head[1]) * 4;
                let sources = usize::from(u16::from_be_bytes([head[2], head[3]]));
                groups.push(head[4..20].to_vec());
                at += 20 + sources * 16 + aux;
            }
            Some(ControlKind::Membership {
                what: Membership::Report,
                groups,
            })
        }
        _ => None,
    }
}

/// IGMP (RFC 2236, RFC 3376): a query (0x11), the three reports (0x12 version
/// 1, 0x16 version 2, 0x22 version 3) and a leave (0x17).
fn igmp(m: &[u8]) -> Option<ControlKind> {
    if m.len() < 8 {
        return None;
    }
    let (what, groups) = match m[0] {
        0x11 => (Membership::Query, named_group(&m[4..8])),
        0x12 | 0x16 => (Membership::Report, named_group(&m[4..8])),
        0x17 => (Membership::Leave, named_group(&m[4..8])),
        0x22 => {
            // Type, reserved, checksum, reserved, the record count, then
            // records of type, aux length (32-bit words), source count and the
            // group, followed by the sources and the aux data.
            let count = usize::from(u16::from_be_bytes([m[6], m[7]]));
            let mut groups = Vec::new();
            let mut at = 8;
            for _ in 0..count {
                let head = m.get(at..at + 8)?;
                let aux = usize::from(head[1]) * 4;
                let sources = usize::from(u16::from_be_bytes([head[2], head[3]]));
                groups.push(head[4..8].to_vec());
                at += 8 + sources * 4 + aux;
            }
            (Membership::Report, groups)
        }
        _ => return None,
    };
    Some(ControlKind::Membership { what, groups })
}

/// A group address field: none when it is all zero (a general query), else
/// the one group.
fn named_group(group: &[u8]) -> Vec<Vec<u8>> {
    if group.iter().all(|b| *b == 0) {
        Vec::new()
    } else {
        alloc::vec![group.to_vec()]
    }
}

/// The flow of an IPv4 packet whose header and first eight bytes an ICMP error
/// quotes: its addresses, protocol and, for TCP and UDP, its two ports.
fn quoted_v4(q: &[u8]) -> Option<FlowKey> {
    if q.len() < 20 || q[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(q[0] & 0x0F) * 4;
    let ports = q.get(ihl..ihl + 4)?;
    let link = transport_link(q[9])?;
    Some(quoted_flow(&q[12..16], &q[16..20], ports, link))
}

/// The flow of an IPv6 packet an ICMPv6 error quotes, when its fixed header
/// names TCP or UDP directly: a packet whose first next header is an extension
/// header names no ports here, and this reader does not walk the chain of a
/// quote that may stop inside it.
fn quoted_v6(q: &[u8]) -> Option<FlowKey> {
    if q.len() < 40 || q[0] >> 4 != 6 {
        return None;
    }
    let ports = q.get(40..44)?;
    let link = transport_link(q[6])?;
    Some(quoted_flow(&q[8..24], &q[24..40], ports, link))
}

fn transport_link(proto: u8) -> Option<LinkKind> {
    match proto {
        6 => Some(LinkKind::Tcp),
        17 => Some(LinkKind::Udp),
        _ => None,
    }
}

fn quoted_flow(src: &[u8], dst: &[u8], ports: &[u8], link: LinkKind) -> FlowKey {
    let sport = u32::from(u16::from_be_bytes([ports[0], ports[1]]));
    let dport = u32::from(u16::from_be_bytes([ports[2], ports[3]]));
    crate::link::flow_key(Endpoint::new(src, sport), Endpoint::new(dst, dport), link)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datagram_tests::{fill_ipv4_checksum, udp_packet};
    use crate::link::LINKTYPE_ETHERNET;

    const LOW: [u8; 4] = [10, 0, 0, 1];
    const HIGH: [u8; 4] = [10, 0, 0, 2];

    /// Ethernet and IPv4 around `payload` of protocol `proto`.
    fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
        let mut ip = alloc::vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0x40, 0, 1, proto, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        fill_ipv4_checksum(&mut ip);
        ip.extend_from_slice(payload);
        let mut eth = alloc::vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        eth
    }

    /// An ICMP destination unreachable of `code` quoting the first bytes of
    /// the IPv4 packet `quoted` (from its IP header on).
    fn unreachable(code: u8, mtu: u16, quoted: &[u8]) -> Vec<u8> {
        let mut m = alloc::vec![3u8, code, 0, 0, 0, 0];
        m.extend_from_slice(&mtu.to_be_bytes());
        m.extend_from_slice(&quoted[..28.min(quoted.len())]);
        m
    }

    fn endpoint(addr: [u8; 4], port: u16) -> Endpoint {
        Endpoint::new(&addr, u32::from(port))
    }

    /// The IP datagram inside an Ethernet frame `udp_packet` built.
    fn ip_of(frame: &[u8]) -> &[u8] {
        &frame[14..]
    }

    #[test]
    fn an_icmp_port_unreachable_names_the_flow_it_quotes() {
        let sent = udp_packet(LOW, 43210, HIGH, 7447, &[0x04]);
        let m = read(
            endpoint(HIGH, 0),
            endpoint(LOW, 0),
            IP_PROTO_ICMP,
            &unreachable(3, 0, ip_of(&sent)),
            9,
        )
        .expect("read");
        let want = crate::link::flow_key(endpoint(LOW, 43210), endpoint(HIGH, 7447), LinkKind::Udp);
        assert_eq!(
            m.kind,
            ControlKind::Unreachable {
                why: Unreachable::Port,
                about: Some(want),
                mtu: None,
            }
        );
        assert_eq!(m.about().map(|(k, e)| (*k, e.packet)), Some((want, 9)));
    }

    #[test]
    fn fragmentation_needed_carries_its_mtu_and_a_short_quote_names_no_flow() {
        let sent = udp_packet(LOW, 43210, HIGH, 7447, &[0x04]);
        let kind = icmp(&unreachable(4, 1400, ip_of(&sent))).expect("read");
        assert!(matches!(
            kind,
            ControlKind::Unreachable {
                why: Unreachable::FragmentationNeeded,
                about: Some(_),
                mtu: Some(1400),
            }
        ));
        let short = icmp(&unreachable(1, 0, &ip_of(&sent)[..20])).expect("read");
        assert_eq!(
            short,
            ControlKind::Unreachable {
                why: Unreachable::Host,
                about: None,
                mtu: None,
            },
            "no ports in the quote, no flow"
        );
        assert_eq!(icmp(&[8, 0, 0, 0, 0, 0, 0, 0]), None, "an echo is not read");
    }

    #[test]
    fn igmp_queries_reports_and_leaves_name_their_groups() {
        let group = [224u8, 0, 0, 224];
        let v2 = |kind: u8, g: [u8; 4]| {
            let mut m = alloc::vec![kind, 100, 0, 0];
            m.extend_from_slice(&g);
            m
        };
        assert_eq!(
            igmp(&v2(0x11, [0; 4])),
            Some(ControlKind::Membership {
                what: Membership::Query,
                groups: Vec::new(),
            }),
            "a general query names no group"
        );
        for (kind, what) in [
            (0x11, Membership::Query),
            (0x16, Membership::Report),
            (0x12, Membership::Report),
            (0x17, Membership::Leave),
        ] {
            assert_eq!(
                igmp(&v2(kind, group)),
                Some(ControlKind::Membership {
                    what,
                    groups: alloc::vec![group.to_vec()],
                }),
                "{kind:#x}"
            );
        }
        // A version 3 report of two records, the first with one source.
        let mut v3 = alloc::vec![0x22u8, 0, 0, 0, 0, 0, 0, 2];
        v3.extend_from_slice(&[4, 0, 0, 1, 224, 0, 0, 224, 10, 0, 0, 9]);
        v3.extend_from_slice(&[2, 0, 0, 0, 239, 1, 2, 3]);
        assert_eq!(
            igmp(&v3),
            Some(ControlKind::Membership {
                what: Membership::Report,
                groups: alloc::vec![group.to_vec(), alloc::vec![239, 1, 2, 3]],
            })
        );
    }

    #[test]
    fn icmpv6_errors_and_mld_are_read() {
        let mut quote = alloc::vec![0x60u8, 0, 0, 0, 0, 8, 17, 64];
        quote.extend_from_slice(&[0xfe; 16]);
        quote.extend_from_slice(&[0xfd; 16]);
        quote.extend_from_slice(&[0xA8, 0xCA, 0x1D, 0x17]);
        let mut port = alloc::vec![1u8, 4, 0, 0, 0, 0, 0, 0];
        port.extend_from_slice(&quote);
        assert!(matches!(
            icmpv6(&port),
            Some(ControlKind::Unreachable {
                why: Unreachable::Port,
                about: Some(_),
                mtu: None,
            })
        ));
        let mut big = alloc::vec![2u8, 0, 0, 0, 0, 0, 0x05, 0x00];
        big.extend_from_slice(&quote);
        assert!(matches!(
            icmpv6(&big),
            Some(ControlKind::Unreachable {
                why: Unreachable::FragmentationNeeded,
                mtu: Some(1280),
                ..
            })
        ));
        let mut query = alloc::vec![130u8, 0, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(&[0; 16]);
        assert_eq!(
            icmpv6(&query),
            Some(ControlKind::Membership {
                what: Membership::Query,
                groups: Vec::new(),
            })
        );
    }

    /// END TO END: a UDP datagram to a closed port, the host's ICMP error
    /// about it, and an IGMP query, in one capture. The error lands on the
    /// flow it quotes, the query in the document's membership, and both are
    /// still counted as skipped packets.
    #[test]
    fn a_capture_puts_the_error_on_its_flow_and_the_query_in_membership() {
        let sent = udp_packet(LOW, 43210, HIGH, 7447, &[0x04]);
        let error = ipv4(HIGH, LOW, IP_PROTO_ICMP, &unreachable(3, 0, ip_of(&sent)));
        let mut query = alloc::vec![0x11u8, 100, 0, 0];
        query.extend_from_slice(&[0; 4]);
        let query = ipv4([10, 0, 0, 254], [224, 0, 0, 1], IP_PROTO_IGMP, &query);
        let packets = [sent, error, query];
        let refs: Vec<(u32, u32, &[u8])> =
            packets.iter().map(|p| (0u32, 0u32, p.as_slice())).collect();
        let file = crate::pcap::write(LINKTYPE_ETHERNET, &refs);
        let d = crate::Dissection::from_capture(&file).expect("the capture reads");

        assert_eq!(d.datagram_flows().len(), 1);
        let errors = d.datagram_flows()[0].ingest.control_errors();
        assert_eq!(errors.errors().len(), 1);
        assert_eq!(errors.errors()[0].why, Unreachable::Port);
        assert_eq!(errors.errors()[0].packet, 1);
        assert_eq!(errors.errors()[0].from, endpoint(HIGH, 0));
        assert_eq!(d.control().messages().len(), 2);
        assert_eq!(
            d.skip_census().not_transport,
            2,
            "still skipped, and counted"
        );

        #[cfg(feature = "dissect")]
        {
            let doc = crate::fields_json::fields_json(&d, &file, None, None);
            assert!(
                doc.contains(
                    "\"icmp_errors\":{\"errors\":[{\"unreachable\":\"port\",\"packet\":1,\
                     \"from\":\"10.0.0.2\",\"mtu\":null}],\"more\":0}"
                ),
                "{doc}"
            );
            assert!(
                doc.contains(
                    "\"membership\":{\"events\":[{\"what\":\"query\",\"packet\":2,\
                     \"from\":\"10.0.0.254\",\"groups\":[]}],\"more\":0}"
                ),
                "{doc}"
            );
        }
    }

    /// The words the documents write are the families revision 76 declares.
    #[test]
    fn the_words_are_the_declared_families() {
        assert_eq!(
            Unreachable::names(),
            crate::doc_revision::CONTROL_UNREACHABLE_R76
        );
        assert_eq!(
            Membership::names(),
            crate::doc_revision::CONTROL_MEMBERSHIP_R76
        );
    }
}
