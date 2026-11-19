// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! WHAT THE IP HEADERS AND THE FRAMES OF ONE FLOW SAID, direction by
//! direction: the facts beside the transport that tell a middlebox's packet
//! from the peer's, one interface's or VLAN's traffic from another's, and a
//! capture's own artefacts from the network's.
//!
//! * The TTL (or hop limit) of every packet, as its range, and of every TCP
//!   segment that carried RST apart: a reset whose TTL is not the peer's was
//!   sent by something between the two.
//! * The VLAN ids and the capture interfaces the direction's packets were read
//!   off, a few of each.
//! * Each packet's IP and transport checksum verdict, counted: per flow and per
//!   direction, which the capture-wide counts cannot place.
//! * How many datagrams arrived as IP fragments and were reassembled, and how
//!   many packets stated an IP length over 1500 bytes, the Ethernet MTU: a
//!   capture taken on the sending host before segmentation offload cut them.
//!
//! Counted at ingest, as the other per-flow facts are, so a retention ceiling
//! does not move them.

use alloc::vec::Vec;

use crate::link::{Checksums, IpFacts, TransportChecksum};

/// How many distinct VLAN ids, and how many interfaces, one direction keeps.
pub const IDS_HELD: usize = 4;

/// The Ethernet MTU a stated IP length is compared with.
pub const ETHERNET_MTU: u32 = 1500;

/// The smallest and the largest of the values seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    /// The smallest.
    pub min: u8,
    /// The largest.
    pub max: u8,
}

impl Range {
    fn widen(range: &mut Option<Range>, value: u8) {
        *range = Some(match *range {
            Some(r) => Range {
                min: r.min.min(value),
                max: r.max.max(value),
            },
            None => Range {
                min: value,
                max: value,
            },
        });
    }
}

/// Distinct ids in order of first sight, up to [`IDS_HELD`], and whether more
/// were seen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ids {
    /// The ids held.
    pub held: Vec<u32>,
    /// A further id was seen and not held.
    pub more: bool,
}

impl Ids {
    fn observe(&mut self, id: u32) {
        if self.held.contains(&id) {
            return;
        }
        if self.held.len() < IDS_HELD {
            self.held.push(id);
        } else {
            self.more = true;
        }
    }
}

/// What one direction of a flow's packets said.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HalfFacts {
    /// Packets counted.
    pub packets: u64,
    /// The TTL range over the packets that had an IP header read whole.
    pub ttl: Option<Range>,
    /// The TTL range over the TCP segments that carried RST.
    pub rst_ttl: Option<Range>,
    /// The VLAN ids of the outermost tags.
    pub vlans: Ids,
    /// The capture interfaces.
    pub interfaces: Ids,
    /// IP header checksums: verified, failed, absent (IPv6 has none).
    pub ip_checksum: [u64; 3],
    /// Transport checksums: verified, failed, absent, left to an offload.
    pub transport_checksum: [u64; 4],
    /// Datagrams reassembled from IP fragments.
    pub reassembled: u64,
    /// Packets whose IP header stated a length over [`ETHERNET_MTU`].
    pub over_mtu: u64,
}

impl HalfFacts {
    fn observe(&mut self, ip: &IpFacts, checksums: &Checksums, rst: bool) {
        self.packets += 1;
        if let Some(ttl) = ip.ttl {
            Range::widen(&mut self.ttl, ttl);
            if rst {
                Range::widen(&mut self.rst_ttl, ttl);
            }
        }
        if let Some(vlan) = ip.vlan {
            self.vlans.observe(u32::from(vlan));
        }
        if let Some(interface) = ip.interface {
            self.interfaces.observe(interface);
        }
        self.ip_checksum[match checksums.ip {
            Some(true) => 0,
            Some(false) => 1,
            None => 2,
        }] += 1;
        self.transport_checksum[match checksums.transport {
            Some(TransportChecksum::Valid) => 0,
            Some(TransportChecksum::Invalid) => 1,
            None => 2,
            Some(TransportChecksum::Partial) => 3,
        }] += 1;
        if ip.reassembled {
            self.reassembled += 1;
        }
        if ip.stated_len.is_some_and(|len| len > ETHERNET_MTU) {
            self.over_mtu += 1;
        }
    }
}

/// Both directions of a flow, `A` then `B`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowFacts {
    halves: [HalfFacts; 2],
}

impl FlowFacts {
    /// One packet of the flow, travelling `a_to_b` or not.
    pub fn observe(&mut self, a_to_b: bool, ip: &IpFacts, checksums: &Checksums, rst: bool) {
        self.halves[usize::from(!a_to_b)].observe(ip, checksums, rst);
    }

    /// Direction `A`'s facts, then `B`'s.
    pub fn halves(&self) -> &[HalfFacts; 2] {
        &self.halves
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datagram_tests::{fill_ipv4_checksum, fill_tcp_checksum};
    use crate::link::LINKTYPE_ETHERNET;

    const LOW: [u8; 4] = [10, 0, 0, 1];
    const HIGH: [u8; 4] = [10, 0, 0, 2];

    fn facts(ttl: u8, vlan: Option<u16>, interface: u32, len: u32) -> IpFacts {
        IpFacts {
            ttl: Some(ttl),
            stated_len: Some(len),
            vlan,
            interface: Some(interface),
            reassembled: false,
        }
    }

    fn checks(ip: Option<bool>, transport: Option<TransportChecksum>) -> Checksums {
        Checksums {
            ip,
            transport,
            tunnel: None,
        }
    }

    #[test]
    fn a_direction_keeps_its_ranges_ids_verdicts_and_counts() {
        let mut f = FlowFacts::default();
        let ok = checks(Some(true), Some(TransportChecksum::Valid));
        f.observe(true, &facts(64, Some(10), 0, 100), &ok, false);
        f.observe(true, &facts(63, Some(10), 1, 9000), &ok, false);
        f.observe(
            true,
            &facts(250, None, 0, 40),
            &checks(Some(false), Some(TransportChecksum::Partial)),
            true,
        );
        f.observe(false, &IpFacts::default(), &checks(None, None), false);
        let [a, b] = f.halves();
        assert_eq!(a.packets, 3);
        assert_eq!(a.ttl, Some(Range { min: 63, max: 250 }));
        assert_eq!(
            a.rst_ttl,
            Some(Range { min: 250, max: 250 }),
            "the reset alone"
        );
        assert_eq!(a.vlans.held, alloc::vec![10]);
        assert_eq!(a.interfaces.held, alloc::vec![0, 1]);
        assert_eq!(a.ip_checksum, [2, 1, 0]);
        assert_eq!(a.transport_checksum, [2, 0, 0, 1]);
        assert_eq!(a.over_mtu, 1);
        assert_eq!(b.packets, 1);
        assert_eq!(b.ttl, None, "no IP header, no TTL");
        assert_eq!(b.ip_checksum, [0, 0, 1]);
    }

    #[test]
    fn the_ids_held_are_bounded_and_say_so() {
        let mut f = FlowFacts::default();
        let none = checks(None, None);
        for vlan in 0..(IDS_HELD as u16 + 2) {
            f.observe(true, &facts(1, Some(vlan), 0, 1), &none, false);
        }
        assert_eq!(f.halves()[0].vlans.held.len(), IDS_HELD);
        assert!(f.halves()[0].vlans.more);
        assert!(!f.halves()[0].interfaces.more);
    }

    /// One option: code, length, value padded to four.
    fn option(code: u16, value: &[u8]) -> Vec<u8> {
        let mut o = code.to_le_bytes().to_vec();
        o.extend_from_slice(&(value.len() as u16).to_le_bytes());
        o.extend_from_slice(value);
        while !o.len().is_multiple_of(4) {
            o.push(0);
        }
        o
    }

    /// One block of `kind` around `body`.
    fn block(kind: u32, body: &[u8]) -> Vec<u8> {
        let total = (12 + body.len()) as u32;
        let mut b = kind.to_le_bytes().to_vec();
        b.extend_from_slice(&total.to_le_bytes());
        b.extend_from_slice(body);
        b.extend_from_slice(&total.to_le_bytes());
        b
    }

    #[test]
    fn an_idb_names_its_interface_and_its_clock_and_a_section_restarts_the_ids() {
        let shb = {
            let mut body = 0x1A2B_3C4Du32.to_le_bytes().to_vec();
            body.extend_from_slice(&[1, 0, 0, 0]);
            body.extend_from_slice(&u64::MAX.to_le_bytes());
            block(0x0A0D_0D0A, &body)
        };
        let idb = |name: Option<&str>, offset: Option<i64>| {
            let mut body = alloc::vec![1u8, 0, 0, 0, 0, 0, 0, 0];
            if let Some(name) = name {
                body.extend(option(2, name.as_bytes()));
            }
            body.extend(option(9, &[9]));
            if let Some(offset) = offset {
                body.extend(option(14, &offset.to_le_bytes()));
            }
            body.extend(option(0, &[]));
            block(1, &body)
        };
        let mut file = shb.clone();
        file.extend(idb(Some("eth0"), Some(-3)));
        file.extend(idb(None, None));
        file.extend(shb);
        file.extend(idb(Some("wlan1"), None));
        let got = crate::pcapng::interface_descriptions(&file);
        let named =
            |section, id, name: Option<&str>, ts_offset| crate::pcapng::InterfaceDescription {
                section,
                id,
                link_type: 1,
                name: name.map(alloc::string::String::from),
                ts_resol: 9,
                ts_offset,
            };
        assert_eq!(
            got,
            alloc::vec![
                named(0, 0, Some("eth0"), -3),
                named(0, 1, None, 0),
                named(1, 0, Some("wlan1"), 0),
            ]
        );
        assert!(crate::pcapng::interface_descriptions(b"not a capture").is_empty());
    }

    /// Ethernet, an optional 802.1Q tag, and IPv4 of `ttl` around a TCP
    /// segment with `flags` from `src` to `dst`.
    fn tcp(src: [u8; 4], dst: [u8; 4], ttl: u8, vlan: Option<u16>, flags: u8) -> Vec<u8> {
        let (sport, dport) = if src == LOW {
            (43210u16, 7447u16)
        } else {
            (7447, 43210)
        };
        let mut seg = Vec::new();
        seg.extend_from_slice(&sport.to_be_bytes());
        seg.extend_from_slice(&dport.to_be_bytes());
        seg.extend_from_slice(&1000u32.to_be_bytes());
        seg.extend_from_slice(&0u32.to_be_bytes());
        seg.extend_from_slice(&[5 << 4, flags, 0, 64, 0, 0, 0, 0]);
        fill_tcp_checksum(src, dst, &mut seg);
        let mut ip = alloc::vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + seg.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0x40, 0, ttl, 6, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        fill_ipv4_checksum(&mut ip);
        ip.extend_from_slice(&seg);
        let mut eth = alloc::vec![0u8; 12];
        if let Some(vlan) = vlan {
            eth.extend_from_slice(&[0x81, 0x00]);
            eth.extend_from_slice(&vlan.to_be_bytes());
        }
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    /// END TO END: a pcapng of two interfaces. The opener's SYN goes out on
    /// interface 0 tagged VLAN 10 at TTL 64; a RST comes back on interface 1 at
    /// TTL 250, which is not the TTL the peer's other packet carried (128). The
    /// flow says each direction's TTL range, its reset's apart, its VLAN and
    /// interface, and the document names the two interfaces.
    #[test]
    fn a_capture_puts_each_directions_header_facts_on_its_flow() {
        let packets = [
            tcp(LOW, HIGH, 64, Some(10), 0x02),
            tcp(HIGH, LOW, 128, None, 0x12),
            tcp(HIGH, LOW, 250, None, 0x04),
        ];
        let file = crate::pcapng::write(
            &[(LINKTYPE_ETHERNET, 6), (LINKTYPE_ETHERNET, 6)],
            &[
                (0, 1, packets[0].as_slice()),
                (1, 2, packets[1].as_slice()),
                (1, 3, packets[2].as_slice()),
            ],
        );
        let d = crate::Dissection::from_capture(&file).expect("the capture reads");
        assert_eq!(d.flows().len(), 1);
        let [a, b] = d.flows()[0].ingest.ip_facts().halves();
        assert_eq!(a.ttl, Some(Range { min: 64, max: 64 }));
        assert_eq!(a.vlans.held, alloc::vec![10]);
        assert_eq!(a.interfaces.held, alloc::vec![0]);
        assert_eq!(a.rst_ttl, None);
        assert_eq!(b.ttl, Some(Range { min: 128, max: 250 }));
        assert_eq!(b.rst_ttl, Some(Range { min: 250, max: 250 }));
        assert_eq!(b.interfaces.held, alloc::vec![1]);
        assert_eq!(b.transport_checksum[0], 2, "both verify");
        // The same segments reach the connection's analysis.
        let tcp = d.flows()[0].ingest.tcp_facts();
        assert_eq!(tcp.attempts().len(), 1);
        assert_eq!(
            tcp.attempts()[0].answer,
            crate::tcp_facts::SynAnswer::SynAck
        );

        #[cfg(feature = "dissect")]
        {
            let doc = crate::fields_json::fields_json(&d, &file, None, None);
            assert!(
                doc.contains(
                    "\"rst_ttl\":{\"min\":250,\"max\":250},\"vlan_ids\":[],\
                     \"interface_ids\":[1]"
                ),
                "{doc}"
            );
            assert!(
                doc.contains(
                    "\"capture_interfaces\":[{\"section\":0,\"id\":0,\"link_type\":1,\
                     \"name\":null,\"ts_resolution\":6,\"ts_offset_s\":0},\
                     {\"section\":0,\"id\":1,\"link_type\":1,\"name\":null,\
                     \"ts_resolution\":6,\"ts_offset_s\":0}]"
                ),
                "{doc}"
            );
        }
    }
}
