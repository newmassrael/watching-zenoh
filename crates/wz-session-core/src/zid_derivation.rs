// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The zid a node derives for itself under the `zid-derivation` policy's `address-ports` value.
//!
//! Upstream draws all sixteen bytes of an unconfigured zid from its random source. A node whose
//! zid must say where it is reachable derives the first half instead, so two nodes of a network
//! that is planned by address hold zids that order and read by that address:
//!
//! | bytes  | content                                                        |
//! |--------|----------------------------------------------------------------|
//! | 0..4   | the node's IPv4 address, in its written order                  |
//! | 4..6   | the lowest port a TCP listener of the node binds, little-endian |
//! | 6..8   | the lowest port a UDP listener of the node binds, little-endian |
//! | 8..16  | random bytes, from the source an upstream zid is drawn from    |
//!
//! A node with no listener of a protocol writes `0` for that port. The address must be one a
//! peer can name the node by: the unspecified address, a multicast group and the limited
//! broadcast address are refused
//! ([`ZidDerivationError`](crate::zid_derivation::ZidDerivationError)), since a zid built on one
//! of them would say nothing of the node. The random half keeps two nodes on one address and
//! ports (a restart, or two processes behind one listener) apart.
//!
//! Pure: the inputs are values, the random half included, so a test names every byte and a host
//! with no allocator derives the same zid.

use crate::session_zid::ZID_MAX;

/// How many bytes of a derived zid are drawn from the random source.
pub const RANDOM_BYTES: usize = 8;

/// Why an address cannot head a derived zid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZidDerivationError {
    /// No listener or stated address gave the node an IPv4 address of its own.
    NoAddress,
    /// `0.0.0.0`: every address of the host, which names none of them.
    Unspecified,
    /// A multicast group address (`224.0.0.0/4`), which names a group and not a node.
    Multicast,
    /// `255.255.255.255`, which names every node of the link.
    Broadcast,
}

impl core::fmt::Display for ZidDerivationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let why = match self {
            Self::NoAddress => "no IPv4 address of the node was stated",
            Self::Unspecified => "the unspecified address names no node",
            Self::Multicast => "a multicast group address names no node",
            Self::Broadcast => "the broadcast address names no node",
        };
        write!(f, "a zid cannot be derived from the node's address: {why}")
    }
}

/// Whether `address` can head a derived zid, and why not.
pub const fn admit_address(address: [u8; 4]) -> Result<(), ZidDerivationError> {
    if address[0] == 0 && address[1] == 0 && address[2] == 0 && address[3] == 0 {
        Err(ZidDerivationError::Unspecified)
    } else if address[0] & 0xF0 == 0xE0 {
        Err(ZidDerivationError::Multicast)
    } else if address[0] == 0xFF && address[1] == 0xFF && address[2] == 0xFF && address[3] == 0xFF {
        Err(ZidDerivationError::Broadcast)
    } else {
        Ok(())
    }
}

/// The sixteen bytes of the zid derived from `address`, the lowest TCP and UDP listener ports
/// (`0` for a protocol the node has no listener on) and `random`, laid out as the module states.
/// Never all zero, since an admitted address is not.
pub fn derive(
    address: [u8; 4],
    tcp_port: u16,
    udp_port: u16,
    random: [u8; RANDOM_BYTES],
) -> Result<[u8; ZID_MAX], ZidDerivationError> {
    admit_address(address)?;
    let tcp = tcp_port.to_le_bytes();
    let udp = udp_port.to_le_bytes();
    Ok([
        address[0], address[1], address[2], address[3], tcp[0], tcp[1], udp[0], udp[1], random[0],
        random[1], random[2], random[3], random[4], random[5], random[6], random[7],
    ])
}

/// What a node's listeners say about it: the IPv4 address the first of them that names one
/// binds to, and the lowest port of its TCP and of its UDP listeners. Fed one listener at a
/// time ([`Self::listener`]), so a caller reads its own endpoint list without collecting it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ListenerFacts {
    address: Option<[u8; 4]>,
    tcp_port: Option<u16>,
    udp_port: Option<u16>,
}

/// The transport of a listener, as far as a derived zid tells them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerTransport {
    /// A stream listener over TCP (`tcp`, and `tls`, `ws` over it).
    Tcp,
    /// A datagram listener over UDP.
    Udp,
}

impl ListenerFacts {
    /// No listener yet.
    pub const fn new() -> Self {
        Self {
            address: None,
            tcp_port: None,
            udp_port: None,
        }
    }

    /// Take one listener of `transport` bound to `address`:`port`. An address that cannot head a
    /// zid (the unspecified one a wildcard listener binds) states no address, and a port of `0`
    /// (one the system picks when it binds) states no port; the first admitted address is kept.
    pub fn listener(&mut self, transport: ListenerTransport, address: [u8; 4], port: u16) {
        if self.address.is_none() && admit_address(address).is_ok() {
            self.address = Some(address);
        }
        if port == 0 {
            return;
        }
        let slot = match transport {
            ListenerTransport::Tcp => &mut self.tcp_port,
            ListenerTransport::Udp => &mut self.udp_port,
        };
        *slot = Some(slot.map_or(port, |lowest| lowest.min(port)));
    }

    /// The zid these listeners derive with `random`, the address `stated` standing in when the
    /// listeners named none (a node whose listeners all bind every address of the host).
    pub fn derive(
        &self,
        stated: Option<[u8; 4]>,
        random: [u8; RANDOM_BYTES],
    ) -> Result<[u8; ZID_MAX], ZidDerivationError> {
        let address = self
            .address
            .or(stated)
            .ok_or(ZidDerivationError::NoAddress)?;
        derive(
            address,
            self.tcp_port.unwrap_or(0),
            self.udp_port.unwrap_or(0),
            random,
        )
    }
}

#[cfg(feature = "alloc")]
impl ListenerFacts {
    /// What a node's `listen` endpoints say of it: each `tcp` and `udp` endpoint that names an
    /// IPv4 address and is not a multicast group (a group is joined, not listened on). An endpoint
    /// that does not parse as an IP one (a name, a device) and every other scheme say nothing.
    pub fn of_endpoints<'e>(endpoints: impl IntoIterator<Item = &'e str>) -> Self {
        use crate::locator::{parse_locator, Proto};
        let mut facts = Self::new();
        for endpoint in endpoints {
            let Ok(parsed) = parse_locator(endpoint) else {
                continue;
            };
            let transport = match parsed.proto {
                Proto::Tcp => ListenerTransport::Tcp,
                Proto::Udp => ListenerTransport::Udp,
                _ => continue,
            };
            if let core::net::SocketAddr::V4(address) = parsed.addr {
                if !address.ip().is_multicast() {
                    facts.listener(transport, address.ip().octets(), address.port());
                }
            }
        }
        facts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The endpoints of a `listen` list: a wildcard listener counts its port and names no
    /// address, a group and a scheme other than `tcp` and `udp` say nothing, and the first
    /// endpoint that binds an address of the node names it.
    #[cfg(feature = "alloc")]
    #[test]
    fn a_listen_list_states_its_first_own_address_and_lowest_ports() {
        let facts = ListenerFacts::of_endpoints([
            "tcp/0.0.0.0:31000",
            "udp/224.0.0.240:30000",
            "tls/10.9.8.6:29000",
            "tcp/10.9.8.7:31500",
            "udp/10.9.8.7:32500",
            "udp/10.9.8.8:32400",
        ]);
        let zid = facts
            .derive(None, RANDOM)
            .expect("a listener names the node");
        assert_eq!(&zid[..4], &[10, 9, 8, 7]);
        assert_eq!(
            &zid[4..6],
            &31_000u16.to_le_bytes(),
            "the wildcard's port is lowest"
        );
        assert_eq!(
            &zid[6..8],
            &32_400u16.to_le_bytes(),
            "the group's port is no listener's"
        );
        assert_eq!(
            ListenerFacts::of_endpoints(["udp/239.1.2.3:30000", "tcp/0.0.0.0:1"])
                .derive(None, RANDOM),
            Err(ZidDerivationError::NoAddress)
        );
    }

    const RANDOM: [u8; RANDOM_BYTES] = [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8];

    /// Every byte in its place: the address as written, each port little-endian, the random half
    /// last and untouched.
    #[test]
    fn a_derived_zid_lays_out_address_ports_and_random_bytes() {
        let zid = derive([10, 20, 30, 40], 0x1234, 0xBEEF, RANDOM).expect("a unicast address");
        assert_eq!(
            zid,
            [
                10, 20, 30, 40, 0x34, 0x12, 0xEF, 0xBE, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
                0xA8
            ]
        );
    }

    /// The same inputs derive the same zid, and only the random half tells two draws apart.
    #[test]
    fn a_seeded_source_derives_the_same_zid_and_another_draw_differs_only_in_its_random_half() {
        let first = derive([10, 20, 30, 40], 17_000, 17_001, RANDOM).expect("admitted");
        let again = derive([10, 20, 30, 40], 17_000, 17_001, RANDOM).expect("admitted");
        assert_eq!(first, again);
        let other = derive([10, 20, 30, 40], 17_000, 17_001, [0x5A; RANDOM_BYTES]).expect("ok");
        assert_eq!(&first[..8], &other[..8]);
        assert_ne!(&first[8..], &other[8..]);
    }

    /// An address that names no node is refused with its reason, and the edges of the multicast
    /// range are where the rule says they are.
    #[test]
    fn an_address_that_names_no_node_is_refused() {
        assert_eq!(
            derive([0, 0, 0, 0], 1, 1, RANDOM),
            Err(ZidDerivationError::Unspecified)
        );
        assert_eq!(
            derive([224, 0, 0, 1], 1, 1, RANDOM),
            Err(ZidDerivationError::Multicast)
        );
        assert_eq!(
            derive([239, 255, 255, 255], 1, 1, RANDOM),
            Err(ZidDerivationError::Multicast)
        );
        assert_eq!(
            derive([255, 255, 255, 255], 1, 1, RANDOM),
            Err(ZidDerivationError::Broadcast)
        );
        assert!(derive([223, 255, 255, 255], 1, 1, RANDOM).is_ok());
        assert!(derive([240, 0, 0, 1], 1, 1, RANDOM).is_ok());
    }

    /// The lowest port of each transport is kept whatever order the listeners come in, a port of
    /// `0` states nothing, and a transport with no listener writes `0`.
    #[test]
    fn the_lowest_listener_port_of_each_transport_is_taken() {
        let mut facts = ListenerFacts::new();
        facts.listener(ListenerTransport::Udp, [10, 1, 1, 9], 21_000);
        facts.listener(ListenerTransport::Tcp, [10, 1, 1, 9], 23_000);
        facts.listener(ListenerTransport::Tcp, [10, 1, 1, 9], 22_000);
        facts.listener(ListenerTransport::Tcp, [10, 1, 1, 9], 0);
        facts.listener(ListenerTransport::Udp, [10, 1, 1, 9], 21_500);
        let zid = facts.derive(None, RANDOM).expect("an address was stated");
        assert_eq!(&zid[..4], &[10, 1, 1, 9]);
        assert_eq!(&zid[4..6], &22_000u16.to_le_bytes());
        assert_eq!(&zid[6..8], &21_000u16.to_le_bytes());

        let mut tcp_only = ListenerFacts::new();
        tcp_only.listener(ListenerTransport::Tcp, [10, 1, 1, 9], 22_000);
        let zid = tcp_only.derive(None, RANDOM).expect("admitted");
        assert_eq!(&zid[6..8], &[0, 0], "no UDP listener writes 0");
    }

    /// A wildcard listener states no address, so the first listener that names one is the node's;
    /// with none, the stated address stands in, and with neither the derivation is refused.
    #[test]
    fn the_address_is_the_first_listener_that_names_one_or_the_stated_one() {
        let mut facts = ListenerFacts::new();
        facts.listener(ListenerTransport::Tcp, [0, 0, 0, 0], 22_000);
        assert_eq!(
            facts.derive(None, RANDOM),
            Err(ZidDerivationError::NoAddress)
        );
        let zid = facts
            .derive(Some([172, 16, 5, 6]), RANDOM)
            .expect("the stated address stands in");
        assert_eq!(&zid[..4], &[172, 16, 5, 6]);

        facts.listener(ListenerTransport::Udp, [192, 168, 77, 3], 21_000);
        facts.listener(ListenerTransport::Udp, [192, 168, 77, 4], 21_001);
        let zid = facts
            .derive(Some([172, 16, 5, 6]), RANDOM)
            .expect("a listener names the address");
        assert_eq!(
            &zid[..4],
            &[192, 168, 77, 3],
            "the first listener that names an address wins over the stated one"
        );
        assert_eq!(
            ListenerFacts::new().derive(Some([224, 1, 1, 1]), RANDOM),
            Err(ZidDerivationError::Multicast),
            "a stated address is held to the same rule"
        );
    }
}
