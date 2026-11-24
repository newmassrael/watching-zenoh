// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The endpoint a session joins a multicast group by, read once into a value of fixed size.
//!
//! A group endpoint is a `udp/` locator naming a multicast group, its config span carrying the
//! socket keys upstream's multicast link reads (`io/zenoh-links/zenoh-link-udp/src/multicast.rs`
//! @ `let join = endpoint.config().values(UDP_MULTICAST_JOIN);`): `iface`, `join`, `ttl`,
//! `bind` and `dscp`. [`parse_group_locator`] reads all of them here, and every engine opens its
//! sockets from the [`GroupLocator`] it answers, so no socket layer reads the text again and no
//! two read it differently.
//!
//! Every field has a size fixed by [`MAX_GROUP_ENDPOINT_LEN`], the longest endpoint a session
//! joins by, which this reader refuses past: an interface name or a list of extra groups that
//! fits that text fits its field, so nothing is allocated and nothing is cut.
//!
//! What is refused here and not at the socket: a `join` that is no multicast group of the
//! group's own family, and a `bind` that is no literal address of that family. Upstream refuses
//! both when its link opens; refusing them before any socket exists answers the same set of
//! endpoints, earlier.

use core::fmt;
use core::net::{IpAddr, SocketAddr};
use core::str::FromStr;

use crate::caps::MAX_GROUP_ENDPOINT_LEN;
use crate::locator_grammar::{config_values, parse_dscp_value, split_locator_parts};

/// The scheme of a UDP multicast group's endpoint.
const UDP_GROUP_PREFIX: &str = "udp/";
/// `iface=<name-or-address>` (zenoh `BIND_INTERFACE`).
const IFACE_KEY: &str = "iface";
/// `join=<group>` (zenoh `UDP_MULTICAST_JOIN`), read as often as it is written.
const JOIN_KEY: &str = "join";
/// `ttl=<n>` (zenoh `UDP_MULTICAST_TTL`).
const TTL_KEY: &str = "ttl";
/// `bind=<address:port>` (zenoh `BIND_SOCKET`).
const BIND_KEY: &str = "bind";
/// `dscp=<value>` (zenoh `DSCP`).
const DSCP_KEY: &str = "dscp";

/// The shortest text a group endpoint's config span can follow: the shortest multicast address
/// written (`ff00::`) on port 0.
const SHORTEST_GROUP_HEAD: usize = "udp/[ff00::]:0#".len();

/// The shortest text one more extra group takes in a config span.
const SHORTEST_JOIN: usize = ";join=ff00::".len();

/// The longest interface name or address an endpoint of [`MAX_GROUP_ENDPOINT_LEN`] bytes can
/// give `iface`: what its field holds.
pub const GROUP_IFACE_CAPACITY: usize =
    MAX_GROUP_ENDPOINT_LEN.saturating_sub(SHORTEST_GROUP_HEAD + "iface=".len());

/// The most extra groups an endpoint of [`MAX_GROUP_ENDPOINT_LEN`] bytes can name: what its field
/// holds. The first `join` of a span needs no separator before it, hence the one byte added.
pub const GROUP_JOIN_CAPACITY: usize =
    (MAX_GROUP_ENDPOINT_LEN.saturating_sub(SHORTEST_GROUP_HEAD) + 1) / SHORTEST_JOIN;

/// A group endpoint, read: what a session joins and which sockets it opens for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupLocator {
    /// A UDP multicast group.
    Udp(UdpGroup),
}

/// A UDP multicast group and the socket keys its endpoint states. Made only by
/// [`parse_group_locator`], so each extra group and the bound address are of the group's family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpGroup {
    group: SocketAddr,
    /// Empty when the endpoint names no interface, as an empty `iface=` names none.
    iface: heapless::String<GROUP_IFACE_CAPACITY>,
    joins: heapless::Vec<IpAddr, GROUP_JOIN_CAPACITY>,
    ttl: Option<u32>,
    bind: Option<SocketAddr>,
    dscp: Option<u32>,
}

impl UdpGroup {
    /// The group's address and port; port 0 asks the host for one when the group is joined.
    pub fn group(&self) -> SocketAddr {
        self.group
    }

    /// `iface=`: the interface, by name or by one of its addresses, the membership is installed
    /// on and what is sent leaves by; `None` leaves the choice to the host.
    pub fn iface(&self) -> Option<&str> {
        (!self.iface.is_empty()).then_some(self.iface.as_str())
    }

    /// Every `join=` group, in the order written, each of the group's family: joined beside the
    /// group on the same socket.
    pub fn joins(&self) -> &[IpAddr] {
        &self.joins
    }

    /// `ttl=`: the hop limit of what is sent, as written; `None` leaves the host's, which is 1.
    /// Whether a datagram's header can carry it is the socket's question.
    pub fn ttl(&self) -> Option<u32> {
        self.ttl
    }

    /// `bind=`: the local address the sending socket binds, of the group's family.
    pub fn bind(&self) -> Option<SocketAddr> {
        self.bind
    }

    /// `dscp=`: the traffic class what is sent is marked with, in upstream's accepted set.
    pub fn dscp(&self) -> Option<u32> {
        self.dscp
    }

    /// The keys of `config` for the group `group` names.
    fn read(group: SocketAddr, config: &str) -> Result<Self, GroupLocatorError> {
        let first = |key: &'static str| config_values(config, key).next();
        let mut iface = heapless::String::new();
        if let Some(name) = first(IFACE_KEY) {
            iface
                .push_str(name)
                .map_err(|()| GroupLocatorError::BadValue(IFACE_KEY))?;
        }
        let mut joins = heapless::Vec::new();
        for text in config_values(config, JOIN_KEY).filter(|text| !text.is_empty()) {
            let join = IpAddr::from_str(text)
                .ok()
                .filter(|join| join.is_ipv4() == group.is_ipv4() && join.is_multicast())
                .ok_or(GroupLocatorError::BadValue(JOIN_KEY))?;
            joins
                .push(join)
                .map_err(|_| GroupLocatorError::BadValue(JOIN_KEY))?;
        }
        let ttl = match first(TTL_KEY).filter(|text| !text.is_empty()) {
            None => None,
            Some(text) => Some(
                text.parse::<u32>()
                    .map_err(|_| GroupLocatorError::BadValue(TTL_KEY))?,
            ),
        };
        let bind = match first(BIND_KEY) {
            None => None,
            Some(text) => Some(
                SocketAddr::from_str(text)
                    .ok()
                    .filter(|bind| bind.is_ipv4() == group.is_ipv4())
                    .ok_or(GroupLocatorError::BadValue(BIND_KEY))?,
            ),
        };
        let dscp = match first(DSCP_KEY) {
            None => None,
            Some(text) => {
                Some(parse_dscp_value(text).ok_or(GroupLocatorError::BadValue(DSCP_KEY))?)
            }
        };
        Ok(Self {
            group,
            iface,
            joins,
            ttl,
            bind,
            dscp,
        })
    }
}

/// Why an endpoint names no group a session joins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupLocatorError {
    /// The endpoint is longer than [`MAX_GROUP_ENDPOINT_LEN`]: no row of the build holds it.
    TooLong,
    /// The endpoint is no `udp/` locator of a multicast address.
    NotAGroup,
    /// The key named holds a value no socket is opened with.
    BadValue(&'static str),
}

impl fmt::Display for GroupLocatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => {
                f.write_str("the group endpoint is longer than MAX_GROUP_ENDPOINT_LEN")
            }
            Self::NotAGroup => f.write_str("the endpoint names no udp multicast group"),
            Self::BadValue(key) => write!(f, "the group endpoint's #{key}= holds no usable value"),
        }
    }
}

/// Read `endpoint` as the group a session joins. The metadata span is not read: no key of it
/// changes which sockets a group is joined with.
pub fn parse_group_locator(endpoint: &str) -> Result<GroupLocator, GroupLocatorError> {
    if endpoint.len() > MAX_GROUP_ENDPOINT_LEN {
        return Err(GroupLocatorError::TooLong);
    }
    let body = endpoint
        .strip_prefix(UDP_GROUP_PREFIX)
        .ok_or(GroupLocatorError::NotAGroup)?;
    let parts = split_locator_parts(body);
    let group = SocketAddr::from_str(parts.address)
        .ok()
        .filter(|group| group.ip().is_multicast())
        .ok_or(GroupLocatorError::NotAGroup)?;
    UdpGroup::read(group, parts.config).map(GroupLocator::Udp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use core::net::{Ipv4Addr, Ipv6Addr};

    fn udp(endpoint: &str) -> UdpGroup {
        match parse_group_locator(endpoint) {
            Ok(GroupLocator::Udp(group)) => group,
            other => panic!("{endpoint}: {other:?}"),
        }
    }

    /// Every key is read into its field, a repeated `join` as often as it is written and any
    /// other key from its first value.
    #[test]
    fn every_key_is_read_into_its_field() {
        let group = udp(
            "udp/239.1.2.3:7447?prio=1-3#iface=eth0;ttl=8;join=239.1.2.4;join=;join=239.1.2.5;\
             bind=10.0.0.1:0;dscp=0x10;ttl=9",
        );
        assert_eq!(
            group.group(),
            SocketAddr::from((Ipv4Addr::new(239, 1, 2, 3), 7447))
        );
        assert_eq!(group.iface(), Some("eth0"));
        assert_eq!(
            group.joins(),
            [
                IpAddr::V4(Ipv4Addr::new(239, 1, 2, 4)),
                IpAddr::V4(Ipv4Addr::new(239, 1, 2, 5))
            ]
        );
        assert_eq!(group.ttl(), Some(8));
        assert_eq!(
            group.bind(),
            Some(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 0)))
        );
        assert_eq!(group.dscp(), Some(0x10));

        let v6 = udp("udp/[ff05::7a:7703]:0#join=ff02::1;iface=");
        assert_eq!(v6.group().port(), 0);
        assert_eq!(v6.iface(), None);
        assert_eq!(
            v6.joins(),
            [IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1))]
        );
        assert_eq!((v6.ttl(), v6.bind(), v6.dscp()), (None, None, None));
    }

    /// Only a `udp/` locator of a multicast address names a group.
    #[test]
    fn an_endpoint_that_names_no_udp_group_is_refused() {
        for endpoint in [
            "udp/127.0.0.1:7447#iface=lo",
            "tcp/239.1.2.3:7447",
            "udp/239.1.2.3",
            "udp/group.example:7447",
            "reth/00:00:00:00:00:00",
            "not a locator",
        ] {
            assert_eq!(
                parse_group_locator(endpoint),
                Err(GroupLocatorError::NotAGroup),
                "{endpoint}"
            );
        }
    }

    /// A key no socket can be opened with is refused by its name, before any socket exists: an
    /// extra group or a bound address of the other family, an extra group that is no group, a
    /// bound address that is no literal, and a hop limit or traffic class that does not parse.
    #[test]
    fn a_key_no_socket_is_opened_with_is_refused_by_name() {
        for (endpoint, key) in [
            ("udp/239.1.2.3:7447#join=ff02::1", JOIN_KEY),
            ("udp/[ff02::1]:7447#join=239.1.2.4", JOIN_KEY),
            ("udp/239.1.2.3:7447#join=10.0.0.1", JOIN_KEY),
            ("udp/239.1.2.3:7447#join=nope", JOIN_KEY),
            ("udp/239.1.2.3:7447#bind=[::1]:0", BIND_KEY),
            ("udp/239.1.2.3:7447#bind=localhost:0", BIND_KEY),
            ("udp/239.1.2.3:7447#bind=", BIND_KEY),
            ("udp/239.1.2.3:7447#ttl=-1", TTL_KEY),
            ("udp/239.1.2.3:7447#dscp=0x04|nope", DSCP_KEY),
        ] {
            assert_eq!(
                parse_group_locator(endpoint),
                Err(GroupLocatorError::BadValue(key)),
                "{endpoint}"
            );
        }
        assert_eq!(udp("udp/239.1.2.3:7447#ttl=").ttl(), None);
    }

    /// An endpoint of `MAX_GROUP_ENDPOINT_LEN` bytes is read, one byte longer is refused by that
    /// name before anything else is read.
    #[test]
    fn an_endpoint_past_the_bound_is_refused_by_it() {
        let head = "udp/239.1.2.3:7447#x=";
        let fill = |len: usize| {
            let mut text = String::from(head);
            while text.len() < len {
                text.push('e');
            }
            text
        };
        assert!(parse_group_locator(&fill(MAX_GROUP_ENDPOINT_LEN)).is_ok());
        assert_eq!(
            parse_group_locator(&fill(MAX_GROUP_ENDPOINT_LEN + 1)),
            Err(GroupLocatorError::TooLong)
        );
        assert_eq!(
            parse_group_locator(&"x".repeat(MAX_GROUP_ENDPOINT_LEN + 1)),
            Err(GroupLocatorError::TooLong)
        );
    }

    /// The fields are sized for the longest endpoint the bound lets in: an interface name and a
    /// list of the shortest extra groups that fill it are read whole.
    #[test]
    fn the_longest_interface_and_join_list_the_bound_lets_in_fit() {
        let mut endpoint = String::from("udp/[ff00::]:0#iface=");
        while endpoint.len() < MAX_GROUP_ENDPOINT_LEN {
            endpoint.push('e');
        }
        assert_eq!(
            udp(&endpoint).iface().map(str::len),
            Some(GROUP_IFACE_CAPACITY)
        );

        let mut endpoint = String::from("udp/[ff00::]:0#join=ff00::");
        while endpoint.len() + SHORTEST_JOIN <= MAX_GROUP_ENDPOINT_LEN {
            endpoint.push_str(";join=ff00::");
        }
        assert_eq!(udp(&endpoint).joins().len(), GROUP_JOIN_CAPACITY);
    }
}
