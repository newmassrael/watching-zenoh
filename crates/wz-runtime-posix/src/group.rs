// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host profile's multicast group seam: a group session's I/O over the host's own sockets.
//!
//! [`GroupSockets`] is the [`GroupTransport`] the shared group drive loop
//! (`wz-session-mcu`'s `group_drive`) runs on, beside lwIP's and Zephyr's, over any host socket
//! that can be a member of a group ([`MulticastSocket`]): the POSIX kernels' (`PosixGroupTransport`)
//! and Winsock's (`windows::group::WindowsGroupTransport`). It has the shape zenoh gives a
//! multicast link (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @
//! `let ucast_sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))`): TWO sockets,
//! a RECEIVER bound to the wildcard address on the group's port so that it can share the port with
//! every other member on this host ([`MulticastSocket::bind_shared`]) and joined to the group, and
//! a SENDER of its own on a port the system picks, so the source a peer sees names this member and
//! no other, even when two members live on one host. One socket for both, as the Zephyr and lwIP
//! transports have, would send every member of a host from the group's port.
//!
//! Nothing allocates: the two sockets are handles and the receive buffer is an array of `RX`
//! bytes inside the value; size it to the batch the group advertises, since a datagram longer than
//! `RX` is truncated by the system and read by the loop as a bad frame.
//!
//! A member leaves the group by closing its receiver: the system drops the membership with the
//! socket on this host, where Zephyr's interface holds it.

use core::net::{IpAddr, SocketAddr};

use wz_runtime_coop::group_transport::{GroupInterface, GroupTransport};
use wz_runtime_coop::udp_link::{unspecified_like, DatagramSocket, SERVICE_WAIT_MS};

#[cfg(unix)]
use crate::net::{PosixNetError, PosixUdpSocket};

/// A host's datagram socket that can be a member of a multicast group: what [`GroupSockets`]
/// asks of it beyond the link's own seam. Each host answers with its own calls; the rules of the
/// two sockets and of the join are [`GroupSockets`]'s, written once.
pub trait MulticastSocket: DatagramSocket {
    /// A socket bound to `at` that other sockets of this host may bind too, as every member of a
    /// group does.
    fn bind_shared(at: SocketAddr) -> Result<Self, Self::Error>;

    /// Join `group` on `interface`, the one the system's routing picks for
    /// [`GroupInterface::Routing`].
    fn join_group(&self, group: IpAddr, interface: GroupInterface) -> Result<(), Self::Error>;

    /// Send multicast datagrams out of `interface`; the routing's choice needs no option.
    fn set_multicast_interface(&self, interface: GroupInterface) -> Result<(), Self::Error>;

    /// The hop limit of the multicast datagrams this socket sends, in the option of its family.
    fn set_multicast_hops(&self, hops: u8) -> Result<(), Self::Error>;

    /// The error of an interface named in the other family than the group's, which is answered
    /// before any socket is opened.
    fn interface_family() -> Self::Error;
}

/// A multicast group session's I/O over two sockets `S` of the host.
pub struct GroupSockets<S: MulticastSocket, const RX: usize> {
    /// The joined receiver, `None` once the session has released its link.
    ingress: Option<S>,
    /// The sender, on a port of its own.
    egress: Option<S>,
    /// The group and its port, where every datagram is sent.
    group: SocketAddr,
    rx: [u8; RX],
    rx_error: Option<S::Error>,
}

/// The POSIX kernels' group transport.
#[cfg(unix)]
pub type PosixGroupTransport<const RX: usize> = GroupSockets<PosixUdpSocket, RX>;

/// The wildcard address of `group`'s family on `port`: what a group's receiver and sender bind,
/// as upstream zenoh binds its group socket to the unspecified address of the group's family
/// (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @
/// `IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),`).
fn wildcard(group: &SocketAddr, port: u16) -> SocketAddr {
    SocketAddr::new(unspecified_like(group.ip()), port)
}

/// The sender of a group: a socket of its family on a port the system picks, sending out of
/// `interface`, with the hop limit `hops` when one is stated and the system's own otherwise (no
/// option is set then).
fn sender<S: MulticastSocket>(
    group: &SocketAddr,
    interface: GroupInterface,
    hops: Option<u8>,
) -> Result<S, S::Error> {
    let egress = S::bind(wildcard(group, 0))?;
    egress.set_multicast_interface(interface)?;
    if let Some(hops) = hops {
        egress.set_multicast_hops(hops)?;
    }
    Ok(egress)
}

impl<S: MulticastSocket, const RX: usize> GroupSockets<S, RX> {
    /// Join `group` (an IPv4 or an IPv6 group, and its port) on `interface`, which is also the one
    /// the node sends out of ([`GroupInterface::Routing`]: the one the system's routing picks for
    /// the group). `hops` is the hop limit of what it sends when one is stated; `None` leaves the
    /// system's own (1: one subnet), as zenoh sets `IP_MULTICAST_TTL` only when its endpoint
    /// states `ttl` (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @
    /// `if let Some(ttl_str) = config.get(UDP_MULTICAST_TTL)`). A stated `ttl` is applied to an
    /// IPv6 group too (`IPV6_MULTICAST_HOPS`), where zenoh 1.10.2 only warns that it cannot, as
    /// the AP's group socket does (`wz_host_net::multicast`). An IPv4 group is joined with IGMP,
    /// an IPv6 one with MLD, each on sockets of the group's family. An interface named in the other
    /// family is [`MulticastSocket::interface_family`], before a socket is opened.
    pub fn join(
        group: SocketAddr,
        interface: GroupInterface,
        hops: Option<u8>,
    ) -> Result<Self, S::Error> {
        if !interface.names_for(&group) {
            return Err(S::interface_family());
        }
        let ingress = S::bind_shared(wildcard(&group, group.port()))?;
        ingress.join_group(group.ip(), interface)?;
        let egress = sender::<S>(&group, interface, hops)?;
        Ok(Self {
            ingress: Some(ingress),
            egress: Some(egress),
            group,
            rx: [0; RX],
            rx_error: None,
        })
    }

    /// The group and port this transport sends to and receives on.
    pub fn group(&self) -> SocketAddr {
        self.group
    }

    /// The port of the sender: the source every peer sees this member's datagrams from.
    pub fn sender_port(&self) -> Option<u16> {
        self.egress.as_ref().map(|socket| socket.local().port())
    }

    /// The most recent receive failure, if the receiver has failed: the seam the loop reads
    /// returns a datagram or nothing, and a failed socket must not read as a quiet group.
    pub fn rx_error(&self) -> Option<S::Error> {
        self.rx_error
    }
}

#[cfg(test)]
impl<S: MulticastSocket, const RX: usize> GroupSockets<S, RX> {
    /// A transport made as [`Self::join`] makes it but for the membership, which is the one step
    /// that needs a multicast route on the host: what the rest of the transport does is the same
    /// whether or not the group was joined. Its port is the one the system gave the receiver.
    pub(crate) fn unjoined(group: SocketAddr, hops: Option<u8>) -> Result<Self, S::Error> {
        let ingress = S::bind_shared(wildcard(&group, 0))?;
        let egress = sender::<S>(&group, GroupInterface::Routing, hops)?;
        Ok(Self {
            group: SocketAddr::new(group.ip(), ingress.local().port()),
            ingress: Some(ingress),
            egress: Some(egress),
            rx: [0; RX],
            rx_error: None,
        })
    }
}

#[cfg(unix)]
impl<const RX: usize> GroupSockets<PosixUdpSocket, RX> {
    /// Join `group` through the interface routing picks for it, and when routing has none (a host
    /// with one subnet route and no default route refuses the join with `ENODEV`), through the
    /// first interface of the group's family that is up, can multicast and is not a loopback
    /// ([`crate::net::multicast_interface`]), which is then also the one the node sends out of. A
    /// host whose routing answers is joined exactly as [`Self::join`] does with
    /// [`GroupInterface::Routing`]; only a refusal reaches the second try, and a host with no such
    /// interface keeps the first refusal.
    pub fn join_by_routing_or_first_interface(
        group: SocketAddr,
        hops: Option<u8>,
    ) -> Result<Self, PosixNetError> {
        match Self::join(group, GroupInterface::Routing, hops) {
            Err(first @ PosixNetError::Membership(_)) => {
                match crate::net::multicast_interface(&group) {
                    Some(interface) => Self::join(group, interface, hops),
                    None => Err(first),
                }
            }
            other => other,
        }
    }
}

/// The POSIX kernels' socket as a group's member: `SO_REUSEADDR` and `SO_REUSEPORT` on the
/// receiver, IGMP (`IP_ADD_MEMBERSHIP`) and MLD (`IPV6_JOIN_GROUP`) for the join.
#[cfg(unix)]
impl MulticastSocket for PosixUdpSocket {
    fn bind_shared(at: SocketAddr) -> Result<Self, PosixNetError> {
        PosixUdpSocket::bind_shared(at)
    }

    fn join_group(&self, group: IpAddr, interface: GroupInterface) -> Result<(), PosixNetError> {
        PosixUdpSocket::join_group(self, group, interface)
    }

    fn set_multicast_interface(&self, interface: GroupInterface) -> Result<(), PosixNetError> {
        PosixUdpSocket::set_multicast_interface(self, interface)
    }

    fn set_multicast_hops(&self, hops: u8) -> Result<(), PosixNetError> {
        PosixUdpSocket::set_multicast_hops(self, hops)
    }

    fn interface_family() -> PosixNetError {
        PosixNetError::InterfaceFamily
    }
}

impl<S: MulticastSocket, const RX: usize> GroupTransport for GroupSockets<S, RX> {
    fn open(&mut self) -> bool {
        self.ingress.is_some() && self.egress.is_some()
    }

    fn close(&mut self) {
        // Closing the receiver is leaving the group.
        self.ingress = None;
        self.egress = None;
    }

    fn service(&self) {
        // The system runs the stack: all this thread owes it is the wait, which a datagram cuts
        // short and which is a tick otherwise, so a node holding sessions beside this one does
        // not wait on the group for longer than it would on a stream.
        if let Some(socket) = &self.ingress {
            socket.wait_readable(SERVICE_WAIT_MS);
        }
    }

    /// A host has no carrier to read here; what ends a group is its receiver failing, which is
    /// what the system reports of an interface that went away (`ENETDOWN`, `ENODEV` on a POSIX
    /// kernel).
    fn carrier_up(&self) -> bool {
        self.rx_error.is_none()
    }

    fn send_to_group(&mut self, datagram: &[u8]) {
        // Best-effort, as the trait says: multicast UDP has no acknowledgement and the next
        // cadence retries.
        if let Some(socket) = &self.egress {
            let _ = socket.send_to(self.group, datagram);
        }
    }

    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        let Some(socket) = &self.ingress else {
            return false;
        };
        match socket.try_recv(&mut self.rx) {
            Ok(Some((len, from))) => {
                f(&self.rx[..len], from);
                true
            }
            Ok(None) => false,
            Err(e) => {
                self.rx_error = Some(e);
                false
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const GROUP: [u8; 4] = [239, 255, 77, 3];

    /// An IPv6 group of site-local scope, unassigned: one no test host uses for anything else.
    const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0x7a, 0x7703);

    /// The wildcard IPv4 address on `port`.
    fn any_v4(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
    }

    fn get_int(fd: core::ffi::c_int, level: core::ffi::c_int, name: core::ffi::c_int) -> i32 {
        let mut value: core::ffi::c_int = -1;
        let mut len = core::mem::size_of::<core::ffi::c_int>() as libc::socklen_t;
        // SAFETY: `value` and `len` are live and writable, and `len` is `value`'s size.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                level,
                name,
                (&mut value as *mut core::ffi::c_int).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0);
        value
    }

    #[test]
    fn two_receivers_may_share_the_groups_port() {
        // The members of one host all bind the group's port; without the two reuse options the
        // second bind is refused.
        let first = PosixUdpSocket::bind_shared(any_v4(0)).expect("a first receiver");
        let port = first.local().port();
        PosixUdpSocket::bind_shared(any_v4(port)).expect("a second receiver on the same port");
        match PosixUdpSocket::bind(any_v4(port)) {
            Err(PosixNetError::Bind(e)) => assert_eq!(e, libc::EADDRINUSE),
            Err(other) => panic!("a different error: {other:?}"),
            Ok(_) => panic!("a plain bind took a port a shared one holds"),
        }
    }

    #[test]
    fn a_group_that_is_not_one_is_not_joined() {
        // A unicast address is no group: the kernel refuses the membership, and the transport
        // does not come up half-made.
        let unicast = SocketAddr::from(([10, 0, 0, 1], 0));
        match PosixGroupTransport::<64>::join(unicast, GroupInterface::Routing, None) {
            Err(PosixNetError::Membership(e)) => assert_eq!(e, libc::EINVAL),
            Err(other) => panic!("a different error: {other:?}"),
            Ok(_) => panic!("joined a unicast address"),
        }
        // The same for an IPv6 unicast address, which MLD refuses as IGMP does an IPv4 one.
        let unicast = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));
        match PosixGroupTransport::<64>::join(unicast, GroupInterface::Routing, None) {
            Err(PosixNetError::Membership(e)) => assert_eq!(e, libc::EINVAL),
            Err(other) => panic!("a different error: {other:?}"),
            Ok(_) => panic!("joined a unicast address"),
        }
    }

    /// An interface named in the other family than the group's is refused before a socket opens.
    #[test]
    fn a_group_given_an_interface_of_the_other_family_is_refused_before_any_socket() {
        let v6 = SocketAddr::from((GROUP_V6, 0));
        let v4 = SocketAddr::from((GROUP, 0));
        for (group, interface) in [
            (v6, GroupInterface::V4(Ipv4Addr::LOCALHOST)),
            (v4, GroupInterface::Index(1)),
        ] {
            assert!(matches!(
                PosixGroupTransport::<64>::join(group, interface, None),
                Err(PosixNetError::InterfaceFamily)
            ));
        }
    }

    /// The shared helper at this module's size: a transport made as `join` makes it but for the
    /// membership.
    fn unjoined(group: SocketAddr, hops: Option<u8>) -> PosixGroupTransport<64> {
        PosixGroupTransport::<64>::unjoined(group, hops).expect("an unjoined transport")
    }

    /// An IPv6 group's sockets are of its family, and its hop limit is the IPv6 option's.
    #[test]
    fn an_ipv6_groups_sockets_are_of_its_family_with_the_hop_limit_asked_for() {
        let transport = unjoined(SocketAddr::from((GROUP_V6, 0)), Some(3));
        let ingress = transport.ingress.as_ref().expect("a receiver");
        let egress = transport.egress.as_ref().expect("a sender");
        assert!(ingress.local().is_ipv6() && egress.local().is_ipv6());
        assert_eq!(
            get_int(egress.fd(), libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS),
            3
        );
    }

    /// A group that states no hop limit leaves the option where the kernel left it, on either
    /// family: the sender reads what a socket nobody set reads, as zenoh's does when its endpoint
    /// states no `ttl`.
    #[test]
    fn a_group_that_states_no_hop_limit_leaves_the_kernels_own() {
        for (group, level, name) in [
            (
                SocketAddr::from((GROUP, 0)),
                libc::IPPROTO_IP,
                libc::IP_MULTICAST_TTL,
            ),
            (
                SocketAddr::from((GROUP_V6, 0)),
                libc::IPPROTO_IPV6,
                libc::IPV6_MULTICAST_HOPS,
            ),
        ] {
            let untouched = PosixUdpSocket::bind(wildcard(&group, 0)).expect("a socket nobody set");
            let kernels = get_int(untouched.fd(), level, name);
            let transport = unjoined(group, None);
            let egress = transport.egress.as_ref().expect("a sender");
            assert_eq!(get_int(egress.fd(), level, name), kernels, "{group}");
        }
    }

    #[test]
    fn the_sender_has_a_port_of_its_own_and_the_hop_limit_asked_for() {
        let a = unjoined(SocketAddr::from((GROUP, 0)), Some(5));
        let b = unjoined(SocketAddr::from((GROUP, 0)), Some(1));
        assert_ne!(
            a.sender_port(),
            b.sender_port(),
            "two members of one host are told apart by their sender's port"
        );
        assert_ne!(
            a.sender_port(),
            Some(a.group().port()),
            "a member does not send from the group's port"
        );
        let egress = a.egress.as_ref().expect("a sender");
        assert_eq!(
            get_int(egress.fd(), libc::IPPROTO_IP, libc::IP_MULTICAST_TTL),
            5
        );
        let other = b.egress.as_ref().expect("a sender");
        assert_eq!(
            get_int(other.fd(), libc::IPPROTO_IP, libc::IP_MULTICAST_TTL),
            1
        );
    }

    #[test]
    fn a_released_transport_sends_and_receives_nothing_and_does_not_open_again() {
        let mut transport = unjoined(SocketAddr::from((GROUP, 0)), None);
        assert!(transport.open());
        transport.close();
        assert!(!transport.open());
        transport.send_to_group(b"x");
        assert!(!transport.recv_with(&mut |_, _| panic!("a datagram from a closed group")));
        assert!(
            transport.carrier_up(),
            "a released link is not a failed one"
        );
    }

    #[test]
    #[ignore = "environment-dependent: needs a multicast route on this host (Layer M runs it)"]
    fn a_datagram_one_member_sends_reaches_another_with_the_senders_own_port() {
        // Both members bind the same port (the second only because both are shared) and the group
        // has a loopback: a member hears its own and every other's.
        let probe = PosixUdpSocket::bind_shared(any_v4(0)).expect("a port");
        let port = probe.local().port();
        let group = SocketAddr::from((GROUP, port));
        let mut a = PosixGroupTransport::<256>::join(group, GroupInterface::Routing, None)
            .expect("member a");
        let mut b = PosixGroupTransport::<256>::join(group, GroupInterface::Routing, None)
            .expect("member b");
        let a_port = a.sender_port().expect("a sender");
        a.send_to_group(b"hello group");
        let mut seen = None;
        for _ in 0..200 {
            b.service();
            if b.recv_with(&mut |bytes, src| seen = Some((bytes.to_vec(), src))) {
                break;
            }
        }
        let (bytes, src) = seen.expect("the datagram reached the other member");
        assert_eq!(bytes, b"hello group");
        assert_eq!(
            src.port(),
            a_port,
            "the source names the member that sent it"
        );
    }
}
