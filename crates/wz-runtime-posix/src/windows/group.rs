// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Windows host's multicast group seam: [`WindowsGroupTransport`], the group transport of
//! [`crate::group`] over Winsock's sockets, the one the shared group drive loop runs on in a
//! Windows process, as the POSIX kernels' is on theirs.
//!
//! The receiver shares the group's port with the other members of this host through
//! `SO_REUSEADDR` alone: Windows has no `SO_REUSEPORT`, and its `SO_REUSEADDR` is both, as
//! zenoh-pico's Windows group listener sets it alone
//! (`vendor/zenoh-pico/src/link/transport/udp/udp_multicast_windows.c` @
//! `SOL_SOCKET, SO_REUSEADDR`). What a POSIX host does when its routing has no interface for the
//! group (it tries the first interface that can multicast) is not done here: Winsock is given the
//! unspecified interface and picks one itself.

use core::net::{IpAddr, SocketAddr};

#[cfg(feature = "host-multicast")]
use windows_sys::Win32::Networking::WinSock as ws;
use wz_runtime_coop::group_transport::GroupInterface;

use super::net::WindowsUdpSocket;
use super::WindowsNetError;
use crate::group::{GroupSockets, MulticastSocket};

/// Winsock's group transport.
pub type WindowsGroupTransport<const RX: usize> = GroupSockets<WindowsUdpSocket, RX>;

/// Winsock's socket as a group's member: IGMP (`IP_ADD_MEMBERSHIP`) and MLD
/// (`IPV6_ADD_MEMBERSHIP`) for the join.
impl MulticastSocket for WindowsUdpSocket {
    fn bind_shared(at: SocketAddr) -> Result<Self, WindowsNetError> {
        WindowsUdpSocket::bind_shared(at)
    }

    fn join_group(&self, group: IpAddr, interface: GroupInterface) -> Result<(), WindowsNetError> {
        WindowsUdpSocket::join_group(self, group, interface)
    }

    fn set_multicast_interface(&self, interface: GroupInterface) -> Result<(), WindowsNetError> {
        WindowsUdpSocket::set_multicast_interface(self, interface)
    }

    fn set_multicast_hops(&self, hops: u8) -> Result<(), WindowsNetError> {
        WindowsUdpSocket::set_multicast_hops(self, hops)
    }

    fn interface_family() -> WindowsNetError {
        WindowsNetError::InterfaceFamily
    }

    #[cfg(feature = "host-multicast")]
    fn make_nonblocking(&self) -> Result<(), WindowsNetError> {
        WindowsUdpSocket::make_nonblocking(self)
    }

    #[cfg(feature = "host-multicast")]
    fn set_multicast_loopback(&self, on: bool) -> Result<(), WindowsNetError> {
        WindowsUdpSocket::set_multicast_loopback(self, on)
    }

    #[cfg(feature = "host-multicast")]
    fn set_traffic_class(&self, class: u32) -> Result<bool, WindowsNetError> {
        WindowsUdpSocket::set_traffic_class(self, class)
    }

    #[cfg(feature = "host-multicast")]
    fn found_no_room(error: &WindowsNetError) -> bool {
        matches!(error, WindowsNetError::Send(ws::SOCKET_ERROR, code)
            if matches!(*code, ws::WSAEWOULDBLOCK | ws::WSAEINTR))
    }

    #[cfg(feature = "host-multicast")]
    fn wait_writable(&self, timeout_us: u64) -> bool {
        WindowsUdpSocket::wait_writable(self, timeout_us)
    }

    #[cfg(feature = "host-multicast")]
    fn wait_readable_any(sockets: &[&Self], timeout_ms: core::ffi::c_int) {
        WindowsUdpSocket::wait_readable_any(sockets, timeout_ms)
    }

    wz_runtime_coop::with_heap_link_seams! {
        #[cfg(feature = "host-multicast")]
        fn writability(
            &self,
        ) -> Option<alloc::boxed::Box<dyn wz_runtime_coop::session_drive::LinkWritability>> {
            WindowsUdpSocket::writability(self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{Ipv4Addr, Ipv6Addr};
    use wz_runtime_coop::group_transport::GroupTransport;
    use wz_runtime_coop::udp_link::DatagramSocket;

    const GROUP: [u8; 4] = [239, 255, 77, 5];

    /// An IPv6 group of site-local scope, unassigned: one no test host uses for anything else.
    const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0x7a, 0x7705);

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
                WindowsGroupTransport::<64>::join(group, interface, None),
                Err(WindowsNetError::InterfaceFamily)
            ));
        }
    }

    /// A unicast address is no group: the system refuses the membership, and the transport does
    /// not come up half-made.
    #[test]
    fn a_group_that_is_not_one_is_not_joined() {
        let unicast = SocketAddr::from(([10, 0, 0, 1], 0));
        assert!(matches!(
            WindowsGroupTransport::<64>::join(unicast, GroupInterface::Routing, None),
            Err(WindowsNetError::Membership(_))
        ));
    }

    #[test]
    fn the_sender_has_a_port_of_its_own_on_either_family() {
        for group in [
            SocketAddr::from((GROUP, 0)),
            SocketAddr::from((GROUP_V6, 0)),
        ] {
            let a = WindowsGroupTransport::<64>::unjoined(group, Some(3)).expect("member a");
            let b = WindowsGroupTransport::<64>::unjoined(group, None).expect("member b");
            assert!(a.sender_port().is_some() && b.sender_port().is_some());
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
            assert_eq!(a.group().is_ipv6(), group.is_ipv6());
        }
    }

    #[test]
    fn two_receivers_may_share_the_groups_port() {
        let any = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        let first = WindowsUdpSocket::bind_shared(any).expect("a first receiver");
        let port = first.local().port();
        WindowsUdpSocket::bind_shared(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
            .expect("a second receiver on the same port");
    }

    #[test]
    fn a_released_transport_sends_and_receives_nothing_and_does_not_open_again() {
        let mut transport =
            WindowsGroupTransport::<64>::unjoined(SocketAddr::from((GROUP, 0)), None)
                .expect("a transport");
        assert!(transport.open());
        transport.close();
        assert!(!transport.open());
        assert_eq!(transport.sender_port(), None);
        transport.send_to_group(b"x");
        assert!(!transport.recv_with(&mut |_, _| panic!("a datagram from a closed group")));
        assert!(
            transport.carrier_up(),
            "a released link is not a failed one"
        );
        assert_eq!(transport.rx_error(), None);
    }

    #[test]
    #[ignore = "environment-dependent: needs a multicast route on this host"]
    fn a_datagram_one_member_sends_reaches_another_with_the_senders_own_port() {
        let probe = WindowsUdpSocket::bind_shared(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
            .expect("a port");
        let port = probe.local().port();
        let group = SocketAddr::from((GROUP, port));
        let mut a = WindowsGroupTransport::<256>::join(group, GroupInterface::Routing, None)
            .expect("member a");
        let mut b = WindowsGroupTransport::<256>::join(group, GroupInterface::Routing, None)
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
