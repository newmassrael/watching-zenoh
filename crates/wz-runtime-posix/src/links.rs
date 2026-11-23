// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host's sockets as the session shell's links on the heap profile.
//!
//! [`PosixLinks`] is `wz_runtime_coop::ip_stack`'s `IpLinks` at [`PosixUdpSocket`] and
//! [`PosixTcpDial`]: a dial to `udp/...` opens the datagram link, a dial to `tcp/...` the stream
//! link over a [`PosixTcpSocket`](crate::stream::PosixTcpSocket), and an accepting link is a
//! datagram link. Each link allocates
//! its buffers when it opens. It is the heap profile's twin of the slot profile's `PosixStack`,
//! and what a program with an allocator (the pico C ABI over the cooperative engine) gives the
//! session shell.

use crate::net::PosixUdpSocket;
use crate::stream::PosixTcpDial;

/// The host's sockets as the session shell's links, on the heap profile, made with
/// `PosixLinks::new(local, PosixTcpDial)`.
pub type PosixLinks = wz_runtime_coop::ip_stack::IpLinks<PosixUdpSocket, PosixTcpDial>;

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::net::{TcpListener, UdpSocket};

    use wz_runtime_coop::session_drive::{Locator, SessionLinks};

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    #[test]
    fn a_dial_names_the_link_it_opens_over_the_hosts_sockets() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let port = listener.local_addr().expect("its port").port();
        let links = PosixLinks::new(LOOPBACK, PosixTcpDial);
        let tcp = links
            .open_initiator(Locator::tcp(SocketAddr::new(LOOPBACK, port)))
            .expect("a connection")
            .sink;
        assert!(tcp.batch_length_prefixed());
        let ends = tcp.link_endpoints().expect("a connection knows both ends");
        assert_eq!(ends.dst.as_str(), std::format!("tcp/127.0.0.1:{port}"));

        let udp = links
            .open_initiator(Locator::udp(SocketAddr::new(LOOPBACK, port)))
            .expect("a datagram socket")
            .sink;
        assert!(!udp.batch_length_prefixed());
    }

    /// Links bound on the IPv4 address dial an IPv6 locator over sockets of its family, as the
    /// stacks of the C ABIs bind every interface of one family and reach the other: the stream's
    /// ends and the datagram link's peer are named in brackets. Needs the host's IPv6 loopback.
    #[test]
    fn links_bound_on_ipv4_dial_an_ipv6_locator_over_its_family() {
        let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).expect("an IPv6 listener");
        let port = listener.local_addr().expect("its port").port();
        let links = PosixLinks::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), PosixTcpDial);
        let tcp = links
            .open_initiator(Locator::tcp(SocketAddr::from((Ipv6Addr::LOCALHOST, port))))
            .expect("a connection")
            .sink;
        let ends = tcp.link_endpoints().expect("a connection knows both ends");
        assert_eq!(ends.dst.as_str(), std::format!("tcp/[::1]:{port}"));
        assert!(ends.src.as_str().starts_with("tcp/[::1]:"), "{}", ends.src);

        let peer = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("an IPv6 datagram socket");
        let udp_port = peer.local_addr().expect("its port").port();
        let udp = links
            .open_initiator(Locator::udp(SocketAddr::from((
                Ipv6Addr::LOCALHOST,
                udp_port,
            ))))
            .expect("a datagram socket of the peer's family")
            .sink;
        let ends = udp
            .link_endpoints()
            .expect("a dialled link knows both ends");
        assert_eq!(ends.dst.as_str(), std::format!("udp/[::1]:{udp_port}"));
        assert!(ends.src.as_str().starts_with("udp/[::]:"), "{}", ends.src);
    }
}
