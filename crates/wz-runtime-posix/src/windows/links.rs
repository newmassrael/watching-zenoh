// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Windows host's sockets as the session shell's links on the heap profile.
//!
//! [`WindowsLinks`] is `wz_runtime_coop::ip_stack`'s `IpLinks` at [`WindowsUdpSocket`] and
//! [`WindowsTcpDial`], as the POSIX half's `PosixLinks` is at its sockets: a dial to `udp/...`
//! opens the datagram link, a dial to `tcp/...` the stream link over a [`WindowsTcpSocket`], and a
//! `tcp/` listener takes connections as faces. What a program with an allocator (the pico C ABI
//! over the cooperative engine) gives the session shell on Windows.

use super::net::WindowsUdpSocket;
use super::stream::{WindowsTcpDial, WindowsTcpSocket};

/// The host's sockets as the session shell's links, on the heap profile, made with
/// `WindowsLinks::new(local, WindowsTcpDial)`.
pub type WindowsLinks = wz_runtime_coop::ip_stack::IpLinks<WindowsUdpSocket, WindowsTcpDial>;

/// The driver [`WindowsLinks`] opens: a datagram or a stream link, as the dial named.
pub type WindowsHeapDriver =
    wz_runtime_coop::ip_stack::HeapIpDriver<WindowsUdpSocket, WindowsTcpSocket>;

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::net::TcpListener;

    use wz_runtime_coop::session_drive::{Locator, SessionLinks};
    use wz_session_core::link::BoxedLinkDriver;

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    #[test]
    fn a_dial_names_the_link_it_opens_over_the_hosts_sockets() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let port = listener.local_addr().expect("its port").port();
        let links = WindowsLinks::new(LOOPBACK, WindowsTcpDial);
        let tcp = links
            .open_initiator(Locator::tcp(SocketAddr::new(LOOPBACK, port)))
            .expect("a connection")
            .pump;
        assert!(tcp.batch_length_prefixed());
        let ends = tcp.link_endpoints().expect("a connection knows both ends");
        assert_eq!(ends.dst.as_str(), std::format!("tcp/127.0.0.1:{port}"));

        let udp = links
            .open_initiator(Locator::udp(SocketAddr::new(LOOPBACK, port)))
            .expect("a datagram socket")
            .pump;
        assert!(!udp.batch_length_prefixed());
    }

    /// Links whose owner waits on them hand the owner a wait on each socket: the cooperative
    /// engine of the pico C ABI waits outside its lock on what these give.
    #[test]
    fn links_waited_by_their_owner_give_a_wait_on_each_socket() {
        use wz_runtime_coop::session_drive::SessionDatagramLink;

        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let port = listener.local_addr().expect("its port").port();
        let links = WindowsLinks::new(LOOPBACK, WindowsTcpDial).waited_by_owner();
        let tcp = links
            .open_initiator(Locator::tcp(SocketAddr::new(LOOPBACK, port)))
            .expect("a connection")
            .pump;
        let wait = tcp.readiness().expect("a stream gives its owner a wait");
        assert!(
            wait.handle().is_some(),
            "the wait names its socket to the system"
        );
        // Nothing has been sent: the wait runs out.
        wait.wait_readable(10);

        let udp = links
            .open_initiator(Locator::udp(SocketAddr::new(LOOPBACK, port)))
            .expect("a datagram socket")
            .pump;
        assert!(udp.readiness().is_some(), "a datagram socket gives one too");
    }
}
