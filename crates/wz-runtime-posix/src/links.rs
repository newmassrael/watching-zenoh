// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host's sockets as the session shell's links on the heap profile.
//!
//! [`PosixLinks`] is `wz_runtime_coop::ip_stack`'s `IpLinks` at [`PosixUdpSocket`] and
//! [`PosixTcpDial`]: a dial to `udp/...` opens the datagram link, a dial to `tcp/...` the stream
//! link over a [`PosixTcpSocket`], and an accepting link is a datagram link. Each link allocates
//! its buffers when it opens. It is the heap profile's twin of the slot profile's `PosixStack`,
//! and what a program with an allocator (the pico C ABI over the cooperative engine) gives the
//! session shell.

use crate::net::PosixUdpSocket;
use crate::stream::{PosixTcpDial, PosixTcpSocket};

/// The host's sockets as the session shell's links, on the heap profile, made with
/// `PosixLinks::new(local, PosixTcpDial)`.
pub type PosixLinks = wz_runtime_coop::ip_stack::IpLinks<PosixUdpSocket, PosixTcpDial>;

/// The driver [`PosixLinks`] opens: a datagram or a stream link, as the dial named.
pub type PosixHeapDriver = wz_runtime_coop::ip_stack::HeapIpDriver<PosixUdpSocket, PosixTcpSocket>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    use wz_runtime_coop::session_drive::{IpEndpoint, Locator, SessionLinks};
    use wz_session_core::link::BoxedLinkDriver;

    const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

    #[test]
    fn a_dial_names_the_link_it_opens_over_the_hosts_sockets() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let port = listener.local_addr().expect("its port").port();
        let links = PosixLinks::new(LOOPBACK, PosixTcpDial);
        let tcp = links
            .open_initiator(Locator::tcp(IpEndpoint {
                addr: LOOPBACK,
                port,
            }))
            .expect("a connection")
            .pump;
        assert!(tcp.batch_length_prefixed());
        let ends = tcp.link_endpoints().expect("a connection knows both ends");
        assert_eq!(ends.dst.as_str(), std::format!("tcp/127.0.0.1:{port}"));

        let udp = links
            .open_initiator(Locator::udp(IpEndpoint {
                addr: LOOPBACK,
                port,
            }))
            .expect("a datagram socket")
            .pump;
        assert!(!udp.batch_length_prefixed());
    }
}
