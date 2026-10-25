// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host profile's multicast group seam: a group session's I/O over the kernel's own sockets.
//!
//! [`PosixGroupTransport`] is the [`GroupTransport`] the shared group drive loop
//! (`wz-session-mcu`'s `group_drive`) runs on, beside lwIP's and Zephyr's. It has the shape
//! zenoh gives a multicast link (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @
//! `let ucast_sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))`): TWO sockets,
//! a RECEIVER bound to the wildcard address on the group's port with `SO_REUSEADDR` and
//! `SO_REUSEPORT` (so it can share the port with every other member on this host) and joined to the
//! group, and a SENDER of its own on a port the kernel picks, so the source a peer sees names this
//! member and no other, even when two members live on one host. One socket for both, as the
//! Zephyr and lwIP transports have, would send every member of a host from the group's port.
//!
//! Nothing allocates: the two sockets are file descriptors and the receive buffer is an array of
//! `RX` bytes inside the value; size it to the batch the group advertises, since a datagram longer
//! than `RX` is truncated by the kernel and read by the loop as a bad frame.
//!
//! A member leaves the group by closing its receiver: the kernel drops the membership with the
//! socket on this host, where Zephyr's interface holds it.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use wz_runtime_coop::group_transport::GroupTransport;
use wz_runtime_coop::udp_link::{DatagramSocket, SERVICE_WAIT_MS};

use crate::net::{PosixNetError, PosixUdpSocket};

/// A multicast group session's I/O over the host's sockets.
pub struct PosixGroupTransport<const RX: usize> {
    /// The joined receiver, `None` once the session has released its link.
    ingress: Option<PosixUdpSocket>,
    /// The sender, on a port of its own.
    egress: Option<PosixUdpSocket>,
    group: ([u8; 4], u16),
    rx: [u8; RX],
    rx_error: Option<PosixNetError>,
}

impl<const RX: usize> PosixGroupTransport<RX> {
    /// Join `group` on `port` through the interface that holds `interface` (the unspecified
    /// address, `[0; 4]`: the one routing picks for the group, which is also the one the kernel
    /// sends out of), sending with the hop limit `ttl` (1: one subnet, the kernel's own default and
    /// zenoh's).
    pub fn join(
        group: [u8; 4],
        port: u16,
        interface: [u8; 4],
        ttl: u8,
    ) -> Result<Self, PosixNetError> {
        let ingress = PosixUdpSocket::bind_shared([0; 4], port)?;
        ingress.join_group(group, interface)?;
        let egress = PosixUdpSocket::bind([0; 4], 0)?;
        if interface != [0; 4] {
            egress.set_multicast_interface(interface)?;
        }
        egress.set_multicast_ttl(ttl)?;
        Ok(Self {
            ingress: Some(ingress),
            egress: Some(egress),
            group: (group, port),
            rx: [0; RX],
            rx_error: None,
        })
    }

    /// Join `group` on `port` through the interface routing picks for it, and when routing has none
    /// (a host with one subnet route and no default route refuses the join with `ENODEV`), through
    /// the first interface that is up, can multicast and is not a loopback
    /// ([`crate::net::multicast_interface`]), which is then also the one the node sends out of. A
    /// host whose routing answers is joined exactly as [`Self::join`] does with the unspecified
    /// address; only a refusal reaches the second try, and a host with no such interface keeps the
    /// first refusal.
    pub fn join_by_routing_or_first_interface(
        group: [u8; 4],
        port: u16,
        ttl: u8,
    ) -> Result<Self, PosixNetError> {
        match Self::join(group, port, [0; 4], ttl) {
            Err(first @ PosixNetError::Membership(_)) => match crate::net::multicast_interface() {
                Some(interface) => Self::join(group, port, interface, ttl),
                None => Err(first),
            },
            other => other,
        }
    }

    /// The `(group, port)` this transport sends to and receives on.
    pub fn group(&self) -> ([u8; 4], u16) {
        self.group
    }

    /// The port of the sender: the source every peer sees this member's datagrams from.
    pub fn sender_port(&self) -> Option<u16> {
        self.egress.as_ref().map(|socket| socket.local().1)
    }

    /// The most recent receive failure, if the receiver has failed: the seam the loop reads
    /// returns a datagram or nothing, and a failed socket must not read as a quiet group.
    pub fn rx_error(&self) -> Option<PosixNetError> {
        self.rx_error
    }
}

impl<const RX: usize> GroupTransport for PosixGroupTransport<RX> {
    fn open(&mut self) -> bool {
        self.ingress.is_some() && self.egress.is_some()
    }

    fn close(&mut self) {
        // Closing the receiver is leaving the group.
        self.ingress = None;
        self.egress = None;
    }

    fn service(&self) {
        // The kernel runs the stack: all this thread owes it is the wait, which a datagram cuts
        // short and which is a tick otherwise, so a node holding sessions beside this one does
        // not wait on the group for longer than it would on a stream.
        if let Some(socket) = &self.ingress {
            socket.wait_readable(SERVICE_WAIT_MS);
        }
    }

    /// A host has no carrier to read here; what ends a group is its receiver failing, which is
    /// what the kernel reports of an interface that went away (`ENETDOWN`, `ENODEV`).
    fn carrier_up(&self) -> bool {
        self.rx_error.is_none()
    }

    fn send_to_group(&mut self, datagram: &[u8]) {
        // Best-effort, as the trait says: multicast UDP has no acknowledgement and the next
        // cadence retries.
        if let Some(socket) = &self.egress {
            let _ = socket.send_to(self.group.0, self.group.1, datagram);
        }
    }

    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        let Some(socket) = &self.ingress else {
            return false;
        };
        match socket.try_recv(&mut self.rx) {
            Ok(Some((len, addr, port))) => {
                f(
                    &self.rx[..len],
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port),
                );
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

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP: [u8; 4] = [239, 255, 77, 3];

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
        let first = PosixUdpSocket::bind_shared([0; 4], 0).expect("a first receiver");
        let port = first.local().1;
        PosixUdpSocket::bind_shared([0; 4], port).expect("a second receiver on the same port");
        match PosixUdpSocket::bind([0; 4], port) {
            Err(PosixNetError::Bind(e)) => assert_eq!(e, libc::EADDRINUSE),
            Err(other) => panic!("a different error: {other:?}"),
            Ok(_) => panic!("a plain bind took a port a shared one holds"),
        }
    }

    #[test]
    fn a_group_that_is_not_one_is_not_joined() {
        // A unicast address is no group: the kernel refuses the membership, and the transport
        // does not come up half-made.
        match PosixGroupTransport::<64>::join([10, 0, 0, 1], 0, [0; 4], 1) {
            Err(PosixNetError::Membership(e)) => assert_eq!(e, libc::EINVAL),
            Err(other) => panic!("a different error: {other:?}"),
            Ok(_) => panic!("joined a unicast address"),
        }
    }

    /// A transport made as `join` makes it but for the membership, which is the one step that
    /// needs a multicast route on the host: what the rest of the transport does is the same
    /// whether or not the group was joined.
    fn unjoined(ttl: u8) -> PosixGroupTransport<64> {
        let ingress = PosixUdpSocket::bind_shared([0; 4], 0).expect("a receiver");
        let egress = PosixUdpSocket::bind([0; 4], 0).expect("a sender");
        egress.set_multicast_ttl(ttl).expect("a hop limit");
        PosixGroupTransport {
            group: (GROUP, ingress.local().1),
            ingress: Some(ingress),
            egress: Some(egress),
            rx: [0; 64],
            rx_error: None,
        }
    }

    #[test]
    fn the_sender_has_a_port_of_its_own_and_the_hop_limit_asked_for() {
        let a = unjoined(5);
        let b = unjoined(1);
        assert_ne!(
            a.sender_port(),
            b.sender_port(),
            "two members of one host are told apart by their sender's port"
        );
        assert_ne!(
            a.sender_port(),
            Some(a.group().1),
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
        let mut transport = unjoined(1);
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
        let probe = PosixUdpSocket::bind_shared([0; 4], 0).expect("a port");
        let port = probe.local().1;
        let mut a = PosixGroupTransport::<256>::join(GROUP, port, [0; 4], 1).expect("member a");
        let mut b = PosixGroupTransport::<256>::join(GROUP, port, [0; 4], 1).expect("member b");
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
