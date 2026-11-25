// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host's raw packet sockets: what the cooperative engine's `reth/` groups run over, on Linux.
//!
//! [`PosixRawEth`] is the device `wz_runtime_coop::raweth_group` is written against
//! ([`RawEthDevice`]), and [`PosixRawEthOpen`] what a stack opens one with ([`RawEthOpen`]): an
//! `AF_PACKET` socket of every protocol (`ETH_P_ALL`) bound to the endpoint's interface, as
//! zenoh-pico opens its raweth socket (`vendor/zenoh-pico/src/link/transport/udp/raweth_unix.c` @
//! `_z_open_raweth`) and `wz-packet-socket` opens the tokio engine's, here without `std` and
//! without blocking. The socket needs `CAP_NET_RAW`: a host that does not grant it refuses the
//! open, as it refuses pico's.
//!
//! Nothing here allocates: the interface name is copied into the request's own field.

#![cfg(target_os = "linux")]

use core::ffi::c_int;

use wz_runtime_coop::group_transport::GroupSend;
use wz_runtime_coop::raweth_group::{RawEthDevice, RawEthOpen};
use wz_runtime_coop::session_drive::{LinkOpenError, WaitOn};

use crate::net::errno;

/// `ETH_P_ALL` in network order, as the socket and its address name the protocol.
const ALL_PROTOCOLS: u16 = (libc::ETH_P_ALL as u16).to_be();

/// One open raw packet socket, bound to an interface, read and written without blocking.
pub struct PosixRawEth {
    fd: c_int,
}

impl RawEthDevice for PosixRawEth {
    // A full device queue is `EAGAIN` or `ENOBUFS`: nothing was sent, and the frame waits for room.
    fn send_frame(&mut self, frame: &[u8]) -> GroupSend {
        loop {
            // SAFETY: `frame` is live and readable for its length.
            let sent = unsafe { libc::send(self.fd, frame.as_ptr().cast(), frame.len(), 0) };
            if sent >= 0 {
                return GroupSend::Sent;
            }
            match errno() {
                libc::EINTR => continue,
                libc::EAGAIN | libc::ENOBUFS => return GroupSend::Full,
                _ => return GroupSend::Failed,
            }
        }
    }

    // A frame longer than `buf` is cut to it, as a datagram socket cuts one. An error is a quiet
    // socket: pico's raweth link reports no carrier, and its receive drops what it cannot read.
    fn recv_frame(&mut self, buf: &mut [u8]) -> Option<usize> {
        loop {
            // SAFETY: `buf` is live and writable for its length.
            let got = unsafe { libc::recv(self.fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
            if got >= 0 {
                return Some(got.unsigned_abs());
            }
            if errno() != libc::EINTR {
                return None;
            }
        }
    }

    fn input_wait(&self) -> Option<WaitOn> {
        crate::net::wait_on(self.fd)
    }

    fn room_wait(&self) -> Option<WaitOn> {
        crate::net::wait_on(self.fd)
    }
}

impl Drop for PosixRawEth {
    fn drop(&mut self) {
        // SAFETY: `fd` is this socket's own descriptor, closed exactly once.
        unsafe { libc::close(self.fd) };
    }
}

/// The host's raw packet sockets as a stack's `reth/` groups.
#[derive(Debug, Clone, Copy, Default)]
pub struct PosixRawEthOpen;

/// A failed call of the open as the stack's refusal: no descriptor left is worth a later try.
fn refused(errno: c_int) -> LinkOpenError {
    match errno {
        libc::EMFILE | libc::ENFILE => LinkOpenError::Exhausted,
        _ => LinkOpenError::Refused,
    }
}

impl RawEthOpen for PosixRawEthOpen {
    type Device = PosixRawEth;

    /// The socket `socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)`, the interface's index by
    /// `SIOCGIFINDEX`, and a `sockaddr_ll` bind to it. A name the request's field cannot hold
    /// with its NUL, or one holding a NUL, names no interface and is
    /// [`LinkOpenError::Unsupported`] before a socket is made, rather than cut into another
    /// interface's name as pico's `strncpy` would cut it.
    fn open(&self, interface: &str) -> Result<PosixRawEth, LinkOpenError> {
        // SAFETY: `ifreq` is plain data, for which all zeroes is a valid value.
        let mut ifreq: libc::ifreq = unsafe { core::mem::zeroed() };
        if interface.len() >= ifreq.ifr_name.len() || interface.as_bytes().contains(&0) {
            return Err(LinkOpenError::Unsupported);
        }
        for (slot, byte) in ifreq.ifr_name.iter_mut().zip(interface.as_bytes()) {
            *slot = *byte as libc::c_char;
        }
        // SAFETY: three ints in, a descriptor or -1 out.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                c_int::from(ALL_PROTOCOLS),
            )
        };
        if fd < 0 {
            return Err(refused(errno()));
        }
        // Closed by its drop on every refusal below.
        let device = PosixRawEth { fd };
        // SAFETY: `fd` is an open socket and `ifreq` a zeroed `struct ifreq` holding the name, as
        // `SIOCGIFINDEX` reads it.
        if unsafe { libc::ioctl(device.fd, libc::SIOCGIFINDEX, &mut ifreq) } < 0 {
            return Err(refused(errno()));
        }
        // SAFETY: the index is the arm of the union `SIOCGIFINDEX` fills.
        let ifindex = unsafe { ifreq.ifr_ifru.ifru_ifindex };
        // SAFETY: `sockaddr_ll` is plain data, for which all zeroes is a valid value.
        let mut addr: libc::sockaddr_ll = unsafe { core::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = ALL_PROTOCOLS;
        addr.sll_ifindex = ifindex;
        addr.sll_pkttype = libc::PACKET_HOST | libc::PACKET_BROADCAST | libc::PACKET_MULTICAST;
        // SAFETY: `addr` is a whole `sockaddr_ll`, its length passed as its own size.
        let bound = unsafe {
            libc::bind(
                device.fd,
                core::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
                core::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if bound < 0 {
            return Err(refused(errno()));
        }
        Ok(device)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name the request cannot hold with its NUL, or one that holds a NUL, is refused before a
    /// socket is made, so on a host without `CAP_NET_RAW` too.
    #[test]
    fn a_name_no_interface_has_is_refused_before_the_socket() {
        let names = [b'e'; libc::IFNAMSIZ];
        let name = |len| core::str::from_utf8(names.get(..len).expect("a name")).expect("text");
        assert!(matches!(
            PosixRawEthOpen.open(name(libc::IFNAMSIZ)),
            Err(LinkOpenError::Unsupported)
        ));
        assert!(matches!(
            PosixRawEthOpen.open("lo\0x"),
            Err(LinkOpenError::Unsupported)
        ));
        // The longest name is let through to the host, which knows no such interface or refuses
        // the socket: refused either way, and not for its length.
        assert!(matches!(
            PosixRawEthOpen.open(name(libc::IFNAMSIZ - 1)),
            Err(LinkOpenError::Refused)
        ));
    }

    /// The open answers as the kernel answers a bare `socket(AF_PACKET)`: a device where it grants
    /// one, and a refusal where it does not, which is what an unprivileged host answers.
    #[test]
    fn the_open_agrees_with_the_kernel_about_privilege() {
        // SAFETY: three ints in, a descriptor or -1 out; the descriptor is closed below.
        let probe =
            unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, c_int::from(ALL_PROTOCOLS)) };
        let granted = probe >= 0;
        if granted {
            // SAFETY: `probe` is an open descriptor this test owns.
            unsafe { libc::close(probe) };
        }
        match (granted, PosixRawEthOpen.open("lo")) {
            (true, Ok(_)) | (false, Err(LinkOpenError::Refused)) => {}
            (true, Err(refusal)) => {
                panic!("the kernel grants AF_PACKET, the open refused: {refusal:?}")
            }
            (false, Ok(_)) => panic!("opened a socket the kernel refuses a bare socket() call"),
            (false, Err(refusal)) => panic!("refused as {refusal:?}, not as the kernel refused"),
        }
    }
}
