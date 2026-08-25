// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y579 (G9) — the raweth (L2) link's TRANSPORT: an `AF_PACKET` socket, and
//! the seam that lets everything above it be driven without one.
//!
//! Reference: `vendor/zenoh-pico/src/link/transport/udp/raweth_unix.c:47-125`
//! (`_z_open_raweth` / `_z_send_raweth` / `_z_receive_raweth` /
//! `_z_close_raweth`). The framing this carries is
//! [`wz_session_core::raweth_link`].
//!
//! Round 1998 (item 470) moved this file out of `wz-runtime-tokio` unchanged.
//! It never used `tokio`; it lived there because that crate already had `std`
//! and `libc`, which is a reason to put a file somewhere and not a reason to
//! keep it there. See this crate's manifest for what that placement cost.
//!
//! ## Why the I/O is behind a trait
//!
//! `AF_PACKET` needs `CAP_NET_RAW`. An unprivileged process — which is what a
//! test run is — cannot open one at all, so a design that hard-wired the
//! syscall would make the ENTIRE link untestable: the framing, the whitelist,
//! the send/receive loop, all of it unreachable behind a `socket()` that
//! returns `EPERM`. Splitting the four operations onto [`RawEthIo`] moves the
//! privileged part to twenty lines and leaves everything above it drivable
//! over any datagram carrier.
//! [`tests::two_links_exchange_real_frames_over_a_datagram_carrier`] drives two
//! links against each other over a `UnixDatagram` pair and exercises the real
//! framing, the real whitelist and the real send/receive path.
//!
//! This is not a test-only indirection: an embedder with a DPDK / XDP / TSN
//! path, or an MCU with a MAC peripheral, has the same shape and no
//! `AF_PACKET`.
//!
//! ## What is NOT claimed
//!
//! The privileged half — `socket(AF_PACKET, SOCK_RAW)`, `SIOCGIFINDEX`, the
//! `sockaddr_ll` bind — is exercised by [`AfPacketSocket::open`], and this
//! machine cannot run it: without `CAP_NET_RAW` the kernel refuses at the
//! first syscall. [`tests::the_socket_agrees_with_the_kernel_about_privilege`]
//! therefore asks the kernel the same question directly and requires wz's
//! answer to MATCH — a refusal where the kernel refuses, a socket where it
//! does not. That is a real assertion on an unprivileged host (it catches an
//! `open` that failed for the wrong reason, or succeeded when it should not),
//! and it becomes the full open path when run with the capability. A frame
//! genuinely leaving a NIC is not proven here and is not claimed.

use std::io;
use std::os::fd::{AsRawFd, RawFd};

use wz_session_core::raweth_link::{
    deframe, frame, MacWhitelist, RawEthError, RawEthHeader, MAC_LEN, MAX_ETH_FRAME_SIZE,
};

/// The datagram carrier a raweth link sends and receives whole frames over.
///
/// Whole FRAMES, not a byte stream: raweth is a datagram link (pico marks it
/// `_is_reliable = false`), so a partial read is a lost frame rather than
/// something to accumulate. Modelling it as a stream would invite a caller to
/// write the reassembly loop that must not exist here.
pub trait RawEthIo {
    /// Send one frame. Returns bytes written.
    fn send_frame(&self, frame: &[u8]) -> io::Result<usize>;
    /// Receive one frame into `buf`. Returns bytes read.
    fn recv_frame(&self, buf: &mut [u8]) -> io::Result<usize>;
}

/// A raw `AF_PACKET` socket bound to one interface.
///
/// Mirrors `_z_open_raweth` (raweth_unix.c:49-75): `socket(AF_PACKET,
/// SOCK_RAW, htons(ETH_P_ALL))`, `SIOCGIFINDEX` for the interface index, then
/// a `sockaddr_ll` bind.
#[derive(Debug)]
pub struct AfPacketSocket {
    fd: RawFd,
}

impl AfPacketSocket {
    /// Open and bind a raw packet socket on `interface`.
    ///
    /// Fails with [`io::ErrorKind::PermissionDenied`] without `CAP_NET_RAW`,
    /// which is the ordinary outcome for an unprivileged process and not a
    /// misconfiguration.
    pub fn open(interface: &str) -> io::Result<Self> {
        // The name is checked BEFORE the socket, so a name that cannot work is
        // not paid for with a descriptor -- and so the check is reachable at
        // all on a host without CAP_NET_RAW, where `socket()` fails first.
        // `ifr_name` is a fixed IFNAMSIZ field including its NUL, so a name
        // that does not fit is rejected rather than silently truncated into a
        // DIFFERENT interface's index; pico's `strncpy(.., strlen(interface))`
        // (raweth_unix.c:57) would copy an unterminated name into the ioctl.
        if interface.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("interface name {interface:?} does not fit IFNAMSIZ"),
            ));
        }
        // ETH_P_ALL in network order, exactly as pico passes it.
        let proto = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;
        // SAFETY: `socket` takes three ints and returns a fd or -1.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let this = Self { fd };

        // The interface index.
        let mut ifreq: libc::ifreq = unsafe { core::mem::zeroed() };
        debug_assert_eq!(ifreq.ifr_name.len(), libc::IFNAMSIZ);
        for (slot, byte) in ifreq.ifr_name.iter_mut().zip(interface.as_bytes()) {
            *slot = *byte as libc::c_char;
        }
        // SAFETY: `fd` is an open socket and `ifreq` is a correctly-sized,
        // zero-initialised `struct ifreq` as SIOCGIFINDEX expects.
        if unsafe { libc::ioctl(this.fd, libc::SIOCGIFINDEX, &mut ifreq) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the union's index arm is the one SIOCGIFINDEX fills.
        let ifindex = unsafe { ifreq.ifr_ifru.ifru_ifindex };

        let mut addr: libc::sockaddr_ll = unsafe { core::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        addr.sll_ifindex = ifindex;
        addr.sll_pkttype = libc::PACKET_HOST | libc::PACKET_BROADCAST | libc::PACKET_MULTICAST;
        // SAFETY: `addr` is a fully-initialised `sockaddr_ll` and its length
        // is passed as its own `size_of`.
        let rc = unsafe {
            libc::bind(
                this.fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                core::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(this)
    }
}

impl AsRawFd for AfPacketSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for AfPacketSocket {
    fn drop(&mut self) {
        // SAFETY: `fd` was returned by `socket` and is closed exactly once —
        // `AfPacketSocket` is not `Clone` and owns the descriptor.
        unsafe { libc::close(self.fd) };
    }
}

impl RawEthIo for AfPacketSocket {
    fn send_frame(&self, frame: &[u8]) -> io::Result<usize> {
        // SAFETY: `frame` is a valid slice and its length is passed with it.
        let n = unsafe { libc::write(self.fd, frame.as_ptr() as *const libc::c_void, frame.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    fn recv_frame(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: `buf` is a valid mutable slice and its capacity is passed
        // with it; a NULL source address asks the kernel not to write one.
        let n = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

/// What a receive produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawEthReceive {
    /// A frame from an admitted source, with its payload.
    Frame {
        /// The frame's header.
        header: RawEthHeader,
        /// The payload its `data_length` delimited.
        payload: Vec<u8>,
    },
    /// A frame whose source MAC the whitelist does not name. Reported rather
    /// than silently dropped: an operator whose whitelist is wrong sees
    /// "nothing arrives", and a filtered count is the difference between that
    /// and a dead link. pico returns `SIZE_MAX` here (raweth_unix.c:114),
    /// which is indistinguishable from a read error.
    Filtered {
        /// The rejected source MAC.
        smac: [u8; MAC_LEN],
    },
    /// The bytes did not form a raweth frame.
    Malformed(RawEthError),
}

/// A raweth link: a carrier, the header template it sends with, and the
/// source-MAC allow-list it receives through.
#[derive(Debug)]
pub struct RawEthLink<T: RawEthIo> {
    io: T,
    header: RawEthHeader,
    whitelist: MacWhitelist,
}

impl<T: RawEthIo> RawEthLink<T> {
    /// Build a link that sends with `header` and admits the sources
    /// `whitelist` names (an empty list admits all — see [`MacWhitelist`]).
    pub fn new(io: T, header: RawEthHeader, whitelist: MacWhitelist) -> Self {
        Self {
            io,
            header,
            whitelist,
        }
    }

    /// The header this link stamps outbound frames with.
    pub fn header(&self) -> &RawEthHeader {
        &self.header
    }

    /// Frame `payload` and send it.
    pub fn send(&self, payload: &[u8]) -> io::Result<usize> {
        let bytes = frame(&self.header, payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        self.io.send_frame(&bytes)
    }

    /// Receive one frame, deframe it, and apply the whitelist.
    pub fn recv(&self) -> io::Result<RawEthReceive> {
        let mut buf = [0u8; MAX_ETH_FRAME_SIZE];
        let n = self.io.recv_frame(&mut buf)?;
        match deframe(&buf[..n]) {
            Ok((header, payload)) => {
                if self.whitelist.accepts(&header.smac) {
                    Ok(RawEthReceive::Frame {
                        header,
                        payload: payload.to_vec(),
                    })
                } else {
                    Ok(RawEthReceive::Filtered { smac: header.smac })
                }
            }
            Err(e) => Ok(RawEthReceive::Malformed(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;
    use wz_session_core::raweth_link::{DEFAULT_ETHTYPE, DEFAULT_INTERFACE};

    /// A `UnixDatagram` standing in for the NIC. Datagram semantics match
    /// `AF_PACKET`'s: one send is one receive, no stream reassembly.
    struct DatagramIo(UnixDatagram);

    impl RawEthIo for DatagramIo {
        fn send_frame(&self, frame: &[u8]) -> io::Result<usize> {
            self.0.send(frame)
        }
        fn recv_frame(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.recv(buf)
        }
    }

    const A: [u8; MAC_LEN] = [0xaa; MAC_LEN];
    const B: [u8; MAC_LEN] = [0xbb; MAC_LEN];

    fn pair() -> (UnixDatagram, UnixDatagram) {
        UnixDatagram::pair().expect("socketpair")
    }

    #[test]
    fn two_links_exchange_real_frames_over_a_datagram_carrier() {
        let (left, right) = pair();
        // Left sends B -> A; right sends A -> B. The MACs are what the
        // whitelist below discriminates on, so they must differ.
        let l = RawEthLink::new(
            DatagramIo(left),
            RawEthHeader::new(A, B, DEFAULT_ETHTYPE, 0),
            MacWhitelist::new(),
        );
        let r = RawEthLink::new(
            DatagramIo(right),
            RawEthHeader::new(B, A, DEFAULT_ETHTYPE, 0),
            MacWhitelist::new(),
        );

        l.send(b"hello raweth").expect("send");
        match r.recv().expect("recv") {
            RawEthReceive::Frame { header, payload } => {
                assert_eq!(payload, b"hello raweth");
                assert_eq!(header.smac, B, "the sender's MAC did not survive");
                assert_eq!(header.dmac, A);
                assert_eq!(header.data_length as usize, payload.len());
            }
            other => panic!("not a frame: {other:?}"),
        }

        // ...and back, so the test is not proving one direction twice.
        r.send(b"ack").expect("send back");
        match l.recv().expect("recv back") {
            RawEthReceive::Frame { payload, header } => {
                assert_eq!(payload, b"ack");
                assert_eq!(header.smac, A);
            }
            other => panic!("not a frame: {other:?}"),
        }
    }

    #[test]
    fn the_whitelist_filters_by_source_and_reports_the_rejection() {
        let (left, right) = pair();
        let l = RawEthLink::new(
            DatagramIo(left),
            RawEthHeader::new(A, B, DEFAULT_ETHTYPE, 0),
            MacWhitelist::new(),
        );
        // The receiver admits only A, and the sender's MAC is B.
        let r = RawEthLink::new(
            DatagramIo(right),
            RawEthHeader::new(B, A, DEFAULT_ETHTYPE, 0),
            MacWhitelist::new().allow(A),
        );
        l.send(b"blocked").expect("send");
        assert_eq!(r.recv().expect("recv"), RawEthReceive::Filtered { smac: B });

        // POSITIVE CONTROL on the same link: a frame from the admitted MAC
        // gets through, so `Filtered` above was the whitelist and not a
        // broken receive path.
        let (l2, r2) = pair();
        let sender = RawEthLink::new(
            DatagramIo(l2),
            RawEthHeader::new(B, A, DEFAULT_ETHTYPE, 0),
            MacWhitelist::new(),
        );
        let receiver = RawEthLink::new(
            DatagramIo(r2),
            RawEthHeader::new(A, B, DEFAULT_ETHTYPE, 0),
            MacWhitelist::new().allow(A),
        );
        sender.send(b"admitted").expect("send");
        match receiver.recv().expect("recv") {
            RawEthReceive::Frame { payload, .. } => assert_eq!(payload, b"admitted"),
            other => panic!("the admitted source was rejected: {other:?}"),
        }
    }

    #[test]
    fn a_vlan_tagged_link_round_trips_and_the_untagged_reader_sees_the_wider_header() {
        let (left, right) = pair();
        let l = RawEthLink::new(
            DatagramIo(left),
            RawEthHeader::new(A, B, DEFAULT_ETHTYPE, 0).with_vlan(0x0064),
            MacWhitelist::new(),
        );
        // The receiver is configured WITHOUT a VLAN; the width is read off the
        // frame, not off local config, so it must still decode.
        let r = RawEthLink::new(
            DatagramIo(right),
            RawEthHeader::new(B, A, DEFAULT_ETHTYPE, 0),
            MacWhitelist::new(),
        );
        l.send(b"tagged").expect("send");
        match r.recv().expect("recv") {
            RawEthReceive::Frame { header, payload } => {
                assert_eq!(payload, b"tagged");
                assert_eq!(header.vlan, Some(0x0064));
            }
            other => panic!("not a frame: {other:?}"),
        }
    }

    #[test]
    fn a_short_frame_is_reported_as_malformed_rather_than_read_past() {
        let (left, right) = pair();
        // Write raw bytes that are not a frame at all.
        left.send(&[0u8; 4]).expect("send garbage");
        let r = RawEthLink::new(
            DatagramIo(right),
            RawEthHeader::new(B, A, DEFAULT_ETHTYPE, 0),
            MacWhitelist::new(),
        );
        assert!(matches!(
            r.recv().expect("recv"),
            RawEthReceive::Malformed(RawEthError::Truncated { got: 4, need: 16 })
        ));
    }

    #[test]
    fn the_socket_agrees_with_the_kernel_about_privilege() {
        // Ask the kernel the same question wz's `open` asks, by hand and with
        // nothing else in the way. Whatever it answers, wz must answer too:
        // this is the assertion that has content on an UNPRIVILEGED host, and
        // it becomes the full open path on a privileged one.
        //
        // SAFETY: three ints in, a fd or -1 out; the fd is closed below.
        let probe = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as libc::c_int,
            )
        };
        let kernel_allows = probe >= 0;
        if kernel_allows {
            // SAFETY: `probe` is an open descriptor this scope owns.
            unsafe { libc::close(probe) };
        }

        match (kernel_allows, AfPacketSocket::open(DEFAULT_INTERFACE)) {
            (true, Ok(_)) => {}
            (false, Err(e)) => assert_eq!(
                e.kind(),
                io::ErrorKind::PermissionDenied,
                "the kernel refused AF_PACKET, but wz reported {e:?} rather than a permission error"
            ),
            (true, Err(e)) => panic!(
                "the kernel grants AF_PACKET but wz's open failed on {DEFAULT_INTERFACE}: {e}"
            ),
            (false, Ok(_)) => {
                panic!("wz opened an AF_PACKET socket the kernel refuses to a bare `socket()` call")
            }
        }
    }

    #[test]
    fn an_interface_name_too_long_for_ifnamsiz_is_rejected_before_the_syscall() {
        // 16 bytes leaves no room for the NUL. Rejecting here is the
        // divergence from pico's `strncpy(.., strlen(interface))`, which would
        // copy an unterminated name into the ioctl.
        let err = AfPacketSocket::open(&"x".repeat(16)).expect_err("must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
