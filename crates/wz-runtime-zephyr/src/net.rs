// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Zephyr profile's network seam: UDP over Zephyr's own BSD sockets.
//!
//! R2916. zenoh-pico's Zephyr port networks through the sockets Zephyr's net
//! stack provides (`vendor/zenoh-pico/src/system/zephyr/network.c`), so it
//! reaches whatever interface the board's Zephyr drivers bring up. This
//! profile used to reuse lwIP `NO_SYS` instead, which has no netif over
//! Zephyr's device drivers: a wz image on real Zephyr hardware could only talk
//! to its own loopback. [`ZephyrUdpSocket`] is the socket, and
//! [`ZephyrUdpDriver`] is the session's link over it — its outbound half is
//! the session core's [`BoxedLinkDriver`], its inbound half the cooperative
//! drive loop's [`SessionDatagramLink`].
//!
//! Zephyr's net stack runs its RX path on its own threads, so there is no
//! input path for the drive loop to pump. What the loop's thread owes it is
//! the CPU: [`SessionDatagramLink::service`] yields for one tick through the
//! board's `wz_yield_ms` seam, the one the deploy's cooperative loop already
//! uses, so the net threads get to run between iterations.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::{Cell, OnceCell, RefCell};
use core::ffi::{c_int, c_void};
use core::mem::size_of;

use wz_runtime_coop::session_drive::SessionDatagramLink;
use wz_session_core::link::{
    BoxedLinkDriver, LinkDropCause, LinkEndpoints, LinkSendOutcome, RxFrame,
};
use wz_session_core::reliability::Reliability;
use zephyr_sys::socket::{
    bind, close, poll, recvfrom, sendto, socket, PollFd, SockLen, SockaddrIn, AF_INET, IPPROTO_UDP,
    POLLIN, SOCK_DGRAM,
};

extern "C" {
    /// `k_msleep(ms)` — a `static inline` in Zephyr's headers, so the board
    /// supplies it as a real symbol; the deploy's cooperative loop yields
    /// through the same seam.
    fn wz_yield_ms(ms: i32);
}

/// The largest UDP payload the session receives in one datagram — the
/// transport's own ceiling, so a whole batch always fits.
pub const UDP_RX_CAPACITY: usize = 65_535;

/// Why a socket call failed. Zephyr reports the cause through `errno`, which
/// is a thread-local the FFI cannot reach portably, so the error names the
/// CALL and keeps its return value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZephyrNetError {
    /// `socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)` returned this.
    Socket(c_int),
    /// `bind` returned this.
    Bind(c_int),
    /// `sendto` took this many bytes (negative: refused) of a datagram.
    Send(isize),
    /// `poll` returned this.
    Poll(c_int),
    /// `recvfrom` returned this although `poll` reported the socket readable.
    Recv(isize),
}

/// One IPv4 UDP socket on Zephyr's net stack, bound to an explicit local
/// address — the address the link's locator names, as zenoh-pico listens on
/// `udp/<ip>:<port>`.
pub struct ZephyrUdpSocket {
    fd: c_int,
    local: ([u8; 4], u16),
}

fn sockaddr(addr: [u8; 4], port: u16) -> SockaddrIn {
    SockaddrIn {
        sin_family: AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: u32::from_ne_bytes(addr),
    }
}

impl ZephyrUdpSocket {
    /// Open a UDP socket and bind it to `addr:port`.
    pub fn bind(addr: [u8; 4], port: u16) -> Result<Self, ZephyrNetError> {
        // SAFETY: plain FFI with value arguments.
        let fd = unsafe { socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) };
        if fd < 0 {
            return Err(ZephyrNetError::Socket(fd));
        }
        // Owned from here, so an early return closes it.
        let this = Self {
            fd,
            local: (addr, port),
        };
        let local = sockaddr(addr, port);
        // SAFETY: `local` is a live `sockaddr_in` of the length passed.
        let rc = unsafe { bind(fd, &local, size_of::<SockaddrIn>() as SockLen) };
        if rc != 0 {
            return Err(ZephyrNetError::Bind(rc));
        }
        Ok(this)
    }

    /// The `(address, port)` this socket is bound to.
    pub fn local(&self) -> ([u8; 4], u16) {
        self.local
    }

    /// Send one datagram to `addr:port`. A short or refused send is an error:
    /// UDP either takes the whole datagram or none of it.
    pub fn send_to(&self, addr: [u8; 4], port: u16, bytes: &[u8]) -> Result<(), ZephyrNetError> {
        let dest = sockaddr(addr, port);
        // SAFETY: `bytes` and `dest` are live for the call, lengths match.
        let sent = unsafe {
            sendto(
                self.fd,
                bytes.as_ptr() as *const c_void,
                bytes.len(),
                0,
                &dest,
                size_of::<SockaddrIn>() as SockLen,
            )
        };
        if sent == bytes.len() as isize {
            Ok(())
        } else {
            Err(ZephyrNetError::Send(sent))
        }
    }

    /// Take one queued datagram into `buf` without blocking: `Ok(None)` when
    /// nothing is queued, else its length and source.
    ///
    /// Readiness is asked of `poll` with a zero timeout rather than read off
    /// `recvfrom`'s `EAGAIN`, because `errno` is out of the FFI's reach and
    /// "nothing yet" must not look like a failure — or a failure like
    /// "nothing yet".
    pub fn try_recv(
        &self,
        buf: &mut [u8],
    ) -> Result<Option<(usize, [u8; 4], u16)>, ZephyrNetError> {
        let mut pfd = PollFd {
            fd: self.fd,
            events: POLLIN,
            revents: 0,
        };
        // SAFETY: one live `pollfd`, zero timeout.
        let ready = unsafe { poll(&mut pfd, 1, 0) };
        if ready < 0 {
            return Err(ZephyrNetError::Poll(ready));
        }
        if ready == 0 || pfd.revents & POLLIN == 0 {
            return Ok(None);
        }
        let mut src = SockaddrIn::default();
        let mut src_len = size_of::<SockaddrIn>() as SockLen;
        // SAFETY: `buf` and `src` are live and writable for the lengths given.
        let got = unsafe {
            recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
                &mut src,
                &mut src_len,
            )
        };
        if got < 0 {
            return Err(ZephyrNetError::Recv(got));
        }
        Ok(Some((
            got as usize,
            src.sin_addr.to_ne_bytes(),
            u16::from_be(src.sin_port),
        )))
    }
}

impl Drop for ZephyrUdpSocket {
    fn drop(&mut self) {
        // SAFETY: `fd` is this socket's own descriptor, closed exactly once.
        unsafe { close(self.fd) };
    }
}

/// `udp/a.b.c.d:port`, zenoh's rendering of a UDP locator.
fn udp_locator(addr: [u8; 4], port: u16) -> String {
    let [a, b, c, d] = addr;
    format!("udp/{a}.{b}.{c}.{d}:{port}")
}

/// The session's link over one [`ZephyrUdpSocket`].
///
/// Outbound sends target the peer captured from the most recent inbound
/// datagram: an acceptor is built with no peer and learns it from the
/// InitSyn, and [`SessionDatagramLink::try_recv`] retargets on every datagram
/// so replies go to whoever just spoke. UDP is connectionless, so
/// `open_blocking` / `close_blocking` are no-ops — the zenoh handshake and
/// Close frame are the session's open and close.
pub struct ZephyrUdpDriver {
    socket: ZephyrUdpSocket,
    peer: Cell<Option<([u8; 4], u16)>>,
    /// The link's two ends, `udp/<ip>:<port>` each, written once — when the
    /// peer is first known.
    endpoints: OnceCell<LinkEndpoints>,
    rx_buf: RefCell<Vec<u8>>,
    /// The last receive failure, kept for the deploy to report: the loop's
    /// seam returns a frame or nothing, and a socket that fails must not
    /// read as a quiet one.
    rx_error: Cell<Option<ZephyrNetError>>,
}

impl ZephyrUdpDriver {
    /// An acceptor's link: no peer until the first datagram names one.
    pub fn acceptor(socket: ZephyrUdpSocket) -> Self {
        Self::with_peer(socket, None)
    }

    /// An initiator's link: replies and first sends go to `peer`.
    pub fn initiator(socket: ZephyrUdpSocket, peer: ([u8; 4], u16)) -> Self {
        Self::with_peer(socket, Some(peer))
    }

    fn with_peer(socket: ZephyrUdpSocket, peer: Option<([u8; 4], u16)>) -> Self {
        let driver = Self {
            socket,
            peer: Cell::new(None),
            endpoints: OnceCell::new(),
            rx_buf: RefCell::new(vec![0u8; UDP_RX_CAPACITY]),
            rx_error: Cell::new(None),
        };
        if let Some(peer) = peer {
            driver.set_peer(peer);
        }
        driver
    }

    fn set_peer(&self, peer: ([u8; 4], u16)) {
        self.peer.set(Some(peer));
        if self.endpoints.get().is_none() {
            let (addr, port) = self.socket.local();
            let _ = self.endpoints.set(LinkEndpoints::new(
                udp_locator(addr, port),
                udp_locator(peer.0, peer.1),
            ));
        }
    }

    /// The peer the next send goes to, once one is known.
    pub fn peer(&self) -> Option<([u8; 4], u16)> {
        self.peer.get()
    }

    /// The most recent receive failure, if the socket has failed.
    pub fn rx_error(&self) -> Option<ZephyrNetError> {
        self.rx_error.get()
    }
}

impl BoxedLinkDriver for ZephyrUdpDriver {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        // UDP is unreliable; the session's reliable channel recovers a drop.
        // A send with no peer yet, or one the stack refuses, is REPORTED
        // (R2371's rule for the lwIP driver), not swallowed.
        let Some((addr, port)) = self.peer.get() else {
            return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
        };
        match self.socket.send_to(addr, port, bytes) {
            Ok(()) => LinkSendOutcome::Sent,
            Err(_) => LinkSendOutcome::Dropped(LinkDropCause::WriterGone),
        }
    }

    fn open_blocking(&self) {}

    fn close_blocking(&self) {}

    fn link_endpoints(&self) -> Option<&LinkEndpoints> {
        self.endpoints.get()
    }
}

impl SessionDatagramLink for ZephyrUdpDriver {
    fn service(&self) {
        // SAFETY: the board's `k_msleep` seam; blocks this thread one tick.
        unsafe { wz_yield_ms(1) };
    }

    fn try_recv(&self) -> Option<RxFrame> {
        let mut buf = self.rx_buf.borrow_mut();
        match self.socket.try_recv(&mut buf) {
            Ok(Some((len, addr, port))) => {
                self.set_peer((addr, port));
                Some(RxFrame::new(buf[..len].to_vec()))
            }
            Ok(None) => None,
            Err(e) => {
                self.rx_error.set(Some(e));
                None
            }
        }
    }
}
