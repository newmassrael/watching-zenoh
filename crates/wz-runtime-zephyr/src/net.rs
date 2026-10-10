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
    bind, close, getsockname, poll, recvfrom, sendto, socket, PollFd, SockLen, SockaddrIn, AF_INET,
    IPPROTO_UDP, POLLIN, SOCK_DGRAM,
};

extern "C" {
    /// `k_msleep(ms)` — a `static inline` in Zephyr's headers, so the board
    /// supplies it as a real symbol; the deploy's cooperative loop yields
    /// through the same seam.
    fn wz_yield_ms(ms: i32);

    /// The board's own IPv4 address on the interface the sessions run on: write
    /// its four octets, most significant first, to `out[0..4]` and return 1, or
    /// return 0 while it has none (a DHCP lease not yet granted, a link not up).
    /// A board serves it from the net stack's interface, so the address is
    /// whatever the interface really holds, never a constant of the firmware.
    fn wzApplicationGetIpv4Address(out: *mut u8) -> i32;

    /// The node's zenoh id: write up to `cap` bytes to `out` and return how many
    /// (1 to 16), or return 0 when the board has no identity to give. A board
    /// serves it from the link-layer address of the interface its sessions run
    /// on, which is unique per NIC and the same on every boot.
    fn wzApplicationGetZid(out: *mut u8, cap: usize) -> usize;
}

/// The longest zenoh id: 16 bytes.
pub const ZID_MAX: usize = 16;

/// How often [`await_board_ipv4`] asks the board again.
const ADDRESS_POLL_MS: u32 = 100;

/// The board's IPv4 address, if its interface has one now.
///
/// The board answering 1 with 0.0.0.0 is read as no address: an unspecified
/// address is what a bound-to-nothing interface reports, and a link that names
/// itself `udp/0.0.0.0:<port>` is not one a peer can reach.
pub fn board_ipv4() -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    // SAFETY: the hook writes four bytes through a pointer to a live local.
    let have = unsafe { wzApplicationGetIpv4Address(octets.as_mut_ptr()) };
    (have == 1 && octets != [0; 4]).then_some(octets)
}

/// The node's zenoh id as the board gives it, 1 to [`ZID_MAX`] bytes, or `None`
/// when it has none. Never a constant of the firmware: two boards running the
/// same image must not claim the same id on one network.
pub fn board_zid() -> Option<Vec<u8>> {
    let mut id = [0u8; ZID_MAX];
    // SAFETY: the hook writes at most `ZID_MAX` bytes through a pointer to a
    // live local of that size, and returns how many.
    let len = unsafe { wzApplicationGetZid(id.as_mut_ptr(), ZID_MAX) };
    (1..=ZID_MAX).contains(&len).then(|| id[..len].to_vec())
}

/// Wait up to `budget_ms` for the board to have an IPv4 address, yielding to the
/// net stack between asks, and return it. `None` is a board that never got one
/// (no DHCP server answered, no link): the caller reports that, since a node
/// with no address has nothing to listen on and no locator to advertise.
pub fn await_board_ipv4(budget_ms: u32) -> Option<[u8; 4]> {
    let mut waited = 0;
    loop {
        if let Some(address) = board_ipv4() {
            return Some(address);
        }
        if waited >= budget_ms {
            return None;
        }
        // SAFETY: the board's `k_msleep` seam; blocks this thread for the poll.
        unsafe { wz_yield_ms(ADDRESS_POLL_MS as i32) };
        waited += ADDRESS_POLL_MS;
    }
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
    /// `getsockname` returned this when the port a bind on port 0 was given
    /// was read back.
    SockName(c_int),
    /// A bind on port 0 succeeded and the stack reported port 0 all the same,
    /// so there is no port for the link's locator to name.
    NoPortChosen,
    /// `sendto` took this many bytes (negative: refused) of a datagram.
    Send(isize),
    /// `poll` returned this.
    Poll(c_int),
    /// `recvfrom` returned this although `poll` reported the socket readable.
    Recv(isize),
}

/// One IPv4 UDP socket on Zephyr's net stack, bound to an explicit local
/// address — the address the link's locator names, as zenoh-pico listens on
/// `udp/<ip>:<port>`. A bind on port 0 lets the stack choose, and
/// [`ZephyrUdpSocket::local`] then names the port it chose, never the 0.
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
    /// Open a UDP socket and bind it to `addr:port`; port 0 has the stack
    /// choose one, as a dialling link needs.
    pub fn bind(addr: [u8; 4], port: u16) -> Result<Self, ZephyrNetError> {
        // SAFETY: plain FFI with value arguments.
        let fd = unsafe { socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) };
        if fd < 0 {
            return Err(ZephyrNetError::Socket(fd));
        }
        // Owned from here, so an early return closes it.
        let mut this = Self {
            fd,
            local: (addr, port),
        };
        let local = sockaddr(addr, port);
        // SAFETY: `local` is a live `sockaddr_in` of the length passed.
        let rc = unsafe { bind(fd, &local, size_of::<SockaddrIn>() as SockLen) };
        if rc != 0 {
            return Err(ZephyrNetError::Bind(rc));
        }
        if port == 0 {
            // The locators the link reports and the source every reply comes
            // from name this port; keeping the 0 that was asked for would
            // render `udp/<ip>:0` for a link that has a real one.
            this.local.1 = this.chosen_port()?;
        }
        Ok(this)
    }

    /// The port the stack bound this socket to.
    fn chosen_port(&self) -> Result<u16, ZephyrNetError> {
        let mut name = SockaddrIn::default();
        let mut len = size_of::<SockaddrIn>() as SockLen;
        // SAFETY: `name` and `len` are live and writable, `len` is `name`'s size.
        let rc = unsafe { getsockname(self.fd, &mut name, &mut len) };
        if rc != 0 {
            return Err(ZephyrNetError::SockName(rc));
        }
        match u16::from_be(name.sin_port) {
            0 => Err(ZephyrNetError::NoPortChosen),
            port => Ok(port),
        }
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
        Self::acceptor_with_capacity(socket, UDP_RX_CAPACITY)
    }

    /// An initiator's link: replies and first sends go to `peer`.
    pub fn initiator(socket: ZephyrUdpSocket, peer: ([u8; 4], u16)) -> Self {
        Self::initiator_with_capacity(socket, peer, UDP_RX_CAPACITY)
    }

    /// An acceptor's link whose receive buffer holds `rx_capacity` bytes: what a
    /// node that runs several links at once sizes to the batch it negotiates,
    /// rather than to the largest datagram UDP can carry ([`UDP_RX_CAPACITY`]).
    /// A datagram longer than that is truncated by the stack, which the session
    /// reads as a bad frame.
    pub fn acceptor_with_capacity(socket: ZephyrUdpSocket, rx_capacity: usize) -> Self {
        Self::with_peer(socket, None, rx_capacity)
    }

    /// [`ZephyrUdpDriver::initiator`] with a receive buffer of `rx_capacity` bytes.
    pub fn initiator_with_capacity(
        socket: ZephyrUdpSocket,
        peer: ([u8; 4], u16),
        rx_capacity: usize,
    ) -> Self {
        Self::with_peer(socket, Some(peer), rx_capacity)
    }

    fn with_peer(
        socket: ZephyrUdpSocket,
        peer: Option<([u8; 4], u16)>,
        rx_capacity: usize,
    ) -> Self {
        let driver = Self {
            socket,
            peer: Cell::new(None),
            endpoints: OnceCell::new(),
            rx_buf: RefCell::new(vec![0u8; rx_capacity]),
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

    // The datagram is lent out of the link's own receive buffer, which the
    // stack has just written: no heap copy of it. The buffer stays borrowed
    // while `f` runs; the session's sends go through the socket, not through
    // it, and a receive from inside `f` would be refused by the `RefCell`.
    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        let mut buf = self.rx_buf.borrow_mut();
        match self.socket.try_recv(&mut buf) {
            Ok(Some((len, addr, port))) => {
                self.set_peer((addr, port));
                f(&buf[..len]);
                true
            }
            Ok(None) => false,
            Err(e) => {
                self.rx_error.set(Some(e));
                false
            }
        }
    }
}
