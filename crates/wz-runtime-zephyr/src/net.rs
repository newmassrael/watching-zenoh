// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//! the CPU: [`SessionDatagramLink::service`] waits on the link's socket for up to
//! one millisecond (`poll` with a timeout), so the net threads get to run between
//! iterations and a datagram that arrives is taken the moment it is queued, not at
//! the end of a sleep.

#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::cell::{Cell, OnceCell, RefCell};
use core::ffi::{c_int, c_void};
use core::fmt::Write;
use core::mem::size_of;

use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use wz_runtime_coop::group_transport::GroupTransport;
use wz_runtime_coop::session_drive::SessionDatagramLink;
#[cfg(feature = "session-slot")]
use wz_runtime_coop::session_drive::{Bind, DriverPump, LinkOpenError, SlotStack, UdpPeer};
use wz_session_core::caps::MAX_LOCATOR_LEN;
#[cfg(feature = "alloc")]
use wz_session_core::link::RxFrame;
use wz_session_core::link::{BoxedLinkDriver, LinkDropCause, LinkEndpoints, LinkSendOutcome};
use wz_session_core::reliability::Reliability;
use zephyr_sys::socket::{
    bind, close, getsockname, poll, recvfrom, sendto, setsockopt, socket, IpMreqn, PollFd, SockLen,
    SockaddrIn, AF_INET, IPPROTO_IP, IPPROTO_UDP, IP_ADD_MEMBERSHIP, IP_DROP_MEMBERSHIP, POLLIN,
    SOCK_DGRAM,
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

    /// Bound every blocking read of the socket `fd` by `ms` milliseconds (`SO_RCVTIMEO`). 0 on
    /// success, -1 when the image has no receive timeout or the stack refuses one. A board
    /// serves it from C because the option's struct is the C library's.
    fn wz_net_set_rcvtimeo_ms(fd: c_int, ms: c_int) -> c_int;

    /// Whether the `recvfrom` that just returned -1 did so because its timeout ran out (a quiet
    /// link), not because it failed. `errno` is out of the FFI's reach.
    fn wz_net_recv_timed_out() -> c_int;
}

/// The longest zenoh id: 16 bytes.
pub const ZID_MAX: usize = 16;

/// How often [`await_board_ipv4`] asks the board again.
const ADDRESS_POLL_MS: u32 = 100;

/// How long one pass of the drive loop waits for its link's socket to have a datagram. It bounds
/// the loop's timers (the lease, the keep-alive, the retransmissions), which are looked at once
/// per pass, so it is as long as the loop has always slept between passes: a quiet link costs
/// the same, a datagram costs none of it.
const SERVICE_WAIT_MS: c_int = 1;

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
#[cfg(feature = "alloc")]
pub fn board_zid() -> Option<Vec<u8>> {
    board_zid_fixed().map(|(id, len)| id[..len].to_vec())
}

/// [`board_zid`] with no allocator: the id's bytes in an array of [`ZID_MAX`], and how many of
/// them are the id. The one place the hook is called.
pub fn board_zid_fixed() -> Option<([u8; ZID_MAX], usize)> {
    let mut id = [0u8; ZID_MAX];
    // SAFETY: the hook writes at most `ZID_MAX` bytes through a pointer to a
    // live local of that size, and returns how many.
    let len = unsafe { wzApplicationGetZid(id.as_mut_ptr(), ZID_MAX) };
    (1..=ZID_MAX).contains(&len).then_some((id, len))
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
    /// `setsockopt` returned this joining or leaving a multicast group. A stack
    /// built without IGMP refuses the join, and so does an interface address no
    /// interface holds.
    Membership(c_int),
}

/// One IPv4 UDP socket on Zephyr's net stack, bound to an explicit local
/// address — the address the link's locator names, as zenoh-pico listens on
/// `udp/<ip>:<port>`. A bind on port 0 lets the stack choose, and
/// [`ZephyrUdpSocket::local`] then names the port it chose, never the 0.
pub struct ZephyrUdpSocket {
    fd: c_int,
    local: ([u8; 4], u16),
    /// The last [`Self::wait_readable`] returned with a datagram queued, and no receive has taken
    /// it since: the next [`Self::try_recv`] reads it without asking `poll` again. Only the one
    /// thread that drives the link touches the socket, so nothing else takes the datagram
    /// between the wait and the read.
    readable: Cell<bool>,
    /// A blocking read of this socket gives up after [`SERVICE_WAIT_MS`] (`SO_RCVTIMEO` took), so
    /// [`Self::recv_waiting`] waits for a datagram and takes it in one call, as zenoh-pico's
    /// reads do. False on an image without the option: the wait is then `poll`'s.
    times_out: bool,
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
        // SAFETY: plain FFI with value arguments, on the descriptor just opened.
        let times_out = unsafe { wz_net_set_rcvtimeo_ms(fd, SERVICE_WAIT_MS) } == 0;
        let mut this = Self {
            fd,
            local: (addr, port),
            readable: Cell::new(false),
            times_out,
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

    /// Join the IPv4 multicast `group` on the interface that holds `interface`.
    ///
    /// The membership belongs to the INTERFACE, not to this socket: Zephyr's
    /// handler calls `net_ipv4_igmp_join` on the interface it resolves, so closing
    /// the socket does not leave the group (see [`Self::leave_group`], which
    /// [`ZephyrGroupTransport`] calls when it drops).
    pub fn join_group(&self, group: [u8; 4], interface: [u8; 4]) -> Result<(), ZephyrNetError> {
        self.membership(IP_ADD_MEMBERSHIP, group, interface)
    }

    /// Leave a group [`Self::join_group`] joined.
    pub fn leave_group(&self, group: [u8; 4], interface: [u8; 4]) -> Result<(), ZephyrNetError> {
        self.membership(IP_DROP_MEMBERSHIP, group, interface)
    }

    fn membership(
        &self,
        option: c_int,
        group: [u8; 4],
        interface: [u8; 4],
    ) -> Result<(), ZephyrNetError> {
        let mreqn = IpMreqn {
            imr_multiaddr: u32::from_ne_bytes(group),
            imr_address: u32::from_ne_bytes(interface),
            imr_ifindex: 0,
        };
        // SAFETY: `mreqn` is a live `net_ip_mreqn` and the length passed is its
        // size, the one length the stack accepts.
        let rc = unsafe {
            setsockopt(
                self.fd,
                IPPROTO_IP,
                option,
                &mreqn as *const IpMreqn as *const c_void,
                size_of::<IpMreqn>() as SockLen,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(ZephyrNetError::Membership(rc))
        }
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

    /// Block until a datagram is queued or `timeout_ms` has passed, and return at once when one
    /// already is. The wait the drive loop makes in place of a sleep: the net stack's own threads
    /// get the CPU while this one waits, as they do in a sleep, but a datagram that arrives wakes
    /// the loop where a sleep would have held it for the rest of the tick. A failed `poll` is
    /// the same as a quiet socket here: the receive that follows reads and reports the error.
    pub fn wait_readable(&self, timeout_ms: c_int) {
        let mut pfd = PollFd {
            fd: self.fd,
            events: POLLIN,
            revents: 0,
        };
        // SAFETY: one live `pollfd`; the timeout bounds the wait.
        let ready = unsafe { poll(&mut pfd, 1, timeout_ms) };
        self.readable.set(ready > 0 && pfd.revents & POLLIN != 0);
    }

    /// Whether [`Self::recv_waiting`] can wait: a blocking read of this socket gives up after
    /// [`SERVICE_WAIT_MS`].
    pub fn times_out(&self) -> bool {
        self.times_out
    }

    /// Wait up to the socket's receive timeout for a datagram and take it into `buf` in the same
    /// call: `Ok(None)` when the timeout ran out, else its length and source. One pass through the
    /// stack where [`Self::wait_readable`] and [`Self::try_recv`] make two, which is what
    /// zenoh-pico's read does. Only for a socket whose [`Self::times_out`] is true: without the
    /// timeout the read would block for ever.
    pub fn recv_waiting(
        &self,
        buf: &mut [u8],
    ) -> Result<Option<(usize, [u8; 4], u16)>, ZephyrNetError> {
        debug_assert!(
            self.times_out,
            "a read without a timeout would block for ever"
        );
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
            // SAFETY: reads the calling thread's `errno`, set by the `recvfrom` above.
            return if unsafe { wz_net_recv_timed_out() } != 0 {
                Ok(None)
            } else {
                Err(ZephyrNetError::Recv(got))
            };
        }
        Ok(Some((
            got as usize,
            src.sin_addr.to_ne_bytes(),
            u16::from_be(src.sin_port),
        )))
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
        // A wait that just reported a datagram has answered the question: the read below cannot
        // block, and asking `poll` again is a second pass through the stack for nothing. The
        // flag is spent by this read, so the next receive asks.
        if !self.readable.replace(false) {
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

/// `udp/a.b.c.d:port`, zenoh's rendering of a UDP locator, written into fixed text: the longest
/// one, `udp/255.255.255.255:65535`, is 25 bytes of the [`MAX_LOCATOR_LEN`] the text has.
fn udp_locator(addr: [u8; 4], port: u16) -> heapless::String<MAX_LOCATOR_LEN> {
    let [a, b, c, d] = addr;
    let mut text = heapless::String::new();
    // Cannot fail: the longest rendering is shorter than the text's capacity.
    let _ = write!(text, "udp/{a}.{b}.{c}.{d}:{port}");
    text
}

/// The session's link over one [`ZephyrUdpSocket`], with its receive buffer in `B`: a `Vec<u8>`
/// on the heap profile ([`ZephyrUdpDriver`]), an array of the batch size on the fixed one
/// ([`FixedUdpDriver`]), where the buffer is part of the driver and the driver is a value in the
/// session's slot, so a datagram costs no allocation.
///
/// Outbound sends target the peer captured from the most recent inbound
/// datagram: an acceptor is built with no peer and learns it from the
/// InitSyn, and [`SessionDatagramLink::try_recv`] retargets on every datagram
/// so replies go to whoever just spoke. UDP is connectionless, so
/// `open_blocking` / `close_blocking` are no-ops — the zenoh handshake and
/// Close frame are the session's open and close.
pub struct UdpDriver<B: AsMut<[u8]>> {
    socket: ZephyrUdpSocket,
    peer: Cell<Option<([u8; 4], u16)>>,
    /// The link's two ends, `udp/<ip>:<port>` each, written once — when the
    /// peer is first known.
    endpoints: OnceCell<LinkEndpoints>,
    rx_buf: RefCell<B>,
    /// A datagram [`SessionDatagramLink::service`] already read into `rx_buf` while it waited
    /// (length and source), for the next receive to hand out without another call into the stack.
    stash: Cell<Option<(usize, [u8; 4], u16)>>,
    /// The last receive failure, kept for the deploy to report: the loop's
    /// seam returns a frame or nothing, and a socket that fails must not
    /// read as a quiet one.
    rx_error: Cell<Option<ZephyrNetError>>,
}

/// The heap profile's driver: its receive buffer is a `Vec<u8>` of the capacity the link was
/// given.
#[cfg(feature = "alloc")]
pub type ZephyrUdpDriver = UdpDriver<Vec<u8>>;

/// The fixed-memory profile's driver: its receive buffer is an array of `RX` bytes inside the
/// value, sized to the batch the session advertises. A datagram longer than `RX` is truncated by
/// the stack, which the session reads as a bad frame.
pub type FixedUdpDriver<const RX: usize> = UdpDriver<[u8; RX]>;

#[cfg(feature = "alloc")]
impl UdpDriver<Vec<u8>> {
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
        Self::acceptor_in(socket, vec![0u8; rx_capacity])
    }

    /// [`ZephyrUdpDriver::initiator`] with a receive buffer of `rx_capacity` bytes.
    pub fn initiator_with_capacity(
        socket: ZephyrUdpSocket,
        peer: ([u8; 4], u16),
        rx_capacity: usize,
    ) -> Self {
        Self::initiator_in(socket, peer, vec![0u8; rx_capacity])
    }
}

impl<B: AsMut<[u8]>> UdpDriver<B> {
    /// An acceptor's link over the receive buffer `rx_buf`: no peer until the first datagram
    /// names one.
    pub fn acceptor_in(socket: ZephyrUdpSocket, rx_buf: B) -> Self {
        Self::with_peer(socket, None, rx_buf)
    }

    /// An initiator's link over the receive buffer `rx_buf`: replies and first sends go to
    /// `peer`.
    pub fn initiator_in(socket: ZephyrUdpSocket, peer: ([u8; 4], u16), rx_buf: B) -> Self {
        Self::with_peer(socket, Some(peer), rx_buf)
    }

    fn with_peer(socket: ZephyrUdpSocket, peer: Option<([u8; 4], u16)>, rx_buf: B) -> Self {
        let driver = Self {
            socket,
            peer: Cell::new(None),
            endpoints: OnceCell::new(),
            rx_buf: RefCell::new(rx_buf),
            stash: Cell::new(None),
            rx_error: Cell::new(None),
        };
        if let Some(peer) = peer {
            driver.set_peer(peer);
        }
        driver
    }

    /// The next datagram: the one `service` already read into `rx_buf`, if it did, else one the
    /// stack has queued. `Ok(None)` when there is none.
    fn next_datagram(
        &self,
        buf: &mut [u8],
    ) -> Result<Option<(usize, [u8; 4], u16)>, ZephyrNetError> {
        match self.stash.take() {
            Some(held) => Ok(Some(held)),
            None => self.socket.try_recv(buf),
        }
    }

    fn set_peer(&self, peer: ([u8; 4], u16)) {
        self.peer.set(Some(peer));
        if self.endpoints.get().is_none() {
            let (addr, port) = self.socket.local();
            let _ = self.endpoints.set(LinkEndpoints::new(
                udp_locator(addr, port).as_str(),
                udp_locator(peer.0, peer.1).as_str(),
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

impl<B: AsMut<[u8]> + 'static> BoxedLinkDriver for UdpDriver<B> {
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

impl<B: AsMut<[u8]> + 'static> SessionDatagramLink for UdpDriver<B> {
    fn service(&self) {
        // Zephyr's net stack runs its own threads: all this thread owes it is the CPU. It gives
        // it by waiting for the socket, so a datagram is taken the moment it is queued, and a
        // quiet socket costs one millisecond, which is what bounds the loop's timers.
        //
        // On a socket whose reads time out, the wait is the read: the datagram is taken into
        // `rx_buf` in the same call that waited for it and held for the receive that follows, so
        // a datagram crosses the stack once, as it does for zenoh-pico. Otherwise `poll` waits and
        // the receive reads.
        if !self.socket.times_out() {
            self.socket.wait_readable(SERVICE_WAIT_MS);
            return;
        }
        if self.stash.get().is_some() {
            return;
        }
        // The buffer is lent out while a receive callback runs; a wait asked for from inside one
        // (the loop does not) falls back to `poll`, which needs no buffer.
        let Ok(mut buf) = self.rx_buf.try_borrow_mut() else {
            self.socket.wait_readable(SERVICE_WAIT_MS);
            return;
        };
        match self.socket.recv_waiting(buf.as_mut()) {
            Ok(held) => self.stash.set(held),
            Err(e) => self.rx_error.set(Some(e)),
        }
    }

    #[cfg(feature = "alloc")]
    fn try_recv(&self) -> Option<RxFrame> {
        let mut buf = self.rx_buf.borrow_mut();
        let bytes: &mut [u8] = buf.as_mut();
        match self.next_datagram(bytes) {
            Ok(Some((len, addr, port))) => {
                self.set_peer((addr, port));
                Some(RxFrame::new(bytes[..len].to_vec()))
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
        let bytes: &mut [u8] = buf.as_mut();
        match self.next_datagram(bytes) {
            Ok(Some((len, addr, port))) => {
                self.set_peer((addr, port));
                f(&bytes[..len]);
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

/// Zephyr's sockets as a stack of the slot profile's session host: the driver in the session's
/// slot is a [`FixedUdpDriver`], and the drive loop pumps it through the driver itself
/// ([`DriverPump`]), because the kernel's threads run the net stack and there is no input path
/// of its own for the loop to advance. `RX` is the receive buffer of each session's driver, the
/// batch the session advertises.
///
/// Nothing is kept for a listener (`Lane` is `()`): the client node dials, and a node that
/// accepts on Zephyr's sockets would bring a lane of its own. The sockets are the kernel's file
/// descriptors, counted by `CONFIG_ZVFS_OPEN_MAX`, so no pool of them is declared here; a
/// descriptor the kernel cannot give is the dial's [`LinkOpenError::Exhausted`], and the
/// session host's tables bound how many are open at once.
#[cfg(feature = "session-slot")]
#[derive(Debug, Clone, Copy)]
pub struct ZephyrStack<const RX: usize> {
    local: [u8; 4],
}

#[cfg(feature = "session-slot")]
impl<const RX: usize> ZephyrStack<RX> {
    /// The stack of a node whose own address is `local`, as its interface holds it.
    pub const fn new(local: [u8; 4]) -> Self {
        Self { local }
    }

    /// The link of a dial to `peer`: a socket on a port the stack picks, with replies and first
    /// sends going to `peer`. What the session host's `dial` is given to open its socket.
    pub fn bind_initiator(&self, peer: UdpPeer) -> Result<FixedUdpDriver<RX>, LinkOpenError> {
        let socket = ZephyrUdpSocket::bind(self.local, 0).map_err(|_| LinkOpenError::Exhausted)?;
        Ok(UdpDriver::initiator_in(
            socket,
            (peer.addr, peer.port),
            [0u8; RX],
        ))
    }
}

#[cfg(feature = "session-slot")]
impl<const RX: usize> Bind<FixedUdpDriver<RX>> for ZephyrStack<RX> {
    fn bind(&mut self, peer: UdpPeer) -> Result<FixedUdpDriver<RX>, LinkOpenError> {
        self.bind_initiator(peer)
    }
}

#[cfg(feature = "session-slot")]
impl<const RX: usize> SlotStack for ZephyrStack<RX> {
    type Driver = FixedUdpDriver<RX>;
    type Pump = DriverPump<FixedUdpDriver<RX>>;
    type Lane = ();

    fn pump(
        &self,
        driver: wz_session_core::session_slot::SlotDriver<FixedUdpDriver<RX>>,
        _lane: Option<()>,
    ) -> Self::Pump {
        DriverPump(driver)
    }
}

/// A multicast group session's I/O over Zephyr's own sockets: the
/// [`GroupTransport`] the shared group drive loop (`wz-session-mcu`'s
/// `group_drive`) runs on, the Zephyr counterpart of lwIP's.
///
/// One UDP socket bound to the wildcard address on the group's port, joined to
/// the group on the interface that holds `interface`, sending to the same
/// `(group, port)`: the shape of the lwIP group socket, so a peer sees the same
/// source port from either. The receive buffer is an array of `RX` bytes inside
/// the value, so a datagram costs no heap; size it to the batch the group
/// advertises. A datagram longer than `RX` is truncated by the stack, which the
/// loop reads as a bad frame.
///
/// UNVERIFIED ON A BOARD. Written against the Zephyr tree's own definitions
/// (the option numbers, the 12-byte payload and the interface-owned membership
/// are read from `include/zephyr/net/socket.h`, `net_ip.h` and
/// `subsys/net/lib/sockets/sockets_inet.c`), and it compiles for the target; it
/// has not run against a real IGMP exchange, which needs a board and a switch
/// that forwards the group. The firmware turns on `CONFIG_NET_IPV4_IGMP`.
pub struct ZephyrGroupTransport<const RX: usize> {
    /// `None` once the session has released its link.
    socket: Option<ZephyrUdpSocket>,
    group: ([u8; 4], u16),
    interface: [u8; 4],
    rx: [u8; RX],
    rx_error: Option<ZephyrNetError>,
}

impl<const RX: usize> ZephyrGroupTransport<RX> {
    /// Bind the wildcard address on `port` and join `group` on the interface
    /// holding `interface` (the board's own address, see [`board_ipv4`]).
    pub fn join(group: [u8; 4], port: u16, interface: [u8; 4]) -> Result<Self, ZephyrNetError> {
        let socket = ZephyrUdpSocket::bind([0; 4], port)?;
        socket.join_group(group, interface)?;
        Ok(Self {
            socket: Some(socket),
            group: (group, port),
            interface,
            rx: [0; RX],
            rx_error: None,
        })
    }

    /// The most recent receive failure, if the socket has failed: the seam the
    /// loop reads returns a datagram or nothing, and a failed socket must not
    /// read as a quiet group.
    pub fn rx_error(&self) -> Option<ZephyrNetError> {
        self.rx_error
    }

    /// Leave the group and close the socket. The membership is the
    /// interface's, not the socket's: closing the socket alone would leave the
    /// interface in the group, and a re-join after a lost link would join a
    /// second time. Best-effort: a failed leave leaves nothing to do.
    fn leave(&mut self) {
        if let Some(socket) = self.socket.take() {
            let _ = socket.leave_group(self.group.0, self.interface);
        }
    }
}

impl<const RX: usize> GroupTransport for ZephyrGroupTransport<RX> {
    fn open(&mut self) -> bool {
        self.socket.is_some()
    }

    fn close(&mut self) {
        self.leave();
    }

    fn service(&self) {
        // Zephyr's net stack runs its own threads: all this thread owes it is
        // the CPU, as for the unicast link, and it gives it the same way. A transport that has
        // left its group holds no socket to wait on and yields one tick instead.
        match &self.socket {
            Some(socket) => socket.wait_readable(SERVICE_WAIT_MS),
            // SAFETY: the board's `k_msleep` seam; blocks this thread one tick.
            None => unsafe { wz_yield_ms(1) },
        }
    }

    /// The interface has a carrier while it holds an address: the board's
    /// answer is 0 for a link that is down or has no lease, which is the
    /// condition the loop must read as a lost link. Zephyr reports an interface
    /// going down through events this thread does not wait on, and the address
    /// hook is the one read the profile already has.
    fn carrier_up(&self) -> bool {
        board_ipv4().is_some()
    }

    fn send_to_group(&mut self, datagram: &[u8]) {
        // Best-effort, as the trait says: multicast UDP has no acknowledgement
        // and the next cadence retries.
        if let Some(socket) = &self.socket {
            let _ = socket.send_to(self.group.0, self.group.1, datagram);
        }
    }

    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        let Some(socket) = &self.socket else {
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

impl<const RX: usize> Drop for ZephyrGroupTransport<RX> {
    fn drop(&mut self) {
        // A transport dropped while its session still held it leaves too.
        self.leave();
    }
}
