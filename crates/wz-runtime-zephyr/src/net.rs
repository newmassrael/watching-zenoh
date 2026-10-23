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
//! `ZephyrUdpDriver` is the session's link over it — its outbound half is
//! the session core's [`BoxedLinkDriver`](wz_session_core::link::BoxedLinkDriver), its inbound
//! half the cooperative drive loop's
//! [`SessionDatagramLink`](wz_runtime_coop::session_drive::SessionDatagramLink).
//!
//! The link itself is not written here. [`DatagramSocket`] is the seam a platform's socket
//! implements, and the driver, its outbound storage and the slot profile's stack over a socket
//! are `wz_runtime_coop::udp_link`, shared with every other stack that has BSD sockets under a
//! cooperative loop. The names this module has always had ([`UdpDriver`], `ZephyrUdpDriver`,
//! [`FixedUdpDriver`], `ZephyrStack`) are that code at this socket.
//!
//! Zephyr's net stack runs its RX path on its own threads, so there is no
//! input path for the drive loop to pump. What the loop's thread owes it is
//! the CPU: [`SessionDatagramLink::service`](wz_runtime_coop::session_drive::SessionDatagramLink::service)
//! waits on the link's socket for up to
//! one millisecond (`poll` with a timeout), so the net threads get to run between
//! iterations and a datagram that arrives is taken the moment it is queued, not at
//! the end of a sleep.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::cell::Cell;
use core::ffi::{c_int, c_void};
use core::mem::size_of;

use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use wz_runtime_coop::group_transport::GroupTransport;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub use wz_runtime_coop::link_storage::HeapTx;
pub use wz_runtime_coop::link_storage::TxStore;
pub use wz_runtime_coop::udp_link::{DatagramSocket, SERVICE_WAIT_MS, UDP_RX_CAPACITY};
use wz_session_core::byte_cells::ByteBuf;
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
    /// `SERVICE_WAIT_MS`.
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

/// The session's link driver reaches this socket through the shared seam. Each method is the
/// inherent one of the same name (an inherent method wins over a trait method of the same name,
/// so none of these calls itself).
impl DatagramSocket for ZephyrUdpSocket {
    type Error = ZephyrNetError;

    fn bind(addr: [u8; 4], port: u16) -> Result<Self, ZephyrNetError> {
        ZephyrUdpSocket::bind(addr, port)
    }

    fn local(&self) -> ([u8; 4], u16) {
        ZephyrUdpSocket::local(self)
    }

    fn send_to(&self, addr: [u8; 4], port: u16, bytes: &[u8]) -> Result<(), ZephyrNetError> {
        ZephyrUdpSocket::send_to(self, addr, port, bytes)
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        ZephyrUdpSocket::wait_readable(self, timeout_ms);
    }

    fn times_out(&self) -> bool {
        ZephyrUdpSocket::times_out(self)
    }

    const CAN_SET_RECEIVE_TIMEOUT: bool = true;

    /// Re-arm `SO_RCVTIMEO` through the board hook that armed it when the socket was opened. A
    /// socket whose first arming was refused takes none, because a read of it blocks for ever
    /// when the timeout is not there to end it.
    fn set_receive_timeout(&self, ms: c_int) -> bool {
        // SAFETY: plain FFI with value arguments, on the descriptor this socket owns.
        self.times_out && unsafe { wz_net_set_rcvtimeo_ms(self.fd, ms) } == 0
    }

    fn recv_waiting(
        &self,
        buf: &mut [u8],
    ) -> Result<Option<(usize, [u8; 4], u16)>, ZephyrNetError> {
        ZephyrUdpSocket::recv_waiting(self, buf)
    }

    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<(usize, [u8; 4], u16)>, ZephyrNetError> {
        ZephyrUdpSocket::try_recv(self, buf)
    }
}

/// The session's link over one [`ZephyrUdpSocket`], with its receive buffer in `B` and its outbound
/// frames built in `T`: a `Vec<u8>` and `HeapTx` on the heap profile (`ZephyrUdpDriver`),
/// claims on the image's byte tables on the fixed one ([`FixedUdpDriver`]). The driver is
/// `wz_runtime_coop::udp_link::UdpDriver`; its constructors and its behaviour are documented there.
pub type UdpDriver<B, T> = wz_runtime_coop::udp_link::UdpDriver<ZephyrUdpSocket, B, T>;

/// The heap profile's driver: its receive buffer is a `Vec<u8>` of the capacity the link was
/// given, and its frames are encoded into a [`HeapTx`] of the capacity it was given, if any.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub type ZephyrUdpDriver = UdpDriver<Vec<u8>, HeapTx>;

/// The fixed-memory profile's driver: its receive buffer and the buffer its frames are built in
/// are each lent by a table the image declares
/// ([`ByteCells`](wz_session_core::byte_cells::ByteCells)), the first as long as the batch the
/// session advertises and the second as long as the largest frame the link carries. A datagram
/// longer than the receive buffer is truncated by the stack, which the session reads as a bad
/// frame.
pub type FixedUdpDriver = UdpDriver<ByteBuf, ByteBuf>;

/// Zephyr's sockets as a stack of the slot profile's session host: the driver in the session's
/// slot is a [`FixedUdpDriver`], and the drive loop pumps it through the driver itself, because
/// the kernel's threads run the net stack and there is no input path of its own for the loop to
/// advance. The stack is `wz_runtime_coop::udp_link::UdpStack` at this socket: the sockets are the
/// kernel's file descriptors, counted by `CONFIG_ZVFS_OPEN_MAX`, so no pool of them is declared
/// here, and a node that accepts on Zephyr's sockets would bring a lane of its own.
#[cfg(feature = "session-slot")]
pub type ZephyrStack = wz_runtime_coop::udp_link::UdpStack<ZephyrUdpSocket>;

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
