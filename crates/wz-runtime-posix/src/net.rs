// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host profile's network seam: UDP over the kernel's own sockets.
//!
//! [`PosixUdpSocket`] is the socket `wz_runtime_coop::udp_link` is written against
//! ([`DatagramSocket`]); the session's link over it is that module's `UdpDriver`, and
//! `slot::PosixStack` opens it, beside the stream socket of `stream`, as the stack the slot
//! profile's session host is given. Nothing here allocates: the socket is a file descriptor and
//! four words.
//!
//! Where Zephyr's socket cannot read `errno` (the FFI has no portable reach for it), this one can,
//! so a non-blocking receive is one `recvfrom` with `MSG_DONTWAIT` and "nothing yet" is the
//! `EAGAIN` it answers, not a `poll` that came first. The blocking receive the loop makes is
//! bounded by `SO_RCVTIMEO` ([`SERVICE_WAIT_MS`]), so a datagram that arrives wakes the loop in
//! the same system call that waited for it.

use core::ffi::c_int;
use core::mem::size_of;

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use wz_runtime_coop::session_drive::LinkReadiness;
use wz_runtime_coop::udp_link::{DatagramSocket, Received, SERVICE_WAIT_MS};

/// Why a socket call failed: the call, and the `errno` it left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosixNetError {
    /// `socket(AF_INET, ...)` failed with this `errno`.
    Socket(c_int),
    /// `setsockopt(SO_RCVTIMEO)` failed with this `errno`.
    ReceiveTimeout(c_int),
    /// `bind` failed with this `errno`.
    Bind(c_int),
    /// `fcntl(F_SETFL, O_NONBLOCK)` on a listening socket failed with this `errno`.
    NonBlocking(c_int),
    /// `setsockopt(SO_REUSEADDR)` failed with this `errno`.
    ReuseAddr(c_int),
    /// `setsockopt(SO_REUSEPORT)` failed with this `errno`.
    ReusePort(c_int),
    /// `setsockopt(IP_ADD_MEMBERSHIP)` failed with this `errno`: the group could not be joined on
    /// the interface asked for.
    Membership(c_int),
    /// `setsockopt` of a multicast egress option (`IP_MULTICAST_IF`, `IP_MULTICAST_TTL`) failed
    /// with this `errno`.
    MulticastOption(c_int),
    /// `listen` failed with this `errno`.
    Listen(c_int),
    /// `getsockname` failed with this `errno` reading back the port a bind on port 0 was given.
    SockName(c_int),
    /// A bind on port 0 succeeded and the kernel reported port 0 all the same, so there is no
    /// port for the link's locator to name.
    NoPortChosen,
    /// `sendto` took this many bytes (negative: refused, with the `errno` in the second field) of
    /// a datagram.
    Send(isize, c_int),
    /// `poll` failed with this `errno`.
    Poll(c_int),
    /// `recvfrom` (or a stream's `recv`) failed with this `errno`.
    Recv(c_int),
    /// `connect` failed with this `errno`.
    Connect(c_int),
    /// `setsockopt(TCP_NODELAY)` failed with this `errno`.
    NoDelay(c_int),
    /// `getpeername` failed with this `errno`.
    PeerName(c_int),
    /// A stream's `sendmsg` failed with this `errno`.
    Write(c_int),
}

/// A wait on a socket that a thread other than its link's makes ([`LinkReadiness`]): `poll` on a
/// duplicate of the socket's descriptor, which this owns and closes. A duplicate and not the
/// number itself, so a wait that outlives the socket never reaches a descriptor number its close
/// has freed for another file.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub(crate) struct FdReadiness(c_int);

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl FdReadiness {
    /// A wait on `fd`, or `None` when the descriptor cannot be duplicated.
    pub(crate) fn of(fd: c_int) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
        // SAFETY: `fd` is the caller's live descriptor; `fcntl` duplicates it or fails.
        let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return None;
        }
        Some(alloc::boxed::Box::new(FdReadiness(dup)))
    }
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl LinkReadiness for FdReadiness {
    fn wait_readable(&self, timeout_ms: u32) {
        let mut pfd = libc::pollfd {
            fd: self.0,
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout = c_int::try_from(timeout_ms).unwrap_or(c_int::MAX);
        // SAFETY: one live `pollfd` over the descriptor this owns; the timeout bounds the wait. A
        // failed or interrupted wait is a quiet socket: the step that follows reports the error.
        unsafe { libc::poll(&mut pfd, 1, timeout) };
    }

    fn handle(&self) -> Option<usize> {
        usize::try_from(self.0).ok()
    }

    fn wait_readable_among(&self, others: &[alloc::sync::Arc<dyn LinkReadiness>], timeout_ms: u32) {
        let mut fds = alloc::vec![libc::pollfd {
            fd: self.0,
            events: libc::POLLIN,
            revents: 0,
        }];
        for other in others {
            match other
                .handle()
                .and_then(|handle| c_int::try_from(handle).ok())
            {
                Some(fd) => fds.push(libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                }),
                // A wait this cannot name to the kernel: the bounded look, so it is not starved
                // behind a wait on the others.
                None => return self.wait_readable(timeout_ms.min(1)),
            }
        }
        let timeout = c_int::try_from(timeout_ms).unwrap_or(c_int::MAX);
        // SAFETY: `fds` is live for the call and its length is the count passed; every descriptor
        // is a duplicate its owner holds open for as long as the wait is held, and the timeout
        // bounds the wait. A failed or interrupted wait is a quiet socket: the step that follows
        // reads and reports the error.
        unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
    }
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl Drop for FdReadiness {
    fn drop(&mut self) {
        // SAFETY: the duplicate is this value's own descriptor, closed exactly once.
        unsafe { libc::close(self.0) };
    }
}

/// The calling thread's `errno`.
#[cfg(target_os = "linux")]
pub(crate) fn errno() -> c_int {
    // SAFETY: `__errno_location` returns the address of the calling thread's `errno`, valid for
    // the thread's life.
    unsafe { *libc::__errno_location() }
}

/// The calling thread's `errno`: bionic's `__errno()`, the same address by another name.
#[cfg(target_os = "android")]
pub(crate) fn errno() -> c_int {
    // SAFETY: `__errno` returns the address of the calling thread's `errno`, valid for the
    // thread's life.
    unsafe { *libc::__errno() }
}

/// The calling thread's `errno`.
#[cfg(target_os = "nto")]
pub(crate) fn errno() -> c_int {
    // SAFETY: `__get_errno_ptr` is what Neutrino's `errno` macro reads: the address of the calling
    // thread's `errno`, valid for the thread's life.
    unsafe { *libc::__get_errno_ptr() }
}

/// Bound every blocking read of `fd` by `ms` milliseconds (`SO_RCVTIMEO`): the `errno` when the
/// kernel refuses.
fn set_receive_timeout_ms(fd: c_int, ms: c_int) -> Result<(), c_int> {
    let timeout = libc::timeval {
        tv_sec: (ms / 1000) as libc::time_t,
        tv_usec: ((ms % 1000) * 1000) as libc::suseconds_t,
    };
    // SAFETY: `timeout` is a live `timeval` and the length passed is its size.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

/// Set the socket option `name` of `level` on `fd` to `value`: the `errno` when the kernel refuses.
pub(crate) fn set_option<T>(fd: c_int, level: c_int, name: c_int, value: &T) -> Result<(), c_int> {
    // SAFETY: `value` is a live `T` and the length passed is its size.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (value as *const T).cast(),
            size_of::<T>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

/// Switch the boolean socket option `name` of `level` on for `fd`.
pub(crate) fn set_flag(fd: c_int, level: c_int, name: c_int) -> Result<(), c_int> {
    set_option(fd, level, name, &(1 as c_int))
}

/// Make `fd` non-blocking or blocking (`fcntl(F_SETFL, O_NONBLOCK)`): the `errno` when the kernel
/// refuses. A socket is made this way and not by a flag of `socket` or `accept4`, which Neutrino
/// does not have: the one call is the same on both kernels, and a connection a non-blocking
/// listener hands over is made blocking here whether the kernel's accept passed the flag on (the
/// BSD one does) or not (Linux's).
pub(crate) fn set_nonblocking(fd: c_int, on: bool) -> Result<(), c_int> {
    // SAFETY: plain system call with value arguments.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(errno());
    }
    let wanted = if on {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    // SAFETY: plain system call with value arguments.
    if wanted != flags && unsafe { libc::fcntl(fd, libc::F_SETFL, wanted) } < 0 {
        return Err(errno());
    }
    Ok(())
}

/// Close `fd` when the process starts another program (`FD_CLOEXEC`): the `errno` when the kernel
/// refuses.
pub(crate) fn set_close_on_exec(fd: c_int) -> Result<(), c_int> {
    // SAFETY: plain system call with value arguments.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(errno());
    }
    Ok(())
}

/// The IPv4 address of the first interface that is up, can multicast and is not a loopback, or
/// none: the interface to give a multicast join when routing has no answer for the group (a board
/// with one subnet route and no default route, where joining on "the interface routing picks"
/// fails with `ENODEV`). The C library's `getifaddrs` is what lists them, on every OS this crate is
/// built for; it takes a list from the C library's own heap and gives it back before returning,
/// and the program's own allocator, which it has none of, is not asked.
pub fn multicast_interface() -> Option<[u8; 4]> {
    let mut list: *mut libc::ifaddrs = core::ptr::null_mut();
    // SAFETY: `list` is a live pointer the call fills; it is freed below whenever the call succeeds.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return None;
    }
    let wanted = (libc::IFF_UP | libc::IFF_MULTICAST) as u32;
    let mut found = None;
    let mut at = list;
    while !at.is_null() {
        // SAFETY: `at` is an entry of the list `getifaddrs` returned, live until `freeifaddrs`.
        let entry = unsafe { &*at };
        let flags = entry.ifa_flags as u32;
        if flags & wanted == wanted
            && flags & (libc::IFF_LOOPBACK as u32) == 0
            && !entry.ifa_addr.is_null()
        {
            // SAFETY: a non-null `ifa_addr` points at a socket address whose family field is valid.
            let family = unsafe { (*entry.ifa_addr).sa_family } as c_int;
            if family == libc::AF_INET {
                // SAFETY: an `AF_INET` address is a `sockaddr_in`.
                let sin = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                let address = sin.sin_addr.s_addr.to_ne_bytes();
                if address != [0; 4] {
                    found = Some(address);
                    break;
                }
            }
        }
        at = entry.ifa_next;
    }
    // SAFETY: `list` is the list `getifaddrs` returned, freed once.
    unsafe { libc::freeifaddrs(list) };
    found
}

pub(crate) fn sockaddr(addr: [u8; 4], port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        // Neutrino's socket address, as the BSDs', carries its own length.
        #[cfg(target_os = "nto")]
        sin_len: size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr),
        },
        sin_zero: [0; 8],
    }
}

/// One IPv4 UDP socket on the host, bound to an explicit local address, with every blocking read
/// of it bounded by [`SERVICE_WAIT_MS`].
pub struct PosixUdpSocket {
    fd: c_int,
    local: ([u8; 4], u16),
}

impl PosixUdpSocket {
    /// A socket bound to `addr:port`; `shared` sets `SO_REUSEADDR` and `SO_REUSEPORT` first, which
    /// is what lets a group's receiver bind the port another member on this host already holds.
    fn open(addr: [u8; 4], port: u16, shared: bool) -> Result<Self, PosixNetError> {
        // SAFETY: plain system call with value arguments.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(PosixNetError::Socket(errno()));
        }
        // Owned from here, so an early return closes it.
        let mut this = Self {
            fd,
            local: (addr, port),
        };
        if let Err(e) = set_receive_timeout_ms(fd, SERVICE_WAIT_MS) {
            return Err(PosixNetError::ReceiveTimeout(e));
        }
        if shared {
            set_flag(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR).map_err(PosixNetError::ReuseAddr)?;
            set_flag(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT).map_err(PosixNetError::ReusePort)?;
        }
        let local = sockaddr(addr, port);
        // SAFETY: `local` is a live `sockaddr_in` of the length passed.
        let rc = unsafe {
            libc::bind(
                fd,
                (&local as *const libc::sockaddr_in).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(PosixNetError::Bind(errno()));
        }
        if port == 0 {
            // The locators the link reports and the source every reply comes from name this
            // port; keeping the 0 that was asked for would render `udp/<ip>:0` for a link that
            // has a real one.
            this.local.1 = this.chosen_port()?;
        }
        Ok(this)
    }

    /// The descriptor, for a test that reads an option back.
    #[cfg(test)]
    pub(crate) fn fd(&self) -> c_int {
        self.fd
    }

    /// A socket bound to `addr:port` that other sockets of this host may bind too, as every member
    /// of a multicast group does (zenoh-pico sets both options on its group listener
    /// unconditionally).
    pub fn bind_shared(addr: [u8; 4], port: u16) -> Result<Self, PosixNetError> {
        Self::open(addr, port, true)
    }

    /// Join `group` on the interface that holds `interface` (the unspecified address: the one the
    /// kernel's routing picks for the group).
    pub fn join_group(&self, group: [u8; 4], interface: [u8; 4]) -> Result<(), PosixNetError> {
        // `ip_mreq`, which every kernel here takes and Neutrino has no wider form of: the group and
        // the address of the interface (the kernel's choice when it is the unspecified one). Linux's
        // `ip_mreqn` is this plus an interface index this code never set.
        let request = libc::ip_mreq {
            imr_multiaddr: libc::in_addr {
                s_addr: u32::from_ne_bytes(group),
            },
            imr_interface: libc::in_addr {
                s_addr: u32::from_ne_bytes(interface),
            },
        };
        set_option(self.fd, libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, &request)
            .map_err(PosixNetError::Membership)
    }

    /// Send multicast datagrams out of the interface that holds `interface`.
    pub fn set_multicast_interface(&self, interface: [u8; 4]) -> Result<(), PosixNetError> {
        let address = libc::in_addr {
            s_addr: u32::from_ne_bytes(interface),
        };
        set_option(self.fd, libc::IPPROTO_IP, libc::IP_MULTICAST_IF, &address)
            .map_err(PosixNetError::MulticastOption)
    }

    /// The hop limit of the multicast datagrams this socket sends (the kernel's default is 1: one
    /// subnet).
    pub fn set_multicast_ttl(&self, ttl: u8) -> Result<(), PosixNetError> {
        set_option(
            self.fd,
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_TTL,
            &c_int::from(ttl),
        )
        .map_err(PosixNetError::MulticastOption)
    }

    /// The port the kernel bound this socket to.
    fn chosen_port(&self) -> Result<u16, PosixNetError> {
        let mut name: libc::sockaddr_in = sockaddr([0; 4], 0);
        let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        // SAFETY: `name` and `len` are live and writable, and `len` is `name`'s size.
        let rc = unsafe {
            libc::getsockname(
                self.fd,
                (&mut name as *mut libc::sockaddr_in).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(PosixNetError::SockName(errno()));
        }
        match u16::from_be(name.sin_port) {
            0 => Err(PosixNetError::NoPortChosen),
            port => Ok(port),
        }
    }

    /// One `recvfrom` with `flags`, into `buf`: the length and source, `Ok(None)` when the call
    /// answered "nothing yet" (`EAGAIN`, which is what a receive timeout and `MSG_DONTWAIT` both
    /// leave) or was interrupted by a signal, any other failure as an error.
    fn receive(&self, buf: &mut [u8], flags: c_int) -> Result<Option<Received>, PosixNetError> {
        let mut src: libc::sockaddr_in = sockaddr([0; 4], 0);
        let mut src_len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        // SAFETY: `buf` and `src` are live and writable for the lengths given.
        let got = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                flags,
                (&mut src as *mut libc::sockaddr_in).cast(),
                &mut src_len,
            )
        };
        if got < 0 {
            return match errno() {
                libc::EAGAIN | libc::EINTR => Ok(None),
                other => Err(PosixNetError::Recv(other)),
            };
        }
        Ok(Some((
            got as usize,
            src.sin_addr.s_addr.to_ne_bytes(),
            u16::from_be(src.sin_port),
        )))
    }
}

impl DatagramSocket for PosixUdpSocket {
    type Error = PosixNetError;

    fn bind(addr: [u8; 4], port: u16) -> Result<Self, PosixNetError> {
        Self::open(addr, port, false)
    }

    fn local(&self) -> ([u8; 4], u16) {
        self.local
    }

    fn send_to(&self, addr: [u8; 4], port: u16, bytes: &[u8]) -> Result<(), PosixNetError> {
        let dest = sockaddr(addr, port);
        // SAFETY: `bytes` and `dest` are live for the call, lengths match.
        let sent = unsafe {
            libc::sendto(
                self.fd,
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
                (&dest as *const libc::sockaddr_in).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if sent == bytes.len() as isize {
            Ok(())
        } else {
            Err(PosixNetError::Send(sent, errno()))
        }
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live `pollfd`; the timeout bounds the wait. A failed or interrupted wait is
        // a quiet socket here: the receive that follows reads and reports the error.
        unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    }

    fn times_out(&self) -> bool {
        // `bind` does not return a socket without its receive timeout.
        true
    }

    const CAN_SET_RECEIVE_TIMEOUT: bool = true;

    fn set_receive_timeout(&self, ms: c_int) -> bool {
        set_receive_timeout_ms(self.fd, ms).is_ok()
    }

    fn recv_waiting(&self, buf: &mut [u8]) -> Result<Option<Received>, PosixNetError> {
        self.receive(buf, 0)
    }

    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<Received>, PosixNetError> {
        self.receive(buf, libc::MSG_DONTWAIT)
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn readiness(&self) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
        FdReadiness::of(self.fd)
    }
}

impl Drop for PosixUdpSocket {
    fn drop(&mut self) {
        // SAFETY: `fd` is this socket's own descriptor, closed exactly once.
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

    fn pair() -> (PosixUdpSocket, PosixUdpSocket) {
        (
            PosixUdpSocket::bind(LOOPBACK, 0).expect("a first socket"),
            PosixUdpSocket::bind(LOOPBACK, 0).expect("a second socket"),
        )
    }

    #[test]
    fn a_descriptor_is_made_non_blocking_and_blocking_again_and_each_is_read_back() {
        let socket = PosixUdpSocket::bind(LOOPBACK, 0).expect("a socket");
        let flags = |fd| unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert_eq!(
            flags(socket.fd()) & libc::O_NONBLOCK,
            0,
            "a fresh socket blocks"
        );
        set_nonblocking(socket.fd(), true).expect("non-blocking");
        assert_ne!(flags(socket.fd()) & libc::O_NONBLOCK, 0);
        set_nonblocking(socket.fd(), true).expect("a second time is no change");
        set_nonblocking(socket.fd(), false).expect("blocking");
        assert_eq!(flags(socket.fd()) & libc::O_NONBLOCK, 0);
        assert_eq!(
            set_nonblocking(-1, true),
            Err(libc::EBADF),
            "a descriptor that is not one is the kernel's refusal, with its errno"
        );
    }

    #[test]
    fn the_interface_for_a_group_is_never_a_loopback_or_the_unspecified_address() {
        // A host in a sandbox may have none; a host that has one names a real, routable address.
        if let Some(address) = multicast_interface() {
            assert_ne!(address, [0; 4], "the unspecified address is no interface");
            assert_ne!(address[0], 127, "a loopback is not where a group is joined");
        }
    }

    #[test]
    fn a_descriptor_is_closed_on_exec_and_a_bad_one_is_refused() {
        let socket = PosixUdpSocket::bind(LOOPBACK, 0).expect("a socket");
        set_close_on_exec(socket.fd()).expect("close-on-exec");
        let flags = unsafe { libc::fcntl(socket.fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        assert_eq!(set_close_on_exec(-1), Err(libc::EBADF));
    }

    #[test]
    fn a_bind_on_port_zero_names_the_port_the_kernel_chose() {
        let socket = PosixUdpSocket::bind(LOOPBACK, 0).expect("a socket");
        let (addr, port) = socket.local();
        assert_eq!(addr, LOOPBACK);
        assert_ne!(port, 0, "the locator must name a real port");
    }

    #[test]
    fn a_datagram_sent_to_a_socket_is_taken_with_its_source() {
        let (a, b) = pair();
        let (b_addr, b_port) = b.local();
        a.send_to(b_addr, b_port, b"ping").expect("a send");
        let mut buf = [0u8; 16];
        let (len, src, src_port) = b
            .recv_waiting(&mut buf)
            .expect("no error")
            .expect("a datagram within the receive timeout");
        assert_eq!(&buf[..len], b"ping");
        assert_eq!(src, LOOPBACK);
        assert_eq!(src_port, a.local().1, "the source is the sender's port");
    }

    #[test]
    fn a_quiet_socket_answers_nothing_yet_both_ways_and_does_not_block() {
        let socket = PosixUdpSocket::bind(LOOPBACK, 0).expect("a socket");
        let mut buf = [0u8; 16];
        assert_eq!(socket.try_recv(&mut buf), Ok(None));
        let started = std::time::Instant::now();
        assert_eq!(socket.recv_waiting(&mut buf), Ok(None));
        let waited = started.elapsed();
        assert!(
            waited < std::time::Duration::from_millis(200),
            "a wait is bounded by the receive timeout, took {waited:?}"
        );
    }

    #[test]
    fn a_queued_datagram_is_taken_without_waiting() {
        let (a, b) = pair();
        let (b_addr, b_port) = b.local();
        a.send_to(b_addr, b_port, b"now").expect("a send");
        // Let the loopback deliver it, then ask without waiting.
        b.wait_readable(100);
        let mut buf = [0u8; 16];
        let (len, ..) = b
            .try_recv(&mut buf)
            .expect("no error")
            .expect("a queued datagram");
        assert_eq!(&buf[..len], b"now");
        assert_eq!(b.try_recv(&mut buf), Ok(None), "and then nothing");
    }

    #[test]
    fn a_longer_receive_timeout_is_taken_and_a_datagram_still_wakes_the_wait_at_once() {
        let (a, b) = pair();
        assert!(b.set_receive_timeout(2000), "the kernel takes two seconds");
        let (b_addr, b_port) = b.local();
        // A thread would make this test timing-dependent; send first, then ask: the wait returns
        // with the datagram without using its two seconds.
        a.send_to(b_addr, b_port, b"early").expect("a send");
        let started = std::time::Instant::now();
        let mut buf = [0u8; 16];
        let (len, ..) = b
            .recv_waiting(&mut buf)
            .expect("no error")
            .expect("the datagram");
        assert_eq!(&buf[..len], b"early");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "a queued datagram does not wait out the timeout"
        );

        // And a quiet socket now waits as long as it was told.
        assert!(b.set_receive_timeout(150));
        let started = std::time::Instant::now();
        assert_eq!(b.recv_waiting(&mut buf), Ok(None));
        let waited = started.elapsed();
        assert!(
            waited >= std::time::Duration::from_millis(120),
            "the wait is the armed 150 ms, took {waited:?}"
        );
    }

    #[test]
    fn a_datagram_longer_than_the_buffer_is_truncated_to_it() {
        let (a, b) = pair();
        let (b_addr, b_port) = b.local();
        a.send_to(b_addr, b_port, b"0123456789").expect("a send");
        let mut buf = [0u8; 4];
        let (len, ..) = b
            .recv_waiting(&mut buf)
            .expect("no error")
            .expect("a datagram");
        assert_eq!(
            len, 4,
            "the stack truncates, which the session reads as a bad frame"
        );
    }

    #[test]
    fn binding_a_port_that_is_taken_is_a_bind_error() {
        let first = PosixUdpSocket::bind(LOOPBACK, 0).expect("a socket");
        let taken = first.local().1;
        match PosixUdpSocket::bind(LOOPBACK, taken) {
            Err(PosixNetError::Bind(e)) => assert_eq!(e, libc::EADDRINUSE),
            Err(other) => panic!("a different error: {other:?}"),
            Ok(_) => panic!("a second bind on a taken port must fail"),
        }
    }
}
