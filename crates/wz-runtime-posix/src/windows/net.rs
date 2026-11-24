// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Windows host's datagram seam: UDP over Winsock, IPv4 and IPv6.
//!
//! [`WindowsUdpSocket`] is the socket `wz_runtime_coop::udp_link` is written against
//! ([`DatagramSocket`]), as the POSIX half's `PosixUdpSocket` is; the session's link over it is
//! that module's `UdpDriver`. Nothing here allocates: the socket is a handle, the address it is
//! bound to and the wait its blocking reads are bounded by.
//!
//! Winsock has no `MSG_DONTWAIT`, so a read that must not block asks `WSAPoll` first and reads
//! only what it reports, and the bounded read of the drive loop is the same poll with the wait
//! the link armed. Two answers of Winsock differ from a POSIX stack's and are made the same here:
//! a datagram longer than the buffer is the buffer's length and not an error, and the report of
//! an unreachable port a send brings back is turned off, where Windows would hand it to the next
//! receive as a reset connection and fail a read that has a datagram behind it.

use core::ffi::c_int;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::sync::atomic::{AtomicI32, Ordering};

use windows_sys::Win32::Networking::WinSock as ws;
use wz_runtime_coop::group_transport::GroupInterface;
use wz_runtime_coop::udp_link::{DatagramSocket, Received, SERVICE_WAIT_MS};

use super::{
    close, in6_addr, in_addr, last_error, name_of, open_socket, poll_readable, set_flag,
    set_option, RawAddr, WindowsNetError,
};

/// One UDP socket on the host, of the family of the address it is bound to, whose bounded read
/// waits as long as its link armed it to ([`SERVICE_WAIT_MS`] until it says otherwise).
pub struct WindowsUdpSocket {
    socket: ws::SOCKET,
    local: SocketAddr,
    wait_ms: AtomicI32,
}

/// Turn off the report of an unreachable port on a datagram socket (`SIO_UDP_CONNRESET`): the
/// code when the system refuses.
fn ignore_unreachable_reports(socket: ws::SOCKET) -> Result<(), i32> {
    let off: i32 = 0;
    let mut returned: u32 = 0;
    // SAFETY: the input is a live `BOOL` of the length passed; no output, no overlapped call.
    let rc = unsafe {
        ws::WSAIoctl(
            socket,
            ws::SIO_UDP_CONNRESET,
            (&off as *const i32).cast(),
            core::mem::size_of::<i32>() as u32,
            core::ptr::null_mut(),
            0,
            &mut returned,
            core::ptr::null_mut(),
            None,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(last_error())
    }
}

impl WindowsUdpSocket {
    /// A socket bound to `at`; `shared` sets `SO_REUSEADDR` first, which is what lets a group's
    /// receiver bind the port another member on this host already holds. Windows has no
    /// `SO_REUSEPORT`: its `SO_REUSEADDR` is both, as zenoh-pico's Windows group listener sets it
    /// alone (`vendor/zenoh-pico/src/link/transport/udp/udp_multicast_windows.c` @
    /// `SOL_SOCKET, SO_REUSEADDR`).
    fn open(at: SocketAddr, shared: bool) -> Result<Self, WindowsNetError> {
        let socket = open_socket(&at, ws::SOCK_DGRAM, ws::IPPROTO_UDP)?;
        // Owned from here, so an early return closes it.
        let mut this = Self {
            socket,
            local: at,
            wait_ms: AtomicI32::new(SERVICE_WAIT_MS),
        };
        ignore_unreachable_reports(socket).map_err(WindowsNetError::ResetReport)?;
        if shared {
            set_flag(socket, ws::SOL_SOCKET, ws::SO_REUSEADDR)
                .map_err(WindowsNetError::ReuseAddr)?;
        }
        let local = RawAddr::of(at);
        // SAFETY: `local` is a live socket address of the length passed.
        if unsafe { ws::bind(socket, local.as_ptr(), local.size()) } != 0 {
            return Err(WindowsNetError::Bind(last_error()));
        }
        if at.port() == 0 {
            // The locators the link reports and the source every reply comes from name this
            // port; keeping the 0 that was asked for would render `udp/<ip>:0` for a link that
            // has a real one.
            this.local.set_port(this.chosen_port()?);
        }
        Ok(this)
    }

    /// A socket bound to `at` that other sockets of this host may bind too, as every member of a
    /// multicast group does (zenoh-pico sets the option on its group listener unconditionally).
    pub fn bind_shared(at: SocketAddr) -> Result<Self, WindowsNetError> {
        Self::open(at, true)
    }

    /// Join `group` on `interface`: an IPv4 group through `IP_ADD_MEMBERSHIP` on the interface
    /// that holds an address, an IPv6 one through `IPV6_ADD_MEMBERSHIP` (MLD) on the interface of
    /// an index, either on the one the system's routing picks for [`GroupInterface::Routing`]. An
    /// interface named in the other family than the group's is
    /// [`WindowsNetError::InterfaceFamily`], before the system is asked.
    pub fn join_group(
        &self,
        group: IpAddr,
        interface: GroupInterface,
    ) -> Result<(), WindowsNetError> {
        match (group, interface) {
            (IpAddr::V4(group), GroupInterface::Routing | GroupInterface::V4(_)) => {
                let interface = match interface {
                    GroupInterface::V4(address) => address,
                    _ => Ipv4Addr::UNSPECIFIED,
                };
                let request = ws::IP_MREQ {
                    imr_multiaddr: in_addr(group),
                    imr_interface: in_addr(interface),
                };
                set_option(self.socket, ws::IPPROTO_IP, ws::IP_ADD_MEMBERSHIP, &request)
                    .map_err(WindowsNetError::Membership)
            }
            (IpAddr::V6(group), GroupInterface::Routing | GroupInterface::Index(_)) => {
                let index = match interface {
                    GroupInterface::Index(index) => index,
                    _ => 0,
                };
                let request = ws::IPV6_MREQ {
                    ipv6mr_multiaddr: in6_addr(group),
                    ipv6mr_interface: index,
                };
                set_option(
                    self.socket,
                    ws::IPPROTO_IPV6,
                    ws::IPV6_ADD_MEMBERSHIP,
                    &request,
                )
                .map_err(WindowsNetError::Membership)
            }
            _ => Err(WindowsNetError::InterfaceFamily),
        }
    }

    /// Send multicast datagrams out of `interface`: the interface that holds an IPv4 address
    /// (`IP_MULTICAST_IF`), the interface of an index (`IPV6_MULTICAST_IF`), or, for the routing's
    /// choice, the one the system picks, which needs no option.
    pub fn set_multicast_interface(
        &self,
        interface: GroupInterface,
    ) -> Result<(), WindowsNetError> {
        match (self.local, interface) {
            (_, GroupInterface::Routing) => Ok(()),
            (SocketAddr::V4(_), GroupInterface::V4(address)) => set_option(
                self.socket,
                ws::IPPROTO_IP,
                ws::IP_MULTICAST_IF,
                &in_addr(address),
            )
            .map_err(WindowsNetError::MulticastOption),
            (SocketAddr::V6(_), GroupInterface::Index(index)) => {
                set_option(self.socket, ws::IPPROTO_IPV6, ws::IPV6_MULTICAST_IF, &index)
                    .map_err(WindowsNetError::MulticastOption)
            }
            _ => Err(WindowsNetError::InterfaceFamily),
        }
    }

    /// The hop limit of the multicast datagrams this socket sends, in the option of its family:
    /// `IP_MULTICAST_TTL` or `IPV6_MULTICAST_HOPS`, each a `DWORD` on Windows (the system's
    /// default is 1: one subnet).
    pub fn set_multicast_hops(&self, hops: u8) -> Result<(), WindowsNetError> {
        let (level, name) = match self.local {
            SocketAddr::V4(_) => (ws::IPPROTO_IP, ws::IP_MULTICAST_TTL),
            SocketAddr::V6(_) => (ws::IPPROTO_IPV6, ws::IPV6_MULTICAST_HOPS),
        };
        set_option(self.socket, level, name, &u32::from(hops))
            .map_err(WindowsNetError::MulticastOption)
    }

    /// Make every call of this socket return at once (`ioctlsocket(FIONBIO)`): a send that finds
    /// no room fails with `WSAEWOULDBLOCK` rather than wait for it.
    #[cfg(feature = "host-multicast")]
    pub(crate) fn make_nonblocking(&self) -> Result<(), WindowsNetError> {
        super::set_nonblocking(self.socket, true).map_err(WindowsNetError::NonBlocking)
    }

    /// Whether this host's other members of a group observe what this socket sends:
    /// `IP_MULTICAST_LOOP` or `IPV6_MULTICAST_LOOP`, each a `DWORD` on Windows.
    #[cfg(feature = "host-multicast")]
    pub(crate) fn set_multicast_loopback(&self, on: bool) -> Result<(), WindowsNetError> {
        let (level, name) = match self.local {
            SocketAddr::V4(_) => (ws::IPPROTO_IP, ws::IP_MULTICAST_LOOP),
            SocketAddr::V6(_) => (ws::IPPROTO_IPV6, ws::IPV6_MULTICAST_LOOP),
        };
        set_option(self.socket, level, name, &u32::from(on))
            .map_err(WindowsNetError::MulticastOption)
    }

    /// Mark what this IPv4 socket sends with the traffic class `class`, as written (`IP_TOS`, a
    /// `DWORD`). An IPv6 socket is not marked here, as upstream leaves it unmarked on Windows:
    /// `Ok(false)`, and nothing is set.
    #[cfg(feature = "host-multicast")]
    pub(crate) fn set_traffic_class(&self, class: u32) -> Result<bool, WindowsNetError> {
        match self.local {
            SocketAddr::V4(_) => set_option(self.socket, ws::IPPROTO_IP, ws::IP_TOS, &class)
                .map(|()| true)
                .map_err(WindowsNetError::MulticastOption),
            SocketAddr::V6(_) => Ok(false),
        }
    }

    /// Wait up to `timeout_us` microseconds for this socket to take another datagram.
    #[cfg(feature = "host-multicast")]
    pub(crate) fn wait_writable(&self, timeout_us: u64) -> bool {
        super::poll_writable(
            self.socket,
            i32::try_from(timeout_us.div_ceil(1_000)).unwrap_or(i32::MAX),
        )
    }

    /// Wait up to `timeout_ms` milliseconds for any of `sockets` to have a datagram: one
    /// `WSAPoll` over them. `WSAPoll` refuses an empty set at once, so with none the thread sleeps
    /// the time instead, as a POSIX `poll` of no descriptor does.
    #[cfg(feature = "host-multicast")]
    pub(crate) fn wait_readable_any(sockets: &[&Self], timeout_ms: c_int) {
        if sockets.is_empty() {
            // SAFETY: a plain system call with a value argument.
            unsafe {
                windows_sys::Win32::System::Threading::Sleep(u32::try_from(timeout_ms).unwrap_or(0))
            };
            return;
        }
        let mut fds: alloc::vec::Vec<ws::WSAPOLLFD> = sockets
            .iter()
            .map(|socket| ws::WSAPOLLFD {
                fd: socket.socket,
                events: ws::POLLRDNORM,
                revents: 0,
            })
            .collect();
        // SAFETY: `fds` is live for the call and its length is the count passed; every socket is
        // one the caller holds open for the call, and the timeout bounds the wait. A failed wait
        // returns early, and the read that follows reports the error.
        unsafe { ws::WSAPoll(fds.as_mut_ptr(), fds.len() as u32, timeout_ms) };
    }

    /// The port the system bound this socket to.
    fn chosen_port(&self) -> Result<u16, WindowsNetError> {
        match name_of(self.socket, ws::getsockname)
            .map_err(WindowsNetError::SockName)?
            .port()
        {
            0 => Err(WindowsNetError::NoPortChosen),
            port => Ok(port),
        }
    }

    /// One `recvfrom` into `buf`, made only once the socket has reported input: the length and
    /// source, `Ok(None)` when the read answered "nothing yet", any other failure as an error. A
    /// datagram longer than `buf` is the buffer's length, as a POSIX stack truncates it (the
    /// session reads it as a bad frame); Winsock fills the buffer and says `WSAEMSGSIZE`. A
    /// datagram whose source is named in a family other than the two is an error: there is no
    /// end to judge it by.
    fn receive(&self, buf: &mut [u8]) -> Result<Option<Received>, WindowsNetError> {
        let mut src = RawAddr::empty();
        let room = i32::try_from(buf.len()).unwrap_or(i32::MAX);
        // SAFETY: `buf` and `src` are live and writable for the lengths given.
        let got = unsafe {
            ws::recvfrom(
                self.socket,
                buf.as_mut_ptr(),
                room,
                0,
                src.as_mut_ptr(),
                src.size_mut(),
            )
        };
        let got = if got == ws::SOCKET_ERROR {
            match last_error() {
                ws::WSAEWOULDBLOCK | ws::WSAEINTR | ws::WSAETIMEDOUT => return Ok(None),
                ws::WSAEMSGSIZE => room,
                other => return Err(WindowsNetError::Recv(other)),
            }
        } else {
            got
        };
        let from = src
            .to_socket_addr()
            .ok_or(WindowsNetError::Recv(ws::WSAEAFNOSUPPORT))?;
        Ok(Some((got as usize, from)))
    }
}

impl DatagramSocket for WindowsUdpSocket {
    type Error = WindowsNetError;

    fn bind(at: SocketAddr) -> Result<Self, WindowsNetError> {
        Self::open(at, false)
    }

    fn local(&self) -> SocketAddr {
        self.local
    }

    fn send_to(&self, to: SocketAddr, bytes: &[u8]) -> Result<(), WindowsNetError> {
        let Ok(len) = i32::try_from(bytes.len()) else {
            return Err(WindowsNetError::Send(ws::SOCKET_ERROR, ws::WSAEMSGSIZE));
        };
        let dest = RawAddr::of(to);
        // SAFETY: `bytes` and `dest` are live for the call, lengths match.
        let sent = unsafe {
            ws::sendto(
                self.socket,
                bytes.as_ptr(),
                len,
                0,
                dest.as_ptr(),
                dest.size(),
            )
        };
        if sent == len {
            Ok(())
        } else {
            Err(WindowsNetError::Send(sent, last_error()))
        }
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        poll_readable(self.socket, timeout_ms);
    }

    fn times_out(&self) -> bool {
        // The bounded read is a wait of the armed length and a read of what it reported.
        true
    }

    const CAN_SET_RECEIVE_TIMEOUT: bool = true;

    /// A wait of no length is refused, where a POSIX socket would read it as "for ever": the link
    /// then waits the tick, which is what it asked for at most.
    fn set_receive_timeout(&self, ms: c_int) -> bool {
        if ms <= 0 {
            return false;
        }
        self.wait_ms.store(ms, Ordering::Relaxed);
        true
    }

    fn recv_waiting(&self, buf: &mut [u8]) -> Result<Option<Received>, WindowsNetError> {
        if !poll_readable(self.socket, self.wait_ms.load(Ordering::Relaxed)) {
            return Ok(None);
        }
        self.receive(buf)
    }

    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<Received>, WindowsNetError> {
        if !poll_readable(self.socket, 0) {
            return Ok(None);
        }
        self.receive(buf)
    }

    fn refuses_address(error: &WindowsNetError) -> bool {
        *error == WindowsNetError::Socket(ws::WSAEAFNOSUPPORT)
    }

    fn address_in_use(error: &WindowsNetError) -> bool {
        *error == WindowsNetError::Bind(ws::WSAEADDRINUSE)
    }

    wz_runtime_coop::with_heap_link_seams! {
        type Waits = super::WindowsWaits;

        fn input_wait(&self) -> Option<wz_runtime_coop::session_drive::WaitOn> {
            Some(wz_runtime_coop::session_drive::WaitOn::Socket(self.socket))
        }

    }
}

wz_runtime_coop::with_heap_link_seams! {
    #[cfg(feature = "host-multicast")]
    impl WindowsUdpSocket {
        /// What a wait for room on this socket names it by.
        pub(crate) fn room_wait(&self) -> Option<wz_runtime_coop::session_drive::WaitOn> {
            Some(wz_runtime_coop::session_drive::WaitOn::Socket(self.socket))
        }
    }
}

wz_runtime_coop::with_heap_link_seams! {
    /// A wake of [`WindowsWaits`](super::WindowsWaits): a datagram socket on the loopback,
    /// non-blocking, ready once a waker sends it a byte.
    #[cfg(feature = "alloc")]
    struct SocketWake(WindowsUdpSocket);

    #[cfg(feature = "alloc")]
    impl alloc::task::Wake for SocketWake {
        fn wake(self: alloc::sync::Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &alloc::sync::Arc<Self>) {
            // A wake that finds the socket's buffer full is ready already.
            let _ = self.0.send_to(self.0.local, &[1]);
        }
    }

    /// The wake of a session over this platform's sockets: `None` when the loopback gives no
    /// socket.
    #[cfg(feature = "alloc")]
    pub(crate) fn self_wake() -> Option<wz_runtime_coop::session_drive::StackWake> {
        let socket =
            WindowsUdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).ok()?;
        super::set_nonblocking(socket.socket, true).ok()?;
        let on = wz_runtime_coop::session_drive::WaitOn::Wake(socket.socket);
        Some(wz_runtime_coop::session_drive::StackWake {
            on,
            waker: core::task::Waker::from(alloc::sync::Arc::new(SocketWake(socket))),
        })
    }

    /// Read what the wake `socket` holds until it holds nothing: the wake is quiet again.
    pub(crate) fn drain_wake(socket: ws::SOCKET) {
        let mut buf = [0u8; 64];
        let room = i32::try_from(buf.len()).unwrap_or(i32::MAX);
        loop {
            // SAFETY: a live buffer of the length passed, on a non-blocking socket of the caller's.
            let read = unsafe { ws::recv(socket, buf.as_mut_ptr(), room, 0) };
            if read <= 0 {
                return;
            }
        }
    }
}

impl Drop for WindowsUdpSocket {
    fn drop(&mut self) {
        close(self.socket);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv6Addr;

    /// The IPv4 loopback, on a port the system picks.
    const LOOPBACK: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

    /// The IPv6 loopback, on a port the system picks.
    const LOOPBACK_V6: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);

    fn pair() -> (WindowsUdpSocket, WindowsUdpSocket) {
        (
            WindowsUdpSocket::bind(LOOPBACK).expect("a first socket"),
            WindowsUdpSocket::bind(LOOPBACK).expect("a second socket"),
        )
    }

    /// A socket option of `socket` read back, as the `DWORD` Windows keeps it in.
    fn option(socket: &WindowsUdpSocket, level: i32, name: i32) -> u32 {
        let mut value: u32 = u32::MAX;
        let mut len = core::mem::size_of::<u32>() as i32;
        // SAFETY: `value` and `len` are live and writable, and `len` is `value`'s size.
        let rc = unsafe {
            ws::getsockopt(
                socket.socket,
                level,
                name,
                (&mut value as *mut u32).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt answered {}", last_error());
        value
    }

    #[test]
    fn a_bind_on_port_zero_names_the_port_the_system_chose() {
        let socket = WindowsUdpSocket::bind(LOOPBACK).expect("a socket");
        assert_eq!(socket.local().ip(), LOOPBACK.ip());
        assert_ne!(
            socket.local().port(),
            0,
            "the locator must name a real port"
        );
    }

    #[test]
    fn a_datagram_sent_to_a_socket_is_taken_with_its_source() {
        let (a, b) = pair();
        a.send_to(b.local(), b"ping").expect("a send");
        let mut buf = [0u8; 16];
        assert!(b.set_receive_timeout(500));
        let (len, src) = b
            .recv_waiting(&mut buf)
            .expect("no error")
            .expect("a datagram within the receive timeout");
        assert_eq!(&buf[..len], b"ping");
        assert_eq!(
            src,
            a.local(),
            "the source is the sender's address and port"
        );
    }

    /// Needs the host's IPv6 loopback.
    #[test]
    fn an_ipv6_datagram_is_taken_with_its_source() {
        let a = WindowsUdpSocket::bind(LOOPBACK_V6).expect("an IPv6 socket");
        let b = WindowsUdpSocket::bind(LOOPBACK_V6).expect("a second IPv6 socket");
        assert_ne!(b.local().port(), 0, "the locator must name a real port");
        a.send_to(b.local(), b"ping6").expect("a send");
        let mut buf = [0u8; 16];
        assert!(b.set_receive_timeout(500));
        let (len, src) = b
            .recv_waiting(&mut buf)
            .expect("no error")
            .expect("a datagram within the receive timeout");
        assert_eq!(&buf[..len], b"ping6");
        assert_eq!(src, a.local(), "the source is the sender's end");
    }

    #[test]
    fn a_quiet_socket_answers_nothing_yet_both_ways_and_does_not_block() {
        let socket = WindowsUdpSocket::bind(LOOPBACK).expect("a socket");
        let mut buf = [0u8; 16];
        assert_eq!(socket.try_recv(&mut buf), Ok(None));
        let started = std::time::Instant::now();
        assert_eq!(socket.recv_waiting(&mut buf), Ok(None));
        let waited = started.elapsed();
        assert!(
            waited < std::time::Duration::from_millis(200),
            "a wait is bounded by the armed wait, took {waited:?}"
        );
    }

    #[test]
    fn a_queued_datagram_is_taken_without_waiting_and_then_nothing() {
        let (a, b) = pair();
        a.send_to(b.local(), b"now").expect("a send");
        b.wait_readable(500);
        let mut buf = [0u8; 16];
        let (len, ..) = b
            .try_recv(&mut buf)
            .expect("no error")
            .expect("a queued datagram");
        assert_eq!(&buf[..len], b"now");
        assert_eq!(b.try_recv(&mut buf), Ok(None), "and then nothing");
    }

    #[test]
    fn a_longer_wait_is_taken_and_a_quiet_socket_waits_it_out() {
        let (_a, b) = pair();
        assert!(b.set_receive_timeout(150));
        let started = std::time::Instant::now();
        let mut buf = [0u8; 16];
        assert_eq!(b.recv_waiting(&mut buf), Ok(None));
        let waited = started.elapsed();
        assert!(
            waited >= std::time::Duration::from_millis(120),
            "the wait is the armed 150 ms, took {waited:?}"
        );
        assert!(!b.set_receive_timeout(0), "a wait of no length is refused");
    }

    #[test]
    fn a_datagram_longer_than_the_buffer_is_truncated_to_it() {
        let (a, b) = pair();
        a.send_to(b.local(), b"0123456789").expect("a send");
        let mut buf = [0u8; 4];
        assert!(b.set_receive_timeout(500));
        let (len, src) = b
            .recv_waiting(&mut buf)
            .expect("a long datagram is no error")
            .expect("a datagram");
        assert_eq!(len, 4, "the buffer's length, as a POSIX stack truncates");
        assert_eq!(&buf, b"0123");
        assert_eq!(src, a.local());
    }

    /// A send to a port nobody holds brings back an unreachable report; with the report turned
    /// off, the next receive of the sender takes the datagram queued behind it.
    #[test]
    fn an_unreachable_port_does_not_fail_the_senders_next_receive() {
        let (a, b) = pair();
        let gone = {
            let closed = WindowsUdpSocket::bind(LOOPBACK).expect("a socket to close");
            closed.local()
        };
        a.send_to(gone, b"to nobody")
            .expect("a send to a closed port");
        std::thread::sleep(std::time::Duration::from_millis(50));
        b.send_to(a.local(), b"after").expect("a send");
        let mut buf = [0u8; 16];
        assert!(a.set_receive_timeout(500));
        let (len, ..) = a
            .recv_waiting(&mut buf)
            .expect("the report of the closed port is not a failed read")
            .expect("the datagram behind it");
        assert_eq!(&buf[..len], b"after");
    }

    #[test]
    fn binding_a_port_that_is_taken_is_a_bind_error() {
        let first = WindowsUdpSocket::bind(LOOPBACK).expect("a socket");
        match WindowsUdpSocket::bind(first.local()) {
            Err(WindowsNetError::Bind(e)) => assert_eq!(e, ws::WSAEADDRINUSE),
            Err(other) => panic!("a different error: {other:?}"),
            Ok(_) => panic!("a second bind on a taken port must fail"),
        }
    }

    #[test]
    fn a_shared_port_is_bound_twice() {
        let first = WindowsUdpSocket::bind_shared(LOOPBACK).expect("a shared socket");
        let second = WindowsUdpSocket::bind_shared(first.local()).expect("the same port again");
        assert_eq!(second.local(), first.local());
    }

    /// Only a socket the system has no family for is the family's refusal: a dial that meets it
    /// is not retried, any other failure is.
    #[test]
    fn only_a_missing_family_is_refused_for_its_family() {
        assert!(WindowsUdpSocket::refuses_address(&WindowsNetError::Socket(
            ws::WSAEAFNOSUPPORT
        )));
        assert!(!WindowsUdpSocket::refuses_address(
            &WindowsNetError::Socket(ws::WSAEMFILE)
        ));
        assert!(!WindowsUdpSocket::refuses_address(&WindowsNetError::Bind(
            ws::WSAEAFNOSUPPORT
        )));
    }

    /// A bind of a port another socket holds is refused as that, kept apart from a system with no
    /// socket to give and from a family it lacks. CONTROL: no socket left is `Exhausted`. Turned
    /// red by a refusal that names every failed bind one way.
    #[test]
    fn a_port_another_socket_holds_is_refused_as_in_use() {
        use wz_runtime_coop::session_drive::LinkOpenError;
        use wz_runtime_coop::udp_link::bind_refused;

        let first = WindowsUdpSocket::bind(LOOPBACK).expect("a socket");
        let taken = WindowsUdpSocket::bind(first.local())
            .err()
            .expect("the port is held");
        assert_eq!(
            bind_refused::<WindowsUdpSocket>(taken),
            LinkOpenError::AddressInUse
        );
        assert_eq!(
            bind_refused::<WindowsUdpSocket>(WindowsNetError::Socket(ws::WSAEMFILE)),
            LinkOpenError::Exhausted,
            "CONTROL: no socket left"
        );
        assert_eq!(
            bind_refused::<WindowsUdpSocket>(WindowsNetError::Socket(ws::WSAEAFNOSUPPORT)),
            LinkOpenError::Unsupported
        );
    }

    #[test]
    fn an_interface_of_the_other_family_is_refused_before_the_system_is_asked() {
        let socket = WindowsUdpSocket::bind(LOOPBACK).expect("an IPv4 socket");
        let v6_group = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(
            socket.join_group(v6_group, GroupInterface::V4(Ipv4Addr::LOCALHOST)),
            Err(WindowsNetError::InterfaceFamily)
        );
        assert_eq!(
            socket.join_group(IpAddr::from([224, 0, 0, 224]), GroupInterface::Index(1)),
            Err(WindowsNetError::InterfaceFamily)
        );
        assert_eq!(
            socket.set_multicast_interface(GroupInterface::Index(1)),
            Err(WindowsNetError::InterfaceFamily)
        );
        assert_eq!(
            socket.set_multicast_interface(GroupInterface::Routing),
            Ok(())
        );
    }

    /// A member joins a group on the interface the routing picks and hears a datagram this host
    /// sends to the group, the multicast path a group transport runs over. Not the loopback: the
    /// Windows loopback adapter carries no group.
    #[test]
    fn a_member_joined_on_the_routings_interface_hears_the_group() {
        let group = Ipv4Addr::new(239, 255, 71, 23);
        let member = WindowsUdpSocket::bind_shared(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
            .expect("a member");
        member
            .join_group(IpAddr::V4(group), GroupInterface::Routing)
            .expect("the join on the routing's interface");
        let sender =
            WindowsUdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).expect("a sender");
        sender
            .set_multicast_interface(GroupInterface::Routing)
            .expect("the routing's egress asks nothing");
        sender
            .send_to(SocketAddr::from((group, member.local().port())), b"group")
            .expect("a send to the group");
        let mut buf = [0u8; 16];
        assert!(member.set_receive_timeout(1000));
        let (len, ..) = member
            .recv_waiting(&mut buf)
            .expect("no error")
            .expect("the group's datagram");
        assert_eq!(&buf[..len], b"group");
    }

    /// The hop limit is set in the option of the socket's family, and read back from it.
    #[test]
    fn the_hop_limit_is_the_option_of_the_sockets_family() {
        let v4 = WindowsUdpSocket::bind(LOOPBACK).expect("an IPv4 socket");
        v4.set_multicast_hops(4).expect("a hop limit");
        assert_eq!(option(&v4, ws::IPPROTO_IP, ws::IP_MULTICAST_TTL), 4);
        let v6 = WindowsUdpSocket::bind(LOOPBACK_V6).expect("an IPv6 socket");
        v6.set_multicast_hops(6).expect("a hop limit");
        assert_eq!(option(&v6, ws::IPPROTO_IPV6, ws::IPV6_MULTICAST_HOPS), 6);
    }

    wz_runtime_coop::with_heap_link_seams! {
        /// The stack's waits name each socket to the system, the set's last one too: a datagram
        /// queued there ends the wait at once. A wait over more sockets than the set holds, or one
        /// that names a handle of another stack's, is the bounded look. CONTROL: a wait over quiet
        /// sockets that fill the set sleeps its time. Turned red by a set that keeps only the first
        /// socket, or one that waits on part of a larger set for the whole time.
        #[test]
        fn the_stacks_waits_name_each_socket_and_look_at_what_they_cannot() {
            use std::time::{Duration, Instant};
            use std::vec::Vec;
            use wz_runtime_coop::session_drive::{LinkWait, LinkWaits, WaitOn};

            let waits = super::super::WindowsWaits;
            let (quiet, sender) = pair();
            let ready = WindowsUdpSocket::bind(LOOPBACK).expect("a socket");
            let on = |socket: &WindowsUdpSocket| {
                LinkWait::input(socket.input_wait().expect("a socket names its handle"))
            };
            let mut set: Vec<LinkWait> = (0..crate::WAIT_SET_SOCKETS).map(|_| on(&quiet)).collect();

            let started = Instant::now();
            waits.wait(&set, 100);
            assert!(
                started.elapsed() >= Duration::from_millis(80),
                "CONTROL: quiet sockets that fill the set sleep the wait's time"
            );

            let started = Instant::now();
            waits.wait(&[on(&quiet), LinkWait::input(WaitOn::AppLink(7))], 5_000);
            assert!(
                started.elapsed() < Duration::from_millis(1_000),
                "a handle of another stack's is the bounded look, took {:?}",
                started.elapsed()
            );

            set.push(on(&quiet));
            let started = Instant::now();
            waits.wait(&set, 5_000);
            assert!(
                started.elapsed() < Duration::from_millis(1_000),
                "a wait past the set is the bounded look, took {:?}",
                started.elapsed()
            );

            set.pop();
            set.pop();
            set.push(on(&ready));
            sender.send_to(ready.local(), b"wake").expect("a send");
            let started = Instant::now();
            waits.wait(&set, 5_000);
            assert!(
                started.elapsed() < Duration::from_millis(2_500),
                "the datagram on the set's last socket ended the wait, took {:?}",
                started.elapsed()
            );
        }

        /// A session's wake ends a wait over the sockets beside it once its waker is woken from
        /// another thread, and the wait that found it reads it quiet: the next wait sleeps its
        /// time. CONTROL: before the waker is woken the wait sleeps too. Turned red by a wake that
        /// is never named to `WSAPoll`, or one left ready after the wait that found it.
        #[cfg(feature = "alloc")]
        #[test]
        fn a_sessions_wake_ends_the_wait_beside_it_and_is_quiet_after() {
            use std::time::{Duration, Instant};
            use wz_runtime_coop::session_drive::{LinkWait, LinkWaits};

            let waits = super::super::WindowsWaits;
            let (quiet, _sender) = pair();
            let wake = waits.wake().expect("the loopback makes a wake");
            let set = [
                LinkWait::input(quiet.input_wait().expect("a socket names its handle")),
                LinkWait::input(wake.on),
            ];
            let started = Instant::now();
            waits.wait(&set, 50);
            assert!(
                started.elapsed() >= Duration::from_millis(40),
                "CONTROL: nothing woke it"
            );
            let waker = wake.waker.clone();
            let waking = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                waker.wake();
            });
            let started = Instant::now();
            waits.wait(&set, 10_000);
            let waited = started.elapsed();
            waking.join().expect("the waking thread");
            assert!(
                waited < Duration::from_secs(5),
                "the wake ended the wait: {waited:?}"
            );
            let started = Instant::now();
            waits.wait(&set, 50);
            assert!(
                started.elapsed() >= Duration::from_millis(40),
                "the wait that found the wake read it quiet"
            );
        }
    }
}
