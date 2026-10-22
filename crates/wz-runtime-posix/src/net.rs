// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host profile's network seam: UDP over the kernel's own sockets.
//!
//! [`PosixUdpSocket`] is the socket `wz_runtime_coop::udp_link` is written against
//! ([`DatagramSocket`]); the session's link over it is that module's `UdpDriver`, and
//! `slot::PosixStack` is its `UdpStack` at this socket, the stack the slot profile's session host
//! is given. Nothing here allocates: the socket is a file descriptor and four words.
//!
//! Where Zephyr's socket cannot read `errno` (the FFI has no portable reach for it), this one can,
//! so a non-blocking receive is one `recvfrom` with `MSG_DONTWAIT` and "nothing yet" is the
//! `EAGAIN` it answers, not a `poll` that came first. The blocking receive the loop makes is
//! bounded by `SO_RCVTIMEO` ([`SERVICE_WAIT_MS`]), so a datagram that arrives wakes the loop in
//! the same system call that waited for it.

use core::ffi::c_int;
use core::mem::size_of;

use wz_runtime_coop::udp_link::{DatagramSocket, Received, SERVICE_WAIT_MS};

/// Why a socket call failed: the call, and the `errno` it left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosixNetError {
    /// `socket(AF_INET, SOCK_DGRAM)` failed with this `errno`.
    Socket(c_int),
    /// `setsockopt(SO_RCVTIMEO)` failed with this `errno`.
    ReceiveTimeout(c_int),
    /// `bind` failed with this `errno`.
    Bind(c_int),
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
    /// `recvfrom` failed with this `errno`.
    Recv(c_int),
}

/// The calling thread's `errno`.
fn errno() -> c_int {
    // SAFETY: `__errno_location` returns the address of the calling thread's `errno`, valid for
    // the thread's life.
    unsafe { *libc::__errno_location() }
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

fn sockaddr(addr: [u8; 4], port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
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
