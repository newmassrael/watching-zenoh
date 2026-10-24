// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host profile's stream seam: TCP over the kernel's own sockets.
//!
//! [`PosixTcpSocket`] is the socket `wz_runtime_coop::stream_link` is written against
//! ([`StreamSocket`]), and [`PosixTcpDial`] the dial a stack opens it with ([`StreamDial`]); the
//! session's link over it is that module's `StreamDriver`. Nothing here allocates: the socket is a
//! file descriptor and its two ends.
//!
//! The socket blocks on a write and never on a read: a write returns once the kernel has taken
//! every byte (a length and its batch go out in one `sendmsg`), and a read is `MSG_DONTWAIT`, the
//! loop's wait being the `poll` of [`StreamSocket::wait_readable`]. `TCP_NODELAY` is set, as
//! zenoh and zenoh-pico set it on every TCP link: a batch is written whole, and holding it back
//! for the next would only delay it.

use core::ffi::c_int;
use core::mem::size_of;

use wz_runtime_coop::session_drive::LinkOpenError;
use wz_runtime_coop::stream_link::{StreamDial, StreamSocket};

use crate::net::{errno, sockaddr, PosixNetError};

/// The most parts one write gathers: a length and its batch, with room to spare.
const MAX_PARTS: usize = 4;

/// One connected IPv4 TCP socket on the host.
pub struct PosixTcpSocket {
    fd: c_int,
    local: ([u8; 4], u16),
    peer: ([u8; 4], u16),
}

/// The `(address, port)` a `getsockname` or `getpeername` of `fd` reports.
fn name_of(
    fd: c_int,
    call: unsafe extern "C" fn(c_int, *mut libc::sockaddr, *mut libc::socklen_t) -> c_int,
) -> Result<([u8; 4], u16), c_int> {
    let mut name: libc::sockaddr_in = sockaddr([0; 4], 0);
    let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: `name` and `len` are live and writable, and `len` is `name`'s size.
    let rc = unsafe { call(fd, (&mut name as *mut libc::sockaddr_in).cast(), &mut len) };
    if rc != 0 {
        return Err(errno());
    }
    Ok((
        name.sin_addr.s_addr.to_ne_bytes(),
        u16::from_be(name.sin_port),
    ))
}

impl PosixTcpSocket {
    /// Connect to `addr:port`, blocking until the connection is made or refused.
    pub fn connect(addr: [u8; 4], port: u16) -> Result<Self, PosixNetError> {
        // SAFETY: plain system call with value arguments.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(PosixNetError::Socket(errno()));
        }
        // Owned from here, so an early return closes it.
        let mut this = Self {
            fd,
            local: ([0; 4], 0),
            peer: (addr, port),
        };
        let one: c_int = 1;
        // SAFETY: `one` is a live `c_int` and the length passed is its size.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                (&one as *const c_int).cast(),
                size_of::<c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(PosixNetError::NoDelay(errno()));
        }
        let peer = sockaddr(addr, port);
        // SAFETY: `peer` is a live `sockaddr_in` of the length passed.
        let rc = unsafe {
            libc::connect(
                fd,
                (&peer as *const libc::sockaddr_in).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(PosixNetError::Connect(errno()));
        }
        this.local = name_of(fd, libc::getsockname).map_err(PosixNetError::SockName)?;
        this.peer = name_of(fd, libc::getpeername).map_err(PosixNetError::PeerName)?;
        Ok(this)
    }
}

/// The host's TCP connect as a stack's dial: the stream a `tcp/` link runs over is a plain
/// connection.
#[derive(Debug, Clone, Copy, Default)]
pub struct PosixTcpDial;

impl StreamDial for PosixTcpDial {
    type Stream = PosixTcpSocket;

    fn dial(&self, addr: [u8; 4], port: u16) -> Result<PosixTcpSocket, LinkOpenError> {
        PosixTcpSocket::connect(addr, port).map_err(|e| match e {
            // The process has no descriptor left: worth a later try, as a full table is.
            PosixNetError::Socket(_) => LinkOpenError::Exhausted,
            _ => LinkOpenError::Refused,
        })
    }
}

impl StreamSocket for PosixTcpSocket {
    type Error = PosixNetError;

    fn local(&self) -> ([u8; 4], u16) {
        self.local
    }

    fn peer(&self) -> ([u8; 4], u16) {
        self.peer
    }

    fn send_parts(&self, parts: &[&[u8]]) -> Result<(), PosixNetError> {
        // The parts not yet written, as iovecs; a short write moves the front forward.
        let mut vecs = [libc::iovec {
            iov_base: core::ptr::null_mut(),
            iov_len: 0,
        }; MAX_PARTS];
        let mut count = 0;
        for part in parts.iter().filter(|part| !part.is_empty()) {
            if count == MAX_PARTS {
                return Err(PosixNetError::Write(libc::EMSGSIZE));
            }
            vecs[count] = libc::iovec {
                iov_base: part.as_ptr().cast_mut().cast(),
                iov_len: part.len(),
            };
            count += 1;
        }
        let mut first = 0;
        while first < count {
            // SAFETY: an all-zero `msghdr` is a valid one with no name and no control data.
            let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
            msg.msg_iov = vecs[first..count].as_mut_ptr();
            msg.msg_iovlen = count - first;
            // SAFETY: every iovec names a live slice of `parts` for its length. MSG_NOSIGNAL: a
            // peer that closed the stream is an error here, not a SIGPIPE.
            let sent = unsafe { libc::sendmsg(self.fd, &msg, libc::MSG_NOSIGNAL) };
            if sent < 0 {
                match errno() {
                    libc::EINTR => continue,
                    other => return Err(PosixNetError::Write(other)),
                }
            }
            let mut sent = sent as usize;
            while first < count && sent >= vecs[first].iov_len {
                sent -= vecs[first].iov_len;
                first += 1;
            }
            if first < count {
                // SAFETY: `sent` is less than this iovec's length, so the new base is inside it.
                vecs[first].iov_base =
                    unsafe { vecs[first].iov_base.cast::<u8>().add(sent) }.cast();
                vecs[first].iov_len -= sent;
            }
        }
        Ok(())
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live `pollfd`; the timeout bounds the wait. A failed or interrupted wait is
        // a quiet socket here: the read that follows reads and reports the error.
        unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    }

    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, PosixNetError> {
        // SAFETY: `buf` is live and writable for its length.
        let got = unsafe {
            libc::recv(
                self.fd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if got < 0 {
            return match errno() {
                libc::EAGAIN | libc::EINTR => Ok(None),
                other => Err(PosixNetError::Recv(other)),
            };
        }
        Ok(Some(got as usize))
    }

    fn shutdown(&self) {
        // SAFETY: plain system call on this socket's own descriptor. A stream already shut is
        // not an error worth reporting here: the link is ending either way.
        unsafe { libc::shutdown(self.fd, libc::SHUT_RDWR) };
    }
}

impl Drop for PosixTcpSocket {
    fn drop(&mut self) {
        // SAFETY: `fd` is this socket's own descriptor, closed exactly once.
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

    /// A connection: this crate's socket, and the far end as std accepted it.
    fn pair() -> (PosixTcpSocket, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let port = listener.local_addr().expect("its port").port();
        let near = PosixTcpSocket::connect(LOOPBACK, port).expect("a connection");
        let (far, _) = listener.accept().expect("the far end");
        (near, far)
    }

    /// Read until `want` bytes have come, waiting on the socket between reads.
    fn read_exactly(socket: &PosixTcpSocket, want: usize) -> std::vec::Vec<u8> {
        let mut out = std::vec::Vec::new();
        let mut buf = [0u8; 64];
        for _ in 0..200 {
            if out.len() >= want {
                break;
            }
            socket.wait_readable(10);
            if let Some(n) = socket.try_read(&mut buf).expect("no error") {
                assert_ne!(n, 0, "the stream ended early");
                out.extend_from_slice(&buf[..n]);
            }
        }
        out
    }

    #[test]
    fn a_connection_names_both_its_ends() {
        let (near, far) = pair();
        assert_eq!(near.peer(), (LOOPBACK, far.local_addr().unwrap().port()));
        assert_eq!(near.local(), (LOOPBACK, far.peer_addr().unwrap().port()));
        assert_ne!(near.local().1, 0);
    }

    /// A loopback port that refuses every connect for as long as the value lives: a TCP socket
    /// bound and never listening, which holds the number so no other `bind(:0)` is handed it.
    /// The guard `wz_runtime_tokio_test_support::refusing_port` is, over this crate's own libc:
    /// that crate pulls the tokio runtime, and with it `wz-session-core/alloc`, which feature
    /// unification would put into this crate's no-allocator test build.
    struct RefusingPort {
        fd: c_int,
        port: u16,
    }

    impl RefusingPort {
        fn hold() -> Self {
            // SAFETY: plain system call with value arguments.
            let fd =
                unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
            assert!(fd >= 0, "a TCP socket");
            let at = sockaddr(LOOPBACK, 0);
            // SAFETY: `at` is a live `sockaddr_in` of the length passed.
            let rc = unsafe {
                libc::bind(
                    fd,
                    (&at as *const libc::sockaddr_in).cast(),
                    size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            assert_eq!(rc, 0, "bind without listen");
            let (_, port) = name_of(fd, libc::getsockname).expect("the bound number");
            Self { fd, port }
        }
    }

    impl Drop for RefusingPort {
        fn drop(&mut self) {
            // SAFETY: `fd` is this guard's own descriptor, closed exactly once.
            unsafe { libc::close(self.fd) };
        }
    }

    #[test]
    fn a_connection_to_a_closed_port_is_refused() {
        let held = RefusingPort::hold();
        match PosixTcpSocket::connect(LOOPBACK, held.port) {
            Err(PosixNetError::Connect(e)) => assert_eq!(e, libc::ECONNREFUSED),
            Err(other) => panic!("a different error: {other:?}"),
            Ok(_) => panic!("nothing listens there"),
        }
    }

    #[test]
    fn the_parts_of_a_send_arrive_in_order_as_one_stream() {
        let (near, mut far) = pair();
        near.send_parts(&[b"\x03\x00", b"abc", b"", b"de"])
            .expect("a send");
        let mut got = [0u8; 7];
        far.read_exact(&mut got).expect("the bytes");
        assert_eq!(&got, b"\x03\x00abcde");
    }

    #[test]
    fn a_large_send_is_written_whole() {
        let (near, mut far) = pair();
        let big = std::vec![0x5au8; 4 << 20];
        let reader = std::thread::spawn(move || {
            let mut got = std::vec::Vec::new();
            far.read_to_end(&mut got).expect("the bytes");
            got.len()
        });
        near.send_parts(&[&big[..1], &big[1..]])
            .expect("a send of four MiB");
        near.shutdown();
        assert_eq!(reader.join().expect("the reader"), big.len());
    }

    #[test]
    fn a_read_takes_what_is_queued_and_says_nothing_yet_without_blocking() {
        let (near, mut far) = pair();
        let mut buf = [0u8; 16];
        assert_eq!(near.try_read(&mut buf), Ok(None));
        far.write_all(b"hello").expect("a write");
        assert_eq!(read_exactly(&near, 5), b"hello");
        assert_eq!(near.try_read(&mut buf), Ok(None), "and then nothing");
    }

    #[test]
    fn the_peer_closing_the_stream_is_a_read_of_nothing() {
        let (near, far) = pair();
        drop(far);
        near.wait_readable(1000);
        let mut buf = [0u8; 16];
        assert_eq!(near.try_read(&mut buf), Ok(Some(0)));
    }

    #[test]
    fn a_shutdown_is_the_end_of_the_stream_at_the_peer() {
        let (near, mut far) = pair();
        near.shutdown();
        let mut buf = [0u8; 16];
        assert_eq!(far.read(&mut buf).expect("a read"), 0);
    }

    #[test]
    fn nagle_is_off() {
        let (near, _far) = pair();
        let mut on: c_int = 0;
        let mut len = size_of::<c_int>() as libc::socklen_t;
        // SAFETY: `on` and `len` are live and writable, and `len` is `on`'s size.
        let rc = unsafe {
            libc::getsockopt(
                near.fd,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                (&mut on as *mut c_int).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(on, 1);
    }
}
