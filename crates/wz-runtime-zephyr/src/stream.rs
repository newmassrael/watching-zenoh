// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Zephyr profile's stream seam: TCP over Zephyr's own BSD sockets, the twin of [`net`]'s
//! UDP socket.
//!
//! [`ZephyrTcpSocket`] is the socket `wz_runtime_coop::stream_link` is written against
//! ([`StreamSocket`]), and [`ZephyrTcpDial`] the dial a stack opens it with ([`StreamDial`]); the
//! session's link over it is that module's `StreamDriver`, and a secure channel over it is a
//! stream over this one (`wz-tls-mbedtls`'s `TlsDial<ZephyrTcpDial>`). Nothing here allocates:
//! the socket is a descriptor and its two ends. The image needs `CONFIG_NET_TCP`; without it a
//! connect fails and the dial is refused.
//!
//! A write blocks until the stack took every byte; a read never blocks, its readiness asked of
//! `poll` (with a zero timeout) rather than read off `recv`'s `EAGAIN`, because `errno` is out of
//! the FFI's reach, as [`net`] does for datagrams. `TCP_NODELAY` is set, as zenoh and zenoh-pico
//! set it on every TCP link.
//!
//! [`net`]: crate::net

use core::cell::Cell;
use core::ffi::{c_int, c_void};
use core::mem::size_of;

use wz_runtime_coop::session_drive::LinkOpenError;
use wz_runtime_coop::stream_link::{StreamDial, StreamSocket};
use zephyr_sys::socket::{
    close, connect, getpeername, getsockname, poll, recv, send, setsockopt, shutdown, socket,
    PollFd, SockLen, SockaddrIn, AF_INET, IPPROTO_TCP, POLLIN, SHUT_RDWR, SOCK_STREAM, TCP_NODELAY,
};

use crate::net::{sockaddr, ZephyrNetError};

/// One connected IPv4 TCP socket on Zephyr's net stack.
pub struct ZephyrTcpSocket {
    fd: c_int,
    local: ([u8; 4], u16),
    peer: ([u8; 4], u16),
    /// The last [`StreamSocket::wait_readable`] returned with bytes queued, and no read has taken
    /// them since: the next read needs no second `poll`. Only the one thread that drives the
    /// link touches the socket.
    readable: Cell<bool>,
}

/// The `(address, port)` a `getsockname` or `getpeername` of `fd` reports.
fn name_of(
    fd: c_int,
    call: unsafe extern "C" fn(c_int, *mut SockaddrIn, *mut SockLen) -> c_int,
) -> Result<([u8; 4], u16), c_int> {
    let mut name = SockaddrIn::default();
    let mut len = size_of::<SockaddrIn>() as SockLen;
    // SAFETY: `name` and `len` are live and writable, and `len` is `name`'s size.
    let rc = unsafe { call(fd, &mut name, &mut len) };
    if rc != 0 {
        return Err(rc);
    }
    Ok((name.sin_addr.to_ne_bytes(), u16::from_be(name.sin_port)))
}

impl ZephyrTcpSocket {
    /// Connect to `addr:port`, blocking until the connection is made or refused.
    pub fn connect(addr: [u8; 4], port: u16) -> Result<Self, ZephyrNetError> {
        // SAFETY: plain FFI with value arguments.
        let fd = unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) };
        if fd < 0 {
            return Err(ZephyrNetError::Socket(fd));
        }
        // Owned from here, so an early return closes it.
        let mut this = Self {
            fd,
            local: ([0; 4], 0),
            peer: (addr, port),
            readable: Cell::new(false),
        };
        let one: c_int = 1;
        // SAFETY: `one` is a live `c_int` and the length passed is its size.
        let rc = unsafe {
            setsockopt(
                fd,
                IPPROTO_TCP,
                TCP_NODELAY,
                &one as *const c_int as *const c_void,
                size_of::<c_int>() as SockLen,
            )
        };
        if rc != 0 {
            return Err(ZephyrNetError::NoDelay(rc));
        }
        let peer = sockaddr(addr, port);
        // SAFETY: `peer` is a live `sockaddr_in` of the length passed.
        let rc = unsafe { connect(fd, &peer, size_of::<SockaddrIn>() as SockLen) };
        if rc != 0 {
            return Err(ZephyrNetError::Connect(rc));
        }
        this.local = name_of(fd, getsockname).map_err(ZephyrNetError::SockName)?;
        this.peer = name_of(fd, getpeername).map_err(ZephyrNetError::PeerName)?;
        Ok(this)
    }

    /// Whether bytes are queued, or the stream has ended (a read then returns 0), within
    /// `timeout_ms`.
    fn poll_readable(&self, timeout_ms: c_int) -> Result<bool, ZephyrNetError> {
        let mut pfd = PollFd {
            fd: self.fd,
            events: POLLIN,
            revents: 0,
        };
        // SAFETY: one live `pollfd`; the timeout bounds the wait.
        let ready = unsafe { poll(&mut pfd, 1, timeout_ms) };
        if ready < 0 {
            return Err(ZephyrNetError::Poll(ready));
        }
        // Any event on the descriptor (data, the end, an error) is something the read reports.
        Ok(ready > 0 && pfd.revents != 0)
    }
}

impl StreamSocket for ZephyrTcpSocket {
    type Error = ZephyrNetError;

    fn local(&self) -> ([u8; 4], u16) {
        self.local
    }

    fn peer(&self) -> ([u8; 4], u16) {
        self.peer
    }

    fn send_parts(&self, parts: &[&[u8]]) -> Result<(), ZephyrNetError> {
        for part in parts {
            let mut rest = *part;
            while !rest.is_empty() {
                // SAFETY: `rest` is live and readable for its length.
                let sent = unsafe { send(self.fd, rest.as_ptr() as *const c_void, rest.len(), 0) };
                if sent <= 0 {
                    return Err(ZephyrNetError::Send(sent));
                }
                rest = &rest[sent as usize..];
            }
        }
        Ok(())
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        // A failed wait is a quiet socket here: the read that follows reports the error.
        self.readable
            .set(self.poll_readable(timeout_ms).unwrap_or(false));
    }

    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, ZephyrNetError> {
        if !self.readable.replace(false) && !self.poll_readable(0)? {
            return Ok(None);
        }
        // SAFETY: `buf` is live and writable for its length. `poll` said a read will not block.
        let got = unsafe { recv(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
        if got < 0 {
            return Err(ZephyrNetError::Recv(got));
        }
        // 0 is the end of the stream.
        Ok(Some(got as usize))
    }

    fn shutdown(&self) {
        // SAFETY: plain FFI on this socket's own descriptor. A stream already shut is not an
        // error worth reporting: the link is ending either way.
        unsafe { shutdown(self.fd, SHUT_RDWR) };
    }
}

impl Drop for ZephyrTcpSocket {
    fn drop(&mut self) {
        // SAFETY: `fd` is this socket's own descriptor, closed exactly once.
        unsafe { close(self.fd) };
    }
}

/// Zephyr's TCP connect as a stack's dial: the stream a `tcp/` link runs over is a plain
/// connection.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZephyrTcpDial;

impl StreamDial for ZephyrTcpDial {
    type Stream = ZephyrTcpSocket;

    fn dial(&self, addr: [u8; 4], port: u16) -> Result<ZephyrTcpSocket, LinkOpenError> {
        ZephyrTcpSocket::connect(addr, port).map_err(|e| match e {
            // The stack had no socket to give: worth a later try, as a full table is.
            ZephyrNetError::Socket(_) => LinkOpenError::Exhausted,
            _ => LinkOpenError::Refused,
        })
    }
}
