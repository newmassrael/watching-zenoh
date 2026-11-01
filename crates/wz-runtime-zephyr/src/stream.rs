// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Zephyr profile's stream seam: TCP over Zephyr's own BSD sockets, the twin of [`net`]'s
//! UDP socket.
//!
//! [`ZephyrTcpSocket`] is the socket `wz_runtime_coop::stream_link` is written against
//! ([`StreamSocket`]), and [`ZephyrTcpDial`] the dial a stack opens it with ([`StreamDial`]);
//! [`ZephyrTcpListener`] is the port a node accepts them on ([`StreamListen`]). The
//! session's link over it is that module's `StreamDriver`, and a secure channel over it is a
//! stream over this one (`wz-tls-mbedtls`'s `TlsDial<ZephyrTcpDial>`, and
//! `TlsListener<ZephyrTcpListener>` for the accepting end). Nothing here allocates:
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
use wz_runtime_coop::stream_link::{StreamDial, StreamListen, StreamSocket};
use zephyr_sys::socket::{
    accept, bind, close, connect, getpeername, getsockname, listen, poll, recv, send, setsockopt,
    shutdown, socket, PollFd, SockLen, SockaddrIn, AF_INET, IPPROTO_TCP, POLLIN, SHUT_RDWR,
    SOCK_STREAM, TCP_NODELAY,
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

/// `TCP_NODELAY` on `fd`, as zenoh and zenoh-pico set it on every TCP link.
fn set_nodelay(fd: c_int) -> Result<(), ZephyrNetError> {
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
    Ok(())
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
        set_nodelay(fd)?;
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

    /// The socket of a connection a listener took: `fd` is its own descriptor, which this owns
    /// from here (an early return closes it), and the peer is the one `accept` named. The same
    /// stream a connect gives, because a connection is the same thing from either end.
    fn accepted(fd: c_int, peer: ([u8; 4], u16)) -> Result<Self, ZephyrNetError> {
        let mut this = Self {
            fd,
            local: ([0; 4], 0),
            peer,
            readable: Cell::new(false),
        };
        set_nodelay(fd)?;
        this.local = name_of(fd, getsockname).map_err(ZephyrNetError::SockName)?;
        Ok(this)
    }

    /// Whether bytes are queued, or the stream has ended (a read then returns 0), within
    /// `timeout_ms`.
    fn poll_readable(&self, timeout_ms: c_int) -> Result<bool, ZephyrNetError> {
        poll_in(self.fd, timeout_ms)
    }
}

/// Whether `fd` has anything for a read or an accept to report within `timeout_ms`.
fn poll_in(fd: c_int, timeout_ms: c_int) -> Result<bool, ZephyrNetError> {
    let mut pfd = PollFd {
        fd,
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

/// The port a node accepts `tcp/` connections on, over Zephyr's own sockets: the listening half
/// of [`ZephyrTcpDial`], and for the same reason a value the stack holds. A secure channel's
/// listener is this one wrapped (`wz-tls-mbedtls`'s `TlsListener<ZephyrTcpListener>`), so the
/// handshake runs between the accept and the link, as it runs after a connect for a dial.
///
/// An accept never blocks: the listener is asked by `poll` (with a zero timeout) whether a
/// connection waits, as a read is, because `errno` is out of the FFI's reach and a would-block
/// cannot be told from a failure by the return value alone.
pub struct ZephyrTcpListener {
    fd: c_int,
    local: ([u8; 4], u16),
    /// The last `accept` that failed although `poll` reported a connection waiting, for the deploy
    /// to report (the way `StreamDriver::error` keeps a link's last failure). Only the one thread
    /// that drives the node touches the listener.
    failed: Cell<Option<ZephyrNetError>>,
}

impl ZephyrTcpListener {
    /// Listen on `addr:port` for connections, up to `backlog` of them queued before one is
    /// taken; port 0 has the stack choose one, which [`StreamListen::local`] then names.
    pub fn listen(addr: [u8; 4], port: u16, backlog: u8) -> Result<Self, ZephyrNetError> {
        // SAFETY: plain FFI with value arguments.
        let fd = unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) };
        if fd < 0 {
            return Err(ZephyrNetError::Socket(fd));
        }
        // Owned from here, so an early return closes it.
        let mut this = Self {
            fd,
            local: (addr, port),
            failed: Cell::new(None),
        };
        let local = sockaddr(addr, port);
        // SAFETY: `local` is a live `sockaddr_in` of the length passed.
        let rc = unsafe { bind(fd, &local, size_of::<SockaddrIn>() as SockLen) };
        if rc != 0 {
            return Err(ZephyrNetError::Bind(rc));
        }
        // SAFETY: plain FFI with value arguments, on a bound socket.
        let rc = unsafe { listen(fd, c_int::from(backlog)) };
        if rc != 0 {
            return Err(ZephyrNetError::Listen(rc));
        }
        this.local = name_of(fd, getsockname).map_err(ZephyrNetError::SockName)?;
        if this.local.1 == 0 {
            return Err(ZephyrNetError::NoPortChosen);
        }
        Ok(this)
    }

    /// The last `accept` that failed with a connection waiting, if one has.
    pub fn last_failure(&self) -> Option<ZephyrNetError> {
        self.failed.get()
    }
}

impl StreamListen for ZephyrTcpListener {
    type Stream = ZephyrTcpSocket;

    fn local(&self) -> ([u8; 4], u16) {
        self.local
    }

    /// The connection waiting, if one does. A connection the stack could not give a descriptor
    /// to, and one whose peer left before it was taken, fail the same way (`errno` is out of
    /// reach), and both are [`LinkOpenError::Exhausted`]: the first stays queued and the next
    /// call tries again, and the second is gone, so the next call finds the port quiet.
    fn accept(&self) -> Result<Option<ZephyrTcpSocket>, LinkOpenError> {
        match poll_in(self.fd, 0) {
            Ok(true) => {}
            Ok(false) => return Ok(None),
            // A listener `poll` cannot read is broken, and no later call mends it.
            Err(e) => {
                self.failed.set(Some(e));
                return Err(LinkOpenError::Unsupported);
            }
        }
        let mut name = SockaddrIn::default();
        let mut len = size_of::<SockaddrIn>() as SockLen;
        // SAFETY: `name` and `len` are live and writable, and `len` is `name`'s size. `poll` said a
        // connection waits, so the call does not block.
        let fd = unsafe { accept(self.fd, &mut name, &mut len) };
        if fd < 0 {
            self.failed.set(Some(ZephyrNetError::Accept(fd)));
            return Err(LinkOpenError::Exhausted);
        }
        let peer = (name.sin_addr.to_ne_bytes(), u16::from_be(name.sin_port));
        match ZephyrTcpSocket::accepted(fd, peer) {
            Ok(socket) => Ok(Some(socket)),
            // The socket owns the descriptor from `accepted`'s first line, so it is closed.
            Err(e) => {
                self.failed.set(Some(e));
                Err(LinkOpenError::Exhausted)
            }
        }
    }
}

impl Drop for ZephyrTcpListener {
    fn drop(&mut self) {
        // SAFETY: `fd` is this listener's own descriptor, closed exactly once.
        unsafe { close(self.fd) };
    }
}
