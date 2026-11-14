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
use core::net::SocketAddr;

use wz_runtime_coop::session_drive::LinkOpenError;
use wz_runtime_coop::stream_link::{StreamDial, StreamListen, StreamSocket};
use zephyr_sys::socket::{
    accept, bind, connect, getpeername, getsockname, listen, poll, recv, send, setsockopt,
    shutdown, PollFd, SockLen, IPPROTO_TCP, POLLIN, SHUT_RDWR, SOCK_STREAM, SOL_SOCKET,
    SO_REUSEADDR, TCP_NODELAY,
};

use crate::net::{name_of, open_socket, RawAddr, ZephyrNetError};

/// One connected TCP socket on Zephyr's net stack, of the family of the address it connected to
/// (an IPv6 one on an image built with `CONFIG_NET_IPV6`).
pub struct ZephyrTcpSocket {
    fd: c_int,
    local: SocketAddr,
    peer: SocketAddr,
    /// The last [`StreamSocket::wait_readable`] returned with bytes queued, and no read has taken
    /// them since: the next read needs no second `poll`. Only the one thread that drives the
    /// link touches the socket.
    readable: Cell<bool>,
    /// The descriptor's close, shared with every wait made on it from another thread
    /// (`crate::fd`).
    _close: crate::fd::FdClose,
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

/// `SO_REUSEADDR` on the listening `fd`, as the POSIX listener sets it: a node restarted on its
/// port is not kept off it by the closed connections of the listener it replaces.
fn set_reuseaddr(fd: c_int) -> Result<(), ZephyrNetError> {
    let one: c_int = 1;
    // SAFETY: `one` is a live `c_int` and the length passed is its size.
    let rc = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &one as *const c_int as *const c_void,
            size_of::<c_int>() as SockLen,
        )
    };
    if rc != 0 {
        return Err(ZephyrNetError::ReuseAddr(rc));
    }
    Ok(())
}

/// A TCP socket of `at`'s family: the descriptor, or the stack's refusal.
fn stream_socket(at: &SocketAddr) -> Result<c_int, ZephyrNetError> {
    open_socket(at, SOCK_STREAM, IPPROTO_TCP)
}

impl ZephyrTcpSocket {
    /// Connect to `to`, blocking until the connection is made or refused.
    pub fn connect(to: SocketAddr) -> Result<Self, ZephyrNetError> {
        let peer = RawAddr::of(to)?;
        let fd = stream_socket(&to)?;
        // Owned from here, so an early return closes it.
        let mut this = Self {
            fd,
            local: to,
            peer: to,
            readable: Cell::new(false),
            _close: crate::fd::FdClose::new(fd),
        };
        set_nodelay(fd)?;
        // SAFETY: `peer` is a live socket address of the length passed.
        let rc = unsafe { connect(fd, peer.as_ptr(), peer.size()) };
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
    /// A peer `accept` wrote in a form this crate does not read is asked of `getpeername`.
    fn accepted(fd: c_int, peer: Option<SocketAddr>) -> Result<Self, ZephyrNetError> {
        const UNNAMED: SocketAddr = SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::UNSPECIFIED,
            0,
        ));
        let mut this = Self {
            fd,
            local: UNNAMED,
            peer: UNNAMED,
            readable: Cell::new(false),
            _close: crate::fd::FdClose::new(fd),
        };
        set_nodelay(fd)?;
        this.local = name_of(fd, getsockname).map_err(ZephyrNetError::SockName)?;
        this.peer = match peer {
            Some(peer) => peer,
            None => name_of(fd, getpeername).map_err(ZephyrNetError::PeerName)?,
        };
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

    fn local(&self) -> SocketAddr {
        self.local
    }

    fn peer(&self) -> SocketAddr {
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

    // Any thread may `poll` a descriptor, so the session's owner waits for this stream outside its
    // lock, as it waits for a datagram socket.
    wz_runtime_coop::with_heap_link_seams! {
        #[cfg(all(
            feature = "alloc",
            not(feature = "session-slot"),
            target_has_atomic = "ptr"
        ))]
        fn readiness(
            &self,
        ) -> Option<alloc::boxed::Box<dyn wz_runtime_coop::session_drive::LinkReadiness>> {
            Some(self._close.readiness())
        }
    }
}

/// Zephyr's TCP connect as a stack's dial: the stream a `tcp/` link runs over is a plain
/// connection.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZephyrTcpDial;

impl StreamDial for ZephyrTcpDial {
    type Stream = ZephyrTcpSocket;

    fn dial(&self, to: SocketAddr) -> Result<ZephyrTcpSocket, LinkOpenError> {
        ZephyrTcpSocket::connect(to).map_err(|e| match e {
            // The stack had no socket to give: worth a later try, as a full table is.
            ZephyrNetError::Socket(_) => LinkOpenError::Exhausted,
            // A family the image was built without, and an end the stack cannot name, stay so.
            ZephyrNetError::NoFamily | ZephyrNetError::ScopeTooWide(_) => {
                LinkOpenError::Unsupported
            }
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
    local: SocketAddr,
    /// The last `accept` that failed although `poll` reported a connection waiting, for the deploy
    /// to report (the way `StreamDriver::error` keeps a link's last failure). Only the one thread
    /// that drives the node touches the listener.
    failed: Cell<Option<ZephyrNetError>>,
    /// The descriptor's close, shared with every wait made on it from another thread
    /// (`crate::fd`).
    _close: crate::fd::FdClose,
}

impl ZephyrTcpListener {
    /// Listen on `at`, over a socket of its family, for connections, up to `backlog` of them
    /// queued before one is taken; port 0 has the stack choose one, which
    /// [`StreamListen::local`] then names.
    pub fn listen(at: SocketAddr, backlog: u8) -> Result<Self, ZephyrNetError> {
        let local = RawAddr::of(at)?;
        let fd = stream_socket(&at)?;
        // Owned from here, so an early return closes it.
        let mut this = Self {
            fd,
            local: at,
            failed: Cell::new(None),
            _close: crate::fd::FdClose::new(fd),
        };
        set_reuseaddr(fd)?;
        // SAFETY: `local` is a live socket address of the length passed.
        let rc = unsafe { bind(fd, local.as_ptr(), local.size()) };
        if rc != 0 {
            return Err(ZephyrNetError::Bind(rc));
        }
        // SAFETY: plain FFI with value arguments, on a bound socket.
        let rc = unsafe { listen(fd, c_int::from(backlog)) };
        if rc != 0 {
            return Err(ZephyrNetError::Listen(rc));
        }
        this.local = name_of(fd, getsockname).map_err(ZephyrNetError::SockName)?;
        if this.local.port() == 0 {
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

    fn local(&self) -> SocketAddr {
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
        let mut name = RawAddr::empty();
        // SAFETY: `name`'s storage and length are live and writable, and the length is its size.
        // `poll` said a connection waits, so the call does not block.
        let fd = unsafe { accept(self.fd, name.as_mut_ptr(), name.size_mut()) };
        if fd < 0 {
            self.failed.set(Some(ZephyrNetError::Accept(fd)));
            return Err(LinkOpenError::Exhausted);
        }
        match ZephyrTcpSocket::accepted(fd, name.to_socket_addr()) {
            Ok(socket) => Ok(Some(socket)),
            // The socket owns the descriptor from `accepted`'s first line, so it is closed.
            Err(e) => {
                self.failed.set(Some(e));
                Err(LinkOpenError::Exhausted)
            }
        }
    }

    // A listening descriptor polls readable while a connection is queued on it.
    wz_runtime_coop::with_heap_link_seams! {
        #[cfg(all(
            feature = "alloc",
            not(feature = "session-slot"),
            target_has_atomic = "ptr"
        ))]
        fn readiness(
            &self,
        ) -> Option<alloc::boxed::Box<dyn wz_runtime_coop::session_drive::LinkReadiness>> {
            Some(self._close.readiness())
        }
    }
}
