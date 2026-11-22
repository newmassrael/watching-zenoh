// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host profile's stream seam: TCP over the kernel's own sockets.
//!
//! [`PosixTcpSocket`] is the socket `wz_runtime_coop::stream_link` is written against
//! ([`StreamSocket`]), and [`PosixTcpDial`] the dial a stack opens it with ([`StreamDial`]); the
//! session's link over it is that module's `StreamDriver`. [`PosixTcpListener`] is the other
//! direction ([`StreamListen`]): the port a node accepts connections on, yielding the same
//! socket. Nothing here allocates: the socket is a file descriptor and its two ends.
//!
//! The socket blocks on a write and never on a read: a write returns once the kernel has taken
//! every byte (a length and its batch go out in one `sendmsg`), and a read is `MSG_DONTWAIT`, the
//! loop's wait being the `poll` of [`StreamSocket::wait_readable`]. `TCP_NODELAY` is set, as
//! zenoh and zenoh-pico set it on every TCP link: a batch is written whole, and holding it back
//! for the next would only delay it.

use core::ffi::c_int;
use core::net::SocketAddr;

use wz_runtime_coop::session_drive::LinkOpenError;
// Compiled where the runtime declares the heap profile's seams (`with_heap_link_seams!`), as every
// implementation of them below is.
wz_runtime_coop::with_heap_link_seams! {
    #[cfg(feature = "alloc")]
    use wz_runtime_coop::session_drive::{LinkReadiness, LinkWritability};
}
use wz_runtime_coop::stream_link::{StreamDial, StreamListen, StreamSocket};
use wz_runtime_coop::ClockSource;

use crate::net::{
    errno, family_of, name_of, poll_writable, set_close_on_exec, set_flag, set_nonblocking,
    PosixNetError, RawAddr,
};

/// The most parts one write gathers: a length and its batch, with room to spare.
const MAX_PARTS: usize = 4;

/// One connected TCP socket on the host, of the family of the address it connected to.
pub struct PosixTcpSocket {
    fd: c_int,
    local: SocketAddr,
    peer: SocketAddr,
}

/// A TCP socket of `at`'s family: the descriptor, or the `errno` of the refusal.
fn stream_socket(at: &SocketAddr) -> Result<c_int, PosixNetError> {
    // SAFETY: plain system call with value arguments.
    let fd = unsafe { libc::socket(family_of(at), libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(PosixNetError::Socket(errno()));
    }
    Ok(fd)
}

/// A failed open of a stream socket as the stack's refusal of the link: a family the kernel has
/// no socket of is permanent for the locator, no descriptor left is worth a later try, and
/// anything else is the other end's or the port's answer, as a retry would meet it.
fn open_refused(error: PosixNetError) -> LinkOpenError {
    match error {
        PosixNetError::Socket(libc::EAFNOSUPPORT) => LinkOpenError::Unsupported,
        PosixNetError::Socket(_) => LinkOpenError::Exhausted,
        _ => LinkOpenError::Refused,
    }
}

impl PosixTcpSocket {
    /// Connect to `to`, blocking until the connection is made or refused.
    pub fn connect(to: SocketAddr) -> Result<Self, PosixNetError> {
        let fd = stream_socket(&to)?;
        // Owned from here, so an early return closes it.
        let mut this = Self {
            fd,
            local: to,
            peer: to,
        };
        set_flag(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY).map_err(PosixNetError::NoDelay)?;
        let peer = RawAddr::of(to);
        // SAFETY: `peer` is a live socket address of the length passed.
        let rc = unsafe { libc::connect(fd, peer.as_ptr(), peer.size()) };
        if rc != 0 {
            return Err(PosixNetError::Connect(errno()));
        }
        this.local = name_of(fd, libc::getsockname).map_err(PosixNetError::SockName)?;
        this.peer = name_of(fd, libc::getpeername).map_err(PosixNetError::PeerName)?;
        Ok(this)
    }
}

impl PosixTcpSocket {
    /// Begin a connection to `to` and return without waiting for it: the socket is non-blocking
    /// until [`StreamSocket::connected`] finds the connection made, and blocking from then on, as
    /// a socket [`Self::connect`] made is. A refusal the kernel knows at once is the error here.
    pub fn connect_started(to: SocketAddr) -> Result<Self, PosixNetError> {
        let fd = stream_socket(&to)?;
        // Owned from here, so an early return closes it.
        let this = Self {
            fd,
            local: to,
            peer: to,
        };
        set_flag(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY).map_err(PosixNetError::NoDelay)?;
        set_nonblocking(fd, true).map_err(PosixNetError::NonBlocking)?;
        let peer = RawAddr::of(to);
        // SAFETY: `peer` is a live socket address of the length passed.
        if unsafe { libc::connect(fd, peer.as_ptr(), peer.size()) } != 0 {
            match errno() {
                // Under way, which `connected` reads; a signal does not stop it either.
                libc::EINPROGRESS | libc::EINTR => {}
                refused => return Err(PosixNetError::Connect(refused)),
            }
        }
        Ok(this)
    }

    /// The error a connection begun without waiting ended with (`SO_ERROR`), 0 when it was made.
    fn connect_error(&self) -> Result<c_int, PosixNetError> {
        let mut error: c_int = 0;
        let mut len = core::mem::size_of::<c_int>() as libc::socklen_t;
        // SAFETY: `error` and `len` are live and writable, and `len` is `error`'s size.
        let rc = unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut error as *mut c_int).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(PosixNetError::Connect(errno()));
        }
        Ok(error)
    }
}

/// The host's TCP connect as a stack's dial: the stream a `tcp/` link runs over is a plain
/// connection.
#[derive(Debug, Clone, Copy, Default)]
pub struct PosixTcpDial;

impl StreamDial for PosixTcpDial {
    type Stream = PosixTcpSocket;

    fn dial(&self, to: SocketAddr) -> Result<PosixTcpSocket, LinkOpenError> {
        PosixTcpSocket::connect(to).map_err(open_refused)
    }

    fn dial_started(&self, to: SocketAddr) -> Result<PosixTcpSocket, LinkOpenError> {
        PosixTcpSocket::connect_started(to).map_err(open_refused)
    }

    wz_runtime_coop::with_heap_link_seams! {
        #[cfg(feature = "alloc")]
        fn listen(
            &self,
            at: SocketAddr,
        ) -> Result<alloc::boxed::Box<dyn StreamListen<Stream = PosixTcpSocket>>, LinkOpenError>
        {
            PosixTcpListener::bind(at)
                .map(|listener| {
                    alloc::boxed::Box::new(listener)
                        as alloc::boxed::Box<dyn StreamListen<Stream = PosixTcpSocket>>
                })
                // The port taken or not the host's to bind is the same answer a retry meets.
                .map_err(open_refused)
        }
    }
}

/// A TCP port the host listens on: the half of the seam [`PosixTcpDial`] is not, handing the stack
/// the connections that arrive as the same [`PosixTcpSocket`] a dial yields.
///
/// The listening descriptor never blocks (`accept` answers at once, and the node's loop is what
/// waits), and `SO_REUSEADDR` is set so that a node restarted on its port is not kept off it by
/// the closed connections the kernel still holds.
pub struct PosixTcpListener {
    fd: c_int,
    local: SocketAddr,
}

impl PosixTcpListener {
    /// The connections that may queue on the port before the kernel refuses new ones: a node
    /// takes them off in its next loop pass, so a handful covers clients arriving together.
    const BACKLOG: c_int = 8;

    /// Listen on `at`, over a socket of its family (port 0: the kernel picks one, read back with
    /// [`StreamListen::local`]).
    pub fn bind(at: SocketAddr) -> Result<Self, PosixNetError> {
        let fd = stream_socket(&at)?;
        // Owned from here, so an early return closes it.
        let mut this = Self { fd, local: at };
        // The listener never waits: a pass of the node's loop asks, and nothing queued is an answer.
        set_nonblocking(fd, true).map_err(PosixNetError::NonBlocking)?;
        set_flag(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR).map_err(PosixNetError::ReuseAddr)?;
        let raw = RawAddr::of(at);
        // SAFETY: `raw` is a live socket address of the length passed.
        let rc = unsafe { libc::bind(fd, raw.as_ptr(), raw.size()) };
        if rc != 0 {
            return Err(PosixNetError::Bind(errno()));
        }
        // SAFETY: plain system call with value arguments.
        if unsafe { libc::listen(fd, Self::BACKLOG) } != 0 {
            return Err(PosixNetError::Listen(errno()));
        }
        this.local = name_of(fd, libc::getsockname).map_err(PosixNetError::SockName)?;
        Ok(this)
    }
}

impl StreamListen for PosixTcpListener {
    type Stream = PosixTcpSocket;

    fn local(&self) -> SocketAddr {
        self.local
    }

    wz_runtime_coop::with_heap_link_seams! {
        #[cfg(feature = "alloc")]
        fn readiness(&self) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
            // A listening descriptor polls readable while a connection is queued on it.
            crate::net::FdReadiness::of(self.fd)
        }
    }

    fn accept(&self) -> Result<Option<PosixTcpSocket>, LinkOpenError> {
        // SAFETY: a null address and length ask for no peer name; the descriptor is this
        // listener's own.
        let fd = unsafe { libc::accept(self.fd, core::ptr::null_mut(), core::ptr::null_mut()) };
        if fd < 0 {
            return match errno() {
                // Nothing waits, or the connection gave up before it was taken; the accept(2)
                // errors it lists for retrying "as for EAGAIN" are connections the network
                // dropped on the way, which leave nothing to take either.
                libc::EAGAIN
                | libc::EINTR
                | libc::ECONNABORTED
                | libc::EPROTO
                | libc::ENETDOWN
                | libc::ENOPROTOOPT
                | libc::EHOSTDOWN
                | libc::ENONET
                | libc::EHOSTUNREACH
                | libc::EOPNOTSUPP
                | libc::ENETUNREACH => Ok(None),
                // No descriptor or memory to give it: the connection stays queued and a later
                // call tries again, as a full table is retried.
                libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM => {
                    Err(LinkOpenError::Exhausted)
                }
                // The descriptor itself is bad: no later call mends it.
                _ => Err(LinkOpenError::Unsupported),
            };
        }
        // Owned from here, so an early return closes it.
        let mut socket = PosixTcpSocket {
            fd,
            local: self.local,
            peer: self.local,
        };
        // A connection reset between the accept and these calls is one that gave up: nothing to
        // take, and the close above is the answer its peer already has. The accepted socket is
        // close-on-exec and blocking, as a dialled one is: its reads are `MSG_DONTWAIT` and its
        // writes wait for the kernel.
        if set_close_on_exec(fd).is_err()
            || set_nonblocking(fd, false).is_err()
            || set_flag(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY).is_err()
        {
            return Ok(None);
        }
        let (Ok(local), Ok(peer)) = (
            name_of(fd, libc::getsockname),
            name_of(fd, libc::getpeername),
        ) else {
            return Ok(None);
        };
        socket.local = local;
        socket.peer = peer;
        Ok(Some(socket))
    }
}

impl Drop for PosixTcpListener {
    fn drop(&mut self) {
        // SAFETY: `fd` is this listener's own descriptor, closed exactly once.
        unsafe { libc::close(self.fd) };
    }
}

/// The iovecs of `parts`, empty ones left out, and how many there are; more than `MAX_PARTS` is
/// refused as `EMSGSIZE`.
fn iovecs(parts: &[&[u8]]) -> Result<([libc::iovec; MAX_PARTS], usize), PosixNetError> {
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
    Ok((vecs, count))
}

impl StreamSocket for PosixTcpSocket {
    type Error = PosixNetError;

    fn local(&self) -> SocketAddr {
        self.local
    }

    fn peer(&self) -> SocketAddr {
        self.peer
    }

    fn send_parts(&self, parts: &[&[u8]]) -> Result<(), PosixNetError> {
        // The parts not yet written, as iovecs; a short write moves the front forward.
        let (mut vecs, count) = iovecs(parts)?;
        let mut first = 0;
        while first < count {
            // SAFETY: an all-zero `msghdr` is a valid one with no name and no control data.
            let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
            msg.msg_iov = vecs[first..count].as_mut_ptr();
            // `usize` on Linux, `i32` on Neutrino: at most the few parts of one frame.
            msg.msg_iovlen = (count - first) as _;
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

    // One `sendmsg` that does not wait (`MSG_DONTWAIT`): the stack takes what its buffer has room
    // for now, and a buffer with none is `EAGAIN`, read as nothing taken. The socket itself stays
    // blocking, so `send_parts` waits for what this leaves, as it waits for any write.
    fn send_parts_now(&self, parts: &[&[u8]]) -> Option<Result<usize, PosixNetError>> {
        let (mut vecs, count) = match iovecs(parts) {
            Ok(built) => built,
            Err(refused) => return Some(Err(refused)),
        };
        loop {
            // SAFETY: an all-zero `msghdr` is a valid one with no name and no control data.
            let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
            msg.msg_iov = vecs[..count].as_mut_ptr();
            // `usize` on Linux, `i32` on Neutrino: at most the few parts of one frame.
            msg.msg_iovlen = count as _;
            // SAFETY: every iovec names a live slice of `parts` for its length. MSG_NOSIGNAL as
            // in `send_parts`.
            let sent =
                unsafe { libc::sendmsg(self.fd, &msg, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
            if sent >= 0 {
                return Some(Ok(sent as usize));
            }
            match errno() {
                libc::EINTR => continue,
                libc::EAGAIN => return Some(Ok(0)),
                other => return Some(Err(PosixNetError::Write(other))),
            }
        }
    }

    // A connect under way reports room once it ends, made or refused, and `SO_ERROR` says which.
    fn connected(&mut self) -> Result<bool, PosixNetError> {
        if !poll_writable(self.fd, 0) {
            return Ok(false);
        }
        match self.connect_error()? {
            0 => {}
            refused => return Err(PosixNetError::Connect(refused)),
        }
        set_nonblocking(self.fd, false).map_err(PosixNetError::NonBlocking)?;
        self.local = name_of(self.fd, libc::getsockname).map_err(PosixNetError::SockName)?;
        self.peer = name_of(self.fd, libc::getpeername).map_err(PosixNetError::PeerName)?;
        Ok(true)
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

    fn wait_writable(&self, timeout_us: u64) -> bool {
        poll_writable(self.fd, timeout_us)
    }

    // Timed on the host's monotonic clock, as the session's timers are.
    fn wait_writable_timed(&self, timeout_us: u64) -> (bool, u64) {
        let started = crate::PosixClock.now_us();
        let room = poll_writable(self.fd, timeout_us);
        (room, crate::PosixClock.now_us().saturating_sub(started))
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

    wz_runtime_coop::with_heap_link_seams! {
        #[cfg(feature = "alloc")]
        fn readiness(&self) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
            crate::net::FdReadiness::of(self.fd)
        }

        #[cfg(feature = "alloc")]
        fn writability(&self) -> Option<alloc::boxed::Box<dyn LinkWritability>> {
            crate::net::FdReadiness::writable_of(self.fd)
        }
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
    use core::mem::size_of;
    use core::net::{Ipv4Addr, Ipv6Addr};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;

    /// `port` on the IPv4 loopback.
    fn at(port: u16) -> SocketAddr {
        SocketAddr::from((LOOPBACK, port))
    }

    /// A connection: this crate's socket, and the far end as std accepted it.
    fn pair() -> (PosixTcpSocket, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let port = listener.local_addr().expect("its port").port();
        let near = PosixTcpSocket::connect(at(port)).expect("a connection");
        let (far, _) = listener.accept().expect("the far end");
        (near, far)
    }

    /// A connection to an IPv6 address is a socket of its family, both of whose ends the kernel
    /// names in it; a listener on one takes connections from it. Needs the host's IPv6 loopback.
    #[test]
    fn an_ipv6_connection_and_listener_name_their_ends_in_their_family() {
        let far = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).expect("an IPv6 listener");
        let near = PosixTcpSocket::connect(far.local_addr().unwrap()).expect("a connection");
        let (taken, from) = far.accept().expect("the far end");
        assert_eq!(near.peer(), far.local_addr().unwrap());
        assert_eq!(near.local(), from);
        assert_eq!(taken.local_addr().unwrap(), near.peer());

        let listener =
            PosixTcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))).expect("a listener");
        assert!(listener.local().is_ipv6());
        assert_ne!(listener.local().port(), 0);
        let dialler = TcpStream::connect(listener.local()).expect("a connection");
        let accepted = accepted(&listener);
        assert_eq!(accepted.peer(), dialler.local_addr().unwrap());
        assert_eq!(accepted.local(), listener.local());
    }

    /// A dial the kernel has no socket family for is the stack's permanent refusal; a dial with no
    /// descriptor left is worth a later try, and a connection refused is the other end's answer.
    #[test]
    fn a_family_the_kernel_lacks_is_unsupported_and_other_failures_are_not() {
        assert_eq!(
            open_refused(PosixNetError::Socket(libc::EAFNOSUPPORT)),
            LinkOpenError::Unsupported
        );
        assert_eq!(
            open_refused(PosixNetError::Socket(libc::EMFILE)),
            LinkOpenError::Exhausted
        );
        assert_eq!(
            open_refused(PosixNetError::Connect(libc::ECONNREFUSED)),
            LinkOpenError::Refused
        );
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

    /// A stream whose peer does not read stops being writable once the stacks hold all they
    /// will, and is writable again once the peer reads: the room a sender of the cooperative
    /// engine waits for. The writes are small enough that a stream that says it is writable takes
    /// each without blocking.
    #[test]
    fn a_stream_the_peer_does_not_read_stops_being_writable_until_it_reads() {
        let (near, mut far) = pair();
        assert!(near.wait_writable(1_000), "an empty stream takes bytes");
        let chunk = [0x5au8; 1024];
        let mut written = 0usize;
        while near.wait_writable(1_000) {
            near.send_parts(&[&chunk])
                .expect("a write the stream said it would take");
            written += chunk.len();
            assert!(
                written < 256 << 20,
                "the stream took {written} bytes and never filled"
            );
        }
        let mut buf = [0u8; 64 * 1024];
        let mut read = 0usize;
        while !near.wait_writable(0) {
            let n = far.read(&mut buf).expect("the far end reads");
            assert_ne!(n, 0, "the stream ended");
            read += n;
            assert!(read <= written, "read more than was written");
        }
        assert!(
            near.wait_writable(1_000),
            "read down, the stream takes bytes again"
        );
    }

    /// A write that does not wait takes what the stream has room for and says how much: all of a
    /// write to a stream with room, in order, and nothing once the peer has stopped reading and
    /// the stacks hold all they will, which it answers at once where a write that waits would wait
    /// for the peer.
    #[test]
    fn a_write_that_does_not_wait_takes_what_the_stream_has_room_for() {
        let (near, mut far) = pair();
        assert_eq!(
            near.send_parts_now(&[&b"he"[..], &b"llo"[..]]),
            Some(Ok(5)),
            "a stream with room takes it all"
        );
        let mut got = [0u8; 5];
        far.read_exact(&mut got).expect("the far end reads");
        assert_eq!(&got, b"hello");
        let chunk = [0x5au8; 1024];
        let mut written = 0usize;
        loop {
            match near.send_parts_now(&[&chunk]) {
                Some(Ok(0)) => break,
                Some(Ok(n)) => written += n,
                other => panic!("a write to a sound stream: {other:?}"),
            }
            assert!(
                written < 256 << 20,
                "the stream took {written} bytes and never filled"
            );
        }
        assert!(written > 0, "the stream took bytes before it filled");
    }

    /// A timed wait for room measures its time on the host's clock: room on an empty stream is
    /// found well inside the wait, and a stream the peer does not read is waited on for about the
    /// whole of it.
    #[test]
    fn a_timed_wait_for_room_reports_the_time_it_took() {
        let (near, _far) = pair();
        let (room, took_us) = near.wait_writable_timed(2_000_000);
        assert!(room, "an empty stream takes bytes");
        assert!(took_us < 1_000_000, "found at once, not after {took_us} us");
        let chunk = [0x5au8; 1024];
        while let Some(Ok(taken)) = near.send_parts_now(&[&chunk]) {
            if taken == 0 {
                break;
            }
        }
        let (room, took_us) = near.wait_writable_timed(50_000);
        assert!(!room, "a stream whose peer reads nothing has no room");
        assert!(took_us >= 40_000, "the wait took its time: {took_us} us");
    }

    wz_runtime_coop::with_heap_link_seams! {
        /// A link that took only part of a frame is woken by its stream's room alone: its owner's
        /// wait, made for room as well while the link owes the stream (`AndRoom`), ends once the far
        /// end reads, with no input and no send, and the one step it wakes writes the rest, every
        /// frame arriving whole and in order. CONTROL: the owner's wait for input alone, while
        /// nothing is owed and the stream has room, sleeps its whole time.
        #[cfg(feature = "alloc")]
        #[test]
        fn a_link_that_owes_the_stream_is_woken_by_room_and_writes_the_rest() {
            use std::sync::Arc;
            use std::time::{Duration, Instant};
            use wz_runtime_coop::link_storage::HeapTx;
            use wz_runtime_coop::session_drive::{
                wait_any, AndRoom, LinkReadiness, SessionDatagramLink,
            };
            use wz_runtime_coop::stream_link::StreamDriver;
            use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome};
            use wz_session_core::reliability::Reliability;

            let (near, mut far) = pair();
            let link =
                StreamDriver::with_buffers(near, 4096, HeapTx::new(2, 2048)).waited_by_owner();
            let ready: Arc<dyn LinkReadiness> =
                Arc::from(link.readiness().expect("the owner's wait"));

            assert!(!link.owes_write(), "CONTROL: nothing is owed");
            let started = Instant::now();
            wait_any(&[Arc::clone(&ready)], 200);
            assert!(
                started.elapsed() >= Duration::from_millis(150),
                "CONTROL: a wait for input alone is not woken by room"
            );

            let frame = [0x5au8; 1000];
            let mut frames = 0usize;
            while !link.owes_write() {
                assert_eq!(
                    link.send_blocking(&frame, Reliability::Reliable),
                    LinkSendOutcome::Sent
                );
                frames += 1;
                assert!(frames < 1 << 16, "the stream never filled");
            }
            let total = frames * (2 + frame.len());
            let reader = std::thread::spawn(move || {
                let mut got = std::vec![0u8; total];
                far.read_exact(&mut got).expect("every frame arrives");
                got
            });
            let mut wakes = 0;
            while link.owes_write() {
                let started = Instant::now();
                wait_any(&[AndRoom::of(Arc::clone(&ready))], 10_000);
                assert!(
                    started.elapsed() < Duration::from_secs(10),
                    "the stream's room ended the wait"
                );
                wakes += 1;
                link.service();
                assert!(wakes < 100, "the rest was never written");
            }
            assert_eq!(wakes, 1, "one wake, and its step wrote the rest");
            let got = reader.join().expect("the reader");
            for (i, written) in got.chunks(2 + frame.len()).enumerate() {
                assert_eq!(&written[..2], &1000u16.to_le_bytes(), "frame {i}'s length");
                assert!(written[2..].iter().all(|&b| b == 0x5a), "frame {i}'s bytes");
            }
        }

        /// The wait for room handed to another thread answers as the socket's own wait does: it
        /// has room while the stream takes bytes, and none once the peer has stopped reading.
        #[cfg(feature = "alloc")]
        #[test]
        fn the_wait_for_room_handed_out_answers_as_the_socket_does() {
            let (near, _far) = pair();
            let wait = near.writability().expect("a duplicate of the descriptor");
            assert!(wait.wait_writable(1_000), "an empty stream takes bytes");
            let chunk = [0x5au8; 1024];
            let mut written = 0usize;
            while near.wait_writable(1_000) {
                near.send_parts(&[&chunk])
                    .expect("a write the stream said it would take");
                written += chunk.len();
                assert!(
                    written < 256 << 20,
                    "the stream took {written} bytes and never filled"
                );
            }
            assert!(
                !wait.wait_writable(1_000),
                "the wait handed out sees the stream full as the socket does"
            );
        }
    }

    #[test]
    fn a_connection_names_both_its_ends() {
        let (near, far) = pair();
        assert_eq!(near.peer(), far.local_addr().unwrap());
        assert_eq!(near.local(), far.peer_addr().unwrap());
        assert_ne!(near.local().port(), 0);
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
            let raw = RawAddr::of(at(0));
            // SAFETY: `raw` is a live socket address of the length passed.
            let rc = unsafe { libc::bind(fd, raw.as_ptr(), raw.size()) };
            assert_eq!(rc, 0, "bind without listen");
            let port = name_of(fd, libc::getsockname)
                .expect("the bound number")
                .port();
            Self { fd, port }
        }
    }

    impl Drop for RefusingPort {
        fn drop(&mut self) {
            // SAFETY: `fd` is this guard's own descriptor, closed exactly once.
            unsafe { libc::close(self.fd) };
        }
    }

    /// A connect begun without waiting is made once the listener has it, names both its ends from
    /// then on and carries bytes; one to a port nobody listens on is refused, at once or when it is
    /// asked.
    #[test]
    fn a_connect_begun_without_waiting_is_made_or_refused_when_asked() {
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let port = listener.local_addr().expect("its port").port();
        let mut near = PosixTcpSocket::connect_started(at(port)).expect("a connect begun");
        let until = Instant::now() + Duration::from_secs(5);
        while !near.connected().expect("the connect is not refused") {
            assert!(Instant::now() < until, "the connect was never made");
            std::thread::sleep(Duration::from_millis(1));
        }
        let (mut far, _) = listener.accept().expect("the far end");
        assert_eq!(near.peer(), listener.local_addr().unwrap());
        assert_eq!(near.local(), far.peer_addr().unwrap());
        near.send_parts(&[b"made"])
            .expect("a made connection carries bytes");
        let mut got = [0u8; 4];
        far.read_exact(&mut got).expect("the bytes");
        assert_eq!(&got, b"made");

        let held = RefusingPort::hold();
        match PosixTcpSocket::connect_started(at(held.port)) {
            Err(PosixNetError::Connect(e)) => assert_eq!(e, libc::ECONNREFUSED),
            Err(other) => panic!("a different error: {other:?}"),
            Ok(mut refused) => {
                let until = Instant::now() + Duration::from_secs(5);
                loop {
                    match refused.connected() {
                        Ok(false) => {
                            assert!(Instant::now() < until, "the refusal never came");
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(PosixNetError::Connect(e)) => {
                            assert_eq!(e, libc::ECONNREFUSED);
                            break;
                        }
                        other => panic!("a connect to a port nobody listens on: {other:?}"),
                    }
                }
            }
        }
    }

    #[test]
    fn a_connection_to_a_closed_port_is_refused() {
        let held = RefusingPort::hold();
        match PosixTcpSocket::connect(at(held.port)) {
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

    /// Whether `TCP_NODELAY` is on for `fd`.
    fn nodelay_of(fd: c_int) -> bool {
        let mut on: c_int = 0;
        let mut len = size_of::<c_int>() as libc::socklen_t;
        // SAFETY: `on` and `len` are live and writable, and `len` is `on`'s size.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                (&mut on as *mut c_int).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0);
        on == 1
    }

    #[test]
    fn nagle_is_off() {
        let (near, _far) = pair();
        assert!(nodelay_of(near.fd));
    }

    /// A connection std makes to the loopback `port`.
    fn std_connect(port: u16) -> TcpStream {
        TcpStream::connect(("127.0.0.1", port)).expect("a connection")
    }

    /// A listener on a port the kernel picked, and that port.
    fn listening() -> (PosixTcpListener, u16) {
        let listener = PosixTcpListener::bind(at(0)).expect("a listener");
        let local = listener.local();
        assert_eq!(local.ip(), LOOPBACK);
        assert_ne!(local.port(), 0, "the kernel's choice is read back");
        (listener, local.port())
    }

    /// The connection `listener` has waiting, polled until it comes: a connect completes in the
    /// kernel before the peer calls `accept`, but not before this thread's next instruction.
    fn accepted(listener: &PosixTcpListener) -> PosixTcpSocket {
        for _ in 0..200 {
            if let Some(socket) = listener.accept().expect("a sound listener") {
                return socket;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("no connection arrived");
    }

    #[test]
    fn an_accept_with_no_connection_waiting_answers_at_once() {
        let (listener, _) = listening();
        for _ in 0..3 {
            assert!(matches!(listener.accept(), Ok(None)));
        }
    }

    #[test]
    fn an_accepted_connection_names_both_its_ends_and_has_nagle_off() {
        let (listener, port) = listening();
        let far = std_connect(port);
        let near = accepted(&listener);
        assert_eq!(near.local(), at(port));
        assert_eq!(near.peer(), far.local_addr().unwrap());
        assert!(nodelay_of(near.fd));
    }

    #[test]
    fn an_accepted_connection_is_a_stream_in_both_directions_and_its_reads_do_not_block() {
        let (listener, port) = listening();
        let mut far = std_connect(port);
        let near = accepted(&listener);
        let mut buf = [0u8; 16];
        assert_eq!(
            near.try_read(&mut buf),
            Ok(None),
            "the listener's own non-blocking flag is not the connection's, and a read is MSG_DONTWAIT"
        );
        far.write_all(b"hello").expect("a write");
        assert_eq!(read_exactly(&near, 5), b"hello");
        near.send_parts(&[b"\x02\x00", b"ok"]).expect("a send");
        let mut got = [0u8; 4];
        far.read_exact(&mut got).expect("the bytes");
        assert_eq!(&got, b"\x02\x00ok");
    }

    #[test]
    fn connections_arrive_in_the_order_they_were_made() {
        let (listener, port) = listening();
        let first = std_connect(port);
        let second = std_connect(port);
        assert_eq!(accepted(&listener).peer(), first.local_addr().unwrap());
        assert_eq!(accepted(&listener).peer(), second.local_addr().unwrap());
    }

    #[test]
    fn a_connection_closed_before_it_is_taken_still_comes_and_reads_as_ended() {
        let (listener, port) = listening();
        drop(std_connect(port));
        let near = accepted(&listener);
        near.wait_readable(1000);
        let mut buf = [0u8; 16];
        assert_eq!(near.try_read(&mut buf), Ok(Some(0)));
    }

    #[test]
    fn a_port_already_listened_on_is_a_bind_error_not_a_second_listener() {
        let (_held, port) = listening();
        match PosixTcpListener::bind(at(port)) {
            Err(PosixNetError::Bind(e)) => assert_eq!(e, libc::EADDRINUSE),
            Err(other) => panic!("a different error: {other:?}"),
            Ok(_) => panic!("the port is taken"),
        }
    }

    #[test]
    fn a_closed_listener_frees_its_port_for_the_next() {
        let (listener, port) = listening();
        let far = std_connect(port);
        let near = accepted(&listener);
        drop(listener);
        drop(near);
        drop(far);
        PosixTcpListener::bind(at(port))
            .expect("SO_REUSEADDR: the closed connections do not hold the port");
    }
}
