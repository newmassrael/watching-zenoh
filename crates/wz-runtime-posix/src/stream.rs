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
    use wz_runtime_coop::session_drive::WaitOn;
    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    use wz_runtime_coop::session_drive::{LinkRead, ReadWaited};
    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    use core::sync::atomic::{AtomicU32, Ordering};
}
use wz_runtime_coop::stream_link::{StreamDial, StreamListen, StreamSocket};
use wz_runtime_coop::ClockSource;

use crate::net::{
    call_at, errno, family_of, name_of, poll_writable, set_close_on_exec, set_flag,
    set_nonblocking, PosixNetError,
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
        call_at(fd, to, libc::connect).map_err(PosixNetError::Connect)?;
        this.learn_ends()?;
        Ok(this)
    }

    /// Read the connection's two ends from the kernel: the one way each connection here, dialled
    /// or accepted, learns them.
    fn learn_ends(&mut self) -> Result<(), PosixNetError> {
        self.local = name_of(self.fd, libc::getsockname).map_err(PosixNetError::SockName)?;
        self.peer = name_of(self.fd, libc::getpeername).map_err(PosixNetError::PeerName)?;
        Ok(())
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
        match call_at(fd, to, libc::connect) {
            // Under way, which `connected` reads; a signal does not stop it either.
            Ok(()) | Err(libc::EINPROGRESS | libc::EINTR) => {}
            Err(refused) => return Err(PosixNetError::Connect(refused)),
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
        call_at(fd, at, libc::bind).map_err(PosixNetError::Bind)?;
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
        // A listening descriptor polls readable while a connection is queued on it.
        fn input_wait(&self) -> Option<WaitOn> {
            crate::net::wait_on(self.fd)
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
        if socket.learn_ends().is_err() {
            return Ok(None);
        }
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

/// One `sendmsg` of `vecs` on `fd` with `flags`, taken again when a signal interrupts it: the
/// bytes the stack took, or the error it answered. The body both stream writes share, out of line
/// so that the message header and the read of `errno` are one copy.
#[inline(never)]
fn send_vecs(fd: c_int, vecs: &mut [libc::iovec], flags: c_int) -> Result<usize, c_int> {
    loop {
        // SAFETY: an all-zero `msghdr` is a valid one with no name and no control data.
        let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
        msg.msg_iov = vecs.as_mut_ptr();
        // `usize` on Linux, `i32` on Neutrino: at most the few parts of one frame.
        msg.msg_iovlen = vecs.len() as _;
        // SAFETY: every iovec names live bytes of the caller's parts for its length.
        let sent = unsafe { libc::sendmsg(fd, &msg, flags) };
        if sent >= 0 {
            return Ok(sent as usize);
        }
        match errno() {
            libc::EINTR => continue,
            other => return Err(other),
        }
    }
}

impl StreamSocket for PosixTcpSocket {
    type Error = PosixNetError;

    type Link<
        B: wz_runtime_coop::link_storage::RxStore + 'static,
        X: wz_runtime_coop::link_storage::TxStore + 'static,
    >
        = wz_runtime_coop::stream_link::StreamDriver<Self, B, X>
    where
        Self: 'static;

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
            // MSG_NOSIGNAL: a peer that closed the stream is an error here, not a SIGPIPE.
            let mut sent = send_vecs(self.fd, &mut vecs[first..count], libc::MSG_NOSIGNAL)
                .map_err(PosixNetError::Write)?;
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
    // for at that moment, and a buffer with none is `EAGAIN`, read as nothing taken. The socket
    // itself stays blocking, so `send_parts` waits for what this leaves, as it waits for any write.
    fn send_parts_now(&self, parts: &[&[u8]]) -> Option<Result<usize, PosixNetError>> {
        let (mut vecs, count) = match iovecs(parts) {
            Ok(built) => built,
            Err(refused) => return Some(Err(refused)),
        };
        Some(
            match send_vecs(
                self.fd,
                &mut vecs[..count],
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            ) {
                Ok(sent) => Ok(sent),
                Err(libc::EAGAIN) => Ok(0),
                Err(other) => Err(PosixNetError::Write(other)),
            },
        )
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
        self.learn_ends()?;
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
        fn input_wait(&self) -> Option<WaitOn> {
            crate::net::wait_on(self.fd)
        }

        fn room_wait(&self) -> Option<WaitOn> {
            crate::net::wait_on(self.fd)
        }

        #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
        fn reader(&self) -> Option<alloc::boxed::Box<dyn LinkRead>> {
            StreamReader::of(self.fd)
                .map(|reader| alloc::boxed::Box::new(reader) as alloc::boxed::Box<dyn LinkRead>)
        }

        #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
        fn read_failure(code: i32) -> Option<PosixNetError> {
            Some(PosixNetError::Recv(code))
        }
    }
}

impl Drop for PosixTcpSocket {
    fn drop(&mut self) {
        // SAFETY: `fd` is this socket's own descriptor, closed exactly once.
        unsafe { libc::close(self.fd) };
    }
}

wz_runtime_coop::with_heap_link_seams! {
/// The read a stream's owner makes from a thread of its own, waiting in the read itself
/// ([`LinkRead`]): one blocking `recv` on a duplicate of the socket's descriptor, which this owns
/// and closes, bounded by the socket's receive timeout (`SO_RCVTIMEO`), as zenoh-pico bounds the
/// `recv` of its read task
/// (`vendor/zenoh-pico/src/link/transport/tcp/tcp_posix.c` @ `SOL_SOCKET, SO_RCVTIMEO`).
/// The timeout is set only when a read asks for another than the one set last, so a read with
/// nothing due before the session's idle wait is the `recv` alone. The timeout is the socket's,
/// shared by its duplicate, and changes nothing else: the link's own reads do not wait
/// (`MSG_DONTWAIT`), and its writes are bounded, if at all, by the send timeout.
#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
pub(crate) struct StreamReader {
    fd: c_int,
    /// The receive timeout set on the socket, in milliseconds; 0 before the first is set.
    armed_ms: AtomicU32,
    /// How often the timeout was set, which the tests count.
    #[cfg(test)]
    arms: core::sync::atomic::AtomicUsize,
}

#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
impl StreamReader {
    /// The owner's read of the stream socket `fd`: `None` when the descriptor cannot be
    /// duplicated, or when the socket does not block, whose `recv` would not wait and whose
    /// owner then waits on its readiness instead.
    pub(crate) fn of(fd: c_int) -> Option<Self> {
        // SAFETY: plain system call with value arguments on the caller's live descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || flags & libc::O_NONBLOCK != 0 {
            return None;
        }
        // SAFETY: `fd` is the caller's live descriptor; `fcntl` duplicates it or fails.
        let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return None;
        }
        Some(Self {
            fd: dup,
            armed_ms: AtomicU32::new(0),
            #[cfg(test)]
            arms: core::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Bound the reads from here on by `ms` milliseconds, at least one (a timeout of zero is
    /// none at all): `false` when the socket refused it.
    fn arm(&self, ms: u32) -> bool {
        let ms = ms.max(1);
        if self.armed_ms.load(Ordering::Relaxed) == ms {
            return true;
        }
        let timeout = libc::timeval {
            tv_sec: (ms / 1000) as _,
            tv_usec: ((ms % 1000) * 1000) as _,
        };
        // SAFETY: `timeout` is a live `timeval` of the length passed, on this read's own
        // descriptor.
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeout as *const libc::timeval).cast(),
                core::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return false;
        }
        #[cfg(test)]
        self.arms.fetch_add(1, Ordering::Relaxed);
        self.armed_ms.store(ms, Ordering::Relaxed);
        true
    }
}

#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
impl LinkRead for StreamReader {
    fn read_waiting(&self, buf: &mut [u8], timeout_ms: u32) -> ReadWaited {
        if buf.is_empty() {
            return ReadWaited::Quiet;
        }
        // A socket that took no timeout would hold the read past every deadline: it is waited on
        // for the time asked and read without waiting, as the step reads it.
        let flags = if self.arm(timeout_ms) {
            0
        } else {
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let timeout = c_int::try_from(timeout_ms).unwrap_or(c_int::MAX);
            // SAFETY: one live `pollfd` over this read's own descriptor; the timeout bounds the
            // wait. A failed wait is a quiet socket: the read below reports the error.
            unsafe { libc::poll(&mut pfd, 1, timeout) };
            libc::MSG_DONTWAIT
        };
        // SAFETY: `buf` is live and writable for its length, and the descriptor is this read's
        // own.
        let got = unsafe { libc::recv(self.fd, buf.as_mut_ptr().cast(), buf.len(), flags) };
        match got {
            0 => ReadWaited::Ended,
            n if n > 0 => ReadWaited::Read(n as usize),
            _ => match errno() {
                // The timeout ran out, or a signal came first: nothing was read.
                libc::EAGAIN | libc::EINTR => ReadWaited::Quiet,
                failed => ReadWaited::Failed(failed),
            },
        }
    }
}

#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
impl Drop for StreamReader {
    fn drop(&mut self) {
        // SAFETY: the duplicate is this value's own descriptor, closed exactly once.
        unsafe { libc::close(self.fd) };
    }
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

    /// Both stream writes go through one `sendmsg` body: a write and a write that does not wait
    /// each deliver their parts in order, empty ones left out, and the body answers the error the
    /// system gave for a socket that is not one.
    #[test]
    fn both_writes_send_their_parts_through_one_body() {
        let (near, mut far) = pair();
        near.send_parts(&[b"ab", b"", b"cde"]).expect("a write");
        assert_eq!(
            near.send_parts_now(&[b"fg", b"h"])
                .map(|sent| sent.expect("taken")),
            Some(3)
        );
        let mut got = [0u8; 8];
        far.read_exact(&mut got).expect("the bytes");
        assert_eq!(&got, b"abcdefgh");
        let mut vecs = [libc::iovec {
            iov_base: b"x".as_ptr().cast_mut().cast(),
            iov_len: 1,
        }];
        assert_eq!(
            send_vecs(-1, &mut vecs, libc::MSG_NOSIGNAL),
            Err(libc::EBADF)
        );
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
        use std::os::fd::AsRawFd;

        let (near, far) = pair();
        // Small buffers at both ends, so the stacks are full after a few writes: a loopback
        // connection grows them to megabytes otherwise, and keeps moving bytes into the far end's
        // buffer after a write was refused, which gives the near end room again.
        set_buffer(near.fd, libc::SO_SNDBUF, 4096);
        set_buffer(far.as_raw_fd(), libc::SO_RCVBUF, 4096);
        let (room, took_us) = near.wait_writable_timed(2_000_000);
        assert!(room, "an empty stream takes bytes");
        assert!(took_us < 1_000_000, "found at once, not after {took_us} us");
        // Fill until a write that does not wait is refused, and again whenever the stacks have
        // since moved bytes on and made room, until a wait finds none.
        let chunk = [0x5au8; 1024];
        let mut waits = 0;
        let took_us = loop {
            loop {
                match near.send_parts_now(&[&chunk]) {
                    Some(Ok(0)) => break,
                    Some(Ok(_)) => {}
                    other => panic!("a write to a sound stream: {other:?}"),
                }
            }
            let (room, took_us) = near.wait_writable_timed(50_000);
            if !room {
                break took_us;
            }
            waits += 1;
            assert!(waits < 1_000, "the stream never filled");
        };
        assert!(took_us >= 40_000, "the wait took its time: {took_us} us");
    }

    /// Set the socket buffer `option` (`SO_SNDBUF`, `SO_RCVBUF`) of `fd` to `bytes`.
    fn set_buffer(fd: c_int, option: c_int, bytes: c_int) {
        // SAFETY: `bytes` is a live `c_int` and the length passed is its size.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&bytes as *const c_int).cast(),
                size_of::<c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "the kernel takes a buffer size");
    }

    wz_runtime_coop::with_heap_link_seams! {
        /// A link that took only part of a frame is woken by its stream's room alone: its owner's
        /// wait, made for room as well while the link owes the stream (`LinkWait::input_or_room`),
        /// ends once the far
        /// end reads, with no input and no send, and the one step it wakes writes the rest, every
        /// frame arriving whole and in order. CONTROL: the owner's wait for input alone, while
        /// nothing is owed and the stream has room, sleeps its whole time.
        #[cfg(feature = "alloc")]
        #[test]
        fn a_link_that_owes_the_stream_is_woken_by_room_and_writes_the_rest() {
            use std::time::{Duration, Instant};
            use wz_runtime_coop::link_storage::HeapTx;
            use wz_runtime_coop::session_drive::{LinkWait, LinkWaits, SessionDatagramLink};
            use wz_runtime_coop::stream_link::StreamDriver;
            use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome};
            use wz_session_core::reliability::Reliability;

            let (near, mut far) = pair();
            let link =
                StreamDriver::with_buffers(near, 4096, HeapTx::new(2, 2048)).waited_by_owner();
            let on = link.input_wait().expect("the owner's wait");
            let waits = crate::net::PosixWaits;

            assert!(!link.owes_write(), "CONTROL: nothing is owed");
            let started = Instant::now();
            waits.wait(&[LinkWait::input(on)], 200);
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
                waits.wait(&[LinkWait::input_or_room(on)], 10_000);
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

        /// A wait for room on the handle the stream names answers as the socket's own wait does:
        /// it has room while the stream takes bytes, and none once the peer has stopped reading.
        #[test]
        fn a_wait_for_room_on_the_streams_handle_answers_as_the_socket_does() {
            use wz_runtime_coop::session_drive::LinkWaits;
            let (near, _far) = pair();
            let on = near.room_wait().expect("the stream's descriptor");
            let waits = crate::net::PosixWaits;
            assert!(waits.wait_room(on, 1_000), "an empty stream takes bytes");
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
                !waits.wait_room(on, 1_000),
                "a wait on the handle sees the stream full as the socket does"
            );
        }

        /// The owner's read of a stream waits in the read itself: what is queued is taken by one
        /// `recv`, the receive timeout set once for every read that asks for the same wait; a read
        /// with nothing queued waits about its timeout and finds nothing, and one that asks for
        /// another wait sets the timeout again; the end of the stream is the end. CONTROL: the
        /// second read asks for the first's wait and sets nothing.
        #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
        #[test]
        fn the_owners_read_waits_in_the_recv_and_sets_its_timeout_once() {
            use core::sync::atomic::Ordering::SeqCst;
            use std::time::{Duration, Instant};

            let (near, mut far) = pair();
            let reader = StreamReader::of(near.fd).expect("a read of a blocking stream");
            let mut buf = [0u8; 64];
            far.write_all(b"\x03\x00abc").expect("the far end writes");
            assert_eq!(reader.read_waiting(&mut buf, 1_000), ReadWaited::Read(5));
            assert_eq!(&buf[..5], b"\x03\x00abc");
            far.write_all(b"de").expect("the far end writes");
            assert_eq!(reader.read_waiting(&mut buf, 1_000), ReadWaited::Read(2));
            assert_eq!(
                reader.arms.load(SeqCst),
                1,
                "CONTROL: one timeout set for both reads"
            );
            let started = Instant::now();
            assert_eq!(reader.read_waiting(&mut buf, 50), ReadWaited::Quiet);
            let took = started.elapsed();
            assert!(
                took >= Duration::from_millis(40),
                "the read waited in the recv, {took:?}"
            );
            assert_eq!(reader.arms.load(SeqCst), 2, "another wait is set again");
            drop(far);
            assert_eq!(reader.read_waiting(&mut buf, 1_000), ReadWaited::Ended);
        }

        /// A read waiting in a stream's `recv` is ended at once when the stream is shut: what a
        /// link let go of with its buffer lent does before it waits the read out.
        #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
        #[test]
        fn shutting_the_stream_ends_a_read_waiting_in_it() {
            use std::time::{Duration, Instant};

            let (near, _far) = pair();
            let reader = StreamReader::of(near.fd).expect("a read of a blocking stream");
            let waiting = std::thread::spawn(move || {
                let mut buf = [0u8; 8];
                let started = Instant::now();
                (reader.read_waiting(&mut buf, 10_000), started.elapsed())
            });
            std::thread::sleep(Duration::from_millis(100));
            near.shutdown();
            let (got, took) = waiting.join().expect("the reading thread");
            assert_eq!(got, ReadWaited::Ended);
            assert!(
                took < Duration::from_secs(5),
                "the shut ended the read, after {took:?}"
            );
        }

        /// A stream that does not block gives no read that waits in itself, whose `recv` would
        /// answer at once: its owner waits on its readiness. CONTROL: the same stream, blocking,
        /// gives one.
        #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
        #[test]
        fn a_stream_that_does_not_block_gives_no_read_that_waits() {
            let (near, _far) = pair();
            set_nonblocking(near.fd, true).expect("the stream stops blocking");
            assert!(near.reader().is_none());
            set_nonblocking(near.fd, false).expect("the stream blocks again");
            assert!(near.reader().is_some(), "CONTROL: a blocking stream gives one");
        }

        /// A link over a host stream that its owner waits on lends its buffer to the owner's read,
        /// which takes the batch the far end wrote, and the link hands the batch over from there.
        /// CONTROL: the link its loop waits on lends nothing.
        #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
        #[test]
        fn a_host_stream_link_lends_its_buffer_to_its_owners_read() {
            use wz_runtime_coop::link_storage::HeapTx;
            use wz_runtime_coop::session_drive::SessionDatagramLink;
            use wz_runtime_coop::stream_link::StreamDriver;

            let (near, _) = pair();
            let looped = StreamDriver::with_buffers(near, 4096, HeapTx::new(2, 2048));
            assert!(
                looped.lend_rx().is_none(),
                "CONTROL: a link its loop waits on"
            );

            let (near, mut far) = pair();
            let link =
                StreamDriver::with_buffers(near, 4096, HeapTx::new(2, 2048)).waited_by_owner();
            far.write_all(b"\x03\x00abc").expect("the far end writes");
            let mut lease = link.lend_rx().expect("the owner's read is lent the buffer");
            lease.read(1_000);
            link.land_rx(lease);
            let mut got = None;
            assert!(link.recv_with(&mut |batch| got = Some(batch.to_vec())));
            assert_eq!(got.as_deref(), Some(&b"abc"[..]));
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
            assert_eq!(
                call_at(fd, at(0), libc::bind),
                Ok(()),
                "bind without listen"
            );
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
