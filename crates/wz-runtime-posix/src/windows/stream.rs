// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Windows host's stream seam: TCP over Winsock.
//!
//! [`WindowsTcpSocket`] is the socket `wz_runtime_coop::stream_link` is written against
//! ([`StreamSocket`]), and [`WindowsTcpDial`] the dial a stack opens it with ([`StreamDial`]);
//! [`WindowsTcpListener`] is the other direction ([`StreamListen`]), the port a node accepts
//! connections on, yielding the same socket. Nothing here allocates: the socket is a handle and
//! its two ends.
//!
//! The socket is non-blocking from its connect on, so a write can be tried without waiting
//! ([`StreamSocket::send_parts_now`]: one `WSASend`, and `WSAEWOULDBLOCK` is nothing taken),
//! which Winsock has no per-call flag for. The write that waits ([`StreamSocket::send_parts`])
//! waits in `WSAPoll` for room and writes on, so it returns once Winsock has taken every byte (a
//! length and its batch go out in one `WSASend`), as the POSIX half's does; a read is one `recv`
//! that does not wait, the loop's wait being the poll of [`StreamSocket::wait_readable`]. `TCP_NODELAY` is set, as zenoh and zenoh-pico set it on every
//! TCP link (`vendor/zenoh-pico/src/link/transport/tcp/tcp_windows.c` @
//! `IPPROTO_TCP, TCP_NODELAY`).

use core::ffi::c_int;
use core::net::SocketAddr;

use windows_sys::Win32::Networking::WinSock as ws;
use wz_runtime_coop::session_drive::LinkOpenError;
use wz_runtime_coop::stream_link::{StreamDial, StreamListen, StreamSocket};
use wz_runtime_coop::ClockSource;

wz_runtime_coop::with_heap_link_seams! {
    #[cfg(feature = "alloc")]
    use wz_runtime_coop::session_drive::{LinkReadiness, LinkWritability};
}

use super::{
    close, keep_from_children, last_error, name_of, open_socket, poll_readable, poll_writable,
    set_flag, set_nonblocking, RawAddr, WindowsNetError,
};

/// The most parts one write gathers: a length and its batch, with room to spare.
const MAX_PARTS: usize = 4;

/// One connected TCP socket on the host, of the family of the address it connected to.
pub struct WindowsTcpSocket {
    socket: ws::SOCKET,
    local: SocketAddr,
    peer: SocketAddr,
}

/// A failed open of a stream socket as the stack's refusal of the link: a family the system has
/// no socket of is permanent for the locator, no socket to give (or no Winsock yet) is worth a
/// later try, and anything else is the other end's or the port's answer, as a retry would meet
/// it.
fn open_refused(error: WindowsNetError) -> LinkOpenError {
    match error {
        WindowsNetError::Socket(ws::WSAEAFNOSUPPORT) => LinkOpenError::Unsupported,
        WindowsNetError::Socket(_) | WindowsNetError::Startup(_) => LinkOpenError::Exhausted,
        _ => LinkOpenError::Refused,
    }
}

impl WindowsTcpSocket {
    /// Connect to `to`, blocking until the connection is made or refused.
    pub fn connect(to: SocketAddr) -> Result<Self, WindowsNetError> {
        let socket = open_socket(&to, ws::SOCK_STREAM, ws::IPPROTO_TCP)?;
        // Owned from here, so an early return closes it.
        let mut this = Self {
            socket,
            local: to,
            peer: to,
        };
        set_flag(socket, ws::IPPROTO_TCP, ws::TCP_NODELAY).map_err(WindowsNetError::NoDelay)?;
        let peer = RawAddr::of(to);
        // SAFETY: `peer` is a live socket address of the length passed.
        if unsafe { ws::connect(socket, peer.as_ptr(), peer.size()) } != 0 {
            return Err(WindowsNetError::Connect(last_error()));
        }
        set_nonblocking(socket, true).map_err(WindowsNetError::NonBlocking)?;
        this.local = name_of(socket, ws::getsockname).map_err(WindowsNetError::SockName)?;
        this.peer = name_of(socket, ws::getpeername).map_err(WindowsNetError::PeerName)?;
        Ok(this)
    }
}

impl WindowsTcpSocket {
    /// Begin a connection to `to` and return without waiting for it: the socket is non-blocking
    /// from here on, as a socket [`Self::connect`] made is once connected, and
    /// [`StreamSocket::connected`] tells when the connection is made. A refusal Winsock knows at
    /// once is the error here.
    pub fn connect_started(to: SocketAddr) -> Result<Self, WindowsNetError> {
        let socket = open_socket(&to, ws::SOCK_STREAM, ws::IPPROTO_TCP)?;
        // Owned from here, so an early return closes it.
        let this = Self {
            socket,
            local: to,
            peer: to,
        };
        set_flag(socket, ws::IPPROTO_TCP, ws::TCP_NODELAY).map_err(WindowsNetError::NoDelay)?;
        set_nonblocking(socket, true).map_err(WindowsNetError::NonBlocking)?;
        let peer = RawAddr::of(to);
        // SAFETY: `peer` is a live socket address of the length passed.
        if unsafe { ws::connect(socket, peer.as_ptr(), peer.size()) } != 0 {
            match last_error() {
                // Under way, which `connected` reads.
                ws::WSAEWOULDBLOCK => {}
                refused => return Err(WindowsNetError::Connect(refused)),
            }
        }
        Ok(this)
    }

    /// Whether the connection begun without waiting has ended, made or refused: `select` with no
    /// wait, which names a refused connect in its exception set on every Windows (`WSAPoll`
    /// reports one only from Windows 10 2004 on).
    fn connect_ended(&self) -> (bool, bool) {
        let mut made = ws::FD_SET {
            fd_count: 1,
            fd_array: [0; 64],
        };
        made.fd_array[0] = self.socket;
        let mut failed = ws::FD_SET {
            fd_count: 1,
            fd_array: [0; 64],
        };
        failed.fd_array[0] = self.socket;
        let now = ws::TIMEVAL {
            tv_sec: 0,
            tv_usec: 0,
        };
        // SAFETY: two live sets of one socket each, and a live timeout; the first argument is
        // ignored by Winsock.
        let ready = unsafe { ws::select(0, core::ptr::null_mut(), &mut made, &mut failed, &now) };
        if ready <= 0 {
            return (false, false);
        }
        (made.fd_count > 0, failed.fd_count > 0)
    }

    /// The error a connection begun without waiting ended with (`SO_ERROR`), 0 when it was made.
    fn connect_error(&self) -> Result<i32, WindowsNetError> {
        let mut error: i32 = 0;
        let mut len = core::mem::size_of::<i32>() as i32;
        // SAFETY: `error` and `len` are live and writable, and `len` is `error`'s size.
        let rc = unsafe {
            ws::getsockopt(
                self.socket,
                ws::SOL_SOCKET,
                ws::SO_ERROR,
                (&mut error as *mut i32).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(WindowsNetError::Connect(last_error()));
        }
        Ok(error)
    }
}

/// The host's TCP connect as a stack's dial: the stream a `tcp/` link runs over is a plain
/// connection.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsTcpDial;

impl StreamDial for WindowsTcpDial {
    type Stream = WindowsTcpSocket;

    fn dial(&self, to: SocketAddr) -> Result<WindowsTcpSocket, LinkOpenError> {
        WindowsTcpSocket::connect(to).map_err(open_refused)
    }

    fn dial_started(&self, to: SocketAddr) -> Result<WindowsTcpSocket, LinkOpenError> {
        WindowsTcpSocket::connect_started(to).map_err(open_refused)
    }

    wz_runtime_coop::with_heap_link_seams! {
        #[cfg(feature = "alloc")]
        fn listen(
            &self,
            at: SocketAddr,
        ) -> Result<alloc::boxed::Box<dyn StreamListen<Stream = WindowsTcpSocket>>, LinkOpenError>
        {
            WindowsTcpListener::bind(at)
                .map(|listener| {
                    alloc::boxed::Box::new(listener)
                        as alloc::boxed::Box<dyn StreamListen<Stream = WindowsTcpSocket>>
                })
                // The port taken or not the host's to bind is the same answer a retry meets.
                .map_err(open_refused)
        }
    }
}

/// A TCP port the host listens on: the half of the seam [`WindowsTcpDial`] is not, handing the
/// stack the connections that arrive as the same [`WindowsTcpSocket`] a dial yields.
///
/// The listening socket never blocks (`accept` answers at once, and the node's loop is what
/// waits), and `SO_REUSEADDR` is set, as zenoh-pico's Windows listener sets it
/// (`vendor/zenoh-pico/src/link/transport/tcp/tcp_windows.c` @ `SOL_SOCKET, SO_REUSEADDR`), so a
/// node restarted on its port is not kept off it by the connections of the one before.
pub struct WindowsTcpListener {
    socket: ws::SOCKET,
    local: SocketAddr,
}

impl WindowsTcpListener {
    /// The connections that may queue on the port before the system refuses new ones: a node
    /// takes them off in its next loop pass, so a handful covers clients arriving together.
    const BACKLOG: i32 = 8;

    /// Listen on `at`, over a socket of its family (port 0: the system picks one, read back with
    /// [`StreamListen::local`]).
    pub fn bind(at: SocketAddr) -> Result<Self, WindowsNetError> {
        let socket = open_socket(&at, ws::SOCK_STREAM, ws::IPPROTO_TCP)?;
        // Owned from here, so an early return closes it.
        let mut this = Self { socket, local: at };
        // The listener never waits: a pass of the node's loop asks, and nothing queued is an
        // answer.
        set_nonblocking(socket, true).map_err(WindowsNetError::NonBlocking)?;
        set_flag(socket, ws::SOL_SOCKET, ws::SO_REUSEADDR).map_err(WindowsNetError::ReuseAddr)?;
        let raw = RawAddr::of(at);
        // SAFETY: `raw` is a live socket address of the length passed.
        if unsafe { ws::bind(socket, raw.as_ptr(), raw.size()) } != 0 {
            return Err(WindowsNetError::Bind(last_error()));
        }
        // SAFETY: value arguments on this listener's own socket.
        if unsafe { ws::listen(socket, Self::BACKLOG) } != 0 {
            return Err(WindowsNetError::Listen(last_error()));
        }
        this.local = name_of(socket, ws::getsockname).map_err(WindowsNetError::SockName)?;
        Ok(this)
    }
}

impl StreamListen for WindowsTcpListener {
    type Stream = WindowsTcpSocket;

    fn local(&self) -> SocketAddr {
        self.local
    }

    wz_runtime_coop::with_heap_link_seams! {
        #[cfg(feature = "alloc")]
        fn readiness(&self) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
            // A listening socket polls readable while a connection is queued on it.
            super::SocketReadiness::of(self.socket)
        }
    }

    fn accept(&self) -> Result<Option<WindowsTcpSocket>, LinkOpenError> {
        // SAFETY: a null address and length ask for no peer name; the socket is this listener's
        // own.
        let socket =
            unsafe { ws::accept(self.socket, core::ptr::null_mut(), core::ptr::null_mut()) };
        if socket == ws::INVALID_SOCKET {
            return match last_error() {
                // Nothing waits, or the connection gave up or was lost on the way before it was
                // taken, which leaves nothing to take either.
                ws::WSAEWOULDBLOCK
                | ws::WSAEINTR
                | ws::WSAECONNRESET
                | ws::WSAECONNABORTED
                | ws::WSAENETDOWN
                | ws::WSAENETRESET
                | ws::WSAEHOSTDOWN
                | ws::WSAEHOSTUNREACH
                | ws::WSAENETUNREACH => Ok(None),
                // No socket or buffer to give it: the connection stays queued and a later call
                // tries again, as a full table is retried.
                ws::WSAEMFILE | ws::WSAENOBUFS => Err(LinkOpenError::Exhausted),
                // The listening socket itself is bad: no later call mends it.
                _ => Err(LinkOpenError::Unsupported),
            };
        }
        // Owned from here, so an early return closes it.
        let mut stream = WindowsTcpSocket {
            socket,
            local: self.local,
            peer: self.local,
        };
        // A connection reset between the accept and these calls is one that gave up: nothing to
        // take, and the close above is the answer its peer already has. An accepted socket
        // inherits the listener's non-blocking mode on Windows, which is the mode a dialled one
        // is given too: its reads do not wait, and a write is tried first.
        if !keep_from_children(socket)
            || set_nonblocking(socket, true).is_err()
            || set_flag(socket, ws::IPPROTO_TCP, ws::TCP_NODELAY).is_err()
        {
            return Ok(None);
        }
        let (Ok(local), Ok(peer)) = (
            name_of(socket, ws::getsockname),
            name_of(socket, ws::getpeername),
        ) else {
            return Ok(None);
        };
        stream.local = local;
        stream.peer = peer;
        Ok(Some(stream))
    }
}

impl Drop for WindowsTcpListener {
    fn drop(&mut self) {
        close(self.socket);
    }
}

/// The buffers of `parts`, empty ones left out, and how many there are; more than `MAX_PARTS`, or
/// a part longer than a `u32`, is refused as `WSAEMSGSIZE`.
fn wsabufs(parts: &[&[u8]]) -> Result<([ws::WSABUF; MAX_PARTS], usize), WindowsNetError> {
    let mut bufs = [ws::WSABUF {
        len: 0,
        buf: core::ptr::null_mut(),
    }; MAX_PARTS];
    let mut count = 0;
    for part in parts.iter().filter(|part| !part.is_empty()) {
        let (true, Ok(len)) = (count < MAX_PARTS, u32::try_from(part.len())) else {
            return Err(WindowsNetError::Write(ws::WSAEMSGSIZE));
        };
        bufs[count] = ws::WSABUF {
            len,
            buf: part.as_ptr().cast_mut(),
        };
        count += 1;
    }
    Ok((bufs, count))
}

impl StreamSocket for WindowsTcpSocket {
    type Error = WindowsNetError;

    fn local(&self) -> SocketAddr {
        self.local
    }

    fn peer(&self) -> SocketAddr {
        self.peer
    }

    fn send_parts(&self, parts: &[&[u8]]) -> Result<(), WindowsNetError> {
        // The parts the stack has still to take; a short write moves the front forward.
        let (mut bufs, count) = wsabufs(parts)?;
        let mut first = 0;
        while first < count {
            let mut sent: u32 = 0;
            // SAFETY: every buffer names a live slice of `parts` for its length, and the count
            // passed is the number of them from `first`. No overlapped structure: the call takes
            // what Winsock has room for at that moment, the socket being non-blocking.
            let rc = unsafe {
                ws::WSASend(
                    self.socket,
                    bufs[first..count].as_ptr(),
                    (count - first) as u32,
                    &mut sent,
                    0,
                    core::ptr::null_mut(),
                    None,
                )
            };
            if rc != 0 {
                match last_error() {
                    ws::WSAEINTR => continue,
                    // No room now: this is the write that waits, so it waits for some.
                    ws::WSAEWOULDBLOCK => {
                        poll_writable(self.socket, -1);
                        continue;
                    }
                    other => return Err(WindowsNetError::Write(other)),
                }
            }
            let mut sent = sent as usize;
            while first < count && sent >= bufs[first].len as usize {
                sent -= bufs[first].len as usize;
                first += 1;
            }
            if first < count {
                // SAFETY: `sent` is less than this buffer's length, so the new start is inside it.
                bufs[first].buf = unsafe { bufs[first].buf.add(sent) };
                bufs[first].len -= sent as u32;
            }
        }
        Ok(())
    }

    // One `WSASend` on the non-blocking socket: Winsock takes what it has room for at that
    // moment, and `WSAEWOULDBLOCK` is nothing taken.
    fn send_parts_now(&self, parts: &[&[u8]]) -> Option<Result<usize, WindowsNetError>> {
        let (bufs, count) = match wsabufs(parts) {
            Ok(built) => built,
            Err(refused) => return Some(Err(refused)),
        };
        loop {
            let mut sent: u32 = 0;
            // SAFETY: every buffer names a live slice of `parts` for its length, and `count` is
            // the number of them. No overlapped structure, and the socket is non-blocking, so the
            // call returns at once.
            let rc = unsafe {
                ws::WSASend(
                    self.socket,
                    bufs[..count].as_ptr(),
                    count as u32,
                    &mut sent,
                    0,
                    core::ptr::null_mut(),
                    None,
                )
            };
            if rc == 0 {
                return Some(Ok(sent as usize));
            }
            match last_error() {
                ws::WSAEINTR => continue,
                ws::WSAEWOULDBLOCK => return Some(Ok(0)),
                other => return Some(Err(WindowsNetError::Write(other))),
            }
        }
    }

    fn connected(&mut self) -> Result<bool, WindowsNetError> {
        match self.connect_ended() {
            (_, true) => {
                let error = self.connect_error()?;
                Err(WindowsNetError::Connect(if error == 0 {
                    ws::WSAECONNREFUSED
                } else {
                    error
                }))
            }
            (false, false) => Ok(false),
            (true, false) => {
                self.local =
                    name_of(self.socket, ws::getsockname).map_err(WindowsNetError::SockName)?;
                self.peer =
                    name_of(self.socket, ws::getpeername).map_err(WindowsNetError::PeerName)?;
                Ok(true)
            }
        }
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        poll_readable(self.socket, timeout_ms);
    }

    fn wait_writable(&self, timeout_us: u64) -> bool {
        poll_writable(
            self.socket,
            i32::try_from(timeout_us.div_ceil(1_000)).unwrap_or(i32::MAX),
        )
    }

    // Timed on the host's monotonic clock, as the session's timers are.
    fn wait_writable_timed(&self, timeout_us: u64) -> (bool, u64) {
        let started = super::WindowsClock.now_us();
        let room = self.wait_writable(timeout_us);
        (room, super::WindowsClock.now_us().saturating_sub(started))
    }

    // The socket does not block (it is made so at its connect and its accept), so the read is
    // asked at once and a stream with nothing queued answers `WSAEWOULDBLOCK`: one call, as the
    // POSIX half's `MSG_DONTWAIT` read is, where a poll first made a read of what is queued two.
    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, WindowsNetError> {
        let room = i32::try_from(buf.len()).unwrap_or(i32::MAX);
        // SAFETY: `buf` is live and writable for the length passed; the socket does not block, so
        // the read does not wait.
        let got = unsafe { ws::recv(self.socket, buf.as_mut_ptr(), room, 0) };
        if got == ws::SOCKET_ERROR {
            return match last_error() {
                ws::WSAEWOULDBLOCK | ws::WSAEINTR => Ok(None),
                other => Err(WindowsNetError::Recv(other)),
            };
        }
        Ok(Some(got as usize))
    }

    fn shutdown(&self) {
        // SAFETY: value arguments on this socket's own handle. A stream already shut is not an
        // error worth reporting here: the link is ending either way.
        unsafe { ws::shutdown(self.socket, ws::SD_BOTH) };
    }

    wz_runtime_coop::with_heap_link_seams! {
        #[cfg(feature = "alloc")]
        fn readiness(&self) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
            super::SocketReadiness::of(self.socket)
        }

        #[cfg(feature = "alloc")]
        fn writability(&self) -> Option<alloc::boxed::Box<dyn LinkWritability>> {
            super::SocketReadiness::writable_of(self.socket)
        }
    }
}

impl Drop for WindowsTcpSocket {
    fn drop(&mut self) {
        close(self.socket);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{Ipv4Addr, Ipv6Addr};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;

    /// `port` on the IPv4 loopback.
    fn at(port: u16) -> SocketAddr {
        SocketAddr::from((LOOPBACK, port))
    }

    /// A connection: this module's socket, and the far end as std accepted it.
    fn pair() -> (WindowsTcpSocket, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let port = listener.local_addr().expect("its port").port();
        let near = WindowsTcpSocket::connect(at(port)).expect("a connection");
        let (far, _) = listener.accept().expect("the far end");
        (near, far)
    }

    /// Read until `want` bytes have come, waiting on the socket between reads.
    fn read_exactly(socket: &WindowsTcpSocket, want: usize) -> std::vec::Vec<u8> {
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

    /// Whether `TCP_NODELAY` is on for `socket`.
    fn nodelay_of(socket: ws::SOCKET) -> bool {
        let mut on: i32 = 0;
        let mut len = core::mem::size_of::<i32>() as i32;
        // SAFETY: `on` and `len` are live and writable, and `len` is `on`'s size.
        let rc = unsafe {
            ws::getsockopt(
                socket,
                ws::IPPROTO_TCP,
                ws::TCP_NODELAY,
                (&mut on as *mut i32).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0);
        on != 0
    }

    /// A listener on a port the system picked, and that port.
    fn listening() -> (WindowsTcpListener, u16) {
        let listener = WindowsTcpListener::bind(at(0)).expect("a listener");
        let local = listener.local();
        assert_eq!(local.ip(), LOOPBACK);
        assert_ne!(local.port(), 0, "the system's choice is read back");
        (listener, local.port())
    }

    /// The connection `listener` has waiting, polled until it comes.
    fn accepted(listener: &WindowsTcpListener) -> WindowsTcpSocket {
        for _ in 0..200 {
            if let Some(socket) = listener.accept().expect("a sound listener") {
                return socket;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("no connection arrived");
    }

    #[test]
    fn a_connection_names_both_its_ends_and_has_nagle_off() {
        let (near, far) = pair();
        assert_eq!(near.peer(), far.local_addr().unwrap());
        assert_eq!(near.local(), far.peer_addr().unwrap());
        assert!(nodelay_of(near.socket));
    }

    /// Needs the host's IPv6 loopback.
    #[test]
    fn an_ipv6_connection_and_listener_name_their_ends_in_their_family() {
        let far = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).expect("an IPv6 listener");
        let near = WindowsTcpSocket::connect(far.local_addr().unwrap()).expect("a connection");
        let (_taken, from) = far.accept().expect("the far end");
        assert_eq!(near.peer(), far.local_addr().unwrap());
        assert_eq!(near.local(), from);

        let listener = WindowsTcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)))
            .expect("a listener");
        assert!(listener.local().is_ipv6());
        let dialler = TcpStream::connect(listener.local()).expect("a connection");
        let accepted = accepted(&listener);
        assert_eq!(accepted.peer(), dialler.local_addr().unwrap());
        assert_eq!(accepted.local(), listener.local());
    }

    #[test]
    fn a_family_the_system_lacks_is_unsupported_and_other_failures_are_not() {
        assert_eq!(
            open_refused(WindowsNetError::Socket(ws::WSAEAFNOSUPPORT)),
            LinkOpenError::Unsupported
        );
        assert_eq!(
            open_refused(WindowsNetError::Socket(ws::WSAEMFILE)),
            LinkOpenError::Exhausted
        );
        assert_eq!(
            open_refused(WindowsNetError::Startup(ws::WSAEINVAL)),
            LinkOpenError::Exhausted
        );
        assert_eq!(
            open_refused(WindowsNetError::Connect(ws::WSAECONNREFUSED)),
            LinkOpenError::Refused
        );
    }

    /// A loopback port that refuses every connect for as long as the value lives: a TCP socket
    /// bound and never listening, which holds the number so no other `bind(:0)` is handed it.
    /// The shape of `wz_runtime_tokio_test_support::refusing_port`, over this module's own Winsock
    /// calls: that crate pulls the tokio runtime, and with it `wz-session-core/alloc`, which feature
    /// unification would put into this crate's no-allocator test build.
    struct RefusingPort {
        socket: ws::SOCKET,
        port: u16,
    }

    impl RefusingPort {
        fn hold() -> Self {
            let socket =
                open_socket(&at(0), ws::SOCK_STREAM, ws::IPPROTO_TCP).expect("a TCP socket");
            let raw = RawAddr::of(at(0));
            // SAFETY: `raw` is a live socket address of the length passed.
            let rc = unsafe { ws::bind(socket, raw.as_ptr(), raw.size()) };
            assert_eq!(rc, 0, "bind without listen");
            let port = name_of(socket, ws::getsockname)
                .expect("the bound number")
                .port();
            Self { socket, port }
        }
    }

    impl Drop for RefusingPort {
        fn drop(&mut self) {
            close(self.socket);
        }
    }

    /// A connect begun without waiting is made once the listener has it, names both its ends from
    /// then on and carries bytes; one to a port nobody listens on is refused, at once or when it is
    /// asked: Windows retries a refused connect for a while, so the refusal comes late.
    #[test]
    fn a_connect_begun_without_waiting_is_made_or_refused_when_asked() {
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let port = listener.local_addr().expect("its port").port();
        let mut near = WindowsTcpSocket::connect_started(at(port)).expect("a connect begun");
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
        match WindowsTcpSocket::connect_started(at(held.port)) {
            Err(WindowsNetError::Connect(e)) => assert_eq!(e, ws::WSAECONNREFUSED),
            Err(other) => panic!("a different error: {other:?}"),
            Ok(mut refused) => {
                let until = Instant::now() + Duration::from_secs(15);
                loop {
                    match refused.connected() {
                        Ok(false) => {
                            assert!(Instant::now() < until, "the refusal never came");
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(WindowsNetError::Connect(e)) => {
                            assert_eq!(e, ws::WSAECONNREFUSED);
                            break;
                        }
                        other => panic!("a connect to a port nobody listens on: {other:?}"),
                    }
                }
            }
        }
    }

    #[test]
    fn a_connection_to_a_port_nobody_listens_on_is_refused() {
        let held = RefusingPort::hold();
        match WindowsTcpSocket::connect(at(held.port)) {
            Err(WindowsNetError::Connect(e)) => assert_eq!(e, ws::WSAECONNREFUSED),
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
    fn more_parts_than_one_write_gathers_are_refused() {
        let (near, _far) = pair();
        assert_eq!(
            near.send_parts(&[b"a", b"b", b"c", b"d", b"e"]),
            Err(WindowsNetError::Write(ws::WSAEMSGSIZE))
        );
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

    /// A write that does not wait takes what the stream has room for and says how much: all of a
    /// write to a stream with room, in order, and nothing once the peer has stopped reading and
    /// the stacks hold all they will (`WSAEWOULDBLOCK`), which it answers at once where the write
    /// that waits would wait for the peer.
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

    #[test]
    fn a_read_takes_what_is_queued_and_says_nothing_yet_without_blocking() {
        let (near, mut far) = pair();
        let mut buf = [0u8; 16];
        assert_eq!(near.try_read(&mut buf), Ok(None));
        far.write_all(b"hello").expect("a write");
        assert_eq!(read_exactly(&near, 5), b"hello");
        assert_eq!(near.try_read(&mut buf), Ok(None), "and then nothing");
    }

    /// A read asks the stream once, with no poll before it: the socket does not block, so a read
    /// of nothing is the stream's own answer and a read of what is queued takes it in the one
    /// call. Two reads and a wait here make one poll, the wait's, where a poll before each read
    /// made three. The CONTROL is the wait, which polls.
    #[test]
    fn a_read_asks_the_stream_with_no_poll_before_it() {
        let (near, mut far) = pair();
        let mut buf = [0u8; 16];
        let polls = super::super::readable_polls();
        assert_eq!(near.try_read(&mut buf), Ok(None), "nothing queued yet");
        assert_eq!(
            super::super::readable_polls(),
            polls,
            "a read of nothing polls nothing"
        );
        far.write_all(b"hello").expect("a write");
        near.wait_readable(1000);
        assert_eq!(
            super::super::readable_polls(),
            polls + 1,
            "CONTROL: the wait polls"
        );
        let got = near
            .try_read(&mut buf)
            .expect("no error")
            .expect("the wait said bytes are queued");
        assert!(
            got > 0 && buf[..got] == b"hello"[..got],
            "{:?}",
            &buf[..got]
        );
        assert_eq!(
            super::super::readable_polls(),
            polls + 1,
            "the read of what is queued polls nothing"
        );
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
    fn an_accept_with_no_connection_waiting_answers_at_once() {
        let (listener, _) = listening();
        for _ in 0..3 {
            assert!(matches!(listener.accept(), Ok(None)));
        }
    }

    /// An accepted socket inherits the listener's non-blocking mode on Windows and keeps it: its
    /// reads do not wait, and the write that waits still writes a MiB whole, waiting for room as
    /// the far end reads.
    #[test]
    fn an_accepted_connection_is_a_stream_in_both_directions_and_its_reads_do_not_block() {
        let (listener, port) = listening();
        let mut far = TcpStream::connect(("127.0.0.1", port)).expect("a connection");
        let near = accepted(&listener);
        assert_eq!(near.local(), at(port));
        assert_eq!(near.peer(), far.local_addr().unwrap());
        assert!(nodelay_of(near.socket));
        let mut buf = [0u8; 16];
        assert_eq!(near.try_read(&mut buf), Ok(None));
        far.write_all(b"hello").expect("a write");
        assert_eq!(read_exactly(&near, 5), b"hello");
        let big = std::vec![0x17u8; 1 << 20];
        let reader = std::thread::spawn(move || {
            let mut got = std::vec![0u8; 1 << 20];
            far.read_exact(&mut got).expect("the bytes");
            got
        });
        near.send_parts(&[&big[..]])
            .expect("a send of one MiB that waits for room");
        assert_eq!(reader.join().expect("the reader"), big);
    }

    #[test]
    fn a_connection_closed_before_it_is_taken_still_comes_and_reads_as_ended() {
        let (listener, port) = listening();
        drop(TcpStream::connect(("127.0.0.1", port)).expect("a connection"));
        let near = accepted(&listener);
        near.wait_readable(1000);
        let mut buf = [0u8; 16];
        assert_eq!(near.try_read(&mut buf), Ok(Some(0)));
    }

    #[test]
    fn a_closed_listener_frees_its_port_for_the_next() {
        let (listener, port) = listening();
        let far = TcpStream::connect(("127.0.0.1", port)).expect("a connection");
        let near = accepted(&listener);
        drop(listener);
        drop(near);
        drop(far);
        WindowsTcpListener::bind(at(port)).expect("the closed connections do not hold the port");
    }

    wz_runtime_coop::with_heap_link_seams! {
        /// The wait for room handed to another thread answers as the socket's own wait does: it
        /// has room while the stream takes bytes, and none once the peer has stopped reading.
        #[cfg(feature = "alloc")]
        #[test]
        fn the_wait_for_room_handed_out_answers_as_the_socket_does() {
            let (near, _far) = pair();
            let wait = near.writability().expect("a duplicate of the socket");
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
}
