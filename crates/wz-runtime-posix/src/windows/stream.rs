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
//! The socket blocks on a write and never on a read, as the POSIX half's does: a write returns
//! once Winsock has taken every byte (a length and its batch go out in one `WSASend`), and a read
//! takes only what `WSAPoll` reported, the loop's wait being the poll of
//! [`StreamSocket::wait_readable`]. `TCP_NODELAY` is set, as zenoh and zenoh-pico set it on every
//! TCP link (`vendor/zenoh-pico/src/link/transport/tcp/tcp_windows.c` @
//! `IPPROTO_TCP, TCP_NODELAY`).

use core::ffi::c_int;
use core::net::SocketAddr;

use windows_sys::Win32::Networking::WinSock as ws;
use wz_runtime_coop::session_drive::LinkOpenError;
use wz_runtime_coop::stream_link::{StreamDial, StreamListen, StreamSocket};

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
        this.local = name_of(socket, ws::getsockname).map_err(WindowsNetError::SockName)?;
        this.peer = name_of(socket, ws::getpeername).map_err(WindowsNetError::PeerName)?;
        Ok(this)
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
        // inherits the listener's non-blocking mode on Windows, so it is made blocking here, as a
        // dialled one is: its reads take only what the poll reported and its writes wait for
        // Winsock.
        if !keep_from_children(socket)
            || set_nonblocking(socket, false).is_err()
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
        let mut first = 0;
        while first < count {
            let mut sent: u32 = 0;
            // SAFETY: every buffer names a live slice of `parts` for its length, and the count
            // passed is the number of them from `first`. No overlapped structure: the call
            // blocks until Winsock has taken the bytes.
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

    fn wait_readable(&self, timeout_ms: c_int) {
        poll_readable(self.socket, timeout_ms);
    }

    fn wait_writable(&self, timeout_us: u64) -> bool {
        poll_writable(
            self.socket,
            i32::try_from(timeout_us.div_ceil(1_000)).unwrap_or(i32::MAX),
        )
    }

    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, WindowsNetError> {
        if !poll_readable(self.socket, 0) {
            return Ok(None);
        }
        let room = i32::try_from(buf.len()).unwrap_or(i32::MAX);
        // SAFETY: `buf` is live and writable for the length passed. The poll reported input (bytes,
        // the end of the stream, or an error), so the read does not wait.
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
    fn an_accept_with_no_connection_waiting_answers_at_once() {
        let (listener, _) = listening();
        for _ in 0..3 {
            assert!(matches!(listener.accept(), Ok(None)));
        }
    }

    /// An accepted socket inherits the listener's non-blocking mode on Windows; it is made
    /// blocking, and its reads still do not wait.
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
            .expect("a blocking send of one MiB");
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
