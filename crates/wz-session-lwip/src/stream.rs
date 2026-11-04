// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The cooperative engine's TCP stream over lwIP (`tcp` feature): [`LwipTcpStream`] is a
//! [`StreamSocket`] and [`LwipTcpDial`] a [`StreamDial`], so the stream link
//! ([`StreamDriver`](wz_runtime_coop::stream_link::StreamDriver)) and everything above it, written
//! once for every stack with sockets, runs over `wz_link_lwip::tcp::LwipTcpSocket`.
//!
//! ## Blocking on a stack that has no threads
//!
//! The contract of a [`StreamSocket`] blocks: a write returns when the stack has taken every byte,
//! a wait returns when bytes are queued or the time is out. lwIP here runs `NO_SYS`, on the one
//! thread that drives the session, and nothing happens in it until it is polled. So each wait is a
//! loop that POLLS lwIP (its input path and its timers, which are what move a TCP connection:
//! acknowledgements, retransmission) until the thing it waits for has happened or the time is out.
//! Time is the port's own millisecond clock, the one lwIP's timers run on
//! ([`LwipLink::now_ms`]), so a stalled peer ends a wait on the target as it does on the host.

use core::cell::RefCell;
use core::ffi::c_int;
use core::ops::Deref;

#[cfg(feature = "static-link-storage")]
use wz_link_lwip::tcp::TcpSocketPool;
use wz_link_lwip::tcp::{LwipTcpListener, LwipTcpSocket, TcpError, TcpState};
use wz_link_lwip::{ipv4_addr_from_octets, ipv4_octets, route_source, LwipLink};
use wz_runtime_coop::session_drive::LinkOpenError;
use wz_runtime_coop::stream_link::{StreamDial, StreamListen, StreamSocket};

/// How long a dial waits for the handshake before it gives the link up.
pub const DIAL_TIMEOUT_MS: u32 = 5_000;

/// How long a write waits for send-buffer room before it reports the stall.
pub const SEND_TIMEOUT_MS: u32 = 5_000;

/// Poll lwIP once: the input path, then the timers.
fn pump(link: &LwipLink) {
    link.poll_loopback();
    link.check_timeouts();
}

/// One connected IPv4 stream over lwIP, with a receive buffer of `RX` bytes (at least the port's
/// receive window: [`LwipTcpSocket::connect`] refuses less).
pub struct LwipTcpStream<L, const RX: usize>
where
    L: Deref<Target = LwipLink> + Clone,
{
    socket: RefCell<LwipTcpSocket<RX>>,
    link: L,
    peer: ([u8; 4], u16),
}

impl<L, const RX: usize> StreamSocket for LwipTcpStream<L, RX>
where
    L: Deref<Target = LwipLink> + Clone,
{
    type Error = TcpError;

    fn local(&self) -> ([u8; 4], u16) {
        let addr = route_source(ipv4_addr_from_octets(self.peer.0)).map_or([0; 4], ipv4_octets);
        (addr, self.socket.borrow().local_port())
    }

    fn peer(&self) -> ([u8; 4], u16) {
        self.peer
    }

    fn send_parts(&self, parts: &[&[u8]]) -> Result<(), TcpError> {
        let started = self.link.now_ms();
        loop {
            match self.socket.borrow_mut().send_parts(parts) {
                Err(TcpError::WouldBlock)
                    if self.link.now_ms().wrapping_sub(started) < SEND_TIMEOUT_MS =>
                {
                    // The send buffer drains as the peer acknowledges: poll lwIP and ask again.
                    pump(&self.link);
                }
                other => return other,
            }
        }
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        let started = self.link.now_ms();
        loop {
            {
                let socket = self.socket.borrow();
                // Bytes queued, or a connection that has nothing more to give: a read that
                // follows reports which.
                if socket.readable() > 0 || socket.state() != TcpState::Open {
                    return;
                }
            }
            // A negative timeout waits for as long as it takes.
            if timeout_ms >= 0
                && self.link.now_ms().wrapping_sub(started) >= timeout_ms.unsigned_abs()
            {
                return;
            }
            pump(&self.link);
        }
    }

    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, TcpError> {
        pump(&self.link);
        self.socket.borrow_mut().try_read(buf)
    }

    fn shutdown(&self) {
        self.socket.borrow_mut().shutdown();
        // The FIN goes out with the next poll.
        pump(&self.link);
    }
}

/// How a node opens its `tcp/` links over lwIP: a value the stack holds, so the stack and the
/// stream link stay written once.
pub struct LwipTcpDial<L, const RX: usize, const S: usize = 0>
where
    L: Deref<Target = LwipLink> + Clone,
{
    link: L,
    /// `static-link-storage`: the cells a connection is made in.
    #[cfg(feature = "static-link-storage")]
    pool: &'static TcpSocketPool<RX, S>,
}

impl<L, const RX: usize, const S: usize> LwipTcpDial<L, RX, S>
where
    L: Deref<Target = LwipLink> + Clone,
{
    /// A dial over `link`, making each connection on the heap.
    #[cfg(not(feature = "static-link-storage"))]
    pub fn new(link: L) -> Self {
        Self { link }
    }

    /// A dial over `link`, making each connection in a cell of `pool`.
    #[cfg(feature = "static-link-storage")]
    pub fn new(link: L, pool: &'static TcpSocketPool<RX, S>) -> Self {
        Self { link, pool }
    }
}

/// What a failed connect means to the stack: a table without room is worth a retry, a receive
/// buffer smaller than the window is a fault of the image's configuration and no retry cures it,
/// and anything else is the other end not taking the link.
fn open_error(why: TcpError) -> LinkOpenError {
    match why {
        TcpError::PcbExhausted | TcpError::SlotsExhausted => LinkOpenError::Exhausted,
        TcpError::RxBelowWindow { .. } => LinkOpenError::Unsupported,
        _ => LinkOpenError::Refused,
    }
}

impl<L, const RX: usize, const S: usize> StreamDial for LwipTcpDial<L, RX, S>
where
    L: Deref<Target = LwipLink> + Clone,
{
    type Stream = LwipTcpStream<L, RX>;

    fn dial(&self, addr: [u8; 4], port: u16) -> Result<Self::Stream, LinkOpenError> {
        #[cfg(not(feature = "static-link-storage"))]
        let socket = LwipTcpSocket::<RX>::connect(&self.link, addr, port);
        #[cfg(feature = "static-link-storage")]
        let socket = LwipTcpSocket::<RX>::connect_in(&self.link, addr, port, self.pool);
        let socket = socket.map_err(open_error)?;

        // The handshake completes as lwIP is polled.
        let started = self.link.now_ms();
        loop {
            match socket.state() {
                TcpState::Open => break,
                TcpState::Connecting => {}
                // Refused (reset), or ended before it began: the socket drops and frees its cell.
                TcpState::PeerClosed | TcpState::Failed(_) => return Err(LinkOpenError::Refused),
            }
            if self.link.now_ms().wrapping_sub(started) >= DIAL_TIMEOUT_MS {
                return Err(LinkOpenError::Refused);
            }
            pump(&self.link);
        }
        Ok(LwipTcpStream {
            socket: RefCell::new(socket),
            link: self.link.clone(),
            peer: (addr, port),
        })
    }
}

/// The slot profile's stack of a node whose links are all `tcp/`: the engine's own `IpStack`,
/// which claims each link's buffers from the image's byte tables and yields the driver the session
/// host runs, over lwIP's stream and with no datagram socket (a `udp/` dial is
/// [`LinkOpenError::Unsupported`], before any buffer is claimed). Its dial is [`LwipTcpDial`] and
/// its acceptor `stack.acceptor(LwipTcpListen::new(..))`.
#[cfg(feature = "session-slot")]
pub type LwipTcpStack<L, const RX: usize, const S: usize = 0> = wz_runtime_coop::ip_stack::IpStack<
    wz_runtime_coop::udp_link::NoDatagram,
    LwipTcpDial<L, RX, S>,
>;

/// How a node takes the `tcp/` connections that arrive on the port it listens on: the other half of
/// [`LwipTcpDial`]. The connection it yields is the same [`LwipTcpStream`] a dial yields, so the
/// stream link over it has nothing to tell which end opened it.
///
/// The listener is a `static` the image declares and starts
/// ([`LwipTcpListener::listen`](wz_link_lwip::tcp::LwipTcpListener::listen)); this holds a
/// reference to it and the handle to lwIP that each accept polls.
pub struct LwipTcpListen<L, const RX: usize, const Q: usize, const S: usize = 0>
where
    L: Deref<Target = LwipLink> + Clone,
{
    link: L,
    listener: &'static LwipTcpListener<RX, Q, S>,
}

impl<L, const RX: usize, const Q: usize, const S: usize> LwipTcpListen<L, RX, Q, S>
where
    L: Deref<Target = LwipLink> + Clone,
{
    /// Take the connections of `listener`, polling lwIP through `link`.
    pub fn new(link: L, listener: &'static LwipTcpListener<RX, Q, S>) -> Self {
        Self { link, listener }
    }
}

impl<L, const RX: usize, const Q: usize, const S: usize> StreamListen for LwipTcpListen<L, RX, Q, S>
where
    L: Deref<Target = LwipLink> + Clone,
{
    type Stream = LwipTcpStream<L, RX>;

    fn local(&self) -> ([u8; 4], u16) {
        // Bound to every address: the port is what names it.
        ([0; 4], self.listener.local_port())
    }

    fn accept(&self) -> Result<Option<Self::Stream>, LinkOpenError> {
        // A connection arrives as its handshake is processed.
        pump(&self.link);
        Ok(self.listener.accept().map(|socket| {
            let peer = socket.peer();
            LwipTcpStream {
                socket: RefCell::new(socket),
                link: self.link.clone(),
                peer,
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ffi::c_void;
    use core::ptr;
    use std::sync::Mutex;
    use std::vec::Vec;

    use lwip_sys::{
        err_t, pbuf, pbuf_copy_partial, pbuf_free, tcp_accept, tcp_bind, tcp_close,
        tcp_listen_with_backlog, tcp_new, tcp_output, tcp_pcb, tcp_recv, tcp_recved, tcp_write,
    };
    use wz_link_lwip::lwip_test_link;
    use wz_runtime_coop::session_drive::LinkProto;

    use super::*;

    const RX: usize = 4096;

    /// An echo server on `port` (raw API, the same stack): whatever arrives is written back, and
    /// `bye` ends the connection from the server's side.
    fn server(port: u16) {
        static MADE: Mutex<Vec<u16>> = Mutex::new(Vec::new());
        let mut made = MADE.lock().unwrap_or_else(|p| p.into_inner());
        if made.contains(&port) {
            return;
        }
        made.push(port);

        unsafe extern "C" fn accept(_: *mut c_void, new: *mut tcp_pcb, _: err_t) -> err_t {
            // SAFETY: a freshly accepted control block.
            unsafe { tcp_recv(new, Some(echo)) };
            0
        }
        unsafe extern "C" fn echo(
            _: *mut c_void,
            pcb: *mut tcp_pcb,
            p: *mut pbuf,
            _: err_t,
        ) -> err_t {
            // SAFETY: lwIP's callback contract: `pcb` live, `p` a chain or null.
            unsafe {
                if p.is_null() {
                    tcp_close(pcb);
                    return 0;
                }
                let len = (*p).tot_len;
                let mut bytes = [0u8; 4096];
                pbuf_copy_partial(p, bytes.as_mut_ptr().cast(), len, 0);
                tcp_recved(pcb, len);
                pbuf_free(p);
                if &bytes[..usize::from(len)] == b"bye" {
                    tcp_close(pcb);
                    return 0;
                }
                tcp_write(pcb, bytes.as_ptr().cast(), len, 1);
                tcp_output(pcb);
            }
            0
        }
        // SAFETY: a listener for the life of the process, on the one thread that drives lwIP.
        unsafe {
            let pcb = tcp_new();
            assert_eq!(tcp_bind(pcb, ptr::null(), port), 0);
            let listener = tcp_listen_with_backlog(pcb, 2);
            assert!(!listener.is_null());
            tcp_accept(listener, Some(accept));
        }
    }

    #[cfg(not(feature = "static-link-storage"))]
    fn dial(link: &LwipLink) -> LwipTcpDial<&LwipLink, RX> {
        LwipTcpDial::new(link)
    }

    #[test]
    fn a_dial_yields_a_stream_that_writes_waits_and_reads_like_a_socket() {
        let (_gate, link) = lwip_test_link();
        server(47_301);
        let stream = dial(&link).dial([127, 0, 0, 1], 47_301).expect("dial");
        assert_eq!(stream.peer(), ([127, 0, 0, 1], 47_301));
        assert_ne!(stream.local().1, 0, "the stack picked a local port");
        assert_eq!(
            <LwipTcpStream<&LwipLink, RX> as StreamSocket>::PROTO,
            LinkProto::Tcp
        );

        assert_eq!(stream.try_read(&mut [0; 8]), Ok(None), "nothing yet");
        stream.send_parts(&[b"he", b"llo"]).unwrap();
        stream.wait_readable(2_000);
        let mut got = [0u8; 8];
        assert_eq!(stream.try_read(&mut got), Ok(Some(5)));
        assert_eq!(&got[..5], b"hello");

        // A wait with nothing coming ends at its time and not before the time is up.
        let before = link.now_ms();
        stream.wait_readable(120);
        let waited = link.now_ms().wrapping_sub(before);
        assert!((100..2_000).contains(&waited), "waited {waited} ms");
    }

    #[test]
    fn a_peer_that_closes_reads_as_the_end_of_the_stream() {
        let (_gate, link) = lwip_test_link();
        server(47_302);
        let stream = dial(&link).dial([127, 0, 0, 1], 47_302).expect("dial");
        stream.send_parts(&[b"bye"]).unwrap();
        stream.wait_readable(2_000);
        assert_eq!(stream.try_read(&mut [0; 8]), Ok(Some(0)));
        stream.shutdown();
    }

    #[test]
    fn a_dial_to_a_port_nobody_listens_on_is_refused() {
        let (_gate, link) = lwip_test_link();
        let refused = dial(&link).dial([127, 0, 0, 1], 47_399);
        assert!(matches!(refused, Err(LinkOpenError::Refused)));
    }

    /// The stream link over lwIP, end to end: the driver length-prefixes a batch, the echo sends
    /// the bytes back, and the driver hands the session the batch whole.
    #[cfg(all(not(feature = "static-link-storage"), not(feature = "session-slot")))]
    #[test]
    fn the_stream_link_frames_a_batch_over_lwip() {
        use wz_runtime_coop::link_storage::HeapTx;
        use wz_runtime_coop::session_drive::SessionDatagramLink;
        use wz_runtime_coop::stream_link::StreamDriver;
        use wz_session_core::link::BoxedLinkDriver;
        use wz_session_core::reliability::Reliability;

        let (_gate, link) = lwip_test_link();
        // The link driver is `'static` (it is a slot's driver on a node), so its stream holds a
        // `'static` handle: the witness is a zero-sized value, leaked here.
        let link: &'static LwipLink = std::boxed::Box::leak(std::boxed::Box::new(link));
        server(47_303);
        let stream = dial(link).dial([127, 0, 0, 1], 47_303).expect("dial");
        let driver = StreamDriver::with_buffers(stream, 2_048, HeapTx::new(2, 2_048));

        let batch = [7u8; 300];
        assert!(matches!(
            driver.send_blocking(&batch, Reliability::Reliable),
            wz_session_core::link::LinkSendOutcome::Sent
        ));
        let mut got: Option<Vec<u8>> = None;
        for _ in 0..4_000 {
            driver.service();
            driver.recv_with(&mut |bytes| got = Some(bytes.to_vec()));
            if got.is_some() {
                break;
            }
        }
        assert_eq!(
            got.as_deref(),
            Some(&batch[..]),
            "the batch came back whole"
        );
        assert_eq!(driver.lost(), None);
    }

    #[cfg(all(not(feature = "static-link-storage"), not(feature = "session-slot")))]
    static LISTENER: LwipTcpListener<RX, 2> = LwipTcpListener::new();

    /// Both ends of a connection are the same stream: a dial and an accept yield streams that the
    /// stream link frames alike, and a batch crosses each way, whole, with the accepted end
    /// knowing its peer.
    #[cfg(all(not(feature = "static-link-storage"), not(feature = "session-slot")))]
    #[test]
    fn a_dialled_and_an_accepted_stream_carry_batches_both_ways_through_the_stream_link() {
        use wz_runtime_coop::link_storage::HeapTx;
        use wz_runtime_coop::session_drive::SessionDatagramLink;
        use wz_runtime_coop::stream_link::StreamDriver;
        use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome};
        use wz_session_core::reliability::Reliability;

        let (_gate, link) = lwip_test_link();
        let link: &'static LwipLink = std::boxed::Box::leak(std::boxed::Box::new(link));
        LISTENER.listen(47_501).unwrap();
        let listen = LwipTcpListen::new(link, &LISTENER);
        assert_eq!(listen.local(), ([0; 4], 47_501));
        assert!(matches!(listen.accept(), Ok(None)), "nothing has arrived");

        let dialled = dial(link).dial([127, 0, 0, 1], 47_501).expect("dial");
        let dialled_port = dialled.local().1;
        let mut accepted = None;
        for _ in 0..4_000 {
            if let Some(stream) = listen.accept().expect("the listener is sound") {
                accepted = Some(stream);
                break;
            }
        }
        let accepted = accepted.expect("the connection that arrived");
        assert_eq!(accepted.peer(), ([127, 0, 0, 1], dialled_port));

        let client = StreamDriver::with_buffers(dialled, 2_048, HeapTx::new(2, 2_048));
        let server = StreamDriver::with_buffers(accepted, 2_048, HeapTx::new(2, 2_048));

        fn carry(
            from: &impl BoxedLinkDriver,
            to: &impl SessionDatagramLink,
            batch: &[u8],
        ) -> Option<Vec<u8>> {
            assert!(matches!(
                from.send_blocking(batch, Reliability::Reliable),
                LinkSendOutcome::Sent
            ));
            let mut got = None;
            for _ in 0..4_000 {
                to.service();
                to.recv_with(&mut |bytes| got = Some(bytes.to_vec()));
                if got.is_some() {
                    break;
                }
            }
            got
        }
        assert_eq!(
            carry(&client, &server, &[1u8; 300]).as_deref(),
            Some(&[1u8; 300][..]),
            "client to server"
        );
        assert_eq!(
            carry(&server, &client, &[9u8; 500]).as_deref(),
            Some(&[9u8; 500][..]),
            "server to client"
        );
        assert_eq!(client.lost(), None);
        assert_eq!(server.lost(), None);
    }

    #[cfg(feature = "session-slot")]
    static SLOT_LISTENER: LwipTcpListener<RX, 2> = LwipTcpListener::new();
    #[cfg(feature = "session-slot")]
    static SLOT_RX: wz_session_core::byte_cells::ByteCells<2_050, 2> =
        wz_session_core::byte_cells::ByteCells::new();
    #[cfg(feature = "session-slot")]
    static SLOT_TX: wz_session_core::byte_cells::ByteCells<2_050, 2> =
        wz_session_core::byte_cells::ByteCells::new();

    /// The engine's slot stack over lwIP's streams: a `tcp/` dial and an accept yield the drivers a
    /// session host runs, the buffers of both from the image's tables, a `udp/` dial is refused as
    /// unsupported before a buffer is claimed, and a batch crosses each way through the drivers.
    #[cfg(all(feature = "session-slot", not(feature = "static-link-storage")))]
    #[test]
    fn a_tcp_only_slot_stack_dials_and_accepts_tcp_and_refuses_udp_as_unsupported() {
        use wz_runtime_coop::ip_stack::IpDriver;
        use wz_runtime_coop::session_drive::{
            Accept, Bind, IpEndpoint, Locator, SessionDatagramLink,
        };
        use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome};
        use wz_session_core::reliability::Reliability;

        let (_gate, link) = lwip_test_link();
        let link: &'static LwipLink = std::boxed::Box::leak(std::boxed::Box::new(link));
        SLOT_LISTENER.listen(47_601).unwrap();

        let mut stack = LwipTcpStack::<&'static LwipLink, RX>::new(
            [127, 0, 0, 1],
            &SLOT_RX,
            &SLOT_TX,
            LwipTcpDial::new(link),
        );
        let router = IpEndpoint {
            addr: [127, 0, 0, 1],
            port: 47_601,
        };
        assert!(
            matches!(
                stack.bind(Locator::udp(router)),
                Err(LinkOpenError::Unsupported)
            ),
            "no datagram socket: permanent, and nothing claimed"
        );
        assert_eq!(SLOT_RX.in_use() + SLOT_TX.in_use(), 0);

        let mut acceptor = stack.acceptor(LwipTcpListen::new(link, &SLOT_LISTENER));
        let client = stack.bind(Locator::tcp(router)).expect("a tcp/ link");
        assert!(matches!(client, IpDriver::Tcp(_)));
        let mut server = None;
        for _ in 0..4_000 {
            if let Some(driver) = acceptor.accept().expect("the listener is sound") {
                server = Some(driver);
                break;
            }
        }
        let server = server.expect("the connection that arrived");
        assert_eq!(SLOT_RX.in_use(), 2, "both links took a receive buffer");

        fn carry(
            from: &impl BoxedLinkDriver,
            to: &impl SessionDatagramLink,
            batch: &[u8],
        ) -> Option<Vec<u8>> {
            assert!(matches!(
                from.send_blocking(batch, Reliability::Reliable),
                LinkSendOutcome::Sent
            ));
            let mut got = None;
            for _ in 0..4_000 {
                to.service();
                to.recv_with(&mut |bytes| got = Some(bytes.to_vec()));
                if got.is_some() {
                    break;
                }
            }
            got
        }
        assert_eq!(
            carry(&client, &server, &[3u8; 400]).as_deref(),
            Some(&[3u8; 400][..]),
            "client to server"
        );
        assert_eq!(
            carry(&server, &client, &[4u8; 700]).as_deref(),
            Some(&[4u8; 700][..]),
            "server to client"
        );
    }
}
