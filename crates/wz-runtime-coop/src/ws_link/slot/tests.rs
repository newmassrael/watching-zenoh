// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

extern crate std;

use core::cell::{Cell, RefCell};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::collections::VecDeque;
use std::rc::Rc;
use std::vec::Vec;

use wz_session_core::byte_cells::ByteCells;
use wz_session_core::entropy::EntropyUnavailable;
use wz_session_core::link::{BoxedLinkDriver, LinkEndsText};
use wz_session_core::ws_link::{
    accept_value, client_key, read_request, write_request, write_response, RequestRead,
};

use super::*;
use crate::session_drive::{LinkProto, SessionDatagramLink};
use crate::stream_link::{NoDial, NoStream, StreamEnds};
use crate::udp_link::NoDatagram;

/// The test's clock, which a wait for input moves on by the time it waited.
type Clock = Rc<Cell<u64>>;

/// One TCP connection of the test: what its peer sent and the link has still to read, and what
/// the link wrote.
struct Net {
    inbox: RefCell<VecDeque<u8>>,
    outbox: RefCell<Vec<u8>>,
    clock: Clock,
}

impl Net {
    fn new(clock: &Clock) -> Rc<Self> {
        Rc::new(Self {
            inbox: RefCell::new(VecDeque::new()),
            outbox: RefCell::new(Vec::new()),
            clock: Rc::clone(clock),
        })
    }

    fn send(&self, bytes: &[u8]) {
        self.inbox.borrow_mut().extend(bytes.iter().copied());
    }

    fn written(&self) -> Vec<u8> {
        self.outbox.borrow().clone()
    }
}

/// The end of a connection to `peer` over `Net`.
struct Conn(Rc<Net>, SocketAddr);

impl StreamSocket for Conn {
    type Error = ();

    type Link<
        B: crate::link_storage::RxStore + 'static,
        X: crate::link_storage::TxStore + 'static,
        W: crate::session_drive::InputWaiter,
    >
        = StreamDriver<Self, B, X, crate::stream_link::LengthPrefix, W>
    where
        Self: 'static;

    fn ends(&self) -> StreamEnds<'_> {
        StreamEnds::Ip {
            proto: LinkProto::Tcp,
            local: SocketAddr::from(([10, 0, 0, 2], 40_002)),
            peer: self.1,
        }
    }

    fn write(&self, bytes: &[u8]) -> Result<usize, ()> {
        self.0.outbox.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        let waited = u64::try_from(timeout_ms).unwrap_or(0) * 1_000;
        self.0.clock.set(self.0.clock.get() + waited);
    }

    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, ()> {
        let mut inbox = self.0.inbox.borrow_mut();
        if inbox.is_empty() {
            return Ok(None);
        }
        let read = buf.len().min(inbox.len());
        for (slot, byte) in buf.iter_mut().zip(inbox.drain(..read)) {
            *slot = byte;
        }
        Ok(Some(read))
    }

    fn shutdown(&self) {}
}

/// A dial whose every connection is `net`, but one to [`REFUSING`]; `V6` false is a stack with
/// no IPv6.
struct Dial<const V6: bool = true>(Rc<Net>);

const REFUSING: u16 = 9;

impl<const V6: bool> StreamDial for Dial<V6> {
    type Stream = Conn;

    const IPV6: bool = V6;

    fn dial(&self, to: SocketAddr) -> Result<Conn, LinkOpenError> {
        if to.port() == REFUSING {
            return Err(LinkOpenError::Refused);
        }
        Ok(Conn(Rc::clone(&self.0), to))
    }
}

/// The connections waiting on a port, in order.
struct Port(Rc<RefCell<VecDeque<Conn>>>);

impl StreamListen for Port {
    type Stream = Conn;

    fn local(&self) -> SocketAddr {
        SocketAddr::from(([0, 0, 0, 0], 7447))
    }

    fn accept(&self) -> Result<Option<Conn>, LinkOpenError> {
        Ok(self.0.borrow_mut().pop_front())
    }
}

/// The stack's clock and entropy: every byte of entropy is zero, so a client's key is known.
#[derive(Clone)]
struct Source(Clock);

impl WsSource for Source {
    fn now_us(&self) -> u64 {
        self.0.get()
    }

    fn fill_entropy(&self, out: &mut [u8]) -> Result<(), EntropyUnavailable> {
        out.fill(0);
        Ok(())
    }
}

const ROUTER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 7447);

const NODE: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

/// The key a dial of [`Source`] writes in its request.
fn zero_key() -> [u8; wz_session_core::ws_link::KEY_LEN] {
    client_key(&[0; 16])
}

/// The server's answer to a request made with `key`.
fn upgrade_answer(key: &[u8; wz_session_core::ws_link::KEY_LEN]) -> Vec<u8> {
    let mut answer = [0u8; 256];
    let len = write_response(&mut answer, &accept_value(key)).expect("room");
    answer[..len].to_vec()
}

/// A client's opening request to `ROUTER`.
fn upgrade_request() -> Vec<u8> {
    let mut request = [0u8; 256];
    let len = write_request(&mut request, ROUTER, &client_key(b"the sample nonce")).expect("room");
    request[..len].to_vec()
}

/// The batch `link` hands over next, if any.
fn received<D: SessionDatagramLink>(link: &D) -> Option<Vec<u8>> {
    let mut got = None;
    link.recv_with(&mut |bytes| got = Some(bytes.to_vec()));
    got
}

type Link = IpDriver<NoDatagram, Conn, NoStream>;

static DIAL_RX: ByteCells<512, 1> = ByteCells::new();
static DIAL_TX: ByteCells<64, 1> = ByteCells::new();

/// A dial writes the opening request and, once the server upgraded the connection, opens the
/// stack's `ws/` link over it, with what followed the server's head as the link's first bytes.
/// Turned red by a `ws/` dial that opens another link, or loses the bytes behind the head.
#[test]
fn a_ws_dial_opens_the_ws_link_once_the_server_upgraded_the_connection() {
    let clock = Clock::default();
    let net = Net::new(&clock);
    net.send(&upgrade_answer(&zero_key()));
    net.send(&[0x82, 0x03, 1, 2, 3]);
    let mut stack =
        IpStack::<NoDatagram, Dial>::new(NODE, &DIAL_RX, &DIAL_TX, Dial(Rc::clone(&net)))
            .with_ws(Source(Rc::clone(&clock)));
    let link: Link = stack
        .bind(Locator::ws(ROUTER))
        .expect("the server upgraded");
    assert!(matches!(link, IpDriver::Ws(_)));
    assert!(
        matches!(read_request(&net.written()), RequestRead::Upgrade { .. }),
        "the dial wrote the opening request"
    );
    assert!(!link.batch_length_prefixed(), "a message frames its batch");
    let ends = link.link_endpoints().expect("a connection knows both ends");
    assert_eq!(ends.dst.as_str(), "ws/10.0.0.1:7447");
    assert_eq!(received(&link), Some(std::vec![1, 2, 3]));
    assert_eq!(DIAL_RX.in_use(), 1);
    assert_eq!(DIAL_TX.in_use(), 1);
}

static REFUSED_RX: ByteCells<512, 1> = ByteCells::new();
static REFUSED_TX: ByteCells<64, 1> = ByteCells::new();

/// A server that answers with anything but the upgrade refuses the dial, and the buffers it
/// claimed go back. Turned red by a dial that takes any answer as an upgrade.
#[test]
fn a_server_that_refuses_the_upgrade_refuses_the_dial_and_gives_its_buffers_back() {
    let clock = Clock::default();
    let net = Net::new(&clock);
    net.send(b"HTTP/1.1 400 Bad Request\r\n\r\n");
    let mut stack =
        IpStack::<NoDatagram, Dial>::new(NODE, &REFUSED_RX, &REFUSED_TX, Dial(Rc::clone(&net)))
            .with_ws(Source(Rc::clone(&clock)));
    let refused: Result<Link, _> = stack.bind(Locator::ws(ROUTER));
    assert!(matches!(refused, Err(LinkOpenError::Refused)));
    assert_eq!(REFUSED_RX.in_use(), 0);
    assert_eq!(REFUSED_TX.in_use(), 0);
}

static SILENT_RX: ByteCells<512, 1> = ByteCells::new();
static SILENT_TX: ByteCells<64, 1> = ByteCells::new();

/// A server that never answers holds the dial only until its wait is over on the stack's clock:
/// then it is refused, as an open worth trying later. Turned red by a wait with no deadline,
/// which never returns here.
#[test]
fn a_server_that_does_not_answer_refuses_the_dial_once_its_wait_is_over() {
    let clock = Clock::default();
    let net = Net::new(&clock);
    let mut stack =
        IpStack::<NoDatagram, Dial>::new(NODE, &SILENT_RX, &SILENT_TX, Dial(Rc::clone(&net)))
            .with_ws(Source(Rc::clone(&clock)));
    let refused: Result<Link, _> = stack.bind(Locator::ws(ROUTER));
    assert!(matches!(refused, Err(LinkOpenError::Refused)));
    assert!(
        clock.get() >= OPEN_WAIT_US,
        "the dial waited its whole wait"
    );
    assert!(
        clock.get() < OPEN_WAIT_US + 1_000_000,
        "and no longer than a service turn past it"
    );
    assert_eq!(SILENT_RX.in_use(), 0);
    assert_eq!(SILENT_TX.in_use(), 0);
}

static UNREACHED_RX: ByteCells<512, 1> = ByteCells::new();
static UNREACHED_TX: ByteCells<64, 1> = ByteCells::new();

/// A `ws/` end the stack cannot reach is refused before a buffer is claimed: a stack with no
/// plain stream, and an IPv6 end of a stack without IPv6, are `Unsupported`; a port that refuses
/// the connection is `Refused` and gives back what it claimed. Turned red by a dial that claims
/// its buffers before it asks whether it carries the protocol.
#[test]
fn a_ws_end_the_stack_cannot_reach_is_refused_and_keeps_nothing() {
    let clock = Clock::default();
    let mut no_stream =
        IpStack::<NoDatagram, NoDial>::new(NODE, &UNREACHED_RX, &UNREACHED_TX, NoDial)
            .with_ws(Source(Rc::clone(&clock)));
    let none: Result<IpDriver<NoDatagram, NoStream, NoStream>, _> =
        no_stream.bind(Locator::ws(ROUTER));
    assert!(matches!(none, Err(LinkOpenError::Unsupported)));

    let net = Net::new(&clock);
    let mut v4 = IpStack::<NoDatagram, Dial<false>>::new(
        NODE,
        &UNREACHED_RX,
        &UNREACHED_TX,
        Dial(Rc::clone(&net)),
    )
    .with_ws(Source(Rc::clone(&clock)));
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 7447);
    let family: Result<Link, _> = v4.bind(Locator::ws(v6));
    assert!(matches!(family, Err(LinkOpenError::Unsupported)));
    assert!(net.written().is_empty(), "nothing was written");

    let refusing = SocketAddr::new(ROUTER.ip(), REFUSING);
    let refused: Result<Link, _> = v4.bind(Locator::ws(refusing));
    assert!(matches!(refused, Err(LinkOpenError::Refused)));
    assert_eq!(UNREACHED_RX.in_use(), 0);
    assert_eq!(UNREACHED_TX.in_use(), 0);
}

static TCP_RX: ByteCells<512, 1> = ByteCells::new();
static TCP_TX: ByteCells<64, 1> = ByteCells::new();

/// A locator of another scheme is the stack's own: a `tcp/` dial of the same stack opens its
/// `tcp/` link, which writes no opening request. Turned red by a stack that dials every locator
/// as a WebSocket.
#[test]
fn a_tcp_dial_of_a_ws_stack_is_the_stacks_own() {
    let clock = Clock::default();
    let net = Net::new(&clock);
    let mut stack = IpStack::<NoDatagram, Dial>::new(NODE, &TCP_RX, &TCP_TX, Dial(Rc::clone(&net)))
        .with_ws(Source(Rc::clone(&clock)));
    let link: Link = stack.bind(Locator::tcp(ROUTER)).expect("a free table");
    assert!(matches!(link, IpDriver::Tcp(_)));
    assert!(link.batch_length_prefixed());
    assert!(net.written().is_empty());
}

static QUEUE_RX: ByteCells<512, 2> = ByteCells::new();
static QUEUE_TX: ByteCells<64, 2> = ByteCells::new();

/// An acceptor of one row takes one connection and answers its request; while that row holds it
/// the listener is not asked for the next, which stays queued on the port, and is taken once the
/// row is free. The accepted link is the server's end of a `ws/` link, and what the client sent
/// behind its request is its first batch. Turned red by an acceptor that takes a connection with
/// no row for it.
#[test]
fn a_full_handshake_table_leaves_the_next_connection_queued_on_the_port() {
    let clock = Clock::default();
    let (first, second) = (Net::new(&clock), Net::new(&clock));
    let queue = Rc::new(RefCell::new(VecDeque::from([
        Conn(Rc::clone(&first), ROUTER),
        Conn(Rc::clone(&second), ROUTER),
    ])));
    let stack =
        IpStack::<NoDatagram, Dial>::new(NODE, &QUEUE_RX, &QUEUE_TX, Dial(Net::new(&clock)))
            .with_ws(Source(Rc::clone(&clock)));
    let mut acceptor: WsAcceptor<Port, NoDatagram, NoStream, Source, 1> =
        stack.acceptor(Port(Rc::clone(&queue)));
    assert_eq!(acceptor.local(), SocketAddr::from(([0, 0, 0, 0], 7447)));

    let waiting: Result<Option<Link>, _> = acceptor.accept();
    assert!(matches!(waiting, Ok(None)), "no request yet");
    assert_eq!(acceptor.handshaking(), 1);
    assert_eq!(
        queue.borrow().len(),
        1,
        "the second connection stays on the port"
    );
    assert_eq!(QUEUE_RX.in_use(), 1, "the row holds its link's buffers");

    first.send(&upgrade_request());
    // A client's frame of the batch [1, 2, 3], masked with a key of zeros.
    first.send(&[0x82, 0x83, 0, 0, 0, 0, 1, 2, 3]);
    let link: Link = acceptor
        .accept()
        .expect("the port is sound")
        .expect("the request was answered");
    assert!(matches!(link, IpDriver::Ws(_)));
    assert!(
        first.written().starts_with(b"HTTP/1.1 101"),
        "the acceptor answered with the upgrade"
    );
    assert_eq!(received(&link), Some(std::vec![1, 2, 3]));
    assert_eq!(acceptor.handshaking(), 0);
    assert_eq!(queue.borrow().len(), 1, "the answer took no new connection");

    let next: Result<Option<Link>, _> = acceptor.accept();
    assert!(matches!(next, Ok(None)));
    assert_eq!(
        acceptor.handshaking(),
        1,
        "the free row took the queued connection"
    );
    assert!(queue.borrow().is_empty());
    assert_eq!(acceptor.refused(), 0);
}

static LATE_RX: ByteCells<512, 1> = ByteCells::new();
static LATE_TX: ByteCells<64, 1> = ByteCells::new();

/// A connection that says nothing holds its row only for the handshake's wait: then it is let
/// go, its row and its buffers free. Turned red by a row kept for a request that never comes.
#[test]
fn a_handshake_not_done_in_time_is_let_go_with_its_row_and_buffers() {
    let clock = Clock::default();
    let quiet = Net::new(&clock);
    let queue = Rc::new(RefCell::new(VecDeque::from([Conn(
        Rc::clone(&quiet),
        ROUTER,
    )])));
    let stack = IpStack::<NoDatagram, Dial>::new(NODE, &LATE_RX, &LATE_TX, Dial(Net::new(&clock)))
        .with_ws(Source(Rc::clone(&clock)));
    let mut acceptor: WsAcceptor<Port, NoDatagram, NoStream, Source, 1> =
        stack.acceptor(Port(Rc::clone(&queue)));
    let waiting: Result<Option<Link>, _> = acceptor.accept();
    assert!(matches!(waiting, Ok(None)));
    assert_eq!(acceptor.handshaking(), 1);
    clock.set(OPEN_WAIT_US - 1);
    let still: Result<Option<Link>, _> = acceptor.accept();
    assert!(matches!(still, Ok(None)));
    assert_eq!(acceptor.handshaking(), 1, "within its wait the row is kept");
    clock.set(OPEN_WAIT_US);
    let gone: Result<Option<Link>, _> = acceptor.accept();
    assert!(matches!(gone, Ok(None)));
    assert_eq!(acceptor.handshaking(), 0);
    assert_eq!(LATE_RX.in_use(), 0);
    assert_eq!(LATE_TX.in_use(), 0);
}

static BAD_RX: ByteCells<512, 1> = ByteCells::new();
static BAD_TX: ByteCells<64, 1> = ByteCells::new();

/// A request that is no upgrade is not answered: the connection is let go and its row freed.
/// Turned red by an acceptor that answers whatever arrives.
#[test]
fn a_request_that_is_no_upgrade_lets_the_connection_go() {
    let clock = Clock::default();
    let client = Net::new(&clock);
    client.send(b"GET / HTTP/1.1\r\nHost: 10.0.0.1:7447\r\n\r\n");
    let queue = Rc::new(RefCell::new(VecDeque::from([Conn(
        Rc::clone(&client),
        ROUTER,
    )])));
    let stack = IpStack::<NoDatagram, Dial>::new(NODE, &BAD_RX, &BAD_TX, Dial(Net::new(&clock)))
        .with_ws(Source(Rc::clone(&clock)));
    let mut acceptor: WsAcceptor<Port, NoDatagram, NoStream, Source, 1> =
        stack.acceptor(Port(Rc::clone(&queue)));
    let refused: Result<Option<Link>, _> = acceptor.accept();
    assert!(matches!(refused, Ok(None)));
    assert_eq!(acceptor.handshaking(), 0);
    assert!(client.written().is_empty(), "no answer was written");
    assert_eq!(BAD_RX.in_use(), 0);
}

static FULL_RX: ByteCells<512, 1> = ByteCells::new();
static FULL_TX: ByteCells<64, 1> = ByteCells::new();

/// A connection taken when the tables have no buffer for its link is closed at once and counted,
/// not left queued nor kept in a row. Turned red by a row taken without its buffers.
#[test]
fn a_connection_the_tables_have_no_buffer_for_is_closed_and_counted() {
    let clock = Clock::default();
    let queue = Rc::new(RefCell::new(VecDeque::from([
        Conn(Net::new(&clock), ROUTER),
        Conn(Net::new(&clock), ROUTER),
    ])));
    let stack = IpStack::<NoDatagram, Dial>::new(NODE, &FULL_RX, &FULL_TX, Dial(Net::new(&clock)))
        .with_ws(Source(Rc::clone(&clock)));
    let mut acceptor: WsAcceptor<Port, NoDatagram, NoStream, Source, 2> =
        stack.acceptor(Port(Rc::clone(&queue)));
    let first: Result<Option<Link>, _> = acceptor.accept();
    assert!(matches!(first, Ok(None)));
    let second: Result<Option<Link>, _> = acceptor.accept();
    assert!(matches!(second, Err(LinkOpenError::Exhausted)));
    assert_eq!(acceptor.refused(), 1);
    assert_eq!(acceptor.handshaking(), 1);
    assert!(
        queue.borrow().is_empty(),
        "the refused connection was taken off the port"
    );
}
