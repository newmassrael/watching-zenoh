// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::Cell;
use core::net::SocketAddr;

use wz_session_core::entropy::EntropyUnavailable;
use wz_session_core::ws_link::{
    accept_value, apply_mask, client_key, read_request, write_request, write_response, RequestRead,
};

use super::*;
use crate::link_storage::{RxStore, TxStore};
use crate::session_drive::{Dialled, LinkProto, NoWaits};
use crate::stream_link::StreamEnds;

/// One TCP connection of the test: the bytes the link reads, the bytes it wrote, whether the
/// connect has completed, and the clock a wait for room lets run.
#[derive(Default)]
struct Net {
    inbox: RefCell<VecDeque<u8>>,
    outbox: RefCell<Vec<u8>>,
    connected: Cell<bool>,
    now_us: Rc<Cell<u64>>,
}

struct Conn(Rc<Net>);

impl StreamSocket for Conn {
    type Error = ();

    type Link<B: RxStore + 'static, X: TxStore + 'static>
        = StreamDriver<Self, B, X>
    where
        Self: 'static;

    fn ends(&self) -> StreamEnds<'_> {
        StreamEnds::Ip {
            proto: LinkProto::Tcp,
            local: SocketAddr::from(([10, 0, 0, 2], 40_000)),
            peer: SocketAddr::from(([10, 0, 0, 1], 7447)),
        }
    }

    fn write(&self, bytes: &[u8]) -> Result<usize, ()> {
        self.0.outbox.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        let waited = u64::try_from(timeout_ms).unwrap_or(0) * 1_000;
        self.0.now_us.set(self.0.now_us.get() + waited);
    }

    fn wait_writable(&self, timeout_us: u64) -> (bool, u64) {
        self.0.now_us.set(self.0.now_us.get() + timeout_us);
        (false, timeout_us)
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

    fn connected(&mut self) -> Result<bool, ()> {
        Ok(self.0.connected.get())
    }

    fn shutdown(&self) {}
}

/// The connections a listener of the test yields, in order.
struct Queue(Rc<RefCell<VecDeque<Conn>>>);

impl StreamListen for Queue {
    type Stream = Conn;

    fn local(&self) -> SocketAddr {
        SocketAddr::from(([0, 0, 0, 0], 7447))
    }

    fn accept(&self) -> Result<Option<Conn>, LinkOpenError> {
        Ok(self.0.borrow_mut().pop_front())
    }
}

/// The dial of the test: every connection it begins is `net`; every listener yields `queue`.
struct Dial {
    net: Rc<Net>,
    queue: Rc<RefCell<VecDeque<Conn>>>,
}

impl StreamDial for Dial {
    type Stream = Conn;

    fn dial(&self, _to: SocketAddr) -> Result<Conn, LinkOpenError> {
        Ok(Conn(Rc::clone(&self.net)))
    }

    fn listen(
        &self,
        _at: SocketAddr,
    ) -> Result<Box<dyn StreamListen<Stream = Conn>>, LinkOpenError> {
        Ok(Box::new(Queue(Rc::clone(&self.queue))))
    }
}

#[derive(Clone)]
struct Open(Rc<Dial>);

impl WsOpen for Open {
    type Dial = Dial;

    fn stream_dial(&self) -> &Dial {
        &self.0
    }
}

impl WsSource for Open {
    fn now_us(&self) -> u64 {
        self.0.net.now_us.get()
    }

    fn fill_entropy(&self, out: &mut [u8]) -> Result<(), EntropyUnavailable> {
        out.fill(0);
        Ok(())
    }
}

/// A stack with no link of its own.
struct NoLinks;

impl SessionLinks for NoLinks {
    type Pump = HeapLink;
    type Dial = Dialled<HeapLink>;
    type Waits = NoWaits;

    fn waits(&self) -> NoWaits {
        NoWaits
    }

    fn open_acceptor(&self, _port: u16) -> Result<OpenedLink<HeapLink>, LinkOpenError> {
        Err(LinkOpenError::Unsupported)
    }

    fn open_initiator(&self, _to: Locator) -> Result<OpenedLink<HeapLink>, LinkOpenError> {
        Err(LinkOpenError::AddressInUse)
    }
}

fn stack() -> (WsLinks<NoLinks, Open>, Rc<Dial>) {
    let dial = Rc::new(Dial {
        net: Rc::new(Net::default()),
        queue: Rc::new(RefCell::new(VecDeque::new())),
    });
    (WsLinks::new(NoLinks, Open(Rc::clone(&dial)), 1), dial)
}

const SERVER: SocketAddr = SocketAddr::new(
    core::net::IpAddr::V4(core::net::Ipv4Addr::new(10, 0, 0, 1)),
    7447,
);

fn received(link: &OpenedLink<HeapLink>) -> Option<Vec<u8>> {
    let mut got = None;
    link.pump.recv_with(&mut |bytes| got = Some(bytes.to_vec()));
    got
}

/// The key the dial wrote in its request, read back as the server reads it, and the accept value
/// it answers with.
fn request_accept(net: &Net) -> [u8; 28] {
    match read_request(&net.outbox.borrow()) {
        RequestRead::Upgrade { accept, .. } => accept,
        other => panic!("the dial wrote no request: {other:?}"),
    }
}

/// A dial connects, writes its request to the end it names, and once the server answers with the
/// accept value of its key is the link, its first batch the frame the server wrote behind its
/// answer. Turned red by a dial that sends before it is connected, takes a wrong accept value, or
/// loses what followed the answer.
#[test]
fn a_dial_upgrades_its_connection_and_keeps_what_followed_the_answer() {
    let (links, dial) = stack();
    let mut pending = links
        .begin_initiator(Locator::ws(SERVER))
        .expect("a dial begun");
    assert!(pending.poll().is_none(), "not connected yet");
    assert!(dial.net.outbox.borrow().is_empty());
    dial.net.connected.set(true);
    assert!(pending.poll().is_none(), "no answer yet");
    assert!(dial
        .net
        .outbox
        .borrow()
        .starts_with(b"GET / HTTP/1.1\r\nHost: 10.0.0.1:7447\r\n"));
    let accept = request_accept(&dial.net);
    let mut answer = [0u8; 256];
    let len = write_response(&mut answer, &accept).expect("room");
    dial.net.inbox.borrow_mut().extend(&answer[..len]);
    dial.net.inbox.borrow_mut().extend([0x82, 0x02, b'o', b'k']);
    let link = pending.poll().expect("answered").expect("upgraded");
    assert_eq!(received(&link).as_deref(), Some(&b"ok"[..]));
}

/// A server that answers with another accept value, or not with an upgrade, refuses the dial; a
/// waiting dial whose connection is never made is refused when its time is up; a locator of
/// another kind is the stack's. Turned red by a dial that takes a server RFC 6455 tells a client
/// to fail, or waits for good.
#[test]
fn a_dial_is_refused_on_a_wrong_answer_and_when_its_time_is_up() {
    let (links, dial) = stack();
    dial.net.connected.set(true);
    let mut pending = links
        .begin_initiator(Locator::ws(SERVER))
        .expect("a dial begun");
    assert!(pending.poll().is_none());
    let mut answer = [0u8; 256];
    let len = write_response(&mut answer, &[b'A'; 28]).expect("room");
    dial.net.inbox.borrow_mut().extend(&answer[..len]);
    assert!(matches!(pending.poll(), Some(Err(LinkOpenError::Refused))));

    let (links, dial) = stack();
    assert!(matches!(
        links.open_initiator(Locator::ws(SERVER)),
        Err(LinkOpenError::Refused)
    ));
    assert!(dial.net.now_us.get() >= OPEN_WAIT_US);

    assert!(matches!(
        links.open_initiator(Locator::tcp(SERVER)),
        Err(LinkOpenError::AddressInUse)
    ));
}

/// A listener answers each accepted connection's request with the accept value of its key and
/// yields the link, its first batch the masked frame the client sent behind the request; it names
/// itself a `ws/` locator. Turned red by a listener that answers before the request is whole, with
/// a wrong value, or loses what followed it.
#[test]
fn a_listener_answers_the_request_and_yields_the_link() {
    let (links, dial) = stack();
    let listener = links
        .open_listener(Locator::ws(SocketAddr::from(([0, 0, 0, 0], 7447))))
        .expect("a listener");
    assert_eq!(
        listener.local(),
        Locator::ws(SocketAddr::from(([0, 0, 0, 0], 7447)))
    );
    let net = Rc::new(Net::default());
    let key = client_key(b"the sample nonce");
    let mut request = [0u8; 256];
    let len = write_request(&mut request, SERVER, &key).expect("room");
    net.inbox.borrow_mut().extend(&request[..len - 1]);
    dial.queue.borrow_mut().push_back(Conn(Rc::clone(&net)));
    assert!(
        listener.accept().expect("no failure").is_none(),
        "half a request"
    );
    assert!(net.outbox.borrow().is_empty());
    assert!(
        listener.input_wait().is_none(),
        "a handshake is read at the node's pace"
    );
    net.inbox.borrow_mut().push_back(request[len - 1]);
    let mut frame = alloc::vec![0x82, 0x83, 1, 2, 3, 4, b'a', b'b', b'c'];
    apply_mask(&mut frame[6..], [1, 2, 3, 4]);
    net.inbox.borrow_mut().extend(frame);
    let link = listener.accept().expect("no failure").expect("the link");
    let mut expected = [0u8; 256];
    let expected_len = write_response(&mut expected, &accept_value(&key)).expect("room");
    assert_eq!(&net.outbox.borrow()[..], &expected[..expected_len]);
    assert_eq!(received(&link).as_deref(), Some(&b"abc"[..]));
}

/// A connection whose request is no upgrade, or whose request has not ended when its time is up,
/// is let go unanswered, and the listener goes on. Turned red by a listener that answers what it
/// should not, or holds a silent connection's buffers for good.
#[test]
fn a_listener_lets_go_of_a_bad_or_silent_connection() {
    let (links, dial) = stack();
    let listener = links
        .open_listener(Locator::ws(SocketAddr::from(([0, 0, 0, 0], 7447))))
        .expect("a listener");
    let bad = Rc::new(Net::default());
    bad.inbox
        .borrow_mut()
        .extend(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n".iter());
    dial.queue.borrow_mut().push_back(Conn(Rc::clone(&bad)));
    assert!(listener.accept().expect("no failure").is_none());
    assert!(bad.outbox.borrow().is_empty());

    let silent = Rc::new(Net::default());
    dial.queue.borrow_mut().push_back(Conn(Rc::clone(&silent)));
    assert!(listener.accept().expect("no failure").is_none());
    assert!(listener.input_wait().is_none(), "a handshake under way");
    dial.net.now_us.set(OPEN_WAIT_US);
    assert!(listener.accept().expect("no failure").is_none());
    let key = client_key(b"the sample nonce");
    let mut request = [0u8; 256];
    let len = write_request(&mut request, SERVER, &key).expect("room");
    silent.inbox.borrow_mut().extend(&request[..len]);
    assert!(listener.accept().expect("no failure").is_none());
    assert!(
        silent.outbox.borrow().is_empty(),
        "a connection let go is not answered"
    );
}

/// A listener takes as many connections off its port as its table has rows: while every row holds
/// a handshake the next connection stays queued on the port, unanswered and not closed, the
/// handshakes under way go on, and a row a handshake leaves takes the queued connection. Turned
/// red by a listener that takes a connection its table has no row for, or that never comes back
/// for one left queued.
#[test]
fn a_listener_leaves_a_connection_queued_while_its_table_is_full() {
    let (_, dial) = stack();
    let links = WsLinks::new(NoLinks, Open(Rc::clone(&dial)), 2);
    let listener = links
        .open_listener(Locator::ws(SocketAddr::from(([0, 0, 0, 0], 7447))))
        .expect("a listener");
    let nets: Vec<Rc<Net>> = (0..3).map(|_| Rc::new(Net::default())).collect();
    for net in &nets {
        dial.queue.borrow_mut().push_back(Conn(Rc::clone(net)));
    }
    for _ in 0..3 {
        assert!(listener.accept().expect("no failure").is_none());
    }
    assert_eq!(dial.queue.borrow().len(), 1, "the third waits on the port");
    assert_eq!(Rc::strong_count(&nets[0]), 2, "the first handshake is held");
    assert_eq!(
        Rc::strong_count(&nets[1]),
        2,
        "the second handshake is held"
    );
    assert!(
        listener.input_wait().is_none(),
        "a full table waits on no port"
    );

    let key = client_key(b"the sample nonce");
    let mut request = [0u8; 256];
    let len = write_request(&mut request, SERVER, &key).expect("room");
    nets[1].inbox.borrow_mut().extend(&request[..len]);
    assert!(listener.accept().expect("no failure").is_some());
    assert_eq!(
        dial.queue.borrow().len(),
        1,
        "taken only once a row is free"
    );
    assert_eq!(Rc::strong_count(&nets[0]), 2, "the first goes on");

    nets[2].inbox.borrow_mut().extend(&request[..len]);
    let link = listener.accept().expect("no failure");
    assert!(dial.queue.borrow().is_empty(), "the queued one is taken");
    assert!(link.is_some(), "and its handshake answered");
    let mut expected = [0u8; 256];
    let expected_len = write_response(&mut expected, &accept_value(&key)).expect("room");
    assert_eq!(&nets[2].outbox.borrow()[..], &expected[..expected_len]);
}

/// A listener of no rows takes no connection. Turned red by a listener that takes one its table
/// has no row for.
#[test]
fn a_listener_of_no_rows_takes_no_connection() {
    let (_, dial) = stack();
    let links = WsLinks::new(NoLinks, Open(Rc::clone(&dial)), 0);
    let listener = links
        .open_listener(Locator::ws(SocketAddr::from(([0, 0, 0, 0], 7447))))
        .expect("a listener");
    let net = Rc::new(Net::default());
    dial.queue.borrow_mut().push_back(Conn(Rc::clone(&net)));
    assert!(listener.accept().expect("no failure").is_none());
    assert_eq!(dial.queue.borrow().len(), 1);
    assert!(listener.input_wait().is_none());
}
