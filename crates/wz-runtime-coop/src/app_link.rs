// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Links over a transport the program supplies, on the cooperative engine.
//!
//! The transport is the engine-neutral [`AppTransport`] of `wz-session-core`. This module makes
//! the cooperative engine's link seams of it: a [`StreamSocket`] and a [`DatagramSocket`] over a
//! link's handle, a [`StreamDial`] that opens streams through the program, a [`GroupTransport`]
//! over a group the program joins, and [`AppLinks`], the session shell's [`SessionLinks`] over all
//! of them, so a session of this engine opens no socket of the system's when a transport is given.
//!
//! # The remainder
//!
//! This engine's stream seam takes every byte or fails ([`StreamSocket::send_parts`]), where the
//! program may take part of them or none (would-block). What the program did not take is held in
//! the transport's table ([`AppLinkTable::hold_remainder`](wz_session_core::app_link_table::AppLinkTable::hold_remainder)),
//! behind anything held before, and offered to the program again at the start of every send and
//! every turn of the link's loop (each read and wait), so the stream's bytes leave in order once
//! the program is writable. The remainder is bounded by the transport's queue bound; past it the
//! send fails, as a socket whose peer stopped reading does. Only this engine copies a remainder:
//! the tokio engine's writer keeps its own offset.
//!
//! # Waiting
//!
//! A wait for input, and an open the program finishes later, are made on the host by parking the
//! thread with a waker the program's calls wake (`host-lock`, the host build). An image has no
//! thread to park: there a wait looks at the table for a bounded number of turns and returns, and
//! the engine's loop comes back to it.

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::c_int;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use wz_session_core::app_link_table::{
    AcceptRead, AppLinkKind, DatagramRead, LinkHandle, OpenProgress, SendGate, SendStep, StreamRead,
};
use wz_session_core::app_transport::AppTransport;

use crate::group_transport::GroupTransport;
use crate::ip_stack::{HeapIpDriver, IpDriver};
use crate::link_storage::HeapTx;
use crate::session_drive::{
    LinkListener, LinkOpenError, LinkProto, Locator, OpenedLink, SessionLinks,
};
use crate::stream_link::{
    StreamDial, StreamDriver, StreamListen, StreamSocket, STREAM_RX_CAPACITY,
};
use crate::udp_link::{DatagramSocket, Received, UdpDriver, UDP_RX_CAPACITY};

/// The longest an open waits for the program to report the link up, in milliseconds: the
/// connect timeout of a zenoh-pico session, which this engine's dial is held to as a whole.
const OPEN_WAIT_MS: u64 = 10_000;

/// Why a call on a link over the program's transport failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppLinkError {
    /// The link is closed.
    Closed,
    /// The program's send failed, or took part of a datagram.
    Failed,
    /// The program could not take a datagram now; it was not sent.
    WouldBlock,
    /// The remainder held for the program would pass the transport's queue bound.
    Full,
    /// A socket of this kind is opened through [`AppLinks`], never bound on its own.
    NotCarried,
}

/// Waiting on a link: parking the host's thread (`wait_parked`), or looking for a bounded number
/// of turns on an image (`wait_turns`). The build names one of them `wait`.
#[cfg(feature = "host-lock")]
use wait_parked as wait;
#[cfg(not(feature = "host-lock"))]
use wait_turns as wait;

#[cfg(feature = "host-lock")]
mod wait_parked {
    extern crate std;

    use alloc::sync::Arc;
    use core::task::Waker;
    use std::task::Wake;
    use std::thread::Thread;
    use std::time::{Duration, Instant};

    struct Unpark(Thread);

    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }

    /// Wait up to `timeout_ms` while `pending` answers `true`, handing it the waker the
    /// program's calls wake this thread by.
    pub(super) fn wait_while(timeout_ms: u64, mut pending: impl FnMut(Option<&Waker>) -> bool) {
        let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        while pending(Some(&waker)) {
            let now = Instant::now();
            if now >= deadline {
                return;
            }
            std::thread::park_timeout(deadline - now);
        }
    }
}

#[cfg(not(feature = "host-lock"))]
mod wait_turns {
    use core::task::Waker;

    /// How many times a wait looks at the table before it returns to the engine's loop.
    const TURNS: u32 = 1 << 12;

    /// Look while `pending` answers `true`, for a bounded number of turns: an image has no thread
    /// to park, and its loop comes back.
    pub(super) fn wait_while(_timeout_ms: u64, mut pending: impl FnMut(Option<&Waker>) -> bool) {
        for _ in 0..TURNS {
            if !pending(None) {
                return;
            }
            core::hint::spin_loop();
        }
    }
}

/// The socket address a locator names, or the unspecified address when it names none.
fn socket_of(locator: &str) -> SocketAddr {
    let address = locator
        .split_once('#')
        .map_or(locator, |(address, _)| address);
    let address = address
        .split_once('/')
        .map_or(address, |(_, address)| address);
    address
        .parse()
        .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
}

/// Open a link of `kind` for `locator` and wait until the program says it is up.
fn open_link(
    transport: &Arc<AppTransport>,
    kind: AppLinkKind,
    locator: &str,
) -> Result<LinkHandle, LinkOpenError> {
    let handle = transport.begin_open(kind, locator);
    let mut progress = OpenProgress::Opening;
    wait::wait_while(OPEN_WAIT_MS, |waker| {
        progress = transport.with(|table| table.poll_open(handle, waker));
        progress == OpenProgress::Opening
    });
    match progress {
        OpenProgress::Open => Ok(handle),
        // Not up in time, or refused: the link is let go, and the dial is one the other end did
        // not take, which the engine tries again later.
        OpenProgress::Opening | OpenProgress::Closed => {
            transport.release(handle);
            Err(LinkOpenError::Refused)
        }
    }
}

/// One link of the program's transport as this engine's seams hold it: released when it drops.
struct Held {
    transport: Arc<AppTransport>,
    handle: LinkHandle,
}

impl Held {
    /// Offer the program `bytes` once, as far as it takes them now: how many it took, 0 when it
    /// would block (or the link is not writable yet).
    fn send_once(&self, bytes: &[u8]) -> Result<usize, AppLinkError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            let gate = self
                .transport
                .with(|table| table.begin_send(self.handle, None));
            let ticket = match gate {
                SendGate::Go(ticket) => ticket,
                SendGate::Blocked | SendGate::Opening | SendGate::Busy => return Ok(0),
                SendGate::Closed => return Err(AppLinkError::Closed),
            };
            let answer = self.transport.port().send(self.handle, bytes);
            let (step, effects) = self
                .transport
                .with(|table| table.send_answered(ticket, bytes.len(), answer));
            self.transport.perform(effects);
            match step {
                SendStep::Retry => {}
                SendStep::Wrote(taken) => return Ok(taken),
                SendStep::Blocked => return Ok(0),
                SendStep::Closed => return Err(AppLinkError::Closed),
                SendStep::Failed => return Err(AppLinkError::Failed),
            }
        }
    }

    /// Offer the program what is held for it, until it would block or has taken all of it.
    fn flush(&self) -> Result<(), AppLinkError> {
        loop {
            let held: Vec<u8> = self
                .transport
                .with(|table| table.remainder(self.handle).to_vec());
            if held.is_empty() {
                return Ok(());
            }
            let taken = self.send_once(&held)?;
            self.transport
                .with(|table| table.drop_remainder(self.handle, taken));
            if taken < held.len() {
                return Ok(());
            }
        }
    }

    /// Send `parts` in order behind what is held: what the program does not take now is held
    /// for it.
    fn send_all(&self, parts: &[&[u8]]) -> Result<(), AppLinkError> {
        self.flush()?;
        for part in parts {
            let held = self
                .transport
                .with(|table| !table.remainder(self.handle).is_empty());
            let taken = if held { 0 } else { self.send_once(part)? };
            if taken < part.len() {
                self.transport
                    .with(|table| table.hold_remainder(self.handle, &part[taken..]))
                    .map_err(|_| AppLinkError::Full)?;
            }
        }
        Ok(())
    }

    /// Wait up to `timeout_ms` for input, offering what is held on the way.
    fn wait_readable(&self, timeout_ms: c_int) {
        let _ = self.flush();
        let timeout_ms = u64::try_from(timeout_ms).unwrap_or(0);
        wait::wait_while(timeout_ms, |waker| {
            !self
                .transport
                .with(|table| table.poll_readable(self.handle, waker))
        });
    }

    /// What a read just made let the program know of: the links it refused that are read down.
    fn tell_drained(&self) {
        let drained = self.transport.with(|table| table.take_drained());
        self.transport.perform(drained);
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.transport.release(self.handle);
    }
}

/// A byte stream over the program's transport: this engine's [`StreamSocket`] over a link.
pub struct AppStreamSocket {
    held: Held,
    local: SocketAddr,
    peer: SocketAddr,
}

impl StreamSocket for AppStreamSocket {
    type Error = AppLinkError;

    fn local(&self) -> SocketAddr {
        self.local
    }

    fn peer(&self) -> SocketAddr {
        self.peer
    }

    fn send_parts(&self, parts: &[&[u8]]) -> Result<(), AppLinkError> {
        self.held.send_all(parts)
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        self.held.wait_readable(timeout_ms);
    }

    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, AppLinkError> {
        // A turn of the link's loop: what is held for the program is offered again.
        self.held.flush()?;
        let handle = self.held.handle;
        let read = self
            .held
            .transport
            .with(|table| table.read_stream(handle, buf, None));
        self.held.tell_drained();
        Ok(match read {
            StreamRead::Bytes(n) => Some(n),
            StreamRead::Empty => None,
            StreamRead::End => Some(0),
        })
    }

    fn shutdown(&self) {
        self.held.transport.release(self.held.handle);
    }
}

/// How this engine opens streams over the program's transport: its [`StreamDial`].
#[derive(Clone)]
pub struct AppStreamDial {
    transport: Arc<AppTransport>,
}

impl StreamDial for AppStreamDial {
    type Stream = AppStreamSocket;

    fn dial(&self, to: SocketAddr) -> Result<AppStreamSocket, LinkOpenError> {
        let locator = Locator::tcp(to).to_string();
        let handle = open_link(&self.transport, AppLinkKind::StreamDial, &locator)?;
        Ok(AppStreamSocket {
            held: Held {
                transport: Arc::clone(&self.transport),
                handle,
            },
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            peer: to,
        })
    }

    fn listen(
        &self,
        at: SocketAddr,
    ) -> Result<Box<dyn StreamListen<Stream = AppStreamSocket>>, LinkOpenError> {
        let locator = Locator::tcp(at).to_string();
        let handle = open_link(&self.transport, AppLinkKind::StreamListen, &locator)?;
        Ok(Box::new(AppStreamListener {
            held: Held {
                transport: Arc::clone(&self.transport),
                handle,
            },
            at,
        }))
    }
}

/// A stream listener over the program's transport: the streams the program accepts on it.
pub struct AppStreamListener {
    held: Held,
    at: SocketAddr,
}

impl StreamListen for AppStreamListener {
    type Stream = AppStreamSocket;

    fn local(&self) -> SocketAddr {
        self.at
    }

    fn accept(&self) -> Result<Option<AppStreamSocket>, LinkOpenError> {
        let next = self
            .held
            .transport
            .with(|table| table.next_accepted(self.held.handle, None));
        match next {
            AcceptRead::Accepted(handle, remote) => Ok(Some(AppStreamSocket {
                held: Held {
                    transport: Arc::clone(&self.held.transport),
                    handle,
                },
                local: self.at,
                peer: socket_of(&remote),
            })),
            AcceptRead::Empty => Ok(None),
            AcceptRead::End => Err(LinkOpenError::Unsupported),
        }
    }
}

/// A datagram link over the program's transport: this engine's [`DatagramSocket`] over a link.
pub struct AppDatagramSocket {
    held: Held,
    /// Where each datagram is said to come from when the program names no source.
    peer: SocketAddr,
}

impl AppDatagramSocket {
    /// Open a datagram link to `to` over `transport`.
    pub fn dial(transport: &Arc<AppTransport>, to: SocketAddr) -> Result<Self, LinkOpenError> {
        let locator = Locator::udp(to).to_string();
        let handle = open_link(transport, AppLinkKind::Datagram, &locator)?;
        Ok(Self {
            held: Held {
                transport: Arc::clone(transport),
                handle,
            },
            peer: to,
        })
    }

    /// Take the next datagram into `buf`: its length (cut to `buf`) and source.
    fn take(&self, buf: &mut [u8]) -> Result<Option<Received>, AppLinkError> {
        let handle = self.held.handle;
        let read = self
            .held
            .transport
            .with(|table| table.read_datagram(handle, None));
        self.held.tell_drained();
        match read {
            DatagramRead::Datagram(datagram) => {
                let n = datagram.bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&datagram.bytes[..n]);
                let source = datagram.source.as_deref().map_or(self.peer, socket_of);
                Ok(Some((n, source)))
            }
            DatagramRead::Empty => Ok(None),
            DatagramRead::End => Err(AppLinkError::Closed),
        }
    }
}

impl DatagramSocket for AppDatagramSocket {
    type Error = AppLinkError;

    fn bind(_at: SocketAddr) -> Result<Self, AppLinkError> {
        Err(AppLinkError::NotCarried)
    }

    fn local(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    }

    fn send_to(&self, _to: SocketAddr, bytes: &[u8]) -> Result<(), AppLinkError> {
        // A datagram goes whole or not at all: one the program cannot take now is dropped, as a
        // socket whose buffer is full drops it.
        match self.held.send_once(bytes)? {
            taken if taken == bytes.len() => Ok(()),
            0 => Err(AppLinkError::WouldBlock),
            _ => Err(AppLinkError::Failed),
        }
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        self.held.wait_readable(timeout_ms);
    }

    fn times_out(&self) -> bool {
        false
    }

    fn recv_waiting(&self, buf: &mut [u8]) -> Result<Option<Received>, AppLinkError> {
        self.take(buf)
    }

    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<Received>, AppLinkError> {
        self.take(buf)
    }
}

/// A group the program joins over its transport: this engine's [`GroupTransport`]. Leaving the
/// group is closing the link.
pub struct AppGroupTransport {
    held: Option<Held>,
}

impl AppGroupTransport {
    /// Join the group `locator` names (a `udp/` locator with `#iface=`) over `transport`.
    pub fn join(transport: &Arc<AppTransport>, locator: &str) -> Result<Self, LinkOpenError> {
        let handle = open_link(transport, AppLinkKind::Group, locator)?;
        Ok(Self {
            held: Some(Held {
                transport: Arc::clone(transport),
                handle,
            }),
        })
    }
}

impl GroupTransport for AppGroupTransport {
    fn open(&mut self) -> bool {
        self.held.as_ref().is_some_and(|held| {
            held.transport
                .with(|table| table.state(held.handle))
                .is_some_and(|state| {
                    matches!(
                        state,
                        wz_session_core::app_link::AppLinkState::Open
                            | wz_session_core::app_link::AppLinkState::Blocked
                    )
                })
        })
    }

    fn close(&mut self) {
        // Dropping the link closes it on the program, which is the leave.
        self.held = None;
    }

    fn service(&self) {}

    fn carrier_up(&self) -> bool {
        self.held.as_ref().is_some_and(|held| {
            held.transport
                .with(|table| table.state(held.handle))
                .is_some_and(|state| {
                    !matches!(
                        state,
                        wz_session_core::app_link::AppLinkState::Closing
                            | wz_session_core::app_link::AppLinkState::Closed
                    )
                })
        })
    }

    fn send_to_group(&mut self, datagram: &[u8]) {
        // Best-effort, as a multicast send is: what the program cannot take now is not sent.
        if let Some(held) = &self.held {
            let _ = held.send_once(datagram);
        }
    }

    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        let Some(held) = &self.held else {
            return false;
        };
        let read = held
            .transport
            .with(|table| table.read_datagram(held.handle, None));
        held.tell_drained();
        match read {
            DatagramRead::Datagram(datagram) => {
                // The table holds a group's datagrams only with their source.
                let source = datagram.source.as_deref().map_or(
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    socket_of,
                );
                f(&datagram.bytes, source);
                true
            }
            DatagramRead::Empty | DatagramRead::End => false,
        }
    }
}

/// The session shell's links over the program's transport: a `tcp/` dial and listen open
/// streams through the program, a `udp/` dial a datagram link, and nothing is a socket of the
/// system's. A `tls/` locator is not carried.
pub struct AppLinks {
    transport: Arc<AppTransport>,
    dial: AppStreamDial,
    datagram_rx: usize,
}

impl AppLinks {
    /// Links over `transport`.
    pub fn new(transport: Arc<AppTransport>) -> Self {
        Self {
            dial: AppStreamDial {
                transport: Arc::clone(&transport),
            },
            transport,
            datagram_rx: UDP_RX_CAPACITY,
        }
    }

    /// Links whose datagram links receive into buffers of `bytes` each, as
    /// [`IpLinks::with_rx_capacity`](crate::ip_stack::IpLinks::with_rx_capacity) states it.
    #[must_use]
    pub fn with_rx_capacity(mut self, bytes: usize) -> Self {
        self.datagram_rx = bytes.clamp(1, UDP_RX_CAPACITY);
        self
    }
}

/// The driver a link of [`AppLinks`] is: a datagram or a stream link over the program's transport.
pub type AppDriver = HeapIpDriver<AppDatagramSocket, AppStreamSocket>;

impl SessionLinks for AppLinks {
    type Pump = Rc<AppDriver>;

    fn open_acceptor(&self, _port: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        // A datagram port that takes whoever sends first is a socket of the system's; the
        // program's transport accepts streams on a listener.
        Err(LinkOpenError::Unsupported)
    }

    fn open_initiator(&self, to: Locator) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        let driver: AppDriver = match to.proto {
            LinkProto::Udp => IpDriver::Udp(UdpDriver::initiator_with_buffers(
                AppDatagramSocket::dial(&self.transport, to.at)?,
                to.at,
                self.datagram_rx,
                HeapTx::new(0, 0),
            )),
            LinkProto::Tcp => IpDriver::Tcp(StreamDriver::with_buffers(
                self.dial.dial(to.at)?,
                STREAM_RX_CAPACITY,
                HeapTx::new(0, 0),
            )),
            LinkProto::Tls => return Err(LinkOpenError::Unsupported),
        };
        let driver = Rc::new(driver);
        Ok(OpenedLink {
            sink: driver.clone(),
            pump: driver,
        })
    }

    fn open_listener(
        &self,
        at: Locator,
    ) -> Result<Box<dyn LinkListener<Self::Pump>>, LinkOpenError> {
        match at.proto {
            LinkProto::Tcp => Ok(Box::new(AppLinkListener {
                listener: self.dial.listen(at.at)?,
            })),
            LinkProto::Udp | LinkProto::Tls => Err(LinkOpenError::Unsupported),
        }
    }
}

/// A `tcp/` listener of [`AppLinks`]: each stream the program accepts is a link.
struct AppLinkListener {
    listener: Box<dyn StreamListen<Stream = AppStreamSocket>>,
}

impl LinkListener<Rc<AppDriver>> for AppLinkListener {
    fn local(&self) -> Locator {
        Locator::tcp(self.listener.local())
    }

    fn accept(&self) -> Result<Option<OpenedLink<Rc<AppDriver>>>, LinkOpenError> {
        let Some(stream) = self.listener.accept()? else {
            return Ok(None);
        };
        let driver = Rc::new(IpDriver::Tcp(StreamDriver::with_buffers(
            stream,
            STREAM_RX_CAPACITY,
            HeapTx::new(0, 0),
        )));
        Ok(Some(OpenedLink {
            sink: driver.clone(),
            pump: driver,
        }))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::string::String;
    use alloc::vec;
    use std::sync::Mutex;
    use wz_session_core::app_link_table::{AppLinkTable, ProgramEvent, ProgramOpen, ProgramSend};
    use wz_session_core::app_transport::{AppPort, TableLock};

    struct HostLock(Mutex<AppLinkTable>);

    impl TableLock for HostLock {
        fn lock_with(&self, f: &mut dyn FnMut(&mut AppLinkTable)) {
            f(&mut self.0.lock().unwrap());
        }
    }

    #[derive(Default)]
    struct Script {
        opens: Mutex<Vec<(LinkHandle, AppLinkKind, String)>>,
        sent: Mutex<Vec<u8>>,
        closes: Mutex<Vec<LinkHandle>>,
        answers: Mutex<Vec<ProgramSend>>,
    }

    struct Port(Arc<Script>);

    impl AppPort for Port {
        fn open(&self, link: LinkHandle, kind: AppLinkKind, locator: &str) -> ProgramOpen {
            self.0
                .opens
                .lock()
                .unwrap()
                .push((link, kind, String::from(locator)));
            ProgramOpen::Up
        }

        fn send(&self, _link: LinkHandle, bytes: &[u8]) -> ProgramSend {
            let mut answers = self.0.answers.lock().unwrap();
            let answer = if answers.is_empty() {
                ProgramSend::Wrote(bytes.len())
            } else {
                answers.remove(0)
            };
            if let ProgramSend::Wrote(n) = answer {
                self.0
                    .sent
                    .lock()
                    .unwrap()
                    .extend_from_slice(&bytes[..n.min(bytes.len())]);
            }
            answer
        }

        fn close(&self, link: LinkHandle) {
            self.0.closes.lock().unwrap().push(link);
        }
    }

    fn transport(bound: usize) -> (Arc<Script>, Arc<AppTransport>) {
        let script = Arc::new(Script::default());
        let transport = Arc::new(AppTransport::new(
            Box::new(HostLock(Mutex::new(AppLinkTable::with_queue_bound(bound)))),
            Box::new(Port(Arc::clone(&script))),
        ));
        (script, transport)
    }

    const PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 7447);

    #[test]
    fn a_dial_opens_a_stream_through_the_program_named_by_its_locator() {
        let (script, transport) = transport(64);
        let stream = AppStreamDial {
            transport: Arc::clone(&transport),
        }
        .dial(PEER)
        .expect("the program answers up");
        assert_eq!(
            script.opens.lock().unwrap()[0],
            (
                stream.held.handle,
                AppLinkKind::StreamDial,
                String::from("tcp/192.0.2.9:7447")
            )
        );
        assert_eq!(stream.peer(), PEER);
        drop(stream);
        assert_eq!(
            script.closes.lock().unwrap().len(),
            1,
            "dropping the socket closes it"
        );
    }

    #[test]
    fn what_the_program_does_not_take_is_held_and_leaves_in_order_once_writable() {
        let (script, transport) = transport(64);
        *script.answers.lock().unwrap() = vec![ProgramSend::Wrote(2), ProgramSend::WouldBlock];
        let stream = AppStreamDial {
            transport: Arc::clone(&transport),
        }
        .dial(PEER)
        .unwrap();
        // The seam takes every byte: two leave, the rest is held.
        stream
            .send_parts(&[b"ab", b"cd", b"ef"])
            .expect("held, not failed");
        assert_eq!(script.sent.lock().unwrap().as_slice(), b"ab");
        assert_eq!(
            transport.with(|table| table.remainder(stream.held.handle).to_vec()),
            b"cdef"
        );
        // A later send queues behind the remainder rather than overtaking it.
        stream.send_parts(&[b"gh"]).unwrap();
        assert_eq!(script.sent.lock().unwrap().as_slice(), b"ab");
        transport
            .event(stream.held.handle, ProgramEvent::Writable)
            .unwrap();
        // The next turn of the loop offers it again.
        let mut buf = [0u8; 4];
        assert_eq!(stream.try_read(&mut buf), Ok(None));
        assert_eq!(script.sent.lock().unwrap().as_slice(), b"abcdefgh");
        assert!(transport.with(|table| table.remainder(stream.held.handle).is_empty()));
    }

    #[test]
    fn a_remainder_past_the_bound_fails_the_send() {
        let (script, transport) = transport(4);
        *script.answers.lock().unwrap() = vec![ProgramSend::WouldBlock];
        let stream = AppStreamDial {
            transport: Arc::clone(&transport),
        }
        .dial(PEER)
        .unwrap();
        assert_eq!(stream.send_parts(&[b"abcdef"]), Err(AppLinkError::Full));
    }

    #[test]
    fn a_stream_reads_what_the_program_hands_in_and_ends_when_it_closes() {
        let (_script, transport) = transport(64);
        let stream = AppStreamDial {
            transport: Arc::clone(&transport),
        }
        .dial(PEER)
        .unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(stream.try_read(&mut buf), Ok(None));
        transport.received(stream.held.handle, b"hi", None).unwrap();
        assert_eq!(stream.try_read(&mut buf), Ok(Some(2)));
        assert_eq!(&buf[..2], b"hi");
        transport
            .event(stream.held.handle, ProgramEvent::Closed)
            .unwrap();
        assert_eq!(
            stream.try_read(&mut buf),
            Ok(Some(0)),
            "the end of the stream"
        );
    }

    #[test]
    fn a_datagram_goes_whole_or_is_dropped() {
        let (script, transport) = transport(64);
        let socket = AppDatagramSocket::dial(&transport, PEER).unwrap();
        socket.send_to(PEER, b"whole").unwrap();
        *script.answers.lock().unwrap() = vec![ProgramSend::WouldBlock, ProgramSend::Wrote(1)];
        assert_eq!(
            socket.send_to(PEER, b"later"),
            Err(AppLinkError::WouldBlock)
        );
        // Blocked until the program says writable: nothing is offered meanwhile.
        assert_eq!(socket.send_to(PEER, b"wait"), Err(AppLinkError::WouldBlock));
        transport
            .event(socket.held.handle, ProgramEvent::Writable)
            .unwrap();
        assert_eq!(socket.send_to(PEER, b"cut"), Err(AppLinkError::Failed));
        assert_eq!(script.sent.lock().unwrap().as_slice(), b"wholec");
        transport
            .received(socket.held.handle, b"in", Some("udp/192.0.2.10:7000"))
            .unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(
            socket.try_recv(&mut buf),
            Ok(Some((2, SocketAddr::from(([192, 0, 2, 10], 7000)))))
        );
        assert_eq!(socket.try_recv(&mut buf), Ok(None));
    }

    #[test]
    fn a_group_is_joined_read_by_member_and_left_on_close() {
        let (script, transport) = transport(64);
        let mut group =
            AppGroupTransport::join(&transport, "udp/239.7.7.7:7447#iface=lan7").expect("joined");
        assert!(group.open());
        assert!(group.carrier_up());
        let handle = group.held.as_ref().unwrap().handle;
        group.send_to_group(b"join");
        assert_eq!(script.sent.lock().unwrap().as_slice(), b"join");
        transport
            .received(handle, b"member", Some("udp/198.51.100.20:7447"))
            .unwrap();
        let mut seen = Vec::new();
        assert!(group.recv_with(&mut |bytes, src| seen.push((bytes.to_vec(), src))));
        assert_eq!(
            seen,
            [(
                b"member".to_vec(),
                SocketAddr::from(([198, 51, 100, 20], 7447))
            )]
        );
        assert!(!group.recv_with(&mut |_, _| {}));
        group.close();
        assert_eq!(
            script.closes.lock().unwrap().as_slice(),
            [handle],
            "the leave"
        );
        assert!(!group.open(), "a group left is not opened again");
    }

    #[test]
    fn the_links_open_a_stream_and_a_datagram_link_and_refuse_tls() {
        let (_script, transport) = transport(64);
        let links = AppLinks::new(Arc::clone(&transport));
        let tcp = links.open_initiator(Locator::tcp(PEER)).expect("a stream");
        assert!(wz_session_core::link::BoxedLinkDriver::batch_length_prefixed(&*tcp.sink));
        let udp = links
            .open_initiator(Locator::udp(PEER))
            .expect("a datagram link");
        assert!(!wz_session_core::link::BoxedLinkDriver::batch_length_prefixed(&*udp.sink));
        assert!(matches!(
            links.open_initiator(Locator::tls(PEER)),
            Err(LinkOpenError::Unsupported)
        ));
        assert!(matches!(
            links.open_acceptor(7447),
            Err(LinkOpenError::Unsupported)
        ));
    }

    #[test]
    fn a_listener_hands_out_the_streams_the_program_accepts() {
        let (_script, transport) = transport(64);
        let links = AppLinks::new(Arc::clone(&transport));
        let listener = links.open_listener(Locator::tcp(PEER)).expect("listening");
        assert!(matches!(listener.accept(), Ok(None)));
        let listening = transport.with(|table| {
            (1..=8)
                .find(|handle| table.kind(*handle) == Some(AppLinkKind::StreamListen))
                .expect("the listener's link")
        });
        transport
            .accepted(listening, "tcp/198.51.100.3:50000")
            .unwrap();
        assert!(matches!(listener.accept(), Ok(Some(_))));
    }
}
