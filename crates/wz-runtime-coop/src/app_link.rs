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
//! # Listening
//!
//! A listener carries nothing itself: the program accepts on it each stream, or each source that
//! sends datagrams to it, and the table holds each as a link of its own
//! (`wz_session_core::app_link_table`). A `tcp/` listener yields a stream link for each accepted
//! stream, a `udp/` one a datagram link for each accepted source, and each is the link of a
//! session run as the acceptor, as a connection taken off a socket's port is. The program has told
//! the sources apart, so a datagram link it accepted is one source's alone: each of its datagrams
//! is read as that source's, whatever the program names with it.
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
    kind_for_locator, AcceptRead, AppLinkKind, DatagramRead, LinkHandle, OpenProgress, SendGate,
    SendStep, StreamRead,
};
use wz_session_core::app_transport::AppTransport;

use crate::group_transport::{GroupSend, GroupTransport};
use crate::ip_stack::{HeapIpDriver, IpDriver};
use crate::link_storage::HeapTx;
use crate::session_drive::{
    LinkListener, LinkOpenError, LinkProto, LinkWritability, Locator, OpenedLink, SessionLinks,
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
    use core::task::{Context, Waker};
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

    /// Wait while `pending` answers `true` and `bound`, a sleep of the session's clock, has not
    /// ended: the thread parks until the program's calls or the clock's move wake it, both by the
    /// one waker, and the wall clock bounds nothing.
    pub(super) fn wait_while_bound(
        mut bound: super::BoundSleep,
        mut pending: impl FnMut(Option<&Waker>) -> bool,
    ) {
        let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        while pending(Some(&waker)) {
            if bound.as_mut().poll(&mut cx).is_ready() {
                return;
            }
            std::thread::park();
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

    /// [`wait_while`] whatever the clock: the turns bound an image's look, and the open's own
    /// deadline on the session's clock is the engine's.
    pub(super) fn wait_while_bound(
        bound: super::BoundSleep,
        pending: impl FnMut(Option<&Waker>) -> bool,
    ) {
        drop(bound);
        wait_while(0, pending);
    }
}

/// A sleep of the session's clock: what an [`OpenBound`] makes.
pub type BoundSleep = core::pin::Pin<Box<dyn core::future::Future<Output = ()> + Send>>;

/// How a session's clock bounds an open over the program's transport: a sleep of that many
/// milliseconds of it. Given for a clock the program moves (a time base it supplies), whose
/// sleeps end when the program says its time has passed them and not when the wall clock's do
/// ([`AppLinks::with_open_bound`]).
pub type OpenBound = Arc<dyn Fn(u64) -> BoundSleep + Send + Sync>;

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

/// Open a link of `kind` for `locator` and wait until the program says it is up: for
/// [`OPEN_WAIT_MS`] of the wall clock, or of the session's clock when `bound` gives a sleep of it.
fn open_link(
    transport: &Arc<AppTransport>,
    kind: AppLinkKind,
    locator: &str,
    bound: Option<&OpenBound>,
) -> Result<LinkHandle, LinkOpenError> {
    let handle = transport.begin_open(kind, locator);
    let mut progress = OpenProgress::Opening;
    let opening = |waker: Option<&core::task::Waker>| {
        progress = transport.with(|table| table.poll_open(handle, waker));
        progress == OpenProgress::Opening
    };
    match bound {
        Some(bound) => wait::wait_while_bound(bound(OPEN_WAIT_MS), opening),
        None => wait::wait_while(OPEN_WAIT_MS, opening),
    }
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

    /// Wait up to `timeout_ms` for the program to take bytes again, offering what is held on the
    /// way: `true` once the link is open and holds nothing for the program (or has ended, which
    /// the send that follows reports).
    fn wait_writable(&self, timeout_ms: u64) -> bool {
        until_writable(&self.transport, self.handle, timeout_ms, || {
            let _ = self.flush();
        })
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

/// Wait up to `timeout_ms` for the program to take bytes on `handle` again, calling `offer` before
/// each look: `true` once the table answers the link writable (open and holding nothing for the
/// program, or ended, which the send that follows reports).
fn until_writable(
    transport: &AppTransport,
    handle: LinkHandle,
    timeout_ms: u64,
    mut offer: impl FnMut(),
) -> bool {
    let mut writable = false;
    wait::wait_while(timeout_ms, |waker| {
        offer();
        writable = transport.with(|table| table.poll_writable(handle, waker));
        !writable
    });
    writable
}

/// A group link's wait for room, asked by a thread other than the one that sends on it: the
/// table's writable answer for the link, as the link's own wait reads it. It names the link and
/// holds nothing of it, so a wait made after the link was released answers at once.
struct GroupRoom {
    transport: Arc<AppTransport>,
    handle: LinkHandle,
}

impl LinkWritability for GroupRoom {
    fn wait_writable(&self, timeout_us: u64) -> bool {
        until_writable(
            &self.transport,
            self.handle,
            timeout_us.div_ceil(1_000),
            || {},
        )
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

    // The program's would-block is the stream's full buffer: a link that holds bytes for the
    // program takes no more until the program says it is writable.
    fn wait_writable(&self, timeout_us: u64) -> bool {
        self.held.wait_writable(timeout_us.div_ceil(1_000))
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
    /// What an open waits on, when it is a clock of the session's ([`AppLinks::with_open_bound`]).
    open_bound: Option<OpenBound>,
}

impl StreamDial for AppStreamDial {
    type Stream = AppStreamSocket;

    fn dial(&self, to: SocketAddr) -> Result<AppStreamSocket, LinkOpenError> {
        let locator = Locator::tcp(to).to_string();
        let handle = open_link(
            &self.transport,
            AppLinkKind::StreamDial,
            &locator,
            self.open_bound.as_ref(),
        )?;
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
        let handle = open_link(
            &self.transport,
            AppLinkKind::StreamListen,
            &locator,
            self.open_bound.as_ref(),
        )?;
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
    /// Whether the source the program names with a datagram is read. A link the session dialled
    /// reads it; a source the program accepted on a listener is one link alone, so each of its
    /// datagrams is `peer`'s whatever the program names.
    reads_sources: bool,
}

impl AppDatagramSocket {
    /// Open a datagram link to `to` over `transport`.
    pub fn dial(transport: &Arc<AppTransport>, to: SocketAddr) -> Result<Self, LinkOpenError> {
        Self::dial_bounded(transport, to, None)
    }

    /// [`Self::dial`] whose open waits on `bound`, a sleep of the session's clock, when there is
    /// one ([`AppLinks::with_open_bound`]).
    pub fn dial_bounded(
        transport: &Arc<AppTransport>,
        to: SocketAddr,
        bound: Option<&OpenBound>,
    ) -> Result<Self, LinkOpenError> {
        let locator = Locator::udp(to).to_string();
        let handle = open_link(transport, AppLinkKind::Datagram, &locator, bound)?;
        Ok(Self {
            held: Held {
                transport: Arc::clone(transport),
                handle,
            },
            peer: to,
            reads_sources: true,
        })
    }

    /// The datagram link of the source the program accepted on a datagram listener as `handle`,
    /// naming it `remote`.
    fn accepted(transport: &Arc<AppTransport>, handle: LinkHandle, remote: &str) -> Self {
        Self {
            held: Held {
                transport: Arc::clone(transport),
                handle,
            },
            peer: socket_of(remote),
            reads_sources: false,
        }
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
                let source = match datagram.source.as_deref() {
                    Some(named) if self.reads_sources => socket_of(named),
                    _ => self.peer,
                };
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
        Self::join_bounded(transport, locator, None)
    }

    /// [`Self::join`] whose open waits on `bound`, a sleep of the session's clock, when there is
    /// one ([`AppLinks::with_open_bound`]).
    pub fn join_bounded(
        transport: &Arc<AppTransport>,
        locator: &str,
        bound: Option<&OpenBound>,
    ) -> Result<Self, LinkOpenError> {
        let handle = open_link(transport, AppLinkKind::Group, locator, bound)?;
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

    // The program's would-block is the group socket's full buffer: the datagram was not sent,
    // and the link takes no more until the program says it is writable. A datagram goes whole
    // or not at all, so one the program took part of is lost.
    fn try_send_to_group(&mut self, datagram: &[u8]) -> GroupSend {
        let Some(held) = &self.held else {
            return GroupSend::Failed;
        };
        match held.send_once(datagram) {
            Ok(taken) if taken == datagram.len() => GroupSend::Sent,
            Ok(0) => GroupSend::Full,
            Ok(_) | Err(_) => GroupSend::Failed,
        }
    }

    // The table's writable answer for the link; a group that was left answers at once, and the
    // send that follows fails.
    fn wait_for_room(&self, timeout_us: u64) -> bool {
        match &self.held {
            Some(held) => held.wait_writable(timeout_us.div_ceil(1_000)),
            None => true,
        }
    }

    fn writability(&self) -> Option<Box<dyn LinkWritability>> {
        let held = self.held.as_ref()?;
        Some(Box::new(GroupRoom {
            transport: Arc::clone(&held.transport),
            handle: held.handle,
        }))
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
/// streams through the program, a `udp/` dial a datagram link, a `udp/` listen a datagram
/// listener and a `udp/` listen naming an interface a group the program joins, and nothing is a
/// socket of the system's. A `tls/` locator is not carried.
pub struct AppLinks {
    transport: Arc<AppTransport>,
    dial: AppStreamDial,
    datagram_rx: usize,
    open_bound: Option<OpenBound>,
}

impl AppLinks {
    /// Links over `transport`.
    pub fn new(transport: Arc<AppTransport>) -> Self {
        Self {
            dial: AppStreamDial {
                transport: Arc::clone(&transport),
                open_bound: None,
            },
            transport,
            datagram_rx: UDP_RX_CAPACITY,
            open_bound: None,
        }
    }

    /// Links whose datagram links receive into buffers of `bytes` each, as
    /// [`IpLinks::with_rx_capacity`](crate::ip_stack::IpLinks::with_rx_capacity) states it.
    #[must_use]
    pub fn with_rx_capacity(mut self, bytes: usize) -> Self {
        self.datagram_rx = bytes.clamp(1, UDP_RX_CAPACITY);
        self
    }

    /// Links whose opens wait for the program to report a link up for [`OPEN_WAIT_MS`] of the
    /// session's clock, which `bound` sleeps on, in place of the wall clock's: the clock of a
    /// session timed by a time base the program supplies.
    #[must_use]
    pub fn with_open_bound(mut self, bound: OpenBound) -> Self {
        self.dial.open_bound = Some(Arc::clone(&bound));
        self.open_bound = Some(bound);
        self
    }
}

/// The driver a link of [`AppLinks`] is: a datagram or a stream link over the program's transport.
pub type AppDriver = HeapIpDriver<AppDatagramSocket, AppStreamSocket>;

impl SessionLinks for AppLinks {
    type Pump = Rc<AppDriver>;

    fn open_acceptor(&self, _port: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        // A datagram port that takes whoever sends first is a socket of the system's; the
        // program's transport accepts streams and datagram sources on listeners
        // (`open_listener`).
        Err(LinkOpenError::Unsupported)
    }

    fn open_initiator(&self, to: Locator) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        let driver: AppDriver = match to.proto {
            LinkProto::Udp => IpDriver::Udp(UdpDriver::initiator_with_buffers(
                AppDatagramSocket::dial_bounded(&self.transport, to.at, self.open_bound.as_ref())?,
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
            LinkProto::Udp => {
                let locator = Locator::udp(at.at).to_string();
                let handle = open_link(
                    &self.transport,
                    AppLinkKind::DatagramListen,
                    &locator,
                    self.open_bound.as_ref(),
                )?;
                Ok(Box::new(AppDatagramListener {
                    held: Held {
                        transport: Arc::clone(&self.transport),
                        handle,
                    },
                    at: at.at,
                    datagram_rx: self.datagram_rx,
                }))
            }
            LinkProto::Tls => Err(LinkOpenError::Unsupported),
        }
    }

    /// The group the program joins for `endpoint`: a `udp/` listen locator naming an interface,
    /// which is what the table opens as a group. Any other endpoint is no group the program's
    /// transport carries, and is refused before the program is asked.
    fn open_group(&self, endpoint: &str) -> Result<Box<dyn GroupTransport>, LinkOpenError> {
        if kind_for_locator(endpoint, true) != Some(AppLinkKind::Group) {
            return Err(LinkOpenError::Unsupported);
        }
        Ok(Box::new(AppGroupTransport::join_bounded(
            &self.transport,
            endpoint,
            self.open_bound.as_ref(),
        )?))
    }
}

/// A `udp/` listener of [`AppLinks`]: each source the program accepts on it is a datagram link.
struct AppDatagramListener {
    held: Held,
    at: SocketAddr,
    /// The receive buffer each accepted link reads into, as [`AppLinks::with_rx_capacity`] set it.
    datagram_rx: usize,
}

impl LinkListener<Rc<AppDriver>> for AppDatagramListener {
    fn local(&self) -> Locator {
        Locator::udp(self.at)
    }

    fn accept(&self) -> Result<Option<OpenedLink<Rc<AppDriver>>>, LinkOpenError> {
        let next = self
            .held
            .transport
            .with(|table| table.next_accepted(self.held.handle, None));
        let socket = match next {
            AcceptRead::Accepted(handle, remote) => {
                AppDatagramSocket::accepted(&self.held.transport, handle, &remote)
            }
            AcceptRead::Empty => return Ok(None),
            AcceptRead::End => return Err(LinkOpenError::Unsupported),
        };
        // The program told this source apart from the others, so the link's remote end is known
        // from the start, as a dialled link's is; the session over it still runs as the acceptor.
        let peer = socket.peer;
        let driver = Rc::new(IpDriver::Udp(UdpDriver::initiator_with_buffers(
            socket,
            peer,
            self.datagram_rx,
            HeapTx::new(0, 0),
        )));
        Ok(Some(OpenedLink {
            sink: driver.clone(),
            pump: driver,
        }))
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
            open_bound: None,
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
            open_bound: None,
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
            open_bound: None,
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
            open_bound: None,
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

    /// A group's datagram the program cannot take now is full and not sent, and the link has no
    /// room until the program says it is writable, whether the group's loop asks or a thread
    /// outside it does; one the program took part of is lost, and a group that was left fails its
    /// send and has room at once.
    #[test]
    fn a_group_datagram_the_program_cannot_take_is_full_until_it_is_writable() {
        let (script, transport) = transport(64);
        let mut group =
            AppGroupTransport::join(&transport, "udp/239.7.7.7:7447#iface=lan7").expect("joined");
        let handle = group.held.as_ref().unwrap().handle;
        let outside = group.writability().expect("a wait from outside the loop");
        assert_eq!(group.try_send_to_group(b"sent"), GroupSend::Sent);
        assert!(
            group.wait_for_room(0),
            "CONTROL: a link that took the datagram"
        );

        *script.answers.lock().unwrap() = vec![ProgramSend::WouldBlock];
        assert_eq!(group.try_send_to_group(b"full"), GroupSend::Full);
        assert!(
            !group.wait_for_room(0),
            "no room until the program is writable"
        );
        assert!(!outside.wait_writable(0), "nor asked from outside");
        assert_eq!(
            group.try_send_to_group(b"held"),
            GroupSend::Full,
            "nothing is offered meanwhile"
        );
        transport.event(handle, ProgramEvent::Writable).unwrap();
        assert!(group.wait_for_room(0));
        assert!(outside.wait_writable(0));

        *script.answers.lock().unwrap() = vec![ProgramSend::Wrote(1)];
        assert_eq!(group.try_send_to_group(b"part"), GroupSend::Failed);
        assert_eq!(script.sent.lock().unwrap().as_slice(), b"sentp");

        group.close();
        assert_eq!(group.try_send_to_group(b"left"), GroupSend::Failed);
        assert!(group.wait_for_room(0));
        assert!(
            outside.wait_writable(0),
            "a wait made after the leave answers at once"
        );
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

    /// The handle the program was asked to open as a datagram listener, and the locator it was
    /// asked for.
    fn datagram_listener_of(script: &Script) -> (LinkHandle, String) {
        script
            .opens
            .lock()
            .unwrap()
            .iter()
            .find(|(_, kind, _)| *kind == AppLinkKind::DatagramListen)
            .map(|(handle, _, locator)| (*handle, locator.clone()))
            .expect("the program was asked to listen for datagrams")
    }

    #[test]
    fn a_datagram_listener_hands_out_each_source_the_program_accepts_as_a_datagram_link() {
        let (script, transport) = transport(64);
        let links = AppLinks::new(Arc::clone(&transport));
        let listener = links
            .open_listener(Locator::udp(PEER))
            .expect("a udp/ listen is carried");
        assert_eq!(listener.local(), Locator::udp(PEER));
        let (listening, locator) = datagram_listener_of(&script);
        assert_eq!(locator, "udp/192.0.2.9:7447");
        assert!(matches!(listener.accept(), Ok(None)), "no source yet");
        transport
            .accepted(listening, "udp/198.51.100.3:50000")
            .expect("a datagram listener accepts");
        let opened = listener
            .accept()
            .expect("the listener stands")
            .expect("the accepted source is a link");
        assert!(
            !wz_session_core::link::BoxedLinkDriver::batch_length_prefixed(&*opened.sink),
            "an accepted source carries datagrams, each a batch"
        );
        assert!(matches!(listener.accept(), Ok(None)), "one link per source");
        // A listener the program closed is broken for good, and the engine lets it go.
        transport.event(listening, ProgramEvent::Closed).unwrap();
        assert!(matches!(listener.accept(), Err(LinkOpenError::Unsupported)));
    }

    #[test]
    fn an_accepted_source_reads_every_datagram_as_its_own() {
        let (script, transport) = transport(64);
        let links = AppLinks::new(Arc::clone(&transport));
        let _listener = links.open_listener(Locator::udp(PEER)).unwrap();
        let (listening, _) = datagram_listener_of(&script);
        transport
            .accepted(listening, "udp/198.51.100.3:50000")
            .unwrap();
        let AcceptRead::Accepted(handle, remote) =
            transport.with(|table| table.next_accepted(listening, None))
        else {
            panic!("the accepted source waits on the listener");
        };
        let socket = AppDatagramSocket::accepted(&transport, handle, &remote);
        // The program names another source, and then none: both are the accepted source's.
        transport
            .received(handle, b"one", Some("udp/203.0.113.7:9"))
            .unwrap();
        transport.received(handle, b"two", None).unwrap();
        let source = SocketAddr::from(([198, 51, 100, 3], 50000));
        let mut buf = [0u8; 8];
        assert_eq!(socket.try_recv(&mut buf), Ok(Some((3, source))));
        assert_eq!(socket.try_recv(&mut buf), Ok(Some((3, source))));
        assert_eq!(socket.try_recv(&mut buf), Ok(None));
        // A dialled link reads the source the program names.
        let dialled = AppDatagramSocket::dial(&transport, PEER).unwrap();
        transport
            .received(dialled.held.handle, b"in", Some("udp/203.0.113.7:9"))
            .unwrap();
        assert_eq!(
            dialled.try_recv(&mut buf),
            Ok(Some((2, SocketAddr::from(([203, 0, 113, 7], 9)))))
        );
    }

    #[test]
    fn the_links_join_a_group_through_the_program_and_refuse_what_names_none() {
        let (script, transport) = transport(64);
        let links = AppLinks::new(Arc::clone(&transport));
        // Neither a datagram listen nor another scheme names a group: refused, with nothing asked
        // of the program.
        for endpoint in ["udp/192.0.2.9:7447", "tcp/239.7.7.7:7447#iface=lan7"] {
            assert!(
                matches!(links.open_group(endpoint), Err(LinkOpenError::Unsupported)),
                "{endpoint}"
            );
        }
        assert!(script.opens.lock().unwrap().is_empty());
        let mut group = links
            .open_group("udp/239.7.7.7:7447#iface=lan7")
            .expect("a group the program joins");
        let (handle, kind, locator) = script.opens.lock().unwrap()[0].clone();
        assert_eq!(
            (kind, locator.as_str()),
            (AppLinkKind::Group, "udp/239.7.7.7:7447#iface=lan7"),
            "the program is asked to join the group the endpoint names"
        );
        // The boxed transport is the group's: taken as the session's link, sent to, read by
        // member, left.
        assert!(group.open());
        assert!(group.carrier_up());
        group.send_to_group(b"beacon");
        assert_eq!(script.sent.lock().unwrap().as_slice(), b"beacon");
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
        group.close();
        assert_eq!(
            script.closes.lock().unwrap().as_slice(),
            [handle],
            "the leave"
        );
    }

    /// A program whose opens stay under way: it never reports a link up.
    #[cfg(feature = "host-lock")]
    struct Unanswered;

    #[cfg(feature = "host-lock")]
    impl AppPort for Unanswered {
        fn open(&self, _link: LinkHandle, _kind: AppLinkKind, _locator: &str) -> ProgramOpen {
            ProgramOpen::Pending
        }

        fn send(&self, _link: LinkHandle, _bytes: &[u8]) -> ProgramSend {
            ProgramSend::WouldBlock
        }

        fn close(&self, _link: LinkHandle) {}
    }

    /// A sleep of a clock the test moves: it ends once the test says the clock passed it, and
    /// wakes whoever waits on it then.
    #[cfg(feature = "host-lock")]
    struct Until {
        passed: Arc<std::sync::atomic::AtomicBool>,
        waker: Arc<Mutex<Option<core::task::Waker>>>,
    }

    #[cfg(feature = "host-lock")]
    impl core::future::Future for Until {
        type Output = ();

        fn poll(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<()> {
            let passed = || self.passed.load(std::sync::atomic::Ordering::SeqCst);
            if passed() {
                return core::task::Poll::Ready(());
            }
            *self.waker.lock().unwrap() = Some(cx.waker().clone());
            if passed() {
                core::task::Poll::Ready(())
            } else {
                core::task::Poll::Pending
            }
        }
    }

    /// An open bounded by the session's clock is given up when that clock passes the bound, long
    /// before the wall clock's ten seconds; while it has not, the open is still waiting.
    #[cfg(feature = "host-lock")]
    #[test]
    fn an_open_bounded_on_the_sessions_clock_is_given_up_when_that_clock_passes() {
        let transport = Arc::new(AppTransport::new(
            Box::new(HostLock(Mutex::new(AppLinkTable::with_queue_bound(64)))),
            Box::new(Unanswered),
        ));
        let passed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waker = Arc::new(Mutex::new(None::<core::task::Waker>));
        let bound: OpenBound = {
            let (passed, waker) = (Arc::clone(&passed), Arc::clone(&waker));
            Arc::new(move |_ms| {
                Box::pin(Until {
                    passed: Arc::clone(&passed),
                    waker: Arc::clone(&waker),
                }) as BoundSleep
            })
        };
        let opening = std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let opened = AppDatagramSocket::dial_bounded(&transport, PEER, Some(&bound));
            (opened.is_err(), started.elapsed())
        });
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            !opening.is_finished(),
            "the open ended while the session's clock stood still"
        );
        passed.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(waker) = waker.lock().unwrap().take() {
            waker.wake();
        }
        let (refused, took) = opening.join().expect("the opening thread");
        assert!(refused, "an open the program never reported up is refused");
        assert!(
            took < std::time::Duration::from_secs(5),
            "the open waited out the wall clock's bound, not the session clock's ({took:?})"
        );
    }

    /// A group's join and a datagram listen of links bounded on the session's clock wait on that
    /// clock as a dial does: still waiting while it stands still, given up once it passes the
    /// bound, long before the wall clock's ten seconds.
    #[cfg(feature = "host-lock")]
    #[test]
    fn a_group_join_and_a_datagram_listen_are_bounded_on_the_sessions_clock() {
        for listen in [false, true] {
            let transport = Arc::new(AppTransport::new(
                Box::new(HostLock(Mutex::new(AppLinkTable::with_queue_bound(64)))),
                Box::new(Unanswered),
            ));
            let passed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let waker = Arc::new(Mutex::new(None::<core::task::Waker>));
            let bound: OpenBound = {
                let (passed, waker) = (Arc::clone(&passed), Arc::clone(&waker));
                Arc::new(move |_ms| {
                    Box::pin(Until {
                        passed: Arc::clone(&passed),
                        waker: Arc::clone(&waker),
                    }) as BoundSleep
                })
            };
            let links = AppLinks::new(transport).with_open_bound(bound);
            let opening = std::thread::spawn(move || {
                let started = std::time::Instant::now();
                let refused = if listen {
                    links.open_listener(Locator::udp(PEER)).is_err()
                } else {
                    links.open_group("udp/239.7.7.7:7447#iface=lan7").is_err()
                };
                (refused, started.elapsed())
            });
            std::thread::sleep(std::time::Duration::from_millis(200));
            assert!(
                !opening.is_finished(),
                "listen={listen}: the open ended while the session's clock stood still"
            );
            passed.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(waker) = waker.lock().unwrap().take() {
                waker.wake();
            }
            let (refused, took) = opening.join().expect("the opening thread");
            assert!(
                refused,
                "listen={listen}: an open never reported up is refused"
            );
            assert!(
                took < std::time::Duration::from_secs(5),
                "listen={listen}: the open waited out the wall clock's bound ({took:?})"
            );
        }
    }
}
