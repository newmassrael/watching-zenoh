// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The links of one transport a program supplies: each handle, its kind, its
//! [`app_link`](crate::app_link) machine, the bytes the program handed in and not yet read, and
//! who waits on it.
//!
//! A program with a network stack of its own hands a session a transport: an `open`, a `send` and
//! a `close` the session calls, and the calls the program makes when bytes arrive or a link
//! changes state. This table is what both sides meet in. It performs no I/O and calls nothing:
//! every method takes what happened and answers what the host must do next ([`Effects`]), which
//! is to call the program's `close` for some links and to wake some tasks, both with no lock held.
//! An engine adapter keeps the table behind its own lock; the program's calls and the session's
//! are each a short critical section around one method.
//!
//! # Handles
//!
//! The table names every link: [`AppLinkTable::reserve`] gives the handle before the program is
//! asked to open anything, so a program that reports the link up (or hands in its first bytes)
//! from its own thread before its `open` call has returned finds the row already there. A handle
//! is never reused for the table's life, so a call naming a link that is gone is refused rather
//! than landing on a newer link; 0 never names one.
//!
//! # Sending
//!
//! A send is two steps around the program's call: [`AppLinkTable::begin_send`], which says
//! whether the link takes bytes now, and [`AppLinkTable::send_answered`] with what the program
//! answered. The bytes themselves are the caller's: a partial send answers how many were
//! written, and the caller sends the rest from that offset, as a writer over a socket does. A
//! would-block parks the writer until the program says the link is writable again. A writable
//! that the program reports between its would-block answer and the table hearing that answer is
//! not lost: the table counts writables, and an answer whose send began before the latest one is
//! retried at once instead of parking.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::task::Waker;

use sce_rust_runtime::helpers::session_id::SessionId;
use sce_rust_runtime::Engine;

use crate::app_link::{AppLinkActions, AppLinkEvent, AppLinkPolicy, AppLinkState};
use crate::duty_outbox::DutyOutbox;

/// The id every link's machine is built under (SCE ADR 0045: the host gives a machine its id). A
/// constant, so the generated constructor never refuses it.
const APP_LINK_SESSION_ID: SessionId = sce_rust_runtime::session_id!("wz-app-link");

/// The name of a link in its transport's table. 0 never names a link.
pub type LinkHandle = u64;

/// What a link is. The first four are what the session asks the program to open; an accepted
/// stream is one the program opened itself on a listener and told the table of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AppLinkKind {
    /// A byte stream the session dials (a `tcp/` connect locator).
    StreamDial = 0,
    /// A listener for byte streams (a `tcp/` listen locator). It carries no bytes itself: the
    /// streams the program accepts on it do.
    StreamListen = 1,
    /// A unicast datagram link (a `udp/` connect locator). Each datagram is one batch.
    Datagram = 2,
    /// A multicast group the session joins (a `udp/` listen locator naming an interface). Each
    /// datagram is one batch, read with the locator it came from.
    Group = 3,
    /// A stream the program accepted on a listener.
    StreamAccepted = 4,
}

impl AppLinkKind {
    /// Whether the link carries a byte stream (framed by the session), as against datagrams.
    pub const fn is_stream(self) -> bool {
        matches!(self, Self::StreamDial | Self::StreamAccepted)
    }

    /// Whether the link carries datagrams, each one batch.
    pub const fn is_datagram(self) -> bool {
        matches!(self, Self::Datagram | Self::Group)
    }
}

/// The kind of link a transport opens for `locator`, or `None` for a locator no kind carries
/// (any scheme but `tcp/` and `udp/`, and a `udp/` listen that names no interface: a listener of
/// unicast datagrams is not a link a pico session opens). `listen` says whether the locator is a
/// listen one.
pub fn kind_for_locator(locator: &str, listen: bool) -> Option<AppLinkKind> {
    let (address, metadata) = locator.split_once('#').unwrap_or((locator, ""));
    let names_interface = metadata.split(';').any(|pair| pair.starts_with("iface="));
    let (scheme, rest) = address.split_once('/')?;
    if rest.is_empty() {
        return None;
    }
    match (scheme, listen) {
        ("tcp", false) => Some(AppLinkKind::StreamDial),
        ("tcp", true) => Some(AppLinkKind::StreamListen),
        ("udp", false) => Some(AppLinkKind::Datagram),
        ("udp", true) if names_interface => Some(AppLinkKind::Group),
        _ => None,
    }
}

/// What the program's `open` answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramOpen {
    /// The link is up now.
    Up,
    /// The open is under way; the program reports `connected` or `closed` later.
    Pending,
    /// The program refused the open, or it failed.
    Refused,
}

/// What the program's `send` answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramSend {
    /// It took this many of the bytes, from the first.
    Wrote(usize),
    /// It took none, and says `writable` when it takes bytes again.
    WouldBlock,
    /// The link is closed.
    Closed,
    /// The send failed; the link is unusable.
    Failed,
}

/// What the program says happened to a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramEvent {
    /// The link the session asked it to open is up.
    Connected,
    /// The link is gone (or its open failed).
    Closed,
    /// A link whose send would block takes bytes again.
    Writable,
}

/// Why a call of the program's was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundRefusal {
    /// No link of this transport has that handle (it never did, or it has been released).
    NoSuchLink,
    /// The link is not up yet: bytes before `connected` are refused.
    NotOpen,
    /// The link is closing or closed.
    Closed,
    /// The call does not apply to the link's kind: bytes on a listener, an accept on a link that
    /// is not one.
    WrongKind,
}

/// Bytes the program handed in, copied at the call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    /// The bytes.
    pub bytes: Vec<u8>,
    /// The locator a datagram came from, when the program named one.
    pub source: Option<String>,
}

/// What the host does after a method returns, with no lock held: call the program's `close` for
/// each link in `close` and then report each with [`AppLinkTable::close_done`], and wake every
/// waker in `wake`.
#[derive(Debug, Default)]
#[must_use = "the program's close and the wakes are the host's to perform"]
pub struct Effects {
    /// The links whose program side the host closes.
    pub close: Vec<LinkHandle>,
    /// The tasks to wake.
    pub wake: Vec<Waker>,
}

impl Effects {
    /// Whether there is nothing to do.
    pub fn is_empty(&self) -> bool {
        self.close.is_empty() && self.wake.is_empty()
    }

    fn absorb(&mut self, other: Effects) {
        self.close.extend(other.close);
        self.wake.extend(other.wake);
    }
}

/// Where a link the session waits to open stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenProgress {
    /// Not up yet; the waker given is woken when that changes.
    Opening,
    /// Up.
    Open,
    /// It will not come up.
    Closed,
}

/// What a read of a stream found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRead {
    /// This many bytes were copied into the buffer.
    Bytes(usize),
    /// Nothing queued; the waker given is woken when bytes arrive or the link closes.
    Empty,
    /// The link is closed and everything it carried has been read.
    End,
}

/// What a read of a datagram link found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatagramRead {
    /// One datagram, whole.
    Datagram(Received),
    /// Nothing queued; the waker given is woken when one arrives or the link closes.
    Empty,
    /// The link is closed and every datagram it carried has been read.
    End,
}

/// What a listener's next accept found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptRead {
    /// A stream the program accepted, and the locator it named for the remote end.
    Accepted(LinkHandle, String),
    /// None waiting; the waker given is woken when one is accepted or the listener closes.
    Empty,
    /// The listener is closed.
    End,
}

/// Whether a send may go to the program now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendGate {
    /// Call the program's send, then report what it answered with this ticket.
    Go(SendTicket),
    /// The link would block; the waker given is woken when it is writable or closed.
    Blocked,
    /// The link is not up yet; the waker given is woken when it is.
    Opening,
    /// The link is closing or closed.
    Closed,
    /// Another send on this link has not been answered yet.
    Busy,
}

/// A send that [`AppLinkTable::begin_send`] let through, to be answered once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendTicket {
    handle: LinkHandle,
    writable_seen: u64,
}

impl SendTicket {
    /// The link the send is on.
    pub const fn handle(self) -> LinkHandle {
        self.handle
    }
}

/// What a send came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendStep {
    /// The program took this many bytes; the caller sends the rest from there.
    Wrote(usize),
    /// The program would block, and the link became writable before the answer was heard: send
    /// again now.
    Retry,
    /// The program would block; the writer waits for its waker.
    Blocked,
    /// The link is closed.
    Closed,
    /// The program's send failed, or it answered more bytes than it was given; the link is
    /// closed.
    Failed,
}

/// The duties a link's machine recorded.
struct LinkDuties {
    duties: DutyOutbox,
}

impl LinkDuties {
    const WAKE: u8 = 1 << 0;
    const CLOSE: u8 = 1 << 1;
}

impl AppLinkActions for LinkDuties {
    const REALIZATION: ::sce_rust_runtime::ActionRealization =
        ::sce_rust_runtime::ActionRealization::Performs;

    fn close_program(&mut self) {
        self.duties.record(Self::CLOSE);
    }

    fn wake_waiters(&mut self) {
        self.duties.record(Self::WAKE);
    }
}

struct Link {
    kind: AppLinkKind,
    machine: Engine<AppLinkPolicy<LinkDuties>>,
    rx: VecDeque<Received>,
    /// How much of the front of `rx` a stream read has already taken.
    rx_front_taken: usize,
    /// The streams accepted on a listener and not yet taken by the session.
    accepted: VecDeque<(LinkHandle, String)>,
    /// The locator the program named for the remote end of an accepted stream.
    remote: Option<String>,
    reader: Option<Waker>,
    writer: Option<Waker>,
    opener: Option<Waker>,
    /// How many times the program has said the link is writable.
    writables: u64,
    /// A send was let through and not yet answered.
    sending: bool,
    /// The session has let the link go; the row goes once the link is closed.
    released: bool,
}

impl Link {
    fn new(kind: AppLinkKind) -> Self {
        let mut machine = Engine::new(AppLinkPolicy::new_with_checked_session_id(
            APP_LINK_SESSION_ID,
            LinkDuties {
                duties: DutyOutbox::default(),
            },
        ));
        // W3C SCXML 3.3: enter the initial `Opening` leaf, which records no duty.
        machine.initialize().unwrap_or_else(|never| match never {});
        let _ = machine.policy().actions().duties.take();
        Self {
            kind,
            machine,
            rx: VecDeque::new(),
            rx_front_taken: 0,
            accepted: VecDeque::new(),
            remote: None,
            reader: None,
            writer: None,
            opener: None,
            writables: 0,
            sending: false,
            released: false,
        }
    }

    fn state(&self) -> AppLinkState {
        self.machine.get_current_state()
    }

    fn is_gone(&self) -> bool {
        matches!(self.state(), AppLinkState::Closing | AppLinkState::Closed)
    }

    /// Run `event` and turn the duties it recorded into what the host does.
    fn drive(&mut self, handle: LinkHandle, event: AppLinkEvent) -> Effects {
        self.machine.process_event(event);
        let duties = self.machine.policy().actions().duties.take();
        let mut effects = Effects::default();
        if duties.has(LinkDuties::WAKE) {
            effects.wake.extend(
                [self.opener.take(), self.reader.take(), self.writer.take()]
                    .into_iter()
                    .flatten(),
            );
        }
        if duties.has(LinkDuties::CLOSE) {
            effects.close.push(handle);
        }
        effects
    }
}

fn keep(slot: &mut Option<Waker>, waker: Option<&Waker>) {
    if let Some(waker) = waker {
        match slot {
            Some(held) if held.will_wake(waker) => {}
            _ => *slot = Some(waker.clone()),
        }
    }
}

/// The links of one transport.
pub struct AppLinkTable {
    links: BTreeMap<LinkHandle, Link>,
    next: LinkHandle,
}

impl Default for AppLinkTable {
    fn default() -> Self {
        Self::new()
    }
}

impl AppLinkTable {
    /// A table with no link.
    pub const fn new() -> Self {
        Self {
            links: BTreeMap::new(),
            next: 1,
        }
    }

    /// How many links the table holds.
    pub fn len(&self) -> usize {
        self.links.len()
    }

    /// Whether the table holds no link.
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    /// The state of a link, `None` for a handle the table does not hold.
    pub fn state(&self, handle: LinkHandle) -> Option<AppLinkState> {
        self.links.get(&handle).map(Link::state)
    }

    /// The kind of a link, `None` for a handle the table does not hold.
    pub fn kind(&self, handle: LinkHandle) -> Option<AppLinkKind> {
        self.links.get(&handle).map(|link| link.kind)
    }

    /// The locator the program named for the remote end of an accepted stream.
    pub fn remote(&self, handle: LinkHandle) -> Option<&str> {
        self.links.get(&handle)?.remote.as_deref()
    }

    /// How many bytes are queued on a link and not yet read.
    pub fn queued_bytes(&self, handle: LinkHandle) -> usize {
        self.links.get(&handle).map_or(0, |link| {
            link.rx
                .iter()
                .map(|received| received.bytes.len())
                .sum::<usize>()
                - link.rx_front_taken
        })
    }

    fn take_handle(&mut self) -> LinkHandle {
        let handle = self.next;
        self.next += 1;
        handle
    }

    /// A new link of `kind`, Opening, before the program is asked to open it.
    pub fn reserve(&mut self, kind: AppLinkKind) -> LinkHandle {
        let handle = self.take_handle();
        self.links.insert(handle, Link::new(kind));
        handle
    }

    /// What the program's `open` of `handle` answered.
    pub fn opened(&mut self, handle: LinkHandle, answer: ProgramOpen) -> Effects {
        let Some(link) = self.links.get_mut(&handle) else {
            return Effects::default();
        };
        if link.state() != AppLinkState::Opening {
            // The program reported the link up or closed from its own thread before its open
            // returned; that report stands.
            return Effects::default();
        }
        match answer {
            ProgramOpen::Up => link.drive(handle, AppLinkEvent::LinkConnected),
            ProgramOpen::Pending => Effects::default(),
            ProgramOpen::Refused => link.drive(handle, AppLinkEvent::LinkClosed),
        }
    }

    /// Where a link the session waits to open stands; `waker` is kept while it is Opening.
    pub fn poll_open(&mut self, handle: LinkHandle, waker: Option<&Waker>) -> OpenProgress {
        let Some(link) = self.links.get_mut(&handle) else {
            return OpenProgress::Closed;
        };
        match link.state() {
            AppLinkState::Opening => {
                keep(&mut link.opener, waker);
                OpenProgress::Opening
            }
            AppLinkState::Open | AppLinkState::Blocked => OpenProgress::Open,
            AppLinkState::Closing | AppLinkState::Closed => OpenProgress::Closed,
        }
    }

    /// The program says `event` happened to `handle`.
    pub fn event(
        &mut self,
        handle: LinkHandle,
        event: ProgramEvent,
    ) -> Result<Effects, InboundRefusal> {
        let link = self
            .links
            .get_mut(&handle)
            .ok_or(InboundRefusal::NoSuchLink)?;
        if link.state() == AppLinkState::Closed {
            return Err(InboundRefusal::Closed);
        }
        Ok(match event {
            ProgramEvent::Connected => match link.state() {
                AppLinkState::Opening => link.drive(handle, AppLinkEvent::LinkConnected),
                // Said again of a link that is up: nothing changes.
                _ => Effects::default(),
            },
            ProgramEvent::Closed => {
                let mut effects = link.drive(handle, AppLinkEvent::LinkClosed);
                effects.absorb(self.close_accepted_of(handle));
                self.forget_if_done(handle);
                effects
            }
            ProgramEvent::Writable => {
                link.writables += 1;
                link.drive(handle, AppLinkEvent::LinkWritable)
            }
        })
    }

    /// The program accepted a stream on `listener`, whose remote end it names `remote`: a new
    /// link, Open, which the session takes with [`Self::next_accepted`].
    pub fn accepted(
        &mut self,
        listener: LinkHandle,
        remote: &str,
    ) -> Result<(LinkHandle, Effects), InboundRefusal> {
        let link = self
            .links
            .get(&listener)
            .ok_or(InboundRefusal::NoSuchLink)?;
        if link.kind != AppLinkKind::StreamListen {
            return Err(InboundRefusal::WrongKind);
        }
        match link.state() {
            AppLinkState::Opening => return Err(InboundRefusal::NotOpen),
            AppLinkState::Closing | AppLinkState::Closed => return Err(InboundRefusal::Closed),
            AppLinkState::Open | AppLinkState::Blocked => {}
        }
        let handle = self.take_handle();
        let mut stream = Link::new(AppLinkKind::StreamAccepted);
        stream.remote = Some(String::from(remote));
        // Nobody waits on the new link yet, so its entry wakes nobody.
        let _ = stream.drive(handle, AppLinkEvent::LinkAccepted);
        self.links.insert(handle, stream);
        let listener_link = self
            .links
            .get_mut(&listener)
            .ok_or(InboundRefusal::NoSuchLink)?;
        listener_link
            .accepted
            .push_back((handle, String::from(remote)));
        let mut effects = Effects::default();
        effects.wake.extend(listener_link.reader.take());
        Ok((handle, effects))
    }

    /// The program hands in `bytes` that arrived on `handle` (with the locator a datagram came
    /// from, if it names one). They are copied, so the program's buffer is its own again when
    /// this returns.
    pub fn received(
        &mut self,
        handle: LinkHandle,
        bytes: &[u8],
        source: Option<&str>,
    ) -> Result<Effects, InboundRefusal> {
        let link = self
            .links
            .get_mut(&handle)
            .ok_or(InboundRefusal::NoSuchLink)?;
        if link.kind == AppLinkKind::StreamListen {
            return Err(InboundRefusal::WrongKind);
        }
        match link.state() {
            AppLinkState::Opening => return Err(InboundRefusal::NotOpen),
            AppLinkState::Closing | AppLinkState::Closed => return Err(InboundRefusal::Closed),
            AppLinkState::Open | AppLinkState::Blocked => {}
        }
        let mut effects = Effects::default();
        // An empty stream chunk carries nothing; an empty datagram is a datagram.
        if bytes.is_empty() && link.kind.is_stream() {
            return Ok(effects);
        }
        link.rx.push_back(Received {
            bytes: bytes.to_vec(),
            source: if link.kind.is_datagram() {
                source.map(String::from)
            } else {
                None
            },
        });
        effects.wake.extend(link.reader.take());
        Ok(effects)
    }

    /// Copy what is queued on stream `handle` into `buf`, as much as fits.
    pub fn read_stream(
        &mut self,
        handle: LinkHandle,
        buf: &mut [u8],
        waker: Option<&Waker>,
    ) -> StreamRead {
        let Some(link) = self.links.get_mut(&handle) else {
            return StreamRead::End;
        };
        let mut copied = 0;
        while copied < buf.len() {
            let Some(front) = link.rx.front() else {
                break;
            };
            let available = &front.bytes[link.rx_front_taken..];
            let n = available.len().min(buf.len() - copied);
            buf[copied..copied + n].copy_from_slice(&available[..n]);
            copied += n;
            link.rx_front_taken += n;
            if link.rx_front_taken == front.bytes.len() {
                link.rx.pop_front();
                link.rx_front_taken = 0;
            }
        }
        if copied > 0 {
            return StreamRead::Bytes(copied);
        }
        if buf.is_empty() {
            return StreamRead::Bytes(0);
        }
        if link.is_gone() {
            return StreamRead::End;
        }
        keep(&mut link.reader, waker);
        StreamRead::Empty
    }

    /// The next datagram queued on `handle`.
    pub fn read_datagram(&mut self, handle: LinkHandle, waker: Option<&Waker>) -> DatagramRead {
        let Some(link) = self.links.get_mut(&handle) else {
            return DatagramRead::End;
        };
        if let Some(datagram) = link.rx.pop_front() {
            return DatagramRead::Datagram(datagram);
        }
        if link.is_gone() {
            return DatagramRead::End;
        }
        keep(&mut link.reader, waker);
        DatagramRead::Empty
    }

    /// The next stream accepted on `listener`. The session owns it from here, and releases it as
    /// it releases any link.
    pub fn next_accepted(&mut self, listener: LinkHandle, waker: Option<&Waker>) -> AcceptRead {
        let Some(link) = self.links.get_mut(&listener) else {
            return AcceptRead::End;
        };
        if let Some((handle, remote)) = link.accepted.pop_front() {
            return AcceptRead::Accepted(handle, remote);
        }
        if link.is_gone() {
            return AcceptRead::End;
        }
        keep(&mut link.reader, waker);
        AcceptRead::Empty
    }

    /// Whether a send on `handle` may go to the program now. `waker` is kept when it may not and
    /// will later.
    pub fn begin_send(&mut self, handle: LinkHandle, waker: Option<&Waker>) -> SendGate {
        let Some(link) = self.links.get_mut(&handle) else {
            return SendGate::Closed;
        };
        if link.kind == AppLinkKind::StreamListen {
            return SendGate::Closed;
        }
        match link.state() {
            AppLinkState::Opening => {
                keep(&mut link.opener, waker);
                SendGate::Opening
            }
            AppLinkState::Blocked => {
                keep(&mut link.writer, waker);
                SendGate::Blocked
            }
            AppLinkState::Closing | AppLinkState::Closed => SendGate::Closed,
            AppLinkState::Open if link.sending => SendGate::Busy,
            AppLinkState::Open => {
                link.sending = true;
                // Kept now, so a writable that comes while the program's answer is on its way
                // wakes this writer.
                keep(&mut link.writer, waker);
                SendGate::Go(SendTicket {
                    handle,
                    writable_seen: link.writables,
                })
            }
        }
    }

    /// What the program's send of `offered` bytes, let through by `ticket`, answered.
    pub fn send_answered(
        &mut self,
        ticket: SendTicket,
        offered: usize,
        answer: ProgramSend,
    ) -> (SendStep, Effects) {
        let handle = ticket.handle;
        let Some(link) = self.links.get_mut(&handle) else {
            return (SendStep::Closed, Effects::default());
        };
        link.sending = false;
        if link.is_gone() {
            // The program closed the link from its own thread while the send was out.
            return (SendStep::Closed, Effects::default());
        }
        match answer {
            ProgramSend::Wrote(written) if written > offered => (
                SendStep::Failed,
                link.drive(handle, AppLinkEvent::SendFailed),
            ),
            ProgramSend::Wrote(written) if written > 0 => {
                (SendStep::Wrote(written), Effects::default())
            }
            // Nothing written of something offered is a send that would block.
            ProgramSend::Wrote(_) | ProgramSend::WouldBlock => {
                if link.writables != ticket.writable_seen {
                    (SendStep::Retry, Effects::default())
                } else {
                    (
                        SendStep::Blocked,
                        link.drive(handle, AppLinkEvent::SendBlocked),
                    )
                }
            }
            ProgramSend::Closed => (
                SendStep::Closed,
                link.drive(handle, AppLinkEvent::SendClosed),
            ),
            ProgramSend::Failed => (
                SendStep::Failed,
                link.drive(handle, AppLinkEvent::SendFailed),
            ),
        }
    }

    /// The session lets `handle` go. A link that is not closed is closed: its handle is in the
    /// effects' `close`, for the host to call the program's close with and then report with
    /// [`Self::close_done`]. The row is forgotten once the link is closed. A listener's accepted
    /// streams that the session never took go with it.
    pub fn release(&mut self, handle: LinkHandle) -> Effects {
        let Some(link) = self.links.get_mut(&handle) else {
            return Effects::default();
        };
        link.released = true;
        let mut effects = link.drive(handle, AppLinkEvent::SessionClose);
        effects.absorb(self.close_accepted_of(handle));
        self.forget_if_done(handle);
        effects
    }

    /// The program's close of `handle` returned.
    pub fn close_done(&mut self, handle: LinkHandle) -> Effects {
        let Some(link) = self.links.get_mut(&handle) else {
            return Effects::default();
        };
        let effects = link.drive(handle, AppLinkEvent::CloseDone);
        self.forget_if_done(handle);
        effects
    }

    /// Release every stream accepted on `listener` that the session never took.
    fn close_accepted_of(&mut self, listener: LinkHandle) -> Effects {
        let pending: Vec<LinkHandle> = match self.links.get_mut(&listener) {
            Some(link) => link.accepted.drain(..).map(|(handle, _)| handle).collect(),
            None => Vec::new(),
        };
        let mut effects = Effects::default();
        for handle in pending {
            effects.absorb(self.release(handle));
        }
        effects
    }

    fn forget_if_done(&mut self, handle: LinkHandle) {
        if self
            .links
            .get(&handle)
            .is_some_and(|link| link.released && link.state() == AppLinkState::Closed)
        {
            self.links.remove(&handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicUsize, Ordering};

    struct Counter(AtomicUsize);

    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counter() -> (Arc<Counter>, Waker) {
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        (counter.clone(), Waker::from(counter))
    }

    fn wakes(effects: Effects) -> usize {
        let n = effects.wake.len();
        for waker in effects.wake {
            waker.wake();
        }
        n
    }

    /// A dialled stream, reported up by the program.
    fn open_stream(table: &mut AppLinkTable) -> LinkHandle {
        let handle = table.reserve(AppLinkKind::StreamDial);
        assert!(table.opened(handle, ProgramOpen::Pending).is_empty());
        let _ = table.event(handle, ProgramEvent::Connected).expect("up");
        handle
    }

    #[test]
    fn the_locators_a_transport_carries_name_their_kind() {
        assert_eq!(
            kind_for_locator("tcp/192.0.2.7:7447", false),
            Some(AppLinkKind::StreamDial)
        );
        assert_eq!(
            kind_for_locator("tcp/192.0.2.7:7447", true),
            Some(AppLinkKind::StreamListen)
        );
        assert_eq!(
            kind_for_locator("udp/192.0.2.7:7447", false),
            Some(AppLinkKind::Datagram)
        );
        assert_eq!(
            kind_for_locator("udp/239.1.2.3:7447#iface=lan7", true),
            Some(AppLinkKind::Group)
        );
        // Refused: a unicast datagram listener, other schemes, a scheme with no address.
        assert_eq!(kind_for_locator("udp/192.0.2.7:7447", true), None);
        for locator in [
            "tls/192.0.2.7:7447",
            "quic/192.0.2.7:7447",
            "serial//dev/ttyX",
            "tcp/",
            "tcp",
        ] {
            assert_eq!(kind_for_locator(locator, false), None, "{locator}");
            assert_eq!(kind_for_locator(locator, true), None, "{locator}");
        }
    }

    #[test]
    fn a_handle_is_never_zero_and_never_reused() {
        let mut table = AppLinkTable::new();
        let first = table.reserve(AppLinkKind::StreamDial);
        assert_ne!(first, 0);
        let _ = table.release(first);
        let _ = table.close_done(first);
        assert_eq!(table.state(first), None, "released and closed: forgotten");
        let second = table.reserve(AppLinkKind::StreamDial);
        assert_ne!(second, first);
    }

    #[test]
    fn an_open_the_program_answers_up_is_open_and_wakes_the_opener() {
        let mut table = AppLinkTable::new();
        let handle = table.reserve(AppLinkKind::StreamDial);
        let (count, waker) = counter();
        assert_eq!(table.poll_open(handle, Some(&waker)), OpenProgress::Opening);
        assert_eq!(wakes(table.opened(handle, ProgramOpen::Up)), 1);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(table.state(handle), Some(AppLinkState::Open));
        assert_eq!(table.poll_open(handle, None), OpenProgress::Open);
    }

    #[test]
    fn a_pending_open_comes_up_on_connected() {
        let mut table = AppLinkTable::new();
        let handle = table.reserve(AppLinkKind::StreamDial);
        assert!(table.opened(handle, ProgramOpen::Pending).is_empty());
        assert_eq!(table.state(handle), Some(AppLinkState::Opening));
        let (_count, waker) = counter();
        let _ = table.poll_open(handle, Some(&waker));
        assert_eq!(
            wakes(table.event(handle, ProgramEvent::Connected).unwrap()),
            1
        );
        assert_eq!(table.state(handle), Some(AppLinkState::Open));
        // Said again: nothing changes.
        assert!(table
            .event(handle, ProgramEvent::Connected)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_report_from_the_program_before_its_open_returned_stands() {
        let mut table = AppLinkTable::new();
        let handle = table.reserve(AppLinkKind::StreamDial);
        let _ = table.event(handle, ProgramEvent::Connected).unwrap();
        // Then the open returns, answering pending: the link stays up.
        assert!(table.opened(handle, ProgramOpen::Pending).is_empty());
        assert_eq!(table.state(handle), Some(AppLinkState::Open));
    }

    #[test]
    fn a_refused_open_is_closed_and_the_opener_hears_it() {
        let mut table = AppLinkTable::new();
        let handle = table.reserve(AppLinkKind::StreamDial);
        let (_count, waker) = counter();
        let _ = table.poll_open(handle, Some(&waker));
        assert_eq!(wakes(table.opened(handle, ProgramOpen::Refused)), 1);
        assert_eq!(table.poll_open(handle, None), OpenProgress::Closed);
        // A pending open the program later reports closed is the same.
        let other = table.reserve(AppLinkKind::StreamDial);
        let _ = table.opened(other, ProgramOpen::Pending);
        let _ = table.event(other, ProgramEvent::Closed).unwrap();
        assert_eq!(table.poll_open(other, None), OpenProgress::Closed);
    }

    #[test]
    fn bytes_before_connected_are_refused() {
        let mut table = AppLinkTable::new();
        let handle = table.reserve(AppLinkKind::StreamDial);
        assert_eq!(
            table.received(handle, b"early", None).unwrap_err(),
            InboundRefusal::NotOpen
        );
    }

    #[test]
    fn received_bytes_are_copied_and_read_across_chunk_boundaries() {
        let mut table = AppLinkTable::new();
        let handle = open_stream(&mut table);
        let (count, waker) = counter();
        let mut buf = [0u8; 4];
        assert_eq!(
            table.read_stream(handle, &mut buf, Some(&waker)),
            StreamRead::Empty
        );
        let mut program_buffer = *b"abc";
        assert_eq!(
            wakes(table.received(handle, &program_buffer, None).unwrap()),
            1
        );
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        // The program reuses its buffer at once; what was queued is a copy.
        program_buffer.copy_from_slice(b"xyz");
        let _ = table.received(handle, b"defg", None).unwrap();
        assert_eq!(table.queued_bytes(handle), 7);
        assert_eq!(
            table.read_stream(handle, &mut buf, None),
            StreamRead::Bytes(4)
        );
        assert_eq!(&buf, b"abcd");
        assert_eq!(
            table.read_stream(handle, &mut buf, None),
            StreamRead::Bytes(3)
        );
        assert_eq!(&buf[..3], b"efg");
        assert_eq!(table.read_stream(handle, &mut buf, None), StreamRead::Empty);
    }

    #[test]
    fn bytes_queued_before_a_close_are_read_and_then_the_stream_ends() {
        let mut table = AppLinkTable::new();
        let handle = open_stream(&mut table);
        let _ = table.received(handle, b"tail", None).unwrap();
        let _ = table.event(handle, ProgramEvent::Closed).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(
            table.read_stream(handle, &mut buf, None),
            StreamRead::Bytes(4)
        );
        assert_eq!(table.read_stream(handle, &mut buf, None), StreamRead::End);
    }

    #[test]
    fn receive_after_close_is_refused() {
        let mut table = AppLinkTable::new();
        let handle = open_stream(&mut table);
        let _ = table.event(handle, ProgramEvent::Closed).unwrap();
        assert_eq!(
            table.received(handle, b"late", None).unwrap_err(),
            InboundRefusal::Closed
        );
        assert_eq!(
            table.event(handle, ProgramEvent::Writable).unwrap_err(),
            InboundRefusal::Closed
        );
        // Released by the session, the row is gone and the handle names nothing.
        let _ = table.release(handle);
        assert_eq!(
            table.received(handle, b"later", None).unwrap_err(),
            InboundRefusal::NoSuchLink
        );
    }

    #[test]
    fn a_reader_waiting_on_a_closing_link_is_woken_and_ends() {
        let mut table = AppLinkTable::new();
        let handle = open_stream(&mut table);
        let (count, waker) = counter();
        let mut buf = [0u8; 2];
        assert_eq!(
            table.read_stream(handle, &mut buf, Some(&waker)),
            StreamRead::Empty
        );
        assert_eq!(wakes(table.event(handle, ProgramEvent::Closed).unwrap()), 1);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(table.read_stream(handle, &mut buf, None), StreamRead::End);
    }

    #[test]
    fn a_partial_send_leaves_the_link_open_and_answers_the_count() {
        let mut table = AppLinkTable::new();
        let handle = open_stream(&mut table);
        let SendGate::Go(ticket) = table.begin_send(handle, None) else {
            panic!("an open link takes a send");
        };
        let (step, effects) = table.send_answered(ticket, 10, ProgramSend::Wrote(4));
        assert_eq!(step, SendStep::Wrote(4));
        assert!(effects.is_empty());
        assert_eq!(table.state(handle), Some(AppLinkState::Open));
        // The rest goes in the next send.
        assert!(matches!(table.begin_send(handle, None), SendGate::Go(_)));
    }

    #[test]
    fn a_second_send_before_the_first_is_answered_is_busy() {
        let mut table = AppLinkTable::new();
        let handle = open_stream(&mut table);
        let SendGate::Go(ticket) = table.begin_send(handle, None) else {
            panic!("an open link takes a send");
        };
        assert_eq!(table.begin_send(handle, None), SendGate::Busy);
        let _ = table.send_answered(ticket, 1, ProgramSend::Wrote(1));
        assert!(matches!(table.begin_send(handle, None), SendGate::Go(_)));
    }

    #[test]
    fn a_would_block_parks_the_writer_until_writable() {
        let mut table = AppLinkTable::new();
        let handle = open_stream(&mut table);
        let (count, waker) = counter();
        let SendGate::Go(ticket) = table.begin_send(handle, Some(&waker)) else {
            panic!("an open link takes a send");
        };
        let (step, _) = table.send_answered(ticket, 8, ProgramSend::WouldBlock);
        assert_eq!(step, SendStep::Blocked);
        assert_eq!(table.state(handle), Some(AppLinkState::Blocked));
        assert_eq!(table.begin_send(handle, Some(&waker)), SendGate::Blocked);
        // Bytes still arrive while the write side is blocked.
        let _ = table.received(handle, b"in", None).unwrap();
        assert_eq!(
            wakes(table.event(handle, ProgramEvent::Writable).unwrap()),
            1
        );
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(table.state(handle), Some(AppLinkState::Open));
        assert!(matches!(table.begin_send(handle, None), SendGate::Go(_)));
    }

    #[test]
    fn nothing_written_of_something_offered_is_a_would_block() {
        let mut table = AppLinkTable::new();
        let handle = open_stream(&mut table);
        let SendGate::Go(ticket) = table.begin_send(handle, None) else {
            panic!("an open link takes a send");
        };
        let (step, _) = table.send_answered(ticket, 3, ProgramSend::Wrote(0));
        assert_eq!(step, SendStep::Blocked);
        assert_eq!(table.state(handle), Some(AppLinkState::Blocked));
    }

    #[test]
    fn a_writable_between_the_would_block_and_its_answer_is_not_lost() {
        let mut table = AppLinkTable::new();
        let handle = open_stream(&mut table);
        let SendGate::Go(ticket) = table.begin_send(handle, None) else {
            panic!("an open link takes a send");
        };
        // The program's send returns would-block, and before the session records it the
        // program's own thread reports the link writable.
        let _ = table.event(handle, ProgramEvent::Writable).unwrap();
        let (step, _) = table.send_answered(ticket, 5, ProgramSend::WouldBlock);
        assert_eq!(
            step,
            SendStep::Retry,
            "the writable came after the send began"
        );
        assert_eq!(table.state(handle), Some(AppLinkState::Open));
    }

    #[test]
    fn a_program_that_answers_more_than_it_was_given_fails_the_link() {
        let mut table = AppLinkTable::new();
        let handle = open_stream(&mut table);
        let SendGate::Go(ticket) = table.begin_send(handle, None) else {
            panic!("an open link takes a send");
        };
        let (step, _) = table.send_answered(ticket, 4, ProgramSend::Wrote(5));
        assert_eq!(step, SendStep::Failed);
        assert_eq!(table.state(handle), Some(AppLinkState::Closed));
    }

    #[test]
    fn a_send_answered_closed_or_failed_closes_the_link() {
        for (answer, step) in [
            (ProgramSend::Closed, SendStep::Closed),
            (ProgramSend::Failed, SendStep::Failed),
        ] {
            let mut table = AppLinkTable::new();
            let handle = open_stream(&mut table);
            let (_count, waker) = counter();
            let mut buf = [0u8; 1];
            let _ = table.read_stream(handle, &mut buf, Some(&waker));
            let SendGate::Go(ticket) = table.begin_send(handle, None) else {
                panic!("an open link takes a send");
            };
            let (got, effects) = table.send_answered(ticket, 2, answer);
            assert_eq!(got, step);
            assert_eq!(wakes(effects), 1, "the reader hears the close");
            assert_eq!(table.state(handle), Some(AppLinkState::Closed));
            assert_eq!(table.begin_send(handle, None), SendGate::Closed);
        }
    }

    #[test]
    fn a_link_closed_while_its_send_was_out_answers_closed() {
        let mut table = AppLinkTable::new();
        let handle = open_stream(&mut table);
        let SendGate::Go(ticket) = table.begin_send(handle, None) else {
            panic!("an open link takes a send");
        };
        let _ = table.event(handle, ProgramEvent::Closed).unwrap();
        let (step, _) = table.send_answered(ticket, 2, ProgramSend::Wrote(2));
        assert_eq!(step, SendStep::Closed);
    }

    #[test]
    fn close_while_blocked_wakes_the_writer_and_closes_the_program_side() {
        let mut table = AppLinkTable::new();
        let handle = open_stream(&mut table);
        let (count, waker) = counter();
        let SendGate::Go(ticket) = table.begin_send(handle, Some(&waker)) else {
            panic!("an open link takes a send");
        };
        let _ = table.send_answered(ticket, 8, ProgramSend::WouldBlock);
        let effects = table.release(handle);
        assert_eq!(effects.close, [handle], "the program is asked to close it");
        assert_eq!(table.state(handle), Some(AppLinkState::Closing));
        assert!(table.received(handle, b"x", None).is_err());
        let done = table.close_done(handle);
        assert_eq!(wakes(done), 1);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(table.state(handle), None, "released and closed: forgotten");
    }

    #[test]
    fn a_link_the_program_closed_is_forgotten_when_released_without_closing_it_again() {
        let mut table = AppLinkTable::new();
        let handle = open_stream(&mut table);
        let _ = table.event(handle, ProgramEvent::Closed).unwrap();
        let effects = table.release(handle);
        assert!(
            effects.close.is_empty(),
            "the program's side is already closed"
        );
        assert_eq!(table.state(handle), None);
    }

    #[test]
    fn releasing_an_opening_link_closes_it_on_the_program() {
        let mut table = AppLinkTable::new();
        let handle = table.reserve(AppLinkKind::StreamDial);
        let _ = table.opened(handle, ProgramOpen::Pending);
        let effects = table.release(handle);
        assert_eq!(effects.close, [handle]);
        // The program reporting closed while its close runs finishes it as well.
        let _ = table.event(handle, ProgramEvent::Closed).unwrap();
        assert_eq!(table.state(handle), None);
        assert!(table.close_done(handle).is_empty());
    }

    #[test]
    fn a_listener_queues_the_streams_the_program_accepts() {
        let mut table = AppLinkTable::new();
        let listener = table.reserve(AppLinkKind::StreamListen);
        // Not listening yet.
        assert_eq!(
            table
                .accepted(listener, "tcp/198.51.100.9:40001")
                .unwrap_err(),
            InboundRefusal::NotOpen
        );
        let _ = table.opened(listener, ProgramOpen::Up);
        let (count, waker) = counter();
        assert_eq!(
            table.next_accepted(listener, Some(&waker)),
            AcceptRead::Empty
        );
        let (stream, effects) = table.accepted(listener, "tcp/198.51.100.9:40001").unwrap();
        assert_eq!(wakes(effects), 1);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(table.kind(stream), Some(AppLinkKind::StreamAccepted));
        assert_eq!(table.state(stream), Some(AppLinkState::Open));
        assert_eq!(table.remote(stream), Some("tcp/198.51.100.9:40001"));
        // An accepted stream takes bytes at once.
        let _ = table.received(stream, b"hi", None).unwrap();
        assert_eq!(
            table.next_accepted(listener, None),
            AcceptRead::Accepted(stream, String::from("tcp/198.51.100.9:40001"))
        );
        assert_eq!(table.next_accepted(listener, None), AcceptRead::Empty);
        // A listener carries no bytes and takes no send.
        assert_eq!(
            table.received(listener, b"x", None).unwrap_err(),
            InboundRefusal::WrongKind
        );
        assert_eq!(table.begin_send(listener, None), SendGate::Closed);
    }

    #[test]
    fn only_a_listener_accepts() {
        let mut table = AppLinkTable::new();
        let stream = open_stream(&mut table);
        assert_eq!(
            table
                .accepted(stream, "tcp/198.51.100.9:40002")
                .unwrap_err(),
            InboundRefusal::WrongKind
        );
        assert_eq!(
            table.accepted(999, "tcp/198.51.100.9:40002").unwrap_err(),
            InboundRefusal::NoSuchLink
        );
    }

    #[test]
    fn a_released_listener_takes_its_untaken_streams_with_it() {
        let mut table = AppLinkTable::new();
        let listener = table.reserve(AppLinkKind::StreamListen);
        let _ = table.opened(listener, ProgramOpen::Up);
        let (stream, _) = table.accepted(listener, "tcp/198.51.100.9:40003").unwrap();
        let effects = table.release(listener);
        assert!(effects.close.contains(&listener));
        assert!(
            effects.close.contains(&stream),
            "the untaken stream is closed too"
        );
        for handle in effects.close {
            let _ = table.close_done(handle);
        }
        assert!(table.is_empty());
    }

    #[test]
    fn a_datagram_is_read_whole_with_the_locator_it_came_from() {
        let mut table = AppLinkTable::new();
        let handle = table.reserve(AppLinkKind::Group);
        let _ = table.opened(handle, ProgramOpen::Up);
        let _ = table
            .received(handle, b"one", Some("udp/198.51.100.4:7447"))
            .unwrap();
        let _ = table.received(handle, b"", None).unwrap();
        assert_eq!(
            table.read_datagram(handle, None),
            DatagramRead::Datagram(Received {
                bytes: b"one".to_vec(),
                source: Some(String::from("udp/198.51.100.4:7447")),
            })
        );
        assert_eq!(
            table.read_datagram(handle, None),
            DatagramRead::Datagram(Received {
                bytes: Vec::new(),
                source: None,
            }),
            "an empty datagram is a datagram"
        );
        assert_eq!(table.read_datagram(handle, None), DatagramRead::Empty);
        let _ = table.event(handle, ProgramEvent::Closed).unwrap();
        assert_eq!(table.read_datagram(handle, None), DatagramRead::End);
    }

    #[test]
    fn a_stream_drops_the_source_the_program_named() {
        let mut table = AppLinkTable::new();
        let handle = open_stream(&mut table);
        let _ = table
            .received(handle, b"ab", Some("tcp/198.51.100.4:1"))
            .unwrap();
        assert_eq!(table.queued_bytes(handle), 2);
    }
}
