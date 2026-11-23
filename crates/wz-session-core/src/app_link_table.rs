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

use alloc::string::String;
use alloc::vec::Vec;
use core::task::Waker;

use sce_rust_runtime::helpers::session_id::SessionId;
use sce_rust_runtime::Engine;

use crate::app_link::{AppLinkActions, AppLinkEvent, AppLinkPolicy, AppLinkState};
use crate::duty_outbox::DutyOutbox;
use crate::limit_binding::Quota;

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
    /// A listener for unicast datagrams (a `udp/` listen locator naming no interface). It carries
    /// no datagram itself: the program tells each source that sends to it apart as a link of its
    /// own, which it accepts on the listener, as a stream.
    DatagramListen = 4,
    /// A stream the program accepted on a listener.
    StreamAccepted = 5,
    /// The datagrams of one source the program accepted on a datagram listener.
    DatagramAccepted = 6,
}

impl AppLinkKind {
    /// Whether the link carries a byte stream (framed by the session), as against datagrams.
    pub const fn is_stream(self) -> bool {
        matches!(self, Self::StreamDial | Self::StreamAccepted)
    }

    /// Whether the link carries datagrams, each one batch.
    pub const fn is_datagram(self) -> bool {
        matches!(self, Self::Datagram | Self::Group | Self::DatagramAccepted)
    }

    /// Whether the link is a listener, which carries nothing itself and on which the program
    /// accepts links.
    pub const fn is_listener(self) -> bool {
        matches!(self, Self::StreamListen | Self::DatagramListen)
    }

    /// The kind of the links the program accepts on a listener of this kind.
    const fn accepted(self) -> Option<Self> {
        match self {
            Self::StreamListen => Some(Self::StreamAccepted),
            Self::DatagramListen => Some(Self::DatagramAccepted),
            _ => None,
        }
    }
}

/// The kind of link a transport opens for `locator`, or `None` for a locator no kind carries
/// (any scheme but `tcp/` and `udp/`). A `udp/` listen naming an interface is a group, one naming
/// none a datagram listener. `listen` says whether the locator is a listen one.
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
        ("udp", true) => Some(AppLinkKind::DatagramListen),
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
    /// The link already queues its bound of bytes the session has not read, so nothing was
    /// taken. The program hands the same bytes in again once the session has read the queue
    /// down: the transport tells it so with `drained` ([`Due::Drained`]).
    Full,
    /// A group's datagram named no source: the session tells the members of a group apart by
    /// the locator each datagram came from.
    NoSource,
    /// The call hands in more than the link could ever hold at once: more bytes than its bound, a
    /// datagram longer than [`DATAGRAM_MAX`], or a locator longer than [`SOURCE_MAX`]. Handed in
    /// again it is refused again; a stream's bytes are taken in smaller calls.
    TooLarge,
}

/// The most bytes one datagram a link carries holds: the widest batch the wire can state.
pub const DATAGRAM_MAX: usize = u16::MAX as usize;

/// The longest locator a datagram is queued with: one less than a byte holds, as the record's
/// length byte keeps 0 for no locator.
pub const SOURCE_MAX: usize = 254;

/// The head of each queued datagram: its length (two bytes, little-endian) and the length of
/// the locator after it, one more than the locator's bytes, 0 for none.
const RECORD_HEAD: usize = 3;

/// A queued datagram copied out whole, for an engine that owns what it reads
/// ([`QueuedDatagram::to_received`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    /// The bytes.
    pub bytes: Vec<u8>,
    /// The locator a datagram came from, when the program named one.
    pub source: Option<String>,
}

/// One datagram as [`AppLinkTable::read_datagram`] finds it, lent from its link's queue for the
/// read: its bytes, in at most two runs where the queue wraps, and the locator it came from.
#[derive(Debug, Clone, Copy)]
pub struct QueuedDatagram<'a> {
    parts: (&'a [u8], &'a [u8]),
    source: Option<&'a str>,
}

impl<'a> QueuedDatagram<'a> {
    /// How many bytes the datagram holds.
    pub fn len(&self) -> usize {
        self.parts.0.len().saturating_add(self.parts.1.len())
    }

    /// Whether the datagram holds no byte.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The locator the datagram came from, when the program named one.
    pub fn source(&self) -> Option<&'a str> {
        self.source
    }

    /// Copy the datagram into `buf`, cut to it: how many bytes were copied.
    pub fn copy_to(&self, buf: &mut [u8]) -> usize {
        let (first, second) = self.parts;
        copy_runs(buf, first, second)
    }

    /// The datagram and its locator copied onto the heap.
    pub fn to_received(&self) -> Received {
        let mut bytes = Vec::with_capacity(self.len());
        bytes.extend_from_slice(self.parts.0);
        bytes.extend_from_slice(self.parts.1);
        Received {
            bytes,
            source: self.source.map(String::from),
        }
    }
}

/// The tasks one link found waiting and has not had woken yet. A link's opener, reader and writer
/// are held in place; a fourth, which only a host that leaves its effects undone while the same
/// link is waited on again can leave, is kept on the heap.
#[derive(Debug, Default)]
struct Wakes {
    held: [Option<Waker>; 3],
    spill: Vec<Waker>,
}

impl Wakes {
    /// Keep `waker` to be woken, once: a waker that wakes the same task as one kept already is
    /// that one.
    fn push(&mut self, waker: Waker) {
        let mut kept = self.held.iter().flatten().chain(self.spill.iter());
        if kept.any(|held| held.will_wake(&waker)) {
            return;
        }
        match self.held.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => *slot = Some(waker),
            None => self.spill.push(waker),
        }
    }

    fn pop(&mut self) -> Option<Waker> {
        self.spill
            .pop()
            .or_else(|| self.held.iter_mut().find_map(Option::take))
    }
}

/// What a table method left for the host to do, with no lock held: whether anything is due. What
/// is due is held by the table, link by link, and the host takes it one item at a time with
/// [`AppLinkTable::next_due`] until there is none, so no call collects a list of its own.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[must_use = "the program's close, its drained and the wakes are the host's to perform"]
pub struct Effects {
    due: bool,
}

impl Effects {
    /// Whether there is nothing to do.
    pub fn is_empty(&self) -> bool {
        !self.due
    }

    fn absorb(&mut self, other: Effects) {
        self.due |= other.due;
    }
}

/// One thing the host does for the table, in the order [`AppLinkTable::next_due`] hands them
/// out: every close first, then every drained, then every wake.
#[derive(Debug)]
pub enum Due {
    /// Call the program's `close` for the link, then report it with
    /// [`AppLinkTable::close_done`].
    Close(LinkHandle),
    /// Tell the program the link, which refused its bytes for being full
    /// ([`InboundRefusal::Full`]), has been read down to half its bound.
    Drained(LinkHandle),
    /// Wake the task.
    Wake(Waker),
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

/// What a read of a datagram link found: `T` is what the reader made of the datagram it was lent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatagramRead<T> {
    /// One datagram, whole, as the reader took it.
    Datagram(T),
    /// Nothing queued; the waker given is woken when one arrives or the link closes.
    Empty,
    /// The link is closed and every datagram it carried has been read.
    End,
}

/// What a listener's next accept found: `T` is what the reader made of the link and of the locator
/// the program named for its remote end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptRead<T> {
    /// A link the program accepted, as the reader took it.
    Accepted(T),
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

/// What a link holds for the session to read, in storage taken when the link is made: a stream's
/// bytes as the program handed them in, or each datagram as a record (its head, its locator, its
/// bytes). A call of the program's copies into it and a read copies out of it, so neither
/// allocates; only a link with no bound grows it.
struct RxRing {
    /// The storage; its length is the ring's capacity.
    buf: Vec<u8>,
    /// Where the oldest byte held is.
    head: usize,
    /// How many bytes are held, the records' heads and locators included.
    len: usize,
}

impl RxRing {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: alloc::vec![0; capacity],
            head: 0,
            len: 0,
        }
    }

    fn capacity(&self) -> usize {
        self.buf.len()
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn free(&self) -> usize {
        self.capacity().saturating_sub(self.len)
    }

    /// Room for `more` bytes, for the one link whose storage could not be taken whole when it was
    /// made: a link with no bound.
    fn grow_for(&mut self, more: usize) {
        let need = self.len.saturating_add(more);
        if need <= self.capacity() {
            return;
        }
        let mut next = alloc::vec![0; need.checked_next_power_of_two().unwrap_or(need)];
        let (first, second) = self.front(self.len);
        copy_runs(&mut next, first, second);
        self.buf = next;
        self.head = 0;
    }

    /// Append `bytes`, which the caller has found room for.
    fn push(&mut self, bytes: &[u8]) {
        debug_assert!(bytes.len() <= self.free(), "the caller found room");
        let capacity = self.capacity();
        // `head` is within the storage and `len` at most its length, so their sum cannot wrap.
        let Some(tail) = self.head.wrapping_add(self.len).checked_rem(capacity) else {
            return;
        };
        // The split point is at most `bytes.len()`, so the split is within it.
        let (to_end, to_front) = bytes.split_at(bytes.len().min(capacity.saturating_sub(tail)));
        copy_at(&mut self.buf, tail, to_end);
        copy_at(&mut self.buf, 0, to_front);
        self.len = self.len.saturating_add(bytes.len());
    }

    /// The oldest `n` bytes held (all of them when fewer are), in at most two runs.
    fn front(&self, n: usize) -> (&[u8], &[u8]) {
        let n = n.min(self.len);
        let first = n.min(self.capacity().saturating_sub(self.head));
        let to_end = self
            .buf
            .get(self.head..self.head.saturating_add(first))
            .unwrap_or_default();
        let from_front = self.buf.get(..n.saturating_sub(first)).unwrap_or_default();
        (to_end, from_front)
    }

    /// Let go of the oldest `n` bytes.
    fn consume(&mut self, n: usize) {
        let n = n.min(self.len);
        self.len = self.len.saturating_sub(n);
        self.head = match self.len {
            0 => 0,
            // `head` is within the storage and `n` at most its length: the sum cannot wrap.
            _ => self
                .head
                .wrapping_add(n)
                .checked_rem(self.capacity())
                .unwrap_or(0),
        };
    }

    /// Move the oldest bytes into `out`, as many as it holds: how many were moved.
    fn take_into(&mut self, out: &mut [u8]) -> usize {
        let (first, second) = self.front(out.len());
        let n = copy_runs(out, first, second);
        self.consume(n);
        n
    }
}

/// Copy `first` and then `second` into the front of `out`, as far as it reaches: how many bytes
/// were copied.
fn copy_runs(out: &mut [u8], first: &[u8], second: &[u8]) -> usize {
    let mut copied = 0usize;
    for (to, from) in out.iter_mut().zip(first.iter().chain(second)) {
        *to = *from;
        copied = copied.saturating_add(1);
    }
    copied
}

/// Copy `bytes` into `buf` from `at`, where the caller found room for them.
fn copy_at(buf: &mut [u8], at: usize, bytes: &[u8]) {
    if let Some(to) = buf.get_mut(at..at.saturating_add(bytes.len())) {
        to.copy_from_slice(bytes);
    }
}

/// The storage a link of `kind` held to `queue` takes when it is made: the bound, and room
/// beside it for one datagram's head and widest locator, so an empty queue takes any datagram up
/// to the bound. A bound of 0 is read as 1, as [`Link::admits`] reads it; a listener carries
/// nothing; a link with no bound starts empty and grows.
fn rx_capacity(kind: AppLinkKind, queue: Quota) -> usize {
    match (kind.is_listener(), queue.most()) {
        (true, _) | (false, None) => 0,
        (false, Some(most)) if kind.is_datagram() => most
            .max(1)
            .saturating_add(RECORD_HEAD)
            .saturating_add(SOURCE_MAX),
        (false, Some(most)) => most.max(1),
    }
}

/// The storage a link held to `queue` takes for the bytes a writer that cannot wait hands over
/// ([`AppLinkTable::hold_remainder`]): the bound, read as 1 when it is 0.
fn remainder_capacity(queue: Quota) -> usize {
    queue.most().map_or(0, |most| most.max(1))
}

/// A link's machine, entered: the W3C SCXML 3.3 entry of the initial `Opening` leaf records no
/// duty.
fn new_machine() -> Engine<AppLinkPolicy<LinkDuties>> {
    let mut machine = Engine::new(AppLinkPolicy::new_with_checked_session_id(
        APP_LINK_SESSION_ID,
        LinkDuties {
            duties: DutyOutbox::default(),
        },
    ));
    machine.initialize().unwrap_or_else(|never| match never {});
    let _ = machine.policy().actions().duties.take();
    machine
}

struct Link {
    kind: AppLinkKind,
    machine: Engine<AppLinkPolicy<LinkDuties>>,
    rx: RxRing,
    /// The bytes the program handed in and the session has not read: what the bound counts, the
    /// datagrams' heads and locators left out.
    queued: usize,
    /// The listener that accepted the link while the session has not taken it from there
    /// ([`AppLinkTable::next_accepted`]); 0 for any other link.
    accepted_by: LinkHandle,
    /// The order the link was accepted in, which a listener hands its links out by.
    accepted_order: u64,
    /// The locator the program named for the remote end of an accepted link, in storage of
    /// [`SOURCE_MAX`] bytes taken with the link's row.
    remote: String,
    /// Whether the program named `remote`: the link was accepted.
    remote_named: bool,
    reader: Option<Waker>,
    writer: Option<Waker>,
    opener: Option<Waker>,
    /// How many times the program has said the link is writable.
    writables: u64,
    /// A send was let through and not yet answered.
    sending: bool,
    /// The session has let the link go; the row is free again once the link is closed.
    released: bool,
    /// The program's bytes were refused for the bound since the queue last drained: it is told
    /// when the session has read the queue down.
    refused_full: bool,
    /// Bytes a writer that cannot wait handed over and the program has not taken yet (an engine
    /// whose stream seam takes every byte or fails; [`AppLinkTable::hold_remainder`]), in
    /// storage of the bound taken with the link's row.
    remainder: Vec<u8>,
    /// The most bytes the link queues in either direction: what the program handed in and the
    /// session has not read, and what a writer that cannot wait handed over and the program has
    /// not taken. The `APP_LINK_QUEUE_BYTES` of the session that opened the link, or of the
    /// listener it was accepted on.
    queue: Quota,
    /// The program's close is due ([`Due::Close`]).
    close_due: bool,
    /// The program is due to be told the link drained ([`Due::Drained`]).
    drained_due: bool,
    /// The tasks due to be woken ([`Due::Wake`]).
    wake_due: Wakes,
}

impl Link {
    /// A link with no handle yet, whose storage takes `rx` bytes for what the program hands in
    /// and `remainder` for what a writer hands over.
    fn with_storage(rx: usize, remainder: usize) -> Self {
        Self {
            kind: AppLinkKind::StreamDial,
            machine: new_machine(),
            rx: RxRing::with_capacity(rx),
            queued: 0,
            accepted_by: 0,
            accepted_order: 0,
            remote: String::with_capacity(SOURCE_MAX),
            remote_named: false,
            reader: None,
            writer: None,
            opener: None,
            writables: 0,
            sending: false,
            released: false,
            refused_full: false,
            remainder: Vec::with_capacity(remainder),
            queue: Quota::at_most(0),
            close_due: false,
            drained_due: false,
            wake_due: Wakes::default(),
        }
    }

    /// Whether the row's storage holds what a link of `kind` held to `queue` takes.
    fn fits(&self, kind: AppLinkKind, queue: Quota) -> bool {
        self.rx.capacity() >= rx_capacity(kind, queue)
            && self.remainder.capacity() >= remainder_capacity(queue)
    }

    /// Make the row a new link of `kind` held to `queue`, Opening, its storage kept. What is
    /// due of the link the row held before stays due: a wake still reaches its task.
    fn reset(&mut self, kind: AppLinkKind, queue: Quota) {
        self.kind = kind;
        self.machine = new_machine();
        self.rx.consume(usize::MAX);
        self.queued = 0;
        self.accepted_by = 0;
        self.accepted_order = 0;
        self.remote.clear();
        self.remote_named = false;
        self.reader = None;
        self.writer = None;
        self.opener = None;
        self.writables = 0;
        self.sending = false;
        self.released = false;
        self.refused_full = false;
        self.remainder.clear();
        self.queue = queue;
    }

    /// Whether the link takes what would leave `count` bytes queued in one direction. A quota of
    /// 0 is read as 1: a link always takes one byte.
    fn admits(&self, count: usize) -> bool {
        count <= 1 || self.queue.admits(count)
    }

    fn state(&self) -> AppLinkState {
        self.machine.get_current_state()
    }

    /// The bytes queued and not yet read.
    fn queued(&self) -> usize {
        self.queued
    }

    /// After a read: a link that refused the program for being full and is now read down to half
    /// of its bound is one the program is told of. A link with no bound refuses nothing.
    fn note_read(&mut self) {
        let read_down = match self.queue.most() {
            Some(most) => self.queued() <= most.max(1).checked_div(2).unwrap_or(0),
            None => true,
        };
        if self.refused_full && read_down {
            self.refused_full = false;
            self.drained_due = true;
        }
    }

    fn is_gone(&self) -> bool {
        matches!(self.state(), AppLinkState::Closing | AppLinkState::Closed)
    }

    /// Whether the link has gone and its row holds nothing due that names it.
    fn is_done(&self) -> bool {
        self.released
            && self.state() == AppLinkState::Closed
            && !self.close_due
            && !self.drained_due
    }

    /// Keep `waker`, when there is one, to be woken once the host does what is due.
    fn wake(&mut self, waker: Option<Waker>) -> Effects {
        match waker {
            Some(waker) => {
                self.wake_due.push(waker);
                Effects { due: true }
            }
            None => Effects::default(),
        }
    }

    /// Run `event` and keep what it asked of the host as due.
    fn drive(&mut self, event: AppLinkEvent) -> Effects {
        self.machine.process_event(event);
        let duties = self.machine.policy().actions().duties.take();
        let mut effects = Effects::default();
        if duties.has(LinkDuties::WAKE) {
            for waker in [self.opener.take(), self.reader.take(), self.writer.take()] {
                effects.absorb(self.wake(waker));
            }
        }
        if duties.has(LinkDuties::CLOSE) {
            self.close_due = true;
            effects.due = true;
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

/// What a wait on a link is for ([`AppLinkTable::wait_link`]): input to read, room to write, or
/// both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkInterest {
    /// Bytes or a datagram to read, a link waiting on a listener, or the link's end.
    pub input: bool,
    /// Room to write, or the link's end.
    pub room: bool,
}

/// A row of the table: a link and its storage. A row whose link has gone keeps the storage and
/// is free (handle 0) for the next link that fits it.
struct Row {
    handle: LinkHandle,
    /// Taken for a session's links at its open ([`AppLinkTable::provision`]): the rows a link
    /// the session opens or the program accepts takes. A listener and a group take rows of their
    /// own, as they are no links of the session's count.
    provisioned: bool,
    link: Link,
}

/// The links of one transport. The transport may carry the links of several sessions, so each
/// link keeps the queue bound of the session that opened it ([`Self::reserve`]). A row and its
/// storage outlive the link in it: a link that comes later takes a free row that holds what it
/// needs, and only a link that finds none allocates.
pub struct AppLinkTable {
    rows: Vec<Row>,
    next: LinkHandle,
    /// The order the next link a listener accepts is given.
    accepted_order: u64,
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
            rows: Vec::new(),
            next: 1,
            accepted_order: 0,
        }
    }

    /// Take now the rows `links` links of a session held to `queue` need, each with the storage
    /// a link of any kind takes, so a link the session opens or the program accepts later finds
    /// its row and allocates nothing. Free rows taken before that hold as much count toward them,
    /// so a session opened again over the transport takes no more.
    pub fn provision(&mut self, links: usize, queue: Quota) {
        let free = self
            .rows
            .iter()
            .filter(|row| {
                row.handle == 0
                    && row.provisioned
                    && row.link.fits(AppLinkKind::DatagramAccepted, queue)
            })
            .count();
        let more = links.saturating_sub(free);
        self.rows.reserve(more);
        for _ in 0..more {
            self.rows.push(Row {
                handle: 0,
                provisioned: true,
                link: Link::with_storage(
                    rx_capacity(AppLinkKind::DatagramAccepted, queue),
                    remainder_capacity(queue),
                ),
            });
        }
    }

    fn at(&self, handle: LinkHandle) -> Option<usize> {
        if handle == 0 {
            return None;
        }
        self.rows.iter().position(|row| row.handle == handle)
    }

    fn link(&self, handle: LinkHandle) -> Option<&Link> {
        let at = self.at(handle)?;
        self.rows.get(at).map(|row| &row.link)
    }

    fn link_mut(&mut self, handle: LinkHandle) -> Option<&mut Link> {
        let at = self.at(handle)?;
        self.rows.get_mut(at).map(|row| &mut row.link)
    }

    /// The next thing due for the host to do, taken from the table: a close, then a drained, then
    /// a wake, until there is none. The host does each with no lock held.
    pub fn next_due(&mut self) -> Option<Due> {
        if let Some(row) = self.rows.iter_mut().find(|row| row.link.close_due) {
            row.link.close_due = false;
            let handle = row.handle;
            self.free_if_done(handle);
            return Some(Due::Close(handle));
        }
        if let Some(row) = self.rows.iter_mut().find(|row| row.link.drained_due) {
            row.link.drained_due = false;
            let handle = row.handle;
            self.free_if_done(handle);
            return Some(Due::Drained(handle));
        }
        self.rows
            .iter_mut()
            .find_map(|row| row.link.wake_due.pop())
            .map(Due::Wake)
    }

    /// Whether anything is due of the links read down: the host then tells the program of them
    /// ([`Due::Drained`]).
    pub fn take_drained(&mut self) -> Effects {
        Effects {
            due: self.rows.iter().any(|row| row.link.drained_due),
        }
    }

    /// How many links the table holds.
    pub fn len(&self) -> usize {
        self.rows.iter().filter(|row| row.handle != 0).count()
    }

    /// Whether the table holds no link.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The state of a link, `None` for a handle the table does not hold.
    pub fn state(&self, handle: LinkHandle) -> Option<AppLinkState> {
        self.link(handle).map(Link::state)
    }

    /// The kind of a link, `None` for a handle the table does not hold.
    pub fn kind(&self, handle: LinkHandle) -> Option<AppLinkKind> {
        self.link(handle).map(|link| link.kind)
    }

    /// The locator the program named for the remote end of an accepted link.
    pub fn remote(&self, handle: LinkHandle) -> Option<&str> {
        let link = self.link(handle)?;
        link.remote_named.then_some(link.remote.as_str())
    }

    /// How many bytes are queued on a link and not yet read.
    pub fn queued_bytes(&self, handle: LinkHandle) -> usize {
        self.link(handle).map_or(0, Link::queued)
    }

    fn take_handle(&mut self) -> LinkHandle {
        let handle = self.next;
        // A count of the links ever named, which no table lives long enough to wrap.
        self.next = self.next.wrapping_add(1);
        handle
    }

    /// A new link of `kind`, Opening, before the program is asked to open it, which queues at most
    /// `queue` bytes in each direction: the `APP_LINK_QUEUE_BYTES` of the session that opens it.
    /// Its row's storage holds the bound, and a call of the program's that hands in more than the
    /// bound at once is refused ([`InboundRefusal::TooLarge`]); a quota of 0 holds one byte at a
    /// time. The links accepted on a listener keep the listener's bound.
    ///
    /// The row is a free one that holds what the link takes, the smallest, else a new one. A
    /// listener and a group never take a provisioned row.
    pub fn reserve(&mut self, kind: AppLinkKind, queue: Quota) -> LinkHandle {
        let handle = self.take_handle();
        let own = kind.is_listener() || kind == AppLinkKind::Group;
        let free = self
            .rows
            .iter_mut()
            .filter(|row| {
                row.handle == 0 && !(own && row.provisioned) && row.link.fits(kind, queue)
            })
            .min_by_key(|row| row.link.rx.capacity());
        match free {
            Some(row) => {
                row.handle = handle;
                row.link.reset(kind, queue);
            }
            None => {
                let mut link =
                    Link::with_storage(rx_capacity(kind, queue), remainder_capacity(queue));
                link.reset(kind, queue);
                self.rows.push(Row {
                    handle,
                    provisioned: false,
                    link,
                });
            }
        }
        handle
    }

    /// What the program's `open` of `handle` answered.
    pub fn opened(&mut self, handle: LinkHandle, answer: ProgramOpen) -> Effects {
        let Some(link) = self.link_mut(handle) else {
            return Effects::default();
        };
        if link.state() != AppLinkState::Opening {
            // The program reported the link up or closed from its own thread before its open
            // returned; that report stands.
            return Effects::default();
        }
        match answer {
            ProgramOpen::Up => link.drive(AppLinkEvent::LinkConnected),
            ProgramOpen::Pending => Effects::default(),
            ProgramOpen::Refused => link.drive(AppLinkEvent::LinkClosed),
        }
    }

    /// Where a link the session waits to open stands; `waker` is kept while it is Opening.
    pub fn poll_open(&mut self, handle: LinkHandle, waker: Option<&Waker>) -> OpenProgress {
        let Some(link) = self.link_mut(handle) else {
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
        let link = self.link_mut(handle).ok_or(InboundRefusal::NoSuchLink)?;
        if link.state() == AppLinkState::Closed {
            return Err(InboundRefusal::Closed);
        }
        Ok(match event {
            ProgramEvent::Connected => match link.state() {
                AppLinkState::Opening => link.drive(AppLinkEvent::LinkConnected),
                // Said again of a link that is up: nothing changes.
                _ => Effects::default(),
            },
            ProgramEvent::Closed => {
                let mut effects = link.drive(AppLinkEvent::LinkClosed);
                effects.absorb(self.close_accepted_of(handle));
                self.free_if_done(handle);
                effects
            }
            ProgramEvent::Writable => {
                // Compared for equality only, so a count that wrapped still tells two apart.
                link.writables = link.writables.wrapping_add(1);
                let mut effects = link.drive(AppLinkEvent::LinkWritable);
                // An open link that holds a remainder has no transition on a writable, but its
                // writer waits for the program to take bytes again, to offer it what it holds.
                if link.state() == AppLinkState::Open && !link.remainder.is_empty() {
                    let writer = link.writer.take();
                    effects.absorb(link.wake(writer));
                }
                effects
            }
        })
    }

    /// The program accepted a link on `listener`, whose remote end it names `remote`: a new
    /// link, Open, which the session takes with [`Self::next_accepted`]. A locator longer than
    /// [`SOURCE_MAX`] is refused ([`InboundRefusal::TooLarge`]).
    pub fn accepted(
        &mut self,
        listener: LinkHandle,
        remote: &str,
    ) -> Result<(LinkHandle, Effects), InboundRefusal> {
        let link = self.link(listener).ok_or(InboundRefusal::NoSuchLink)?;
        let Some(accepted_kind) = link.kind.accepted() else {
            return Err(InboundRefusal::WrongKind);
        };
        match link.state() {
            AppLinkState::Opening => return Err(InboundRefusal::NotOpen),
            AppLinkState::Closing | AppLinkState::Closed => return Err(InboundRefusal::Closed),
            AppLinkState::Open | AppLinkState::Blocked => {}
        }
        if remote.len() > SOURCE_MAX {
            return Err(InboundRefusal::TooLarge);
        }
        let queue = link.queue;
        let handle = self.reserve(accepted_kind, queue);
        let order = self.accepted_order;
        // A count of the links ever accepted, which no table lives long enough to wrap.
        self.accepted_order = self.accepted_order.wrapping_add(1);
        let stream = self.link_mut(handle).ok_or(InboundRefusal::NoSuchLink)?;
        stream.remote.push_str(remote);
        stream.remote_named = true;
        stream.accepted_by = listener;
        stream.accepted_order = order;
        // Nobody waits on the new link yet, so its entry wakes nobody.
        let _ = stream.drive(AppLinkEvent::LinkAccepted);
        let listener_link = self.link_mut(listener).ok_or(InboundRefusal::NoSuchLink)?;
        let reader = listener_link.reader.take();
        Ok((handle, listener_link.wake(reader)))
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
        let link = self.link_mut(handle).ok_or(InboundRefusal::NoSuchLink)?;
        if link.kind.is_listener() {
            return Err(InboundRefusal::WrongKind);
        }
        match link.state() {
            AppLinkState::Opening => return Err(InboundRefusal::NotOpen),
            AppLinkState::Closing | AppLinkState::Closed => return Err(InboundRefusal::Closed),
            AppLinkState::Open | AppLinkState::Blocked => {}
        }
        if link.kind == AppLinkKind::Group && source.is_none() {
            return Err(InboundRefusal::NoSource);
        }
        // An empty stream chunk carries nothing; an empty datagram is a datagram.
        if bytes.is_empty() && link.kind.is_stream() {
            return Ok(Effects::default());
        }
        let datagram = link.kind.is_datagram();
        // A stream's bytes carry no locator: a source the program names with them is dropped.
        let source = if datagram { source } else { None };
        let widest = link.queue.most().map(|most| most.max(1));
        if widest.is_some_and(|widest| bytes.len() > widest)
            || (datagram
                && (bytes.len() > DATAGRAM_MAX
                    || source.is_some_and(|named| named.len() > SOURCE_MAX)))
        {
            return Err(InboundRefusal::TooLarge);
        }
        let stored = if datagram {
            RECORD_HEAD
                .saturating_add(source.map_or(0, str::len))
                .saturating_add(bytes.len())
        } else {
            bytes.len()
        };
        if widest.is_none() {
            link.rx.grow_for(stored);
        }
        // Past the bound nothing is taken, and the program learns when to hand it in again. An
        // empty queue takes whatever passed the checks above: the storage holds the bound.
        if !link.rx.is_empty()
            && (!link.admits(link.queued().saturating_add(bytes.len())) || stored > link.rx.free())
        {
            link.refused_full = true;
            return Err(InboundRefusal::Full);
        }
        if datagram {
            let name = source.map_or(&[][..], str::as_bytes);
            // Both fit their bytes: the lengths were checked against DATAGRAM_MAX and SOURCE_MAX.
            let [low, high] = u16::try_from(bytes.len()).unwrap_or(u16::MAX).to_le_bytes();
            let named = match source {
                Some(_) => u8::try_from(name.len())
                    .unwrap_or(u8::MAX)
                    .saturating_add(1),
                None => 0,
            };
            link.rx.push(&[low, high, named]);
            link.rx.push(name);
        }
        link.rx.push(bytes);
        link.queued = link.queued.saturating_add(bytes.len());
        let reader = link.reader.take();
        Ok(link.wake(reader))
    }

    /// Copy what is queued on stream `handle` into `buf`, as much as fits.
    pub fn read_stream(
        &mut self,
        handle: LinkHandle,
        buf: &mut [u8],
        waker: Option<&Waker>,
    ) -> StreamRead {
        let Some(link) = self.link_mut(handle) else {
            return StreamRead::End;
        };
        let copied = link.rx.take_into(buf);
        link.queued = link.queued.saturating_sub(copied);
        if copied > 0 {
            link.note_read();
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

    /// Whether a read of `handle` would answer now: bytes or a datagram are queued, a link is
    /// waiting on the listener, or the link is closing or closed. `waker` is kept when it would
    /// not, and woken when it would.
    pub fn poll_readable(&mut self, handle: LinkHandle, waker: Option<&Waker>) -> bool {
        let waiting = self.rows.iter().any(|row| row.link.accepted_by == handle);
        let Some(link) = self.link_mut(handle) else {
            return true;
        };
        if !link.rx.is_empty() || waiting || link.is_gone() {
            return true;
        }
        keep(&mut link.reader, waker);
        false
    }

    /// Whether what `interest` asks of `handle` is there now: input to read ([`Self::poll_readable`])
    /// or room to write ([`Self::poll_writable`]). A handle that names no link any more answers
    /// `true` at once and keeps nothing: a handle is never reused, so its waiter finds the link gone
    /// when it looks again, and the link that took its row never wakes it. Otherwise `waker` is
    /// kept for each side asked and woken when that side would answer, and the answer is `false`.
    /// A wait that asks for neither side answers `true`.
    ///
    /// The answer is a hint, as every wake is: the waiter looks again under its own lock.
    pub fn wait_link(&mut self, handle: LinkHandle, interest: LinkInterest, waker: &Waker) -> bool {
        if self.at(handle).is_none() || !(interest.input || interest.room) {
            return true;
        }
        if (interest.input && self.poll_readable(handle, None))
            || (interest.room && self.poll_writable(handle, None))
        {
            return true;
        }
        if interest.input {
            let _ = self.poll_readable(handle, Some(waker));
        }
        if interest.room {
            let _ = self.poll_writable(handle, Some(waker));
        }
        false
    }

    /// The next datagram queued on `handle`, lent to `take` where the queue holds it and let go
    /// of once `take` returns: what `take` made of it.
    pub fn read_datagram<T>(
        &mut self,
        handle: LinkHandle,
        waker: Option<&Waker>,
        take: impl FnOnce(QueuedDatagram<'_>) -> T,
    ) -> DatagramRead<T> {
        let Some(link) = self.link_mut(handle) else {
            return DatagramRead::End;
        };
        // A stream's bytes are no datagrams; a listener holds none.
        if !link.kind.is_datagram() {
            return DatagramRead::End;
        }
        if link.rx.is_empty() {
            if link.is_gone() {
                return DatagramRead::End;
            }
            keep(&mut link.reader, waker);
            return DatagramRead::Empty;
        }
        let mut head = [0u8; RECORD_HEAD];
        link.rx.take_into(&mut head);
        let [low, high, named_byte] = head;
        let len = usize::from(u16::from_le_bytes([low, high]));
        let mut name = [0u8; SOURCE_MAX];
        let named = name
            .get_mut(..usize::from(named_byte).saturating_sub(1))
            .map_or(0, |slot| link.rx.take_into(slot));
        // The locator was a `str` when it was queued.
        let source = match named_byte {
            0 => None,
            _ => core::str::from_utf8(name.get(..named).unwrap_or_default()).ok(),
        };
        let (first, second) = link.rx.front(len);
        let taken = take(QueuedDatagram {
            parts: (first, second),
            source,
        });
        link.rx.consume(len);
        link.queued = link.queued.saturating_sub(len);
        link.note_read();
        DatagramRead::Datagram(taken)
    }

    /// The next link accepted on `listener`, the oldest first, lent to `take` with the locator
    /// the program named for its remote end: what `take` made of them. The session owns the link
    /// from here, and releases it as it releases any link.
    pub fn next_accepted<T>(
        &mut self,
        listener: LinkHandle,
        waker: Option<&Waker>,
        take: impl FnOnce(LinkHandle, &str) -> T,
    ) -> AcceptRead<T> {
        if self.at(listener).is_none() {
            return AcceptRead::End;
        }
        let oldest = self
            .rows
            .iter_mut()
            .filter(|row| row.link.accepted_by == listener)
            .min_by_key(|row| row.link.accepted_order);
        if let Some(row) = oldest {
            row.link.accepted_by = 0;
            return AcceptRead::Accepted(take(row.handle, &row.link.remote));
        }
        let Some(link) = self.link_mut(listener) else {
            return AcceptRead::End;
        };
        if link.is_gone() {
            return AcceptRead::End;
        }
        keep(&mut link.reader, waker);
        AcceptRead::Empty
    }

    /// Whether the program would take bytes sent on `handle` now: the link is open and holds no
    /// remainder for it. `waker` is kept when it would not, and woken when the program reports
    /// the link writable, up or closed. A link that is closing, closed or unknown answers `true`:
    /// the send that follows meets its end and reports it. Nothing is begun, unlike
    /// [`Self::begin_send`]: this is the room a writer waits for before it builds what it sends.
    pub fn poll_writable(&mut self, handle: LinkHandle, waker: Option<&Waker>) -> bool {
        let Some(link) = self.link_mut(handle) else {
            return true;
        };
        match link.state() {
            AppLinkState::Open if link.remainder.is_empty() => true,
            AppLinkState::Closing | AppLinkState::Closed => true,
            AppLinkState::Opening => {
                keep(&mut link.opener, waker);
                false
            }
            _ => {
                keep(&mut link.writer, waker);
                false
            }
        }
    }

    /// Whether a send on `handle` may go to the program now. `waker` is kept when it may not and
    /// will later.
    pub fn begin_send(&mut self, handle: LinkHandle, waker: Option<&Waker>) -> SendGate {
        let Some(link) = self.link_mut(handle) else {
            return SendGate::Closed;
        };
        if link.kind.is_listener() {
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
        let Some(link) = self.link_mut(handle) else {
            return (SendStep::Closed, Effects::default());
        };
        link.sending = false;
        if link.is_gone() {
            // The program closed the link from its own thread while the send was out.
            return (SendStep::Closed, Effects::default());
        }
        match answer {
            ProgramSend::Wrote(written) if written > offered => {
                (SendStep::Failed, link.drive(AppLinkEvent::SendFailed))
            }
            ProgramSend::Wrote(written) if written > 0 => {
                (SendStep::Wrote(written), Effects::default())
            }
            // Nothing written of something offered is a send that would block.
            ProgramSend::Wrote(_) | ProgramSend::WouldBlock => {
                if link.writables != ticket.writable_seen {
                    (SendStep::Retry, Effects::default())
                } else {
                    (SendStep::Blocked, link.drive(AppLinkEvent::SendBlocked))
                }
            }
            ProgramSend::Closed => (SendStep::Closed, link.drive(AppLinkEvent::SendClosed)),
            ProgramSend::Failed => (SendStep::Failed, link.drive(AppLinkEvent::SendFailed)),
        }
    }

    /// Hold `bytes` a writer sends on `handle` and the program has not taken, behind any held
    /// before: the remainder of a writer that cannot wait for the program (an engine whose stream
    /// seam takes every byte or fails), which offers it again from [`Self::remainder`] and drops
    /// what the program took with [`Self::drop_remainder`]. Refused, with nothing held, on a link
    /// that is closing or closed, and past the bound ([`InboundRefusal::Full`]). The bytes go into
    /// storage of the bound the link's row holds.
    pub fn hold_remainder(
        &mut self,
        handle: LinkHandle,
        bytes: &[u8],
    ) -> Result<(), InboundRefusal> {
        let link = self.link_mut(handle).ok_or(InboundRefusal::NoSuchLink)?;
        if link.is_gone() {
            return Err(InboundRefusal::Closed);
        }
        if !link.admits(link.remainder.len().saturating_add(bytes.len())) {
            return Err(InboundRefusal::Full);
        }
        link.remainder.extend_from_slice(bytes);
        Ok(())
    }

    /// The bytes held on `handle` for the program, oldest first; empty for a link not held.
    pub fn remainder(&self, handle: LinkHandle) -> &[u8] {
        self.link(handle)
            .map_or(&[][..], |link| link.remainder.as_slice())
    }

    /// The program took the first `taken` bytes of the remainder of `handle`. A remainder that
    /// this leaves empty on an open link is room again, with no call of the program's to say so:
    /// the writer waiting for it is woken (a writer may wait while another task drains the link).
    pub fn drop_remainder(&mut self, handle: LinkHandle, taken: usize) -> Effects {
        let Some(link) = self.link_mut(handle) else {
            return Effects::default();
        };
        let taken = taken.min(link.remainder.len());
        link.remainder.drain(..taken);
        if taken > 0 && link.remainder.is_empty() && link.state() == AppLinkState::Open {
            let writer = link.writer.take();
            return link.wake(writer);
        }
        Effects::default()
    }

    /// The session lets `handle` go. A link that is not closed is closed: its close is due
    /// ([`Due::Close`]), for the host to call the program's close and then report it with
    /// [`Self::close_done`]. The row is free again once the link is closed. A listener's accepted
    /// links that the session never took go with it.
    pub fn release(&mut self, handle: LinkHandle) -> Effects {
        let Some(link) = self.link_mut(handle) else {
            return Effects::default();
        };
        link.released = true;
        // A link the session lets go is no longer the listener's to hand out.
        link.accepted_by = 0;
        let mut effects = link.drive(AppLinkEvent::SessionClose);
        effects.absorb(self.close_accepted_of(handle));
        self.free_if_done(handle);
        effects
    }

    /// The program's close of `handle` returned.
    pub fn close_done(&mut self, handle: LinkHandle) -> Effects {
        let Some(link) = self.link_mut(handle) else {
            return Effects::default();
        };
        // The close is done, whoever called it: one still due names a close that happened.
        link.close_due = false;
        let effects = link.drive(AppLinkEvent::CloseDone);
        self.free_if_done(handle);
        effects
    }

    /// Release every link accepted on `listener` that the session never took.
    fn close_accepted_of(&mut self, listener: LinkHandle) -> Effects {
        let mut effects = Effects::default();
        while let Some(row) = self
            .rows
            .iter_mut()
            .find(|row| row.link.accepted_by == listener)
        {
            row.link.accepted_by = 0;
            let handle = row.handle;
            effects.absorb(self.release(handle));
        }
        effects
    }

    /// Free the row of `handle` once its link is gone and nothing due names it.
    fn free_if_done(&mut self, handle: LinkHandle) {
        if let Some(row) = self.at(handle).and_then(|at| self.rows.get_mut(at)) {
            if row.link.is_done() {
                row.handle = 0;
            }
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

    /// What a host did for what the table held due: the links it would close, the links it told
    /// were drained, and how many tasks it woke.
    #[derive(Debug, Default)]
    struct Performed {
        close: Vec<LinkHandle>,
        drained: Vec<LinkHandle>,
        wakes: usize,
    }

    /// Do what `effects` says is due, as a transport's perform does it, without a program: a
    /// close is noted and not reported done.
    fn perform(table: &mut AppLinkTable, effects: Effects) -> Performed {
        let mut done = Performed::default();
        if effects.is_empty() {
            return done;
        }
        while let Some(due) = table.next_due() {
            match due {
                Due::Close(link) => done.close.push(link),
                Due::Drained(link) => done.drained.push(link),
                Due::Wake(waker) => {
                    waker.wake();
                    done.wakes += 1;
                }
            }
        }
        done
    }

    /// How many tasks `call` made due to be woken, woken.
    fn wakes(table: &mut AppLinkTable, call: impl FnOnce(&mut AppLinkTable) -> Effects) -> usize {
        let effects = call(table);
        perform(table, effects).wakes
    }

    /// The links the table is due to tell the program were drained, told.
    fn drained(table: &mut AppLinkTable) -> Vec<LinkHandle> {
        let effects = table.take_drained();
        perform(table, effects).drained
    }

    /// A link a listener accepted and the locator the program named for it, as a reader takes them.
    fn taken_link(handle: LinkHandle, remote: &str) -> (LinkHandle, String) {
        (handle, String::from(remote))
    }

    /// The queue bound of a link whose test does not reach it.
    const QUEUE: Quota = Quota::at_most(1 << 16);

    /// A dialled stream, reported up by the program.
    fn open_stream(table: &mut AppLinkTable) -> LinkHandle {
        open_stream_under(table, QUEUE)
    }

    /// [`open_stream`] of a link that queues at most `queue` bytes.
    fn open_stream_under(table: &mut AppLinkTable, queue: Quota) -> LinkHandle {
        let handle = table.reserve(AppLinkKind::StreamDial, queue);
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
        assert_eq!(
            kind_for_locator("udp/192.0.2.7:7447", true),
            Some(AppLinkKind::DatagramListen)
        );
        // Refused: other schemes, a scheme with no address.
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

    /// A wait on a handle that names no link any more answers at once and keeps nothing: the link
    /// that took its row later wakes no waiter of the old handle. Turned red by a wait that finds a
    /// row by its storage and not by its handle, or one that keeps a waker for a stale handle.
    #[test]
    fn a_wait_on_a_stale_handle_answers_at_once_and_the_rows_next_link_wakes_no_one() {
        let mut table = AppLinkTable::new();
        let old = open_stream(&mut table);
        let _ = table.release(old);
        let _ = table.close_done(old);
        assert_eq!(table.state(old), None, "the old link is gone");
        let (count, waker) = counter();
        let both = LinkInterest {
            input: true,
            room: true,
        };
        assert!(
            table.wait_link(old, both, &waker),
            "a stale handle answers at once"
        );
        let new = open_stream(&mut table);
        assert_ne!(new, old);
        assert_eq!(table.rows.len(), 1, "the new link took the old link's row");
        let _ = wakes(&mut table, |table| {
            table.received(new, b"data", None).expect("taken")
        });
        assert_eq!(
            count.0.load(Ordering::SeqCst),
            0,
            "the old handle's waiter is not woken"
        );
    }

    /// A wait on a live link answers at once when its side is there, and otherwise keeps the waker
    /// and wakes it when that side comes: input when the program hands bytes in. A wait for
    /// nothing answers at once. Turned red by a wait that keeps no waker, or answers `true` with
    /// nothing to read.
    #[test]
    fn a_wait_on_a_live_link_is_woken_when_its_side_comes() {
        let mut table = AppLinkTable::new();
        let link = open_stream(&mut table);
        let (count, waker) = counter();
        let input = LinkInterest {
            input: true,
            room: false,
        };
        assert!(!table.wait_link(link, input, &waker), "nothing to read yet");
        assert_eq!(
            wakes(&mut table, |table| table
                .received(link, b"data", None)
                .expect("taken")),
            1
        );
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(table.wait_link(link, input, &waker), "input is there now");
        let nothing = LinkInterest {
            input: false,
            room: false,
        };
        assert!(table.wait_link(link, nothing, &waker));
    }

    /// A wait for room on an open link that holds a remainder is woken by the program's writable,
    /// which has no transition while the link is open: the writer offers the program what it holds.
    /// Turned red by a writable that wakes only a blocked link's writer.
    #[test]
    fn a_writable_wakes_a_room_wait_on_a_link_that_holds_a_remainder() {
        let mut table = AppLinkTable::new();
        let link = open_stream(&mut table);
        table
            .hold_remainder(link, b"held")
            .expect("an open link holds a remainder");
        let (count, waker) = counter();
        let room = LinkInterest {
            input: false,
            room: true,
        };
        assert!(
            !table.wait_link(link, room, &waker),
            "a remainder takes the room"
        );
        assert_eq!(
            wakes(&mut table, |table| table
                .event(link, ProgramEvent::Writable)
                .expect("an open link")),
            1
        );
        assert_eq!(count.0.load(Ordering::SeqCst), 1, "the writer is woken");
        assert_eq!(table.state(link), Some(AppLinkState::Open));
    }

    /// A drain that leaves a remainder empty on an open link wakes the writer waiting for room,
    /// though the program made no call; a drain that leaves bytes held wakes no one. Turned red by
    /// a room wait that sleeps past the drain another task did.
    #[test]
    fn a_drain_that_empties_a_remainder_wakes_the_room_wait() {
        let mut table = AppLinkTable::new();
        let link = open_stream(&mut table);
        table
            .hold_remainder(link, b"held")
            .expect("an open link holds a remainder");
        let (count, waker) = counter();
        let room = LinkInterest {
            input: false,
            room: true,
        };
        assert!(!table.wait_link(link, room, &waker));
        assert_eq!(wakes(&mut table, |table| table.drop_remainder(link, 2)), 0);
        assert_eq!(count.0.load(Ordering::SeqCst), 0, "bytes are still held");
        assert_eq!(wakes(&mut table, |table| table.drop_remainder(link, 2)), 1);
        assert_eq!(count.0.load(Ordering::SeqCst), 1, "the writer is woken");
        assert!(table.wait_link(link, room, &waker), "room again");
    }

    #[test]
    fn a_handle_is_never_zero_and_never_reused() {
        let mut table = AppLinkTable::new();
        let first = table.reserve(AppLinkKind::StreamDial, QUEUE);
        assert_ne!(first, 0);
        let _ = table.release(first);
        let _ = table.close_done(first);
        assert_eq!(table.state(first), None, "released and closed: forgotten");
        let second = table.reserve(AppLinkKind::StreamDial, QUEUE);
        assert_ne!(second, first);
    }

    #[test]
    fn an_open_the_program_answers_up_is_open_and_wakes_the_opener() {
        let mut table = AppLinkTable::new();
        let handle = table.reserve(AppLinkKind::StreamDial, QUEUE);
        let (count, waker) = counter();
        assert_eq!(table.poll_open(handle, Some(&waker)), OpenProgress::Opening);
        assert_eq!(
            wakes(&mut table, |table| table.opened(handle, ProgramOpen::Up)),
            1
        );
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(table.state(handle), Some(AppLinkState::Open));
        assert_eq!(table.poll_open(handle, None), OpenProgress::Open);
    }

    #[test]
    fn a_pending_open_comes_up_on_connected() {
        let mut table = AppLinkTable::new();
        let handle = table.reserve(AppLinkKind::StreamDial, QUEUE);
        assert!(table.opened(handle, ProgramOpen::Pending).is_empty());
        assert_eq!(table.state(handle), Some(AppLinkState::Opening));
        let (_count, waker) = counter();
        let _ = table.poll_open(handle, Some(&waker));
        assert_eq!(
            wakes(&mut table, |table| table
                .event(handle, ProgramEvent::Connected)
                .unwrap()),
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
        let handle = table.reserve(AppLinkKind::StreamDial, QUEUE);
        let _ = table.event(handle, ProgramEvent::Connected).unwrap();
        // Then the open returns, answering pending: the link stays up.
        assert!(table.opened(handle, ProgramOpen::Pending).is_empty());
        assert_eq!(table.state(handle), Some(AppLinkState::Open));
    }

    #[test]
    fn a_refused_open_is_closed_and_the_opener_hears_it() {
        let mut table = AppLinkTable::new();
        let handle = table.reserve(AppLinkKind::StreamDial, QUEUE);
        let (_count, waker) = counter();
        let _ = table.poll_open(handle, Some(&waker));
        assert_eq!(
            wakes(&mut table, |table| table
                .opened(handle, ProgramOpen::Refused)),
            1
        );
        assert_eq!(table.poll_open(handle, None), OpenProgress::Closed);
        // A pending open the program later reports closed is the same.
        let other = table.reserve(AppLinkKind::StreamDial, QUEUE);
        let _ = table.opened(other, ProgramOpen::Pending);
        let _ = table.event(other, ProgramEvent::Closed).unwrap();
        assert_eq!(table.poll_open(other, None), OpenProgress::Closed);
    }

    #[test]
    fn bytes_before_connected_are_refused() {
        let mut table = AppLinkTable::new();
        let handle = table.reserve(AppLinkKind::StreamDial, QUEUE);
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
            wakes(&mut table, |table| table
                .received(handle, &program_buffer, None)
                .unwrap()),
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
        assert_eq!(
            wakes(&mut table, |table| table
                .event(handle, ProgramEvent::Closed)
                .unwrap()),
            1
        );
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
            wakes(&mut table, |table| table
                .event(handle, ProgramEvent::Writable)
                .unwrap()),
            1
        );
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(table.state(handle), Some(AppLinkState::Open));
        assert!(matches!(table.begin_send(handle, None), SendGate::Go(_)));
    }

    /// A link takes bytes when it is open and holds nothing for the program. A blocked one does
    /// not, keeps the waiter and wakes it with the program's writable, which nothing the poll did
    /// begins; one that holds a remainder does not either; a closed one answers that it does, so
    /// the send that follows meets its end.
    #[test]
    fn a_link_is_writable_when_it_is_open_and_holds_nothing() {
        let mut table = AppLinkTable::new();
        let handle = open_stream(&mut table);
        assert!(
            table.poll_writable(handle, None),
            "an open link with nothing held"
        );
        let SendGate::Go(ticket) = table.begin_send(handle, None) else {
            panic!("an open link takes a send");
        };
        let (step, _) = table.send_answered(ticket, 8, ProgramSend::WouldBlock);
        assert_eq!(step, SendStep::Blocked);
        let (count, waker) = counter();
        assert!(
            !table.poll_writable(handle, Some(&waker)),
            "a blocked link takes nothing"
        );
        assert_eq!(
            wakes(&mut table, |table| table
                .event(handle, ProgramEvent::Writable)
                .unwrap()),
            1
        );
        assert_eq!(count.0.load(Ordering::SeqCst), 1, "the waiter is woken");
        assert!(table.poll_writable(handle, None), "writable again");
        assert!(
            matches!(table.begin_send(handle, None), SendGate::Go(_)),
            "the poll began no send"
        );
        table
            .hold_remainder(handle, b"held")
            .expect("an open link holds a remainder");
        assert!(
            !table.poll_writable(handle, None),
            "a link holding bytes for the program takes no more"
        );
        let mut closed = AppLinkTable::new();
        let gone = open_stream(&mut closed);
        let _ = closed.event(gone, ProgramEvent::Closed).expect("closed");
        assert!(
            closed.poll_writable(gone, None),
            "a closed link answers at once"
        );
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
            assert_eq!(
                perform(&mut table, effects).wakes,
                1,
                "the reader hears the close"
            );
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
        assert_eq!(
            perform(&mut table, effects).close,
            [handle],
            "the program is asked to close it"
        );
        assert_eq!(table.state(handle), Some(AppLinkState::Closing));
        assert!(table.received(handle, b"x", None).is_err());
        let done = table.close_done(handle);
        assert_eq!(perform(&mut table, done).wakes, 1);
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
            perform(&mut table, effects).close.is_empty(),
            "the program's side is already closed"
        );
        assert_eq!(table.state(handle), None);
    }

    #[test]
    fn releasing_an_opening_link_closes_it_on_the_program() {
        let mut table = AppLinkTable::new();
        let handle = table.reserve(AppLinkKind::StreamDial, QUEUE);
        let _ = table.opened(handle, ProgramOpen::Pending);
        let effects = table.release(handle);
        assert_eq!(perform(&mut table, effects).close, [handle]);
        // The program reporting closed while its close runs finishes it as well.
        let _ = table.event(handle, ProgramEvent::Closed).unwrap();
        assert_eq!(table.state(handle), None);
        assert!(table.close_done(handle).is_empty());
    }

    #[test]
    fn a_listener_queues_the_streams_the_program_accepts() {
        let mut table = AppLinkTable::new();
        let listener = table.reserve(AppLinkKind::StreamListen, QUEUE);
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
            table.next_accepted(listener, Some(&waker), taken_link),
            AcceptRead::Empty
        );
        let (stream, effects) = table.accepted(listener, "tcp/198.51.100.9:40001").unwrap();
        assert_eq!(perform(&mut table, effects).wakes, 1);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(table.kind(stream), Some(AppLinkKind::StreamAccepted));
        assert_eq!(table.state(stream), Some(AppLinkState::Open));
        assert_eq!(table.remote(stream), Some("tcp/198.51.100.9:40001"));
        // An accepted stream takes bytes at once.
        let _ = table.received(stream, b"hi", None).unwrap();
        assert_eq!(
            table.next_accepted(listener, None, taken_link),
            AcceptRead::Accepted((stream, String::from("tcp/198.51.100.9:40001")))
        );
        assert_eq!(
            table.next_accepted(listener, None, taken_link),
            AcceptRead::Empty
        );
        // A listener carries no bytes and takes no send.
        assert_eq!(
            table.received(listener, b"x", None).unwrap_err(),
            InboundRefusal::WrongKind
        );
        assert_eq!(table.begin_send(listener, None), SendGate::Closed);
    }

    #[test]
    fn a_datagram_listener_accepts_each_source_as_a_datagram_link() {
        let mut table = AppLinkTable::new();
        let listener = table.reserve(AppLinkKind::DatagramListen, QUEUE);
        let _ = table.opened(listener, ProgramOpen::Up);
        let (link, _) = table.accepted(listener, "udp/198.51.100.7:40000").unwrap();
        assert_eq!(table.kind(link), Some(AppLinkKind::DatagramAccepted));
        let _ = table
            .received(link, b"d", Some("udp/198.51.100.7:40000"))
            .unwrap();
        assert!(matches!(
            table.read_datagram(link, None, |datagram| datagram.to_received()),
            DatagramRead::Datagram(_)
        ));
        // The listener itself carries nothing and sends nothing.
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
        let listener = table.reserve(AppLinkKind::StreamListen, QUEUE);
        let _ = table.opened(listener, ProgramOpen::Up);
        let (stream, _) = table.accepted(listener, "tcp/198.51.100.9:40003").unwrap();
        let effects = table.release(listener);
        let performed = perform(&mut table, effects);
        assert!(performed.close.contains(&listener));
        assert!(
            performed.close.contains(&stream),
            "the untaken stream is closed too"
        );
        for handle in performed.close {
            let _ = table.close_done(handle);
        }
        assert!(table.is_empty());
    }

    #[test]
    fn a_datagram_is_read_whole_with_the_locator_it_came_from() {
        let mut table = AppLinkTable::new();
        let handle = table.reserve(AppLinkKind::Group, QUEUE);
        let _ = table.opened(handle, ProgramOpen::Up);
        let _ = table
            .received(handle, b"one", Some("udp/198.51.100.4:7447"))
            .unwrap();
        let _ = table
            .received(handle, b"", Some("udp/198.51.100.5:7447"))
            .unwrap();
        // A group's datagram that names no source is refused: the members are told apart by it.
        assert_eq!(
            table.received(handle, b"anon", None).unwrap_err(),
            InboundRefusal::NoSource
        );
        assert_eq!(
            table.read_datagram(handle, None, |datagram| datagram.to_received()),
            DatagramRead::Datagram(Received {
                bytes: b"one".to_vec(),
                source: Some(String::from("udp/198.51.100.4:7447")),
            })
        );
        assert_eq!(
            table.read_datagram(handle, None, |datagram| datagram.to_received()),
            DatagramRead::Datagram(Received {
                bytes: Vec::new(),
                source: Some(String::from("udp/198.51.100.5:7447")),
            }),
            "an empty datagram is a datagram"
        );
        assert_eq!(
            table.read_datagram(handle, None, |datagram| datagram.to_received()),
            DatagramRead::Empty
        );
        let _ = table.event(handle, ProgramEvent::Closed).unwrap();
        assert_eq!(
            table.read_datagram(handle, None, |datagram| datagram.to_received()),
            DatagramRead::End
        );
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

    #[test]
    fn bytes_past_the_bound_are_refused_and_change_nothing() {
        let mut table = AppLinkTable::new();
        let handle = open_stream_under(&mut table, Quota::at_most(8));
        let _ = table.received(handle, b"abcdef", None).unwrap();
        assert_eq!(
            table.received(handle, b"ghi", None).unwrap_err(),
            InboundRefusal::Full
        );
        assert_eq!(
            table.queued_bytes(handle),
            6,
            "nothing of the refused call was taken"
        );
        // What fits is still taken.
        let _ = table.received(handle, b"gh", None).unwrap();
        assert_eq!(table.queued_bytes(handle), 8);
    }

    #[test]
    fn a_refused_program_is_told_once_the_queue_is_read_down_to_half() {
        let mut table = AppLinkTable::new();
        let handle = open_stream_under(&mut table, Quota::at_most(8));
        let _ = table.received(handle, b"abcdefgh", None).unwrap();
        assert!(table.received(handle, b"i", None).is_err());
        let mut buf = [0u8; 3];
        assert_eq!(
            table.read_stream(handle, &mut buf, None),
            StreamRead::Bytes(3)
        );
        assert!(
            drained(&mut table).is_empty(),
            "five bytes still queued: above half the bound"
        );
        assert_eq!(
            table.read_stream(handle, &mut buf, None),
            StreamRead::Bytes(3)
        );
        assert_eq!(drained(&mut table), [handle], "two queued: at most half");
        assert!(drained(&mut table).is_empty(), "told once");
        // The retry is taken.
        let _ = table.received(handle, b"i", None).unwrap();
        assert_eq!(table.queued_bytes(handle), 3);
    }

    #[test]
    fn a_link_never_refused_is_never_reported_drained() {
        let mut table = AppLinkTable::new();
        let handle = open_stream_under(&mut table, Quota::at_most(8));
        let _ = table.received(handle, b"abc", None).unwrap();
        let mut buf = [0u8; 8];
        let _ = table.read_stream(handle, &mut buf, None);
        assert!(drained(&mut table).is_empty());
    }

    #[test]
    fn a_datagram_up_to_the_bound_is_taken_and_one_past_it_is_too_large() {
        let mut table = AppLinkTable::new();
        let handle = table.reserve(AppLinkKind::Datagram, Quota::at_most(4));
        let _ = table.opened(handle, ProgramOpen::Up);
        assert_eq!(
            table.received(handle, b"longer", None).unwrap_err(),
            InboundRefusal::TooLarge,
            "no queue of this link could take it"
        );
        let _ = table
            .received(handle, b"four", Some("udp/198.51.100.4:7447"))
            .unwrap();
        assert_eq!(
            table.received(handle, b"x", None).unwrap_err(),
            InboundRefusal::Full
        );
        assert!(matches!(
            table.read_datagram(handle, None, |datagram| datagram.to_received()),
            DatagramRead::Datagram(_)
        ));
        assert_eq!(drained(&mut table), [handle]);
    }
    #[test]
    fn a_held_remainder_is_offered_in_order_and_dropped_as_taken() {
        let mut table = AppLinkTable::new();
        let handle = open_stream_under(&mut table, Quota::at_most(8));
        table.hold_remainder(handle, b"abc").unwrap();
        table.hold_remainder(handle, b"de").unwrap();
        assert_eq!(table.remainder(handle), b"abcde");
        let _ = table.drop_remainder(handle, 2);
        assert_eq!(table.remainder(handle), b"cde");
        assert_eq!(
            table.hold_remainder(handle, b"fghijk").unwrap_err(),
            InboundRefusal::Full,
            "past the bound"
        );
        assert_eq!(
            table.remainder(handle),
            b"cde",
            "nothing of the refused hold was kept"
        );
        let _ = table.drop_remainder(handle, 99);
        assert!(table.remainder(handle).is_empty());
        let _ = table.event(handle, ProgramEvent::Closed).unwrap();
        assert_eq!(
            table.hold_remainder(handle, b"x").unwrap_err(),
            InboundRefusal::Closed
        );
    }

    #[test]
    fn each_link_is_held_to_the_bound_it_was_opened_with() {
        let mut table = AppLinkTable::new();
        let narrow = open_stream_under(&mut table, Quota::at_most(4));
        let wide = open_stream_under(&mut table, Quota::at_most(8));
        let _ = table.received(narrow, b"abc", None).unwrap();
        let _ = table.received(wide, b"abc", None).unwrap();
        assert_eq!(
            table.received(narrow, b"de", None).unwrap_err(),
            InboundRefusal::Full
        );
        let _ = table.received(wide, b"de", None).unwrap();
        assert_eq!(table.queued_bytes(narrow), 3, "the refusal took nothing");
        assert_eq!(table.queued_bytes(wide), 5);
    }

    #[test]
    fn an_accepted_link_keeps_the_bound_of_its_listener() {
        let mut table = AppLinkTable::new();
        let listener = table.reserve(AppLinkKind::StreamListen, Quota::at_most(4));
        let _ = table.opened(listener, ProgramOpen::Up);
        let (stream, _) = table.accepted(listener, "tcp/198.51.100.9:40004").unwrap();
        let _ = table.received(stream, b"abcd", None).unwrap();
        assert_eq!(
            table.received(stream, b"e", None).unwrap_err(),
            InboundRefusal::Full
        );
        assert_eq!(table.queued_bytes(stream), 4);
    }

    #[test]
    fn a_link_with_no_bound_takes_every_byte() {
        let mut table = AppLinkTable::new();
        let handle = open_stream_under(&mut table, Quota::UNBOUNDED);
        for _ in 0..4 {
            let _ = table.received(handle, &[0u8; 1024], None).unwrap();
        }
        assert_eq!(table.queued_bytes(handle), 4096);
        table.hold_remainder(handle, &[0u8; 4096]).unwrap();
        assert_eq!(table.remainder(handle).len(), 4096);
    }

    #[test]
    fn a_link_of_no_bytes_holds_one_byte_at_a_time() {
        let mut table = AppLinkTable::new();
        let handle = open_stream_under(&mut table, Quota::at_most(0));
        assert_eq!(
            table.received(handle, b"ab", None).unwrap_err(),
            InboundRefusal::TooLarge
        );
        let _ = table.received(handle, b"a", None).unwrap();
        assert_eq!(
            table.received(handle, b"c", None).unwrap_err(),
            InboundRefusal::Full
        );
        table.hold_remainder(handle, b"x").unwrap();
        assert_eq!(
            table.hold_remainder(handle, b"y").unwrap_err(),
            InboundRefusal::Full
        );
    }

    /// A datagram link opened under `queue`, up.
    fn open_datagram_under(table: &mut AppLinkTable, queue: Quota) -> LinkHandle {
        let handle = table.reserve(AppLinkKind::Datagram, queue);
        let _ = table.opened(handle, ProgramOpen::Up);
        handle
    }

    /// `len` bytes that differ from their neighbours, so a run read from the wrong place shows.
    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|at| (at as u8).wrapping_add(seed)).collect()
    }

    #[test]
    fn datagrams_are_read_whole_where_the_queue_wraps() {
        let mut table = AppLinkTable::new();
        let handle = open_datagram_under(&mut table, Quota::at_most(60_000));
        let source = Some("udp/198.51.100.4:7447");
        let read = |table: &mut AppLinkTable| {
            table.read_datagram(handle, None, |datagram| datagram.to_received())
        };
        // Two held at a time, so each one queued after the first lands where the last left off
        // and the storage, a little over one widest datagram, wraps under them.
        let mut held = alloc::collections::VecDeque::new();
        for seed in 0..6u8 {
            let datagram = pattern(25_000, seed);
            let _ = table.received(handle, &datagram, source).unwrap();
            held.push_back(datagram);
            if held.len() == 2 {
                let oldest = held.pop_front().unwrap();
                assert_eq!(
                    read(&mut table),
                    DatagramRead::Datagram(Received {
                        bytes: oldest,
                        source: source.map(String::from),
                    }),
                    "datagram {seed}"
                );
            }
        }
        let last = held.pop_front().unwrap();
        assert_eq!(
            read(&mut table),
            DatagramRead::Datagram(Received {
                bytes: last,
                source: source.map(String::from),
            })
        );
        assert_eq!(table.queued_bytes(handle), 0);
    }

    #[test]
    fn stream_bytes_are_read_in_order_where_the_queue_wraps() {
        let mut table = AppLinkTable::new();
        let handle = open_stream_under(&mut table, Quota::at_most(60_000));
        let first = pattern(40_000, 1);
        let second = pattern(40_000, 2);
        let _ = table.received(handle, &first, None).unwrap();
        let mut buf = alloc::vec![0u8; 30_000];
        assert_eq!(
            table.read_stream(handle, &mut buf, None),
            StreamRead::Bytes(30_000)
        );
        assert_eq!(buf[..], first[..30_000]);
        // Ten thousand bytes still held near the middle: the next forty thousand wrap.
        let _ = table.received(handle, &second, None).unwrap();
        let mut rest = alloc::vec![0u8; 50_000];
        assert_eq!(
            table.read_stream(handle, &mut rest, None),
            StreamRead::Bytes(50_000)
        );
        assert_eq!(rest[..10_000], first[30_000..]);
        assert_eq!(rest[10_000..], second[..]);
        assert_eq!(table.queued_bytes(handle), 0);
    }

    #[test]
    fn a_datagram_is_copied_cut_to_the_buffer() {
        let mut table = AppLinkTable::new();
        let handle = open_datagram_under(&mut table, QUEUE);
        let _ = table.received(handle, b"abcdef", None).unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(
            table.read_datagram(handle, None, |datagram| {
                let source = datagram.source().map(String::from);
                (datagram.len(), datagram.copy_to(&mut buf), source)
            }),
            DatagramRead::Datagram((6, 4, None))
        );
        assert_eq!(&buf, b"abcd");
        assert_eq!(
            table.queued_bytes(handle),
            0,
            "the whole datagram was let go"
        );
    }

    #[test]
    fn an_empty_locator_is_read_back_as_named() {
        let mut table = AppLinkTable::new();
        let handle = open_datagram_under(&mut table, QUEUE);
        let _ = table.received(handle, b"x", Some("")).unwrap();
        assert_eq!(
            table.read_datagram(handle, None, |datagram| datagram.to_received()),
            DatagramRead::Datagram(Received {
                bytes: b"x".to_vec(),
                source: Some(String::new()),
            })
        );
    }

    #[test]
    fn what_no_storage_could_hold_is_refused_as_too_large() {
        let mut table = AppLinkTable::new();
        let datagrams = open_datagram_under(&mut table, QUEUE);
        assert_eq!(
            table
                .received(datagrams, &alloc::vec![0u8; DATAGRAM_MAX + 1], None)
                .unwrap_err(),
            InboundRefusal::TooLarge
        );
        let long = "u".repeat(SOURCE_MAX + 1);
        assert_eq!(
            table
                .received(datagrams, b"x", Some(long.as_str()))
                .unwrap_err(),
            InboundRefusal::TooLarge
        );
        // At the edges both are taken.
        let edge = "u".repeat(SOURCE_MAX);
        let _ = table
            .received(
                datagrams,
                &alloc::vec![0u8; DATAGRAM_MAX],
                Some(edge.as_str()),
            )
            .unwrap();
        let stream = open_stream_under(&mut table, Quota::at_most(4));
        assert_eq!(
            table.received(stream, b"fives", None).unwrap_err(),
            InboundRefusal::TooLarge
        );
        assert_eq!(table.queued_bytes(stream), 0, "nothing of it was taken");
        let _ = table.received(stream, b"four", None).unwrap();
        // A link with no bound grows to what it is handed.
        let open = open_stream_under(&mut table, Quota::UNBOUNDED);
        let _ = table
            .received(open, &alloc::vec![0u8; 2 * DATAGRAM_MAX], None)
            .unwrap();
        assert_eq!(table.queued_bytes(open), 2 * DATAGRAM_MAX);
    }

    #[test]
    fn a_queue_whose_storage_is_full_refuses_under_the_bound_and_says_when_it_drains() {
        let mut table = AppLinkTable::new();
        let bound = 2 * DATAGRAM_MAX;
        let handle = open_datagram_under(&mut table, Quota::at_most(bound));
        let source = "s".repeat(SOURCE_MAX);
        let mut taken = 0;
        while table.received(handle, b"d", Some(source.as_str())).is_ok() {
            taken += 1;
        }
        assert_eq!(
            taken,
            (bound + RECORD_HEAD + SOURCE_MAX) / (RECORD_HEAD + SOURCE_MAX + 1),
            "each datagram's head and locator take storage the bound does not count"
        );
        assert!(table.queued_bytes(handle) < bound / 2);
        assert_eq!(
            table
                .received(handle, b"d", Some(source.as_str()))
                .unwrap_err(),
            InboundRefusal::Full
        );
        assert!(matches!(
            table.read_datagram(handle, None, |_| ()),
            DatagramRead::Datagram(())
        ));
        assert_eq!(drained(&mut table), [handle]);
        let _ = table.received(handle, b"d", Some(source.as_str())).unwrap();
    }

    #[test]
    fn a_stream_link_lends_no_datagram() {
        let mut table = AppLinkTable::new();
        let handle = open_stream(&mut table);
        let _ = table.received(handle, b"ab", None).unwrap();
        assert!(matches!(
            table.read_datagram(handle, None, |_| ()),
            DatagramRead::End
        ));
        assert_eq!(table.queued_bytes(handle), 2, "the stream's bytes stay");
    }

    #[test]
    fn a_task_due_to_be_woken_is_woken_once_however_many_wait() {
        let mut wakes = Wakes::default();
        let counters: Vec<_> = (0..5).map(|_| counter()).collect();
        for (_, waker) in &counters {
            wakes.push(waker.clone());
            // The same task again is the one kept.
            wakes.push(waker.clone());
        }
        let mut woken = 0;
        while let Some(waker) = wakes.pop() {
            waker.wake();
            woken += 1;
        }
        assert_eq!(woken, 5, "past one link's three the rest are kept too");
        for (count, _) in &counters {
            assert_eq!(count.0.load(Ordering::SeqCst), 1);
        }
    }

    /// The rows the table holds, free or not.
    fn rows(table: &AppLinkTable) -> usize {
        table.rows.len()
    }

    #[test]
    fn a_provisioned_row_is_taken_by_a_dial_and_by_an_accept_and_kept_for_the_next() {
        let mut table = AppLinkTable::new();
        let queue = Quota::at_most(64);
        table.provision(2, queue);
        assert_eq!(rows(&table), 2);
        assert!(table.is_empty(), "a provisioned row holds no link");
        let dial = table.reserve(AppLinkKind::StreamDial, queue);
        let listener = table.reserve(AppLinkKind::StreamListen, queue);
        assert_eq!(rows(&table), 3, "the listener takes a row of its own");
        let _ = table.opened(listener, ProgramOpen::Up);
        let (accepted, _) = table.accepted(listener, "tcp/198.51.100.9:40005").unwrap();
        assert_eq!(
            rows(&table),
            3,
            "the accepted link takes the other provisioned row"
        );
        // The accepted link's storage holds the whole bound.
        let _ = table.opened(dial, ProgramOpen::Up);
        let _ = table.received(accepted, &[7u8; 64], None).unwrap();
        for link in [dial, accepted] {
            let effects = table.release(link);
            let _ = perform(&mut table, effects);
            let _ = table.close_done(link);
        }
        assert_eq!(table.len(), 1, "the listener is left");
        // The session opened again takes the rows it left free.
        table.provision(2, queue);
        assert_eq!(rows(&table), 3);
        let again = table.reserve(AppLinkKind::Datagram, queue);
        assert!(
            again > accepted,
            "a handle is never reused, though its row is"
        );
        assert_eq!(rows(&table), 3);
        assert_eq!(
            table.queued_bytes(again),
            0,
            "nothing of the row's last link is left"
        );
        // A link held to a wider bound than any free row holds takes a row of its own.
        let _ = table.reserve(AppLinkKind::StreamDial, Quota::at_most(1 << 10));
        assert_eq!(rows(&table), 4);
    }

    #[test]
    fn a_listener_hands_out_its_links_oldest_first() {
        let mut table = AppLinkTable::new();
        let listener = table.reserve(AppLinkKind::StreamListen, QUEUE);
        let _ = table.opened(listener, ProgramOpen::Up);
        let (first, _) = table.accepted(listener, "tcp/198.51.100.9:1").unwrap();
        let (second, _) = table.accepted(listener, "tcp/198.51.100.9:2").unwrap();
        assert!(table.poll_readable(listener, None));
        assert_eq!(
            table.next_accepted(listener, None, taken_link),
            AcceptRead::Accepted((first, String::from("tcp/198.51.100.9:1")))
        );
        assert_eq!(
            table.next_accepted(listener, None, taken_link),
            AcceptRead::Accepted((second, String::from("tcp/198.51.100.9:2")))
        );
        assert!(!table.poll_readable(listener, None));
        let long = "t".repeat(SOURCE_MAX + 1);
        assert_eq!(
            table.accepted(listener, &long).unwrap_err(),
            InboundRefusal::TooLarge
        );
    }

    #[test]
    fn what_is_due_is_handed_out_closes_first_then_drained_then_wakes() {
        let mut table = AppLinkTable::new();
        let full = open_stream_under(&mut table, Quota::at_most(2));
        let _ = table.received(full, b"ab", None).unwrap();
        assert!(table.received(full, b"c", None).is_err());
        let (count, waker) = counter();
        let closing = open_stream(&mut table);
        let mut buf = [0u8; 2];
        let _ = table.read_stream(closing, &mut buf, Some(&waker));
        let _ = table.read_stream(full, &mut buf, None);
        let _ = table.event(closing, ProgramEvent::Closed).unwrap();
        let third = open_stream(&mut table);
        let _ = table.release(third);
        let mut order = Vec::new();
        while let Some(due) = table.next_due() {
            order.push(match due {
                Due::Close(_) => "close",
                Due::Drained(_) => "drained",
                Due::Wake(waker) => {
                    waker.wake();
                    "wake"
                }
            });
        }
        // The program's own close of a link may or may not leave a close of the table's due; the
        // order is what is asserted.
        order.dedup();
        assert_eq!(order, ["close", "drained", "wake"]);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(table.next_due().is_none());
    }
}
